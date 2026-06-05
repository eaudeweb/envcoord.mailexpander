#!/usr/bin/env python
# -*- coding: utf-8 -*-

from copy import deepcopy
from envcoord.mailexpander.expander import Expander, RETURN_CODES, log
from mock import Mock
from test_ldap_agent import StubbedLdapAgent
import email
import ldap
import logging
import os
import smtplib
import unittest


log.setLevel(logging.CRITICAL)


def ldap_search(dn, scope, ldap_data, **kwargs):
    """ Used to return data from different ldap_data sources """
    for l_dn, l_scope, data in ldap_data:
        if (l_dn, l_scope) == (dn, scope):
            return data
    return []


class ExpanderTest(unittest.TestCase):

    def setUp(self):
        self.agent = StubbedLdapAgent(ldap_server='', user_dn='', user_pw='')
        self.agent.roles_with_member = Mock(return_value=[])
        self.mock_conn = self.agent.conn

        self.expander = Expander(self.agent)
        self.expander.send_emails = Mock(return_value=RETURN_CODES['EX_OK'])

        # Load fixtures from ./fixtures directory into dictionary with keys as
        # filenames without extentions
        self.fixtures = {}
        fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        fixture_paths = os.listdir(fixtures_dir)
        for fixture_filename in fixture_paths:
            fixture_path = os.path.join(fixtures_dir, fixture_filename)
            if os.path.isfile(fixture_path):
                content = None
                f = open(fixture_path, 'rb')
                content = f.read()
                f.close()
                self.fixtures[os.path.splitext(fixture_filename)[0]] = content

        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        self.ldap_data = [
            (role_dn('test'), ldap.SCOPE_BASE, [
                [role_dn('test'), {
                    'objectClass': ['groupOfUniqueNames'],
                    'uniqueMember': [user_dn('userone'), user_dn('usertwo'),
                                     user_dn('user3'), user_dn('user4')],
                    'permittedPerson': [user_dn('user4')],
                    'permittedSender': ['test@email.com',
                                        '*@email.com', 'members', 'owners'],
                    'owner': [user_dn('user3')]
                }],
            ]),
            (role_dn('test-gb'), ldap.SCOPE_BASE, [
                [role_dn('test-gb'), {
                    'objectClass': ['groupOfUniqueNames'],
                    'uniqueMember': [user_dn('user3')],
                    'permittedPerson': [user_dn('user4')],
                    'permittedSender': ['test@email.com',
                                        '*@email.com', 'members', 'owners'],
                    'owner': [user_dn('user3')]
                }],
            ]),
            (role_dn('test-ro'), ldap.SCOPE_BASE, [
                [role_dn('test-ro'), {
                    'objectClass': ['groupOfUniqueNames'],
                    'uniqueMember': [user_dn('user4')],
                    'permittedPerson': [user_dn('user4')],
                    'permittedSender': ['test@email.com',
                                        '*@email.com', 'members', 'owners'],
                    'owner': [user_dn('user4')]
                }],
            ]),
            (role_dn('unowned'), ldap.SCOPE_BASE, [
                [role_dn('unowned'), {
                    'objectClass': ['groupOfUniqueNames'],
                    'uniqueMember': [user_dn('userone'), user_dn('usertwo')],
                    'permittedPerson': [user_dn('user4')],
                    'permittedSender': ['test@email.com',
                                        '*@email.com', 'members', 'owners'],
                }],
            ]),
            (user_dn('userone'), ldap.SCOPE_BASE, [
                (user_dn('userone'), {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                    'telephoneNumber': ['555 1234 2'],
                    'o': ['Testers Club'],
                }),
            ]),
            (user_dn('usertwo'), ldap.SCOPE_BASE, [
                (user_dn('usertwo'), {
                    'cn': ['User two'],
                    'mail': ['user_two@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 2'],
                }),
            ]),
            (user_dn('user3'), ldap.SCOPE_BASE, [
                (user_dn('user3'), {
                    'cn': ['User three'],
                    'mail': ['user_three@example.com',
                             'user_3333@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 2'],
                }),
            ]),
            (user_dn('user4'), ldap.SCOPE_BASE, [
                (user_dn('user4'), {
                    'cn': ['User four'],
                    'mail': ['user_four@example.com'],
                    'telephoneNumber': ['5155 1234 2'],
                    'o': ['Testers Club 5'],
                }),
            ]),
        ]

        def ldap_search_called(dn, scope, **kwargs):
            return ldap_search(dn, scope, self.ldap_data, **kwargs)

        self.mock_conn.search_s.side_effect = ldap_search_called

        self.agent.roles_with_member.side_effect = self.roles_with_member

    def roles_with_member(self, dn):
        """ """
        result = []
        for l_dn, scope, l_data in self.ldap_data:
            if 'groupOfUniqueNames' in l_data[0][1].get('objectClass', []):
                if dn in l_data[0][1].get('uniqueMember', []):
                    result.append(l_dn)
        if result:
            return [item.split(',')[0][3:] for item in result]
        else:
            return []

    def test_error_codes_in_agent(self):
        no_user = RETURN_CODES['EX_NOUSER']
        ok = RETURN_CODES['EX_OK']
        assert self.expander.expand('user_one@example.com',
                                    'test@roles.eionet.europa.eu', "") == ok
        assert self.expander.expand('user_one@example.com',
                                    'test1@roles.eionet.europa.eu', "") == \
            no_user

    def test_can_expand_by_inheritance(self):
        """ Test if people specified in above hierarchy can expand
        """

        from_email = 'user_one@example.com'
        role = "user_one"

        role_data = {'description': 'no owner',
                     'members_data': {},
                     'permittedSender': ['test@email.com'],
                     }
        assert self.expander.can_expand(from_email, role, role_data) is False

        def patched(role_id, role_data):
            role_data['permittedSender'].append('user_one@example.com')
            return role_data

        old = self.expander.add_inherited_senders
        self.expander.add_inherited_senders = patched
        assert self.expander.can_expand(from_email, role, role_data) is True
        self.expander.add_inherited_senders = old

    def test_add_inherited_senders(self):
        class Agent(Mock):

            def _role_dn(self, role_id):
                return "cn=top-middle-end,cn=top-middle,"\
                       "cn=top,ou=Roles,o=EIONET,l=Europe"

            def _ancestor_roles_dn(self, role_dn):
                return [
                    "cn=top-middle-end,cn=top-middle,cn=top,ou=Roles,"
                    "o=EIONET,l=Europe",
                    "cn=top-middle,cn=top,ou=Roles,o=EIONET,l=Europe",
                    "cn=top,ou=Roles,o=EIONET,l=Europe",
                ]

            def _query(self, user_id):
                data = {
                    'parent_owner': {'mail': ['parent_owner@example.com']},
                    'top_person': {'mail': ['root_parent_person@example.com']},
                    'member_one': {'mail': ['member_one@example.com']}
                }
                return data[user_id]

            def _role_info(self, role_dn):
                data = {
                    "cn=top-middle-end,cn=top-middle,cn=top,ou=Roles,"
                    "o=EIONET,l=Europe":
                        {'permittedSender': []},
                    "cn=top-middle,cn=top,ou=Roles,o=EIONET,l=Europe":
                        {'permittedSender': ['owners',
                                             'members',
                                             'parent_sender@example.com'],
                         'owner': ['parent_owner'],
                         'members': ['member_one'],
                         },
                    "cn=top,ou=Roles,o=EIONET,l=Europe":
                        {'permittedSender': [],
                         'permittedPerson': ['top_person']},
                }
                return data[role_dn]

        self.expander.agent = Agent()
        role_data = self.expander.add_inherited_senders(
            'top-middle-end', {'permittedSender': ['control']})

        assert set(role_data['permittedSender']) == set(
            ['control',
             'parent_owner@example.com',
             'parent_sender@example.com',
             'member_one@example.com',
             'root_parent_person@example.com'])

    def test_send(self):
        """ Test successful sending of the e-mails (7bit, 8bit, base64, binary)
        After the modifications of the headers during the expantion
        the content itself should remain unmodified.

        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'
        # dest_emails = ['user_two@example.com', 'user_one@example.com']

        self.expander.can_expand = Mock(return_value=True)

        for fixture_name, fixture_content in self.fixtures.iteritems():
            return_code = self.expander.expand(from_email, role_email,
                                               self.fixtures[fixture_name])
            self.assertEqual(return_code, RETURN_CODES['EX_OK'])

            new_body = self.expander.send_emails.call_args[0][2]

            em = email.message_from_string(new_body)
            self.assertEqual(len(em.get_all('sender')), 1)
            self.assertEqual(em.get('sender'), role_email)
            # Subject may contain line breaks from long header folding
            subject = ' '.join(em.get('subject').split())
            self.assertIn('[Sent on behalf of %s]' % from_email, subject)

            ignore_headers = ('received', 'sender', 'subject', 'list-id',
                              'list-post', 'return-path', 'x-auth-id',
                              'from', 'cc')  # Checked above or modified
            # Check the rest of the message, make sure they stay the same
            old_em = email.message_from_string(
                email.message_from_string(fixture_content).as_string())

            for header, value in em.items():
                if header.lower() not in ignore_headers:
                    self.assertEquals(value, old_em.get(header))

            if hasattr(str, 'partition'):  # Don't test if <2.5
                # Based on boundary make sure the message body is untouched
                boundary = em.get_boundary()
                old_body = old_em.as_string().rpartition(boundary)[0].\
                    partition(boundary)[2].partition(boundary)[2]
                new_body = em.as_string().rpartition(boundary)[0].\
                    partition(boundary)[2].partition(boundary)[2]
                self.assertEquals(old_body, new_body)

    def test_send_to_owners(self):
        from_email = 'user_one@example.com'
        role_email = 'owner-test@roles.eionet.europa.eu'
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_three@example.com', 'user_3333@example.com'])

    def test_owner_ndr_routed_to_single_mailbox(self):
        """ MTA delivery-failure notices ("Undeliverable" DSNs) bounce back to
        owner-<role>@ with a null envelope sender. They must be funnelled to
        the single configured mailbox, not fanned out to the role's owners.
        """
        self.expander.bounce_send_to = 'ccpie.ccim@health.fgov.be'
        # role-with-an-owner, but the DSN has a null/empty envelope sender
        for null_sender in ('', 'MAILER-DAEMON'):
            self.expander.send_emails.reset_mock()
            res = self.expander.expand(null_sender,
                                       'owner-test@roles.eionet.europa.eu',
                                       self.fixtures['content_7bit'])
            self.assertEqual(res, RETURN_CODES['EX_OK'])
            self.assertEqual(self.expander.send_emails.call_args[0][1],
                             ['ccpie.ccim@health.fgov.be'])

    def test_owner_ndr_falls_back_to_no_owner_send_to(self):
        """ If bounce_send_to is unset, NDR routing falls back to
        no_owner_send_to.
        """
        self.expander.bounce_send_to = ''
        self.expander.no_owner_send_to = 'ccpie.ccim@health.fgov.be'
        res = self.expander.expand('', 'owner-test@roles.eionet.europa.eu',
                                   self.fixtures['content_7bit'])
        self.assertEqual(res, RETURN_CODES['EX_OK'])
        self.assertEqual(self.expander.send_emails.call_args[0][1],
                         ['ccpie.ccim@health.fgov.be'])

    def test_owner_ndr_missing_config(self):
        """ A delivery-failure notice with no mailbox configured returns
        EX_CONFIG rather than silently dropping it.
        """
        self.expander.bounce_send_to = ''
        self.expander.no_owner_send_to = ''
        res = self.expander.expand('', 'owner-test@roles.eionet.europa.eu',
                                   self.fixtures['content_7bit'])
        self.assertEqual(res, RETURN_CODES['EX_CONFIG'])

    def test_send_filtered(self):

        from_email = 'test@email.com'
        role_email = 'test@roles.eionet.europa.eu'
        role_email_gb = 'test-gb@roles.eionet.europa.eu'

        self.expander.roles_to_filter = []
        self.expander.filter_str = ''
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(set(self.expander.send_emails.call_args[0][1]),
                          set(['user_four@example.com',
                               'user_three@example.com',
                               'user_3333@example.com',
                               'user_two@example.com',
                               'user_one@example.com']))

        self.expander.roles_to_filter = []
        self.expander.filter_str = '-gb'
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(set(self.expander.send_emails.call_args[0][1]),
                          set(['user_four@example.com',
                               'user_three@example.com',
                               'user_3333@example.com',
                               'user_two@example.com',
                               'user_one@example.com']))

        self.expander.roles_to_filter = ['test']
        self.expander.filter_str = ''
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(set(self.expander.send_emails.call_args[0][1]),
                          set(['user_four@example.com',
                               'user_three@example.com',
                               'user_3333@example.com',
                               'user_two@example.com',
                               'user_one@example.com']))

        self.expander.roles_to_filter = ['test']
        self.expander.filter_str = '-gb'
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(set(self.expander.send_emails.call_args[0][1]),
                          set(['user_four@example.com',
                               'user_two@example.com',
                               'user_one@example.com']))

        self.expander.roles_to_filter = ['test']
        self.expander.filter_str = '-gb'
        self.expander.expand(from_email, role_email_gb,
                             self.fixtures['content_7bit'])
        self.assertEquals(set(self.expander.send_emails.call_args[0][1]),
                          set(['user_three@example.com',
                               'user_3333@example.com']))

    def test_send_to_fallback_owner(self):
        from_email = 'user_one@example.com'
        role_email = 'owner-unowned@roles.eionet.europa.eu'
        self.expander.no_owner_send_to = 'test@example.com'
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1],
                          ['test@example.com'])
        del self.expander.no_owner_send_to

    def test_send_to_fallback_owner_missing_config(self):
        from_email = 'user_one@example.com'
        role_email = 'owner-unowned@roles.eionet.europa.eu'
        res = self.expander.expand(from_email, role_email,
                                   self.fixtures['content_7bit'])
        self.assertEquals(res, RETURN_CODES['EX_CONFIG'])

    def test_smtp_failure(self):
        """ SMTP Failure test """

        self.expander.send_emails = Mock(side_effect=smtplib.SMTPException)
        return_code = self.expander.expand('user_one@example.com',
                                           'test@roles.eionet.europa.eu',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_SOFTWARE'])

    def test_can_expand(self):
        """ Check if the user can expand, test with invalid
        ldap entries

        """
        def send_emails_called(from_email, emails, content):
            """ Content is modified but this is not the subject of this test"""
            assert set(emails) == set([
                'user_four@example.com', 'user_three@example.com',
                'user_3333@example.com', 'user_two@example.com',
                'user_one@example.com'])
            return RETURN_CODES['EX_OK']

        self.expander.send_emails.side_effect = send_emails_called

        role_email = 'test@roles.eionet.europa.eu'
        return_code = self.expander.expand('test@email.com',
                                           role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # Should work see permittedSender: *@email.com
        return_code = self.expander.expand('someone@email.com',
                                           role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # Should fail - no such user
        return_code = self.expander.expand('someone@yyyy.ro', role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOPERM'])

        # Owner can send
        return_code = self.expander.expand('user_three@example.com',
                                           role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # Member can send
        return_code = self.expander.expand('user_one@example.com',
                                           role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # PermitedPerson
        return_code = self.expander.expand('user_four@example.com',
                                           role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # PermitedPerson with CamelCase - email addresses are case insensitve
        return_code = self.expander.expand('User_Four@example.com',
                                           role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # *@email as destination
        return_code = self.expander.expand('user_four@example.com',
                                           '*@email.com',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

        # te*@email as destination
        return_code = self.expander.expand('user_four@example.com',
                                           'te*@email.com',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

    def test_anyone_can_expand(self):
        """ Anyone can expand.
        'anyone' value in permittedSender attribute

        """
        user_dn = self.agent._user_dn

        self.agent.get_role = Mock(return_value={
            'description': 'anyone',
            'owner': [user_dn('userone')],
            'members_data': {
                user_dn('userone'): {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
                user_dn('usertest1'): {
                    'cn': ['User 1'],
                    'mail': ['user.1@example.com'],
                },
            },
            'uniqueMember': [
                user_dn('userone'),
                user_dn('usertwo'),
            ],
            'permittedSender': ['anyone', ],
        })
        return_code = self.expander.expand('test12342424@email.com',
                                           'test_empty@roles.eionet.europa.eu',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_ldap(self):
        """ Test ldap errors """

        from_email = 'user_one@example.com'
        role_email = 'test12@roles.eionet.europa.eu'

        # Should fail.. no such role
        return_code = self.expander.expand(from_email, role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

        # Ldap server is down
        self.agent.get_role = Mock(side_effect=ldap.SERVER_DOWN)
        return_code = self.expander.expand(from_email, role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_TEMPFAIL'])

        # Other error
        self.agent.get_role = Mock(side_effect=TypeError)
        return_code = self.expander.expand(from_email, role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_NOUSER'])

    def test_batch(self):
        """ Test sending batch e-mails. Generate 120 ldap users and expect
        batches of 50 e-mails

        """
        user_dn = self.agent._user_dn

        user_dns = []
        ldap_data = deepcopy(self.ldap_data)

        for i in range(1, 119):
            ldap_data.append(
                (user_dn('usertest%s' % i), ldap.SCOPE_BASE, [
                    (user_dn('usertest%s' % i), {
                        'cn': ['User %s' % i],
                        'mail': ['user.%s@example.com' % i],
                        'telephoneNumber': ['11111'],
                        'o': ['Testers Club %s' % i],
                    }),
                ], )
            )
            user_dns.append(user_dn('usertest%s' % i))
        ldap_data[0][2][0][1]['uniqueMember'].extend(
            user_dns)  # Adding members

        def ldap_search_called(dn, scope, **kwargs):
            return ldap_search(dn, scope, ldap_data, **kwargs)

        self.mock_conn.search_s.side_effect = ldap_search_called

        global total_mails
        total_mails = 0  # Count all emails

        def send_emails_called(from_email, emails, content):
            assert len(emails) <= 50
            global total_mails
            total_mails += len(emails)
            return RETURN_CODES['EX_OK']

        self.expander.send_emails.side_effect = send_emails_called
        self.expander.expand('user_one@example.com',
                             'test@roles.eionet.europa.eu',
                             self.fixtures['content_7bit'])
        # we should have 4 users initially in test, of which user3
        # has two emails + 118 users added in this method;
        # 3 x 1 + 1 * 2 + 118 = 123
        self.assertEqual(total_mails, 123)

    def test_empty_role(self):
        """ Test invalid role scenarios (missing members,
        empty uniqueMember's)

        """

        # No owner attribute - should not fail
        self.agent.get_role = Mock(return_value={
            'description': 'no owner',
            'members_data': {
                'uid=userone,ou=Users,o=EIONET,l=Europe': {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
                'uid=usertest1,ou=Users,o=EIONET,l=Europe': {
                    'cn': ['User 1'],
                    'mail': ['user.1@example.com'],
                },
            },
            'uniqueMember': [
                'uid=userone,ou=Users,o=EIONET,l=Europe',
                'uid=usertwo,ou=Users,o=EIONET,l=Europe',
            ],
            'permittedSender': [
                'test@email.com'
            ]
        })
        return_code = self.expander.expand('test@email.com',
                                           'test_empty@roles.eionet.europa.eu',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_case_insensitive_sender(self):
        """ Test case insensitive permited sender, as per #24827

        """
        self.agent.get_role = Mock(return_value={
            'description': 'no owner',
            'members_data': {
                'uid=userone,ou=Users,o=EIONET,l=Europe': {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
            },
            'permittedSender': [
                'awp2016n2017@email.com'
            ]
        })
        return_code = self.expander.expand('AWP2016n2017@email.com',
                                           'test_insensitive@roles.eionet.europa.eu',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_send_headers(self):
        """ Test that From, Return-Path, X-Auth-ID, Sender are all set to
        role_email, and the original sender is added to CC.
        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'

        self.expander.can_expand = Mock(return_value=True)
        return_code = self.expander.expand(from_email, role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        new_body = self.expander.send_emails.call_args[0][2]
        em = email.message_from_string(new_body)

        self.assertEqual(em.get('Sender'), role_email)
        self.assertEqual(em.get('From'), role_email)
        self.assertEqual(em.get('Return-Path'), 'test+bounce@roles.eionet.europa.eu')
        self.assertEqual(em.get('X-Auth-ID'), role_email)
        self.assertIn(from_email, em.get('Cc'))

    def test_send_preserves_existing_cc(self):
        """ When the original email already has a CC header, the original
        sender should be appended to it.
        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'
        existing_cc = 'other@example.com'

        self.expander.can_expand = Mock(return_value=True)
        # Inject a CC header into the fixture content (uses CRLF)
        content = self.fixtures['content_7bit'].replace(
            '\r\n\r\n', '\r\nCc: %s\r\n\r\n' % existing_cc, 1)
        return_code = self.expander.expand(from_email, role_email, content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        new_body = self.expander.send_emails.call_args[0][2]
        em = email.message_from_string(new_body)
        cc = em.get('Cc')
        self.assertIn(existing_cc, cc)
        self.assertIn(from_email, cc)

    def test_skip_confirmation_email(self):
        """ When skip_confirmation_email is set, no confirmation email should
        be sent after successful expansion.
        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'

        self.expander.can_expand = Mock(return_value=True)
        self.expander.send_confirmation_email = Mock(
            return_value=RETURN_CODES['EX_OK'])
        self.expander.skip_confirmation_email = 'true'

        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertFalse(self.expander.send_confirmation_email.called)

    def test_confirmation_email_sent_by_default(self):
        """ When skip_confirmation_email is not set, a confirmation email
        should be sent after successful expansion.
        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'

        self.expander.can_expand = Mock(return_value=True)
        self.expander.send_confirmation_email = Mock(
            return_value=RETURN_CODES['EX_OK'])
        self.expander.skip_confirmation_email = None

        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertTrue(self.expander.send_confirmation_email.called)

    def test_also_send_to(self):
        """ When also_send_to is configured, emails should also be sent
        to those addresses.
        """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'

        self.expander.can_expand = Mock(return_value=True)
        self.expander.also_send_to = ['archive@example.com',
                                      'monitor@example.com']

        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])

        # Find the call that sent to also_send_to
        also_call = None
        for call in self.expander.send_emails.call_args_list:
            if call[0][1] == ['archive@example.com', 'monitor@example.com']:
                also_call = call
                break
        self.assertIsNotNone(also_call,
                             "also_send_to addresses were not sent to")

    def test_can_expand_email_with_equals(self):
        """ Test that from_email with = character is handled correctly.
        Fix for #18085: bounced emails can have encoded addresses like
        user=original@bounce.domain.com
        """
        role_data = {
            'members_data': {},
            'permittedSender': ['original@bounce.domain.com'],
        }
        self.expander.add_inherited_senders = lambda role_id, role_data: \
            role_data
        result = self.expander.can_expand(
            'user=original@bounce.domain.com', 'test', role_data)
        self.assertTrue(result)

    def test_deactivated_role_rejected(self):
        """ Email to a deactivated role should be rejected and the sender
        should receive a notification.
        """
        user_dn = self.agent._user_dn

        self.agent.get_role = Mock(return_value={
            'description': 'deactivated role',
            'l': ['deactivated:True'],
            'members_data': {
                user_dn('userone'): {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
            },
            'uniqueMember': [user_dn('userone')],
            'permittedSender': ['anyone'],
        })
        return_code = self.expander.expand(
            'test@email.com',
            'test_deactivated@roles.eionet.europa.eu',
            self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # Verify that the deactivation notice was sent to the sender
        self.assertTrue(self.expander.send_emails.called)
        call_args = self.expander.send_emails.call_args[0]
        self.assertEqual(call_args[1], ['test@email.com'])
        notice_content = call_args[2]
        self.assertIn('deactivated', notice_content)

    def test_deactivated_role_false_allows_sending(self):
        """ A role with deactivated:False should work normally.
        """
        user_dn = self.agent._user_dn

        self.agent.get_role = Mock(return_value={
            'description': 'active role',
            'l': ['deactivated:False'],
            'members_data': {
                user_dn('userone'): {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
            },
            'uniqueMember': [user_dn('userone')],
            'permittedSender': ['anyone'],
        })
        return_code = self.expander.expand(
            'test@email.com',
            'test_active@roles.eionet.europa.eu',
            self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_role_without_l_attribute_allows_sending(self):
        """ A role without the 'l' attribute should not be considered
        deactivated (backwards compatibility).
        """
        user_dn = self.agent._user_dn

        self.agent.get_role = Mock(return_value={
            'description': 'no l attribute',
            'members_data': {
                user_dn('userone'): {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                },
            },
            'uniqueMember': [user_dn('userone')],
            'permittedSender': ['anyone'],
        })
        return_code = self.expander.expand(
            'test@email.com',
            'test_nol@roles.eionet.europa.eu',
            self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

    def test_is_deactivated(self):
        """ Test is_deactivated with various 'l' attribute values.
        """
        self.assertTrue(
            self.expander.is_deactivated({'l': ['deactivated:True']}))
        self.assertTrue(
            self.expander.is_deactivated({'l': ['Deactivated:True']}))
        self.assertFalse(
            self.expander.is_deactivated({'l': ['deactivated:False']}))
        self.assertFalse(
            self.expander.is_deactivated({}))

    def test_return_path_with_bounce(self):
        """ Test that Return-Path is set to role+bounce@domain """
        from_email = 'user_one@example.com'
        role_email = 'test@roles.eionet.europa.eu'

        self.expander.can_expand = Mock(return_value=True)
        return_code = self.expander.expand(from_email, role_email,
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        # Check that Return-Path was set correctly
        new_body = self.expander.send_emails.call_args[0][2]
        em = email.message_from_string(new_body)
        self.assertEqual(em.get('return-path'), 'test+bounce@roles.eionet.europa.eu')

    def test_bounce_forwarding_to_configured_address(self):
        """ Test that bounce messages are forwarded to bounce_send_to """
        from_email = 'mailer-daemon@somewhere.com'
        role_email = 'test+bounce@roles.eionet.europa.eu'
        bounce_content = self.fixtures['content_7bit']

        self.expander.bounce_send_to = 'bounces@example.com'
        return_code = self.expander.expand(from_email, role_email,
                                           bounce_content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])

        self.assertTrue(self.expander.send_emails.called)
        call_args = self.expander.send_emails.call_args[0]
        self.assertEqual(call_args[0], self.expander.noreply)
        self.assertEqual(call_args[1], ['bounces@example.com'])
        self.assertEqual(call_args[2], bounce_content)

    def test_bounce_no_configured_address(self):
        """ Test that bounces are dropped when no bounce_send_to is set """
        from_email = 'mailer-daemon@somewhere.com'
        role_email = 'test+bounce@roles.eionet.europa.eu'
        bounce_content = self.fixtures['content_7bit']

        self.expander.bounce_send_to = ''
        return_code = self.expander.expand(from_email, role_email,
                                           bounce_content)
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])
        self.assertFalse(self.expander.send_emails.called)

    def test_subject_tag_uses_role_address_not_full_to(self):
        """ The Subject tag must carry the short list address, never the whole
        incoming To: header. A reply whose To: lists every recipient must not
        bloat the Subject (Exchange drops oversized subjects, so recipients
        would otherwise get the message with no subject at all).
        """
        from email.header import decode_header
        self.expander.can_expand = Mock(return_value=True)
        self.expander.skip_confirmation_email = True

        big_to = ', '.join('user%02d@example.com' % i for i in range(60))
        content = ('From: sender@example.com\r\n'
                   'To: ' + big_to + '\r\n'
                   'Subject: Hello\r\n\r\nbody\r\n')
        role_email = 'test@roles.eionet.europa.eu'
        rc = self.expander.expand('user_one@example.com', role_email, content)
        self.assertEqual(rc, RETURN_CODES['EX_OK'])

        sent = self.expander.send_emails.call_args[0][2]
        subj = email.message_from_string(sent).get('subject')
        decoded = u''.join(
            (p.decode(c or 'ascii') if isinstance(p, bytes) else p)
            for p, c in decode_header(subj))
        self.assertIn(u'[%s]' % role_email, decoded)      # list address present
        self.assertNotIn(u'user59@example.com', decoded)  # full To excluded
        self.assertLess(len(subj), 300)                   # bounded, not multi-KB


if __name__ == '__main__':
    unittest.main()
