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
        assert self.expander.expand('user_one@example.com', 'test', "") == ok
        assert self.expander.expand('user_one@example.com', 'test1', "") == \
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
            self.assertEqual(em.get('sender'), 'owner-' + role_email)
            self.assertTrue(em.get('subject').startswith(
                '[%s]' % role_email.split('@')[0]))

            ignore_headers = ('received', 'sender', 'subject', 'list-id',
                              'list-post', )  # Checked above
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

    def test_send_filtered(self):

        from_email = 'test@email.com'
        role_email = 'test@roles.eionet.europa.eu'
        role_email_gb = 'test-gb@roles.eionet.europa.eu'

        self.expander.roles_to_filter = []
        self.expander.filter_str = ''
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_four@example.com', 'user_three@example.com',
            'user_3333@example.com', 'user_two@example.com',
            'user_one@example.com'])

        self.expander.roles_to_filter = []
        self.expander.filter_str = '-gb'
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_four@example.com', 'user_three@example.com',
            'user_3333@example.com', 'user_two@example.com',
            'user_one@example.com'])

        self.expander.roles_to_filter = ['test']
        self.expander.filter_str = ''
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_four@example.com', 'user_three@example.com',
            'user_3333@example.com', 'user_two@example.com',
            'user_one@example.com'])

        self.expander.roles_to_filter = ['test']
        self.expander.filter_str = '-gb'
        self.expander.expand(from_email, role_email,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_four@example.com', 'user_two@example.com',
            'user_one@example.com'])

        self.expander.roles_to_filter = ['test']
        self.expander.filter_str = '-gb'
        self.expander.expand(from_email, role_email_gb,
                             self.fixtures['content_7bit'])
        self.assertEquals(self.expander.send_emails.call_args[0][1], [
            'user_three@example.com', 'user_3333@example.com'])

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
            assert emails == [
                'user_four@example.com', 'user_three@example.com',
                'user_3333@example.com', 'user_two@example.com',
                'user_one@example.com']
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
                                           'test_insensitive',
                                           self.fixtures['content_7bit'])
        self.assertEqual(return_code, RETURN_CODES['EX_OK'])


if __name__ == '__main__':
    unittest.main()
