from envcoord.mailexpander import ldap_agent
from mock import Mock   #, patch    #, wraps
import ldap
import unittest


def called_mock(dn, scope, calls_list):
    expected_dn, expected_scope, ret = calls_list.pop(0)
    assert dn == expected_dn
    assert scope == expected_scope
    return ret


class StubbedLdapAgent(ldap_agent.LdapAgent):
    def connect(self):
        return Mock()

class LdapAgentTest(unittest.TestCase):
    def setUp(self):
        self.agent = StubbedLdapAgent(ldap_server='', user_dn='', user_pw='')
        self.mock_conn = self.agent.conn

    def test_get_role(self):
        """ Getting role information also
        Test the permittedPerson and the permittedSender attributes """
        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        # no local members
        calls_list = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'), {
                    'uniqueMember': [ user_dn('userone'), user_dn('usertwo')],
                    'permittedPerson': [ user_dn('userone') ],
                    'permittedSender': ['alexandru.plugaru@eaudeweb.ro',
                                        '*@eaudeweb.ro', 'members']
                }),
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
            ])
        ]

        def mock_called(dn, scope):
            return called_mock(dn, scope, calls_list)

        self.mock_conn.search_s.side_effect = mock_called

        role_data = self.agent.get_role('A')
        assert role_data['permittedSender'] == ['alexandru.plugaru@eaudeweb.ro',
                                           '*@eaudeweb.ro', 'members']
        assert role_data['permittedPerson'] == [
            'uid=userone,ou=Users,o=EIONET,l=Europe']

        assert role_data['members_data'] == {
            user_dn('userone'): {
                'cn': ['User one'],
                'mail': ['user_one@example.com'],
                'telephoneNumber': ['555 1234 2'],
                'o': ['Testers Club'],
            },
            user_dn('usertwo'): {
                'cn': ['User two'],
                'mail': ['user_two@example.com'],
                'telephoneNumber': ['5155 1234 2'],
                'o': ['Testers Club 2'],
            }}

    def test_missing_unique_member(self):
        """ When an unique member is missing """

        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        # Missing member usertwo
        calls_list = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'), {
                    'uniqueMember': [ user_dn('userone'), user_dn('usertwo') ]
                }),
            ]),
            (user_dn('userone'), ldap.SCOPE_BASE, [
                (user_dn('userone'), {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                    'telephoneNumber': ['555 1234 2'],
                    'o': ['Testers Club'],
                }),
            ]),
        ]

        def mock_called(dn, scope):
            return called_mock(dn, scope, calls_list)
        self.mock_conn.search_s.side_effect = mock_called

        #Should not raise an error but instead return the data with existing
        #users
        data = self.agent.get_role('A')
        assert len(data['members_data']) == 1
        assert data['members_data'].keys() == [user_dn('userone')]

    def test_empty_member(self):
        """ When an uniqueMember is empty """

        role_dn = self.agent._role_dn
        user_dn = self.agent._user_dn

        # Empty uniqueMember
        calls_list = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'), {
                    'uniqueMember': [ user_dn('userone'), '' ]
                }),
            ]),
            (user_dn('userone'), ldap.SCOPE_BASE, [
                (user_dn('userone'), {
                    'cn': ['User one'],
                    'mail': ['user_one@example.com'],
                    'telephoneNumber': ['555 1234 2'],
                    'o': ['Testers Club'],
                }),
            ]),
        ]

        def mock_called(dn, scope):
            expected_dn, expected_scope, ret = calls_list.pop(0)
            assert dn == expected_dn
            assert scope == expected_scope
            return ret
        self.mock_conn.search_s.side_effect = mock_called
        role_data = self.agent.get_role('A')
        self.assertEquals(len(role_data['members_data']), 1)
        self.assertEquals([user_dn('userone')],
                    role_data['members_data'].keys())
