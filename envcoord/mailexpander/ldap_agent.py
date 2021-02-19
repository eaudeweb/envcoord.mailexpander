# -*- coding: utf-8 -*-
from string import ascii_lowercase
import ldap
import ldap.filter
import re

__version__ = """$Id$"""


class LdapAgent(object):
    def __init__(self, **config):
        self.ldap_server = config['ldap_server']
        if not (self.ldap_server.startswith('ldap://') or
                self.ldap_server.startswith('ldaps://')):
            self.ldap_server = 'ldaps://' + self.ldap_server
        self.conn = self.connect()
        self.conn.protocol_version = ldap.VERSION3
        self.conn.simple_bind_s(config['user_dn'].strip(),
                                config['user_pw'].strip())
        self._encoding = config.get('encoding', 'utf-8')
        self._user_dn_suffix = config.get('users_dn',
                                          "ou=Users,o=EIONET,l=Europe")
        self._role_dn_suffix = config.get('roles_dn',
                                          "ou=Roles,o=EIONET,l=Europe")

    def connect(self):
        conn = ldap.initialize(self.ldap_server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _ancestor_roles_dn(self, role_dn):
        """
        Given a subrole dn, returns a list of all ancestors. First is
        the given subrole, then the ancestors, with last element the top-most
        one.
        """

        # Example usage::
        #     >>> self._ancestor_roles_dn(
        #     ...   "cn=eionet-nfp,cn=eionet,ou=Roles,o=EIONET,l=Europe")
        #     ['cn=eionet-nfp,ou=Roles,o=EIONET,l=Europe',
        #      'cn=eionet,ou=Roles,o=EIONET,l=Europe']

        assert role_dn.endswith(',' + self._role_dn_suffix), "Invalid Role DN"
        role_dn_start = role_dn[: - (len(self._role_dn_suffix) + 1)]
        dn_bits = role_dn_start.split(',')
        dn_bits.reverse()

        ancestors = []
        accumulator = self._role_dn_suffix
        for bit in dn_bits:
            assert bit.startswith('cn=')
            accumulator = bit + "," + accumulator
            ancestors.insert(0, accumulator)

        return ancestors

    def _query(self, dn):
        # This query naively thinks that all searches return something
        return self.conn.search_s(dn, ldap.SCOPE_BASE)[0][1]

    def _role_dn(self, role_id):
        if role_id is None:
            id_bits = []
        else:
            id_bits = role_id.split('-')

        dn_start = ''
        for c in range(len(id_bits), 0, -1):
            dn_start += 'cn=%s,' % '-'.join(id_bits[:c])
        return dn_start + self._role_dn_suffix

    def _user_id(self, user_dn):
        assert user_dn.endswith(',' + self._user_dn_suffix)
        assert user_dn.startswith('uid=')
        user_id = user_dn[len('uid='): - (len(self._user_dn_suffix) + 1)]
        assert ',' not in user_id
        return user_id

    def _user_dn(self, user_id):
        assert ',' not in user_id
        return 'uid=' + user_id + ',' + self._user_dn_suffix

    def _role_info(self, query_dn):
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE)
        try:
            assert len(result) == 1
            dn, attr = result[0]
            assert dn.lower() == query_dn.lower()
        except AssertionError:
            raise ValueError

        return attr

    def get_role(self, role_id):
        """ Returns a dictionary describing the role `role_id`.
        Also return all the members and their emails

        """

        query_dn = self._role_dn(role_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE)

        try:
            assert len(result) == 1
            dn, attr = result[0]
            assert dn.lower() == query_dn.lower()
        except AssertionError:
            raise ValueError

        def get_data(data, key, target_attr):
            return_attr = {}
            if key in data:
                for dn in data[key]:
                    if dn == '':
                        continue  # Ignore empty DN attributes
                    try:
                        return_attr[dn] = self._query(dn)
                    except Exception:
                        pass  # Ignore members that don't exist in ldap anymore
            return {target_attr: return_attr}

        attr.update(get_data(attr, 'uniqueMember', 'members_data'))
        attr.update(get_data(attr, 'owner', 'owners_data'))

        return attr

    def filter_roles(
            self, pattern, prefix_dn=None,
            filterstr='(objectClass=groupOfUniqueNames)', attrlist=()):
        """
        Returns all roles matching `pattern`.
        We can use `prefix_dn` to restrict searching pool and/or filterstr
        Returns list of tuples, with role_id and attrs in `attrlist`

        """
        query_dn = self._role_dn_suffix
        if prefix_dn:
            query_dn = prefix_dn + ',' + query_dn
        result = self.conn.search_s(query_dn, ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=attrlist)

        pattern = pattern.lower()
        for ch in pattern:
            if ch not in ascii_lowercase + '-*':
                return set()

        if not pattern:
            return set()

        pattern = pattern.replace('-', r'\b\-\b').replace('*', r'.*')
        pattern = r'\b' + pattern + r'\b'
        compiled_pattern = re.compile(pattern)

        out = []
        in_out = set()
        for dn, attr in result:
            role_id = self._role_id(dn)
            if role_id is None:
                continue

            if compiled_pattern.search(role_id.lower()) is not None:
                if role_id not in in_out:
                    out.append((role_id, attr))
                    in_out.add(role_id)

        return out

    def get_userid_for_email(self, email, no_disabled=True):
        disabled_filter = "(!(employeeType=*disabled*))"

        query = email.encode(self._encoding)
        pattern = '(&(objectClass=person){0}(mail=%s))'.format(disabled_filter)
        query_filter = ldap.filter.filter_format(pattern, (query,))

        result = self.conn.search_s(self._user_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query_filter)
        if result:
            return result[0][1]['uid'][0]

    def _role_id(self, role_dn):
        if role_dn == self._role_dn_suffix:
            return None
        assert role_dn.endswith(',' + self._role_dn_suffix)
        role_dn_start = role_dn[: - (len(self._role_dn_suffix) + 1)]
        dn_bits = role_dn_start.split(',')
        dn_bits.reverse()

        current_bit = None
        for bit in dn_bits:
            assert bit.startswith('cn=')
            bit = bit[len('cn='):]
            if current_bit is None:
                assert '-' not in bit
            else:
                assert bit.startswith(current_bit + '-')
                assert '-' not in bit[len(current_bit) + 1:]
            current_bit = bit

        return current_bit

    def roles_with_member(self, member_dn):
        """
        Returns roles of a user

        """
        role_dn = self._role_dn_suffix
        filter_tmpl = '(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))'
        filterstr = ldap.filter.filter_format(filter_tmpl, (member_dn,))
        result = self.conn.search_s(role_dn, ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=())
        for dn, attr in result:
            yield dn
