#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ConfigParser import ConfigParser
from fnmatch import fnmatch
from ldap_agent import LdapAgent
from logging.handlers import SysLogHandler
from subprocess import Popen, PIPE
import email
import fcntl
import getopt
import ldap
import logging
import operator
import os
import re
import smtplib
import string
import sys
import time

__version__ = """$Id: expander.py 40888 2017-04-05 09:47:09Z tiberich $"""


try:
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
except ImportError as e:      # pragma: no cover
    from email.MIMEText import MIMEText
    from email.MIMEMultipart import MIMEMultipart

try:
    from functools import wraps
except ImportError:
    def wraps(func):
        def decorator(wrapper):
            for name in ('__module__', '__name__', '__doc__'):
                setattr(wrapper, name, getattr(func, name))
                wrapper.__dict__.update(func.__dict__)
            return wrapper
        return decorator


RETURN_CODES = {
    'EX_OK':           0,   # successful termination
    'EX_USAGE':        64,  # command line usage error
    'EX_DATAERR':      65,  # data format error
    'EX_NOINPUT':      66,  # cannot open input
    'EX_NOUSER':       67,  # addressee unknown
    'EX_NOHOST':       68,  # host name unknown
    'EX_UNAVAILABLE':  69,  # service unavailable
    'EX_SOFTWARE':     70,  # internal software error
    'EX_OSERR':        71,  # system error (e.g., can't fork)
    'EX_OSFILE':       72,  # critical OS file missing
    'EX_CANTCREAT':    73,  # can't create (user) output file
    'EX_IOERR':        74,  # input/output error
    'EX_TEMPFAIL':     75,  # temp failure; user is invited to retry
    'EX_PROTOCOL':     76,  # remote error in protocol
    'EX_NOPERM':       77,  # permission denied
    'EX_CONFIG':       78,  # configuration error
}


sys.tracebacklimit = 0
log = logging.getLogger('rolesexpander')
log.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)


class SimplifiedRole(object):
    """
    A simple way of representing and addressing attributes
    of an NFP/NRC Role

    """

    def __init__(self, role_id, description):
        m = re.match(r'^eionet-(nfp|nrc)-(.*)(mc|cc)-([^-]*)$', role_id,
                     re.IGNORECASE)
        if m:
            self.type = m.groups()[0].lower()
            self.country = m.groups()[3].lower()
            self.role_id = role_id
            self.description = description
        else:
            raise ValueError("Not a valid NFP/NRC role")
        if not self.country or (self.type not in ('nfp', 'nrc')):
            raise ValueError("Not a valid NFP/NRC role")

    def split(self, s='-'):
        return self.role_id.split(s)


def log_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            log.exception("Uncaught exception from %r", func)
            return RETURN_CODES['EX_SOFTWARE']

    return wrapper


class Expander(object):
    """ Sendmail mailer. Uses LDAP roles to send e-mails to ldap users in that
    specific role. Same behavior as a maillist.

    """

    def __init__(self, ldap_agent, **config):
        self.agent = ldap_agent
        self.sendmail_path = config.get('sendmail_path', '/usr/sbin/sendmail')
        self.archivefile = config.get('mailbox', None)
        also_string = config.get('also_send_to', '')
        self.also_send_to = map(string.strip, also_string.split(','))
        self.noreply = config.get('no_reply', 'no-reply@eea.europa.eu')
        self.no_owner_send_to = config.get('no_owner_send_to', '').strip()
        self.filter_str = config.get('filter_str', '').strip()
        self.roles_to_filter = []
        roles_to_filter = config.get(
            'roles_to_filter', '')
        if roles_to_filter:
            self.roles_to_filter = roles_to_filter.strip().split(',')

    def _get_nfp_roles(self, uid):
        out = []
        filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                     self.agent._user_dn(uid))
        nfp_roles = self.agent.filter_roles(
            "eionet-nfp-*-*", prefix_dn="cn=eionet-nfp,cn=eionet",
            filterstr=filterstr, attrlist=("description",))

        for nfp in nfp_roles:
            try:
                role = SimplifiedRole(nfp[0], nfp[1]['description'][0])
            except ValueError:
                continue
            else:
                out.append(role)

        return sorted(out, key=operator.attrgetter('role_id'))

    def get_nfp_countries(self, uid):
        """ Returns a list of country codes where user (uid) is NFP
        """

        return [role.country for role in self._get_nfp_roles(uid)]

    @log_exceptions
    def expand(self, from_email, role_email, content, debug_mode=False):
        """ Send e-mails to ldap users based on `role_email` checking if
        `from_email` is allowed to do so. Prepend the `role` name to the e-mail
        subject. Modify the headers according to these priciples:
        http://tools.ietf.org/html/rfc5321#page-31
        Also queue max 50 messages per send so that the mailer can deliver them
        asynchronously.

        Arguments::

            from_email -- Sender e-mail (as received from sendmail)
            role_email -- A pseudo address (ldap-role@roles.eionet.europa.eu)
            content -- E-mail headers and body

        """

        role = role_email.split('@')[0]
        log.info("New mail from %s to %s", from_email, role_email)

        """ If an e-mail is sent to a role starting with owner- then get
        the `owner` attributes of that `role` and send them the message.
        This is useful when unintended e-mail is sent such as vacation
        reponses.
        """
        send_to_owners = False
        if role.lower().startswith('owner-'):
            role = role.split('owner-')[1]
            send_to_owners = True
        try:
            role_data = self.agent.get_role(role)
            assert 'members_data' in role_data, (
                '`uniqueMember` attribute is missing')
            # It is perfectly legit to have no owner
            # assert 'owner' in role_data, (
            #    '`owner` attribute is missing')
        except AssertionError:
            log.exception("In %r role:" % role)
            return RETURN_CODES['EX_NOUSER']
        except ldap.SERVER_DOWN:
            log.error("LDAP server is down")
            return RETURN_CODES['EX_TEMPFAIL']
        except (ldap.NO_SUCH_OBJECT, ValueError):
            log.info("%r role not found in ldap", role)
            return RETURN_CODES['EX_NOUSER']
        except Exception, e:
            log.error("%r role not found exception, %r" % (role, e))
            return RETURN_CODES['EX_NOUSER']

        top_role = role.split('-')[0]

        if send_to_owners is True:  # Send e-mail to owners
            owners = role_data['owners_data']
            for owner_dn, owner_data in owners.items():
                retval = self.send_emails(from_email, owner_data['mail'],
                                          content)
                if retval != RETURN_CODES['EX_OK']:
                    return retval
            if not owners:
                log.info("No owner found, sending to %s",
                         self.no_owner_send_to)
                if not debug_mode:
                    if self.no_owner_send_to:
                        retval = self.send_emails(
                            from_email, [self.no_owner_send_to], content)
                        if retval != RETURN_CODES['EX_OK']:
                            return retval
                    else:
                        return RETURN_CODES['EX_CONFIG']
            return RETURN_CODES['EX_OK']

        # Check if from_email can expand
        if self.can_expand(from_email, role, role_data) is False:
            return RETURN_CODES['EX_NOPERM']

        # Add the necessary headers such as Received and modify the subject
        # with [role]
        em = email.message_from_string(content)
        # Prepend to subject:
        subject = em.get('subject', '(no-subject)')
        if not ("[%s] " % role) in subject:
            subject = "[%s] %s" % (role, subject)
            try:
                em.replace_header('subject', subject)
            except KeyError:
                em.add_header('subject', subject)

        # Add Sender: header
        sender = 'owner-' + role_email
        del em['Sender']  # Exception won't be raised
        em['Sender'] = sender
        # List-Post etc. is described in RFC 2369
        del em['List-Help']
        del em['List-Subscribe']
        del em['List-Unsubscribe']
        del em['List-Owner']
        # List-ID is described in RFC 2919
        del em['List-ID']
        em['List-ID'] = '<%s>' % role_email.replace('@', '.')
        del em['List-Post']
        # Used by Thunderbird and KMail
        em['List-Post'] = '<mailto:%s>' % role_email

        content = em.as_string()

        # Split the emails in to batches
        email_batches = [[]]
        batch = 0
        batch_size = 50  # Send in email batches

        for dn, data in role_data['members_data'].iteritems():
            # if there is a filter and the mail was not sent directly to
            # a role matching the filter, remove all users from subroles
            # mathching that filter
            if (top_role in self.roles_to_filter and
                    self.filter_str not in role):
                filter_out = False
                member_roles = self.agent.roles_with_member(dn)
                for member_role in member_roles:
                    # we remove only users who are members of a
                    # subbranch of the current top_role that contains
                    # the filtered string
                    if (top_role in member_role and
                            self.filter_str in member_role):
                        log.info('filtered out %s' % dn)
                        filter_out = True
                        break
                if filter_out:
                    continue
            if len(email_batches[batch]) >= batch_size:
                batch += 1
                email_batches.append([])  # Init new batch
            clean_addresses = filter(lambda i: i.find(
                '@') > 0, data.get('mail', ['']))
            email_batches[batch].extend(clean_addresses)

        if not debug_mode:
            self.write_to_archive(from_email, content)

            # If there are any addresses to always send to
            if self.also_send_to != ['']:
                retval = self.send_emails(
                    'owner-' + role_email, self.also_send_to, content)

            # Send e-mails
            for emails in email_batches:
                retval = self.send_emails(
                    'owner-' + role_email, emails, content)
                if retval != RETURN_CODES['EX_OK']:
                    return retval
            try:
                retval = self.send_confirmation_email(
                    subject, from_email, role)
            except Exception:
                log.exception("Error sending confirmation")
            else:
                if retval != RETURN_CODES['EX_OK']:
                    log.error("Error sending confirmation: %d", retval)

        return RETURN_CODES['EX_OK']

    def add_inherited_senders(self, role_id, role_data):
        """ Add as permitted senders everyone that inherits
        """
        # also add permitted from all the parents
        # this allows "inheriting" permissions from above roles
        # see http://taskman.eionet.europa.eu/issues/20422

        if 'permittedPerson' not in role_data:
            role_data['permittedPerson'] = []

        role_dn = self.agent._role_dn(role_id)
        parent_roles = self.agent._ancestor_roles_dn(role_dn)[1:]
        senders = set(role_data['permittedSender'])

        for parent_role_dn in parent_roles:
            role_info = self.agent._role_info(parent_role_dn)

            if 'permittedSender' not in role_info:
                continue

            for sender_pattern in role_info['permittedSender']:
                sender_pattern = sender_pattern.lower()
                if sender_pattern == 'owners':
                    if 'owner' in role_info:
                        for owner_dn in role_info['owner']:
                            try:
                                owner = self.agent._query(owner_dn)
                            except Exception, e:
                                # Log that we couldn't get the email.
                                log.exception(
                                    "Invalid `owner` DN: %s; %s" % (owner_dn,
                                                                    e))
                                continue

                            senders.update([x.lower() for x in owner['mail']])
                elif sender_pattern == 'members':
                    members = role_info.get('members', [])
                    for user_dn in members:
                        user_info = self.agent._query(user_dn)
                        senders.update([x.lower() for x in user_info['mail']])
                elif '@' in sender_pattern:
                    senders.add(sender_pattern)

            for person_dn in role_info.get('permittedPerson', []):
                try:
                    email = self.agent._query(person_dn)['mail'][0]
                except Exception, e:
                    # Log that we couldn't get the email.
                    log.exception("Invalid DN: %s; %s" (person_dn, e))
                    continue
                else:
                    senders.add(email)

        role_data['permittedSender'] = filter(None, set(senders))

        return role_data

    def can_expand(self, from_email, role, role_data):
        """ Check if the from_email has the permissions to send to the current
        role.

        The current role lookup can take the following scenarios:

        * Looking at the permittedSender value:

        permittedSender -- Possible values:
                        - 'anyone' (All senders are accepted)
                        - 'members' (All `uniqueMember` attributes),
                        - 'owners' (All `owner` attributes),
                        - *@domain.com, admin.*@domain.com (fnmatch patters)
                        - alex@domain.com (simple email addresses)

        This takes into account everything from parent levels, too, per
        http://taskman.eionet.europa.eu/issues/20422

        * Looking at the permittedPerson value:

        permittedPerson -- DN of a user (match the user's email with
        `from_email`)

        * Checking to see if the user is an NFP for the country for that
        role email. (Ticket http://taskman.eionet.europa.eu/issues/22529)
        """

        role_data = self.add_inherited_senders(role_id=role,
                                               role_data=role_data)

        # Convert to lower in case of mixed-case e-mail addresses
        from_email = from_email.lower()

        # Fix for #18085;
        # Treat the case where the email address contains the = character.
        # the eionet accounts only use "clean" emails
        # assume a single @ inside email address
        ident, host = from_email.split('@')
        name = ident.split('=')[-1]
        from_email = "@".join((name, host))

        if 'permittedSender' in role_data:
            if 'anyone' in role_data['permittedSender']:
                return True
            for sender_pattern in role_data['permittedSender']:
                sender_pattern = sender_pattern.lower()
                if sender_pattern == 'owners':
                    if 'owner' in role_data:
                        for owner_dn in role_data['owner']:
                            try:
                                owner = self.agent._query(owner_dn)
                            except Exception, e:
                                # Log that we couldn't get the email.
                                log.exception(
                                    "Invalid `owner` DN: %s; %s" (owner_dn, e))
                                continue
                            if from_email in map(str.lower, owner['mail']):
                                return True
                elif sender_pattern == 'members':
                    if 'members_data' in role_data:
                        for user_dn, user_attrs in \
                                role_data['members_data'].iteritems():
                            if from_email in \
                                    map(str.lower, user_attrs['mail']):
                                return True
                elif fnmatch(from_email, sender_pattern):
                    return True

        if 'permittedPerson' in role_data:
            for permitted_dn in role_data['permittedPerson']:
                try:
                    persons_emails = self.agent._query(permitted_dn)['mail']
                    if from_email in map(str.lower, persons_emails):
                        return True
                except Exception, e:
                    # Log that we couldn't get the email.
                    log.exception("Invalid DN: %s; %s" % (permitted_dn, e))
                    continue

        if role.startswith('eionet-nrc'):
            country = self._country_for_role(role)
            if country:
                if self.is_nfp_for_country(from_email, country):
                    return True

        return False

    def is_nfp_for_country(self, from_email, country):
        """ Email belongs to member of NFP role for that country code?
        """

        user_id = self.agent.get_userid_for_email(from_email)
        if not user_id:
            return False

        nfp_roles = self.get_nfp_roles_for_country(country)
        for role_id in nfp_roles:
            role_data = self.agent.get_role(role_id)
            for user_dn in role_data.get('uniqueMember', []):
                if user_id == self.agent._user_id(user_dn):
                    return True

        return False

    def _country_for_role(self, role):
        try:
            _, _, _, _, country = role.split('-')
        except IndexError:
            return None
        return country

    def get_nfp_roles_for_country(self, country_code):
        out = []
        filterstr = "(objectClass=groupOfUniqueNames)"
        nfp_roles = self.agent.filter_roles(
            "eionet-nfp-*-%s" % country_code,
            prefix_dn="cn=eionet-nfp,cn=eionet", filterstr=filterstr,
            attrlist=("description",))

        for nfp in nfp_roles:
            out.append(nfp[0])

        return sorted(out)

    def send_confirmation_email(self, subject, to_email, role):
        """ If sending emails succeeded send a confirmation email to sender and
        let him know that everything went as expected

        """
        log.info("Sending confirmation email to %s", to_email)
        content = ""
        confirmation_email_template = os.path.join(os.path.dirname(__file__),
                                                   'templates',
                                                   'confirmation_email.html')
        if os.path.isfile(confirmation_email_template):
            f = open(confirmation_email_template, 'rb')
            content = f.read()
            f.close()

        content = content.replace('{{role_id}}', role)

        html_part = MIMEText(content, 'html')
        message = MIMEMultipart('alternative')
        message['Subject'] = "Confirmation: %s" % subject
        message['From'] = self.noreply
        message['To'] = to_email
        message.attach(html_part)

        smtp = smtplib.SMTP('localhost')
        try:
            try:
                smtp.sendmail(self.noreply, to_email, message.as_string())
                log.debug('Confirmation email sent to %s', to_email)
            except smtplib.SMTPException:
                log.exception("SMTP Error")
                log.error("Failed to send confirmation email "
                          "using smtplib to %s", to_email)
                return RETURN_CODES['EX_PROTOCOL']
            except Exception, e:
                log.exception("Smtplib error %s", e)
                return RETURN_CODES['EX_UNAVAILABLE']
        finally:
            try:
                smtp.quit()
            except Exception:
                pass

        return RETURN_CODES['EX_OK']

    def send_emails(self, from_email, emails, content):
        """ Use /usr/bin/sendmail or fallback to smtplib.

        """
        if len(emails) == 0:  # Nobody to send to - it happens
            return RETURN_CODES['EX_OK']
        try:
            # This should be secure check:
            # http://docs.python.org/library/subprocess.html#using-the-subprocess-module
            # It turns out that sendmail splits the addresses on space,
            # eventhough there is one address per argument. See RFC5322 section
            # 3.4 Try: /usr/sbin/sendmail 'soren.roug @eea.europa.eu' and it
            # will complain about the address. We therefore clean them with
            # smtplib.quoteaddr
            quotedemails = map(smtplib.quoteaddr, emails)
            ps = Popen([self.sendmail_path,
                        '-f',
                        smtplib.quoteaddr(from_email),
                        '--'] + quotedemails,
                       stdin=PIPE)
            ps.stdin.write(content)
            ps.stdin.flush()
            ps.stdin.close()
            return_code = ps.wait()
            if return_code in (RETURN_CODES['EX_OK'],
                               RETURN_CODES['EX_TEMPFAIL']):
                log.debug("Sent emails to %r", emails)
                return RETURN_CODES['EX_OK']
            else:
                log.error("Failed to send emails using sendmail to %r. "
                          "/usr/sbin/sendmail exited with code %d", emails,
                          return_code)
            return return_code
        except OSError:  # fallback to smtplib
            # Since this is the same mailer we use localhost
            # Smtplib quotes the addresses internally
            log.exception("Cannot use sendmail program. Falling back to "
                          "smtplib.")
            log.warning(
                "If the smtp connection fails some emails will be lost")
            smtp = smtplib.SMTP('localhost')
            try:
                try:
                    smtp.sendmail(from_email, emails, content)
                    log.debug("Sent emails to %r", emails)
                except smtplib.SMTPException:
                    log.exception("SMTP Error")
                    log.error(
                        "Failed to send emails using smtplib to %r", emails)
                    return RETURN_CODES['EX_PROTOCOL']
                except Exception, e:
                    log.exception("Smtplib error %s" % e)
                    return RETURN_CODES['EX_UNAVAILABLE']
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
            return RETURN_CODES['EX_OK']

    def write_to_archive(self, from_email, content):
        """ Write the email to a MBOX file. (mailbox only does read-only in Python 2.4)
        The lockf call can return IOError, which we abort to writing on
        It is more important that we send the email than we save the message
        """
        if self.archivefile is None:
            return  # No mailbox to write to
        mboxfd = open(self.archivefile, 'ab')
        try:
            # Get an exclusive lock - don't block
            fcntl.lockf(mboxfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # We could try 10 times and sleep one second between each try
            # if we get an EAGAIN or EACCES error
            # except IOError, e:
            #     if e.errno in (errno.EAGAIN, errno.EACCES): ...
        except Exception, e:
            log.error("Unable to acquire exclusive lock on %s; e" %
                      (self.archivefile, e))
            return
        mboxfd.write('From ' + from_email + '  ' + time.asctime() + '\n')
        mboxfd.write(content)
        mboxfd.write('\n')
        # Not really necessary - we close it
        fcntl.lockf(mboxfd, fcntl.LOCK_UN)
        mboxfd.close()


def usage():
    print ("%s [-t] -r [to-email] -f [from-email] -c [config-file] "
           "-l [ldap-host] -o [logfile]") % sys.argv[0]
    # You can't log when you have just removed the log handler
    # log.error("Invalid arguments %r" % sys.argv)
    sys.exit(RETURN_CODES['EX_USAGE'])


def main():
    # Don't return log to output when in mailer

    try:  # Handle cmd arguments
        opts, args = getopt.getopt(sys.argv[1:], "c:r:f:l:o:t")
    except getopt.GetoptError:
        usage()

    logfile = None
    ldap_config = {}
    # sendmail_path = ''
    debug_mode = False
    expander_config = {}
    try:
        opts = dict(opts)
        from_email = opts['-f']
        role_email = opts['-r']
        if '-c' in opts:
            config = ConfigParser()
            config.read([opts['-c']])
            logfile = opts.get('-o', config.get('expander', 'log'))
            expander_config = dict(config.items('expander'))
            ldap_config = dict(config.items('ldap'))
        else:
            ldap_config['ldap_server'] = opts['-l']
            logfile = opts.get('-o')

        if '-t' in opts:
            debug_mode = True

    except KeyError:
        usage()

    if debug_mode:
        log.setLevel(logging.DEBUG)
    else:
        log.removeHandler(stream_handler)

    if logfile is not None:
        if logfile == 'syslog':
            log_handler = SysLogHandler('/dev/log',
                                        facility=SysLogHandler.LOG_LOCAL6)
            formatter = logging.Formatter(
                "%(name)s: %(levelname)s - %(message)s")
            log_handler.setFormatter(formatter)
        else:
            log_handler = logging.FileHandler(logfile, 'a')
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s")
            log_handler.setFormatter(formatter)
        log.setLevel(logging.INFO)
        log.addHandler(log_handler)

    log.debug("=========== starting rolesmailer ============")
    try:
        # Message body + headers come from raw_input. Make sure they stay
        # untouched
        content = ""
        if not debug_mode:
            while True:
                buffer = sys.stdin.read()
                if not buffer:
                    break
                content += buffer

        # Open connection with the ldap
        try:
            agent = LdapAgent(**ldap_config)
        except Exception, e:
            log.error("Cannot connect to LDAP %s; %s" % (
                ldap_config['ldap_server'], e))
            return RETURN_CODES['EX_TEMPFAIL']

        expander = Expander(agent, **expander_config)
        return expander.expand(from_email, role_email, content, debug_mode)
    except Exception, e:
        log.exception("e")
        return RETURN_CODES['EX_SOFTWARE']


if __name__ == '__main__':
    sys.exit(main())
