envcoord.mailexpander postfix configuration
===========================================

This is a guide on how to configure postfix to call the role expander.

1. Configure a postfix mailbox (`zope` in this example) to catch all emails
   without an existing account, or all emails to a subdomain
   (like `roles.envcoord.health.fgov.be`).

2. Install the program using the install.sh script (in this example
   we'll user /var/local/envcoord.mailexpander).
   The python-ldap
   package should be previously installed as a system package.

3. Fill in real data in the /var/local/envcoord.roleexpander/roleexpander.ini
   (copied from roleexpander.ini.example)

4. Add the following lines in /etc/postfix/master.cf. after the smtp line:

   `mailexp   unix  -       n       n       -       1         pipe
      flags=FR. user=zope argv=/var/local/envcoord.mailexpander/bin/roleexpander
      -r ${recipient} -f ${sender} -c /var/local/envcoord.mailexpander/roleexpander.ini`
