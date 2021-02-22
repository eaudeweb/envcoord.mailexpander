envcoord.mailexpander
=====================

This program acts as a sendmail mailer and allows sending mails to a certain
ldap group (role) based on a few rules.

The ldap role should have 2 attributes:
    permittedPerson -- DN pointing to a ldap user
    permittedSender -- Email, patterns and 2 preset strings: 'members', 'owners'
    owner -- DN pointing to a ldap user

Starting with 23 September 2014, this program will inherit senders from roles upper
in the inheritance chain.

Usage/Installation
------------------

To configure the sendmail see docs/POSTFIX.rst

To test the program, run it with the -t switch (this will not send any email) and
look for the return code with the "echo $?" bash command.

Unit testing
------------
Go to envcoord/mailexpander/tests and run the tests. You have to have the mock package installed.
