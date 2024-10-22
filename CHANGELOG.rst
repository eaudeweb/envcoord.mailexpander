1.00 (unreleased)
======================
* Bugfix: correct original to in the subject when CC is present
  [dumitval]
* Change subject info to 'Subject [original sender] [original to role]'
  [dumitval]
* Move "Sent on behalf of" message to the subject [dumitval]
* from_email is now equal to the recipiend role email instead of the original
  sender, to avoid the emails being identified as spam [valipod]

0.16 (unreleased)
======================
* allow filtering of role members for specified top roles [dumitval]

0.15 (2018-04-23)
======================
* updated ini example files to use ldaps [dumitval]

0.14 (2018-04-20)
======================
* ldaps is now the default connection type
  [valipod #94809]

0.13 (2017-04-03)
======================
* Bug fix: use log.exception instead of log.error when handling an unknown
  error
  [tiberich #83622]

0.12 (2017-01-25)
======================
* Feature: use a fallback email when there's a group with no owner email
  [tiberich #77456 ]

0.11 (2016-10-04)
======================
* Bug fix: don't fail when permittedSender is missing from role info
  [tiberich #77456 ]

0.10 (2014-09-24)
======================
* Bug fix: fix bug in expanding with permitted sender email
  [tiberich #20422]

0.9 (2014-09-23)
======================
* Bug fix: fix mail expansion when mail info for owner, from LDAP search returns list
  [tiberich #20422]

0.8 (2014-09-23)
======================
* Feature: added the -t switch to test if an expansion will go or not.
  [tiberich #20422]

0.7 (2014-09-23)
======================
* Bug fix: added _role_info method to ldap agent
  [tiberich #20422]

0.6 (2014-08-13)
======================
* Change: inherit permitted senders from parent roles
  [tiberich #20422]

0.5 (2014-01-23)
======================
* Bug fix: parse the email address into components, to retrieve the real address of the sender,
  in case that sender's ISP decorates the address with additional info
  [tiberich #18055]

0.4 (unreleased)
======================
* #4543 feature: send back a confirmation email to sender [bogdatan, simiamih]
