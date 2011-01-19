PUSHDIVERT(-1)

ifdef(`EXPANDER_MAILER_PATH',, `define(`EXPANDER_MAILER_PATH', /usr/local/bin/mailexpander)')
ifdef(`EXPANDER_MAILER_ARGS',, `define(`EXPANDER_MAILER_ARGS', `mailexpander -l ldap.eionet.europa.eu -r $u')')dnl

POPDIVERT

#################################
###   EEA Roles Mail expander ###
#################################

VERSIONID(`$Id: rolesmail.m4,v 0.1 2011/01/12 00:00:00 ca Exp $')
Mrolesmail, P=EXPANDER_MAILER_PATH,
		F=DFMuX,
		F=f,
		S=EnvFromSMTP/HdrFromSMTP,
		R=EnvToSMTP/HdrFromSMTP,
		T=DNS/RFC822/SMTP,
		A=EXPANDER_MAILER_ARGS
