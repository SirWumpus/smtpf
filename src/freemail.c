/*
 * freemail.c
 *
 * Copyright 2009 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_FREEMAIL

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_mail_strict[] =
  "Verify that free mail sender originates from a free mail server.\n"
"#"
;

Option optMailStrict		= { "mail-strict", "-", usage_mail_strict };

Stats stat_mail_strict_fail	= { STATS_TABLE_MAIL, "mail-strict-fail" };

FreemailTable freemail_table[] = {
	{ "aim.*",		"*.aol.*" 	},
	{ "aol.*",		"*.aol.*" 	},
	{ "gmail.*",		"*.google.*"	},
	{ "googlemail.*",	"*.google.*"	},
	{ "googlegroups.*",	"*.google.*"	},
	{ "hotmail.*",		"*.hotmail.*"	},
	{ "hotmail.*",		"*.live.*"	},
	{ "live.*",		"*.live.*"	},
	{ "live.*",		"*.hotmail.*"	},
	{ "yahoo.*",		"*.yahoo.*"	},
	{ "ymail.com",		"*.yahoo.*"	},
	{ "rocketmail.com",	"*.yahoo.*"	},
	{ "*groups.yahoo.com",	"*.yahoo.*"	},
	{ NULL, NULL }
};

/***********************************************************************
 ***
 ***********************************************************************/

int
freemailRegister(Session *sess, va_list ignore)
{
	optionsRegister(&optMailStrict, 0);

	(void) statsRegister(&stat_mail_strict_fail);

	return SMTPF_CONTINUE;
}

int
freemailRcpt(Session *sess, va_list args)
{
	FreemailTable *item;

	LOG_TRACE(sess, 920, freemailMail);

	if (!optMailStrict.value || CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_2ND_MX))
		return SMTPF_CONTINUE;

	for (item = freemail_table; item->mail != NULL; item++) {
		if (TextFind(sess->msg.mail->domain.string, item->mail, -1, 1) != -1)
			break;
	}

	if (item->mail == NULL)
		return SMTPF_CONTINUE;

	if (CLIENT_ANY_SET(sess, CLIENT_IS_FORGED)
	|| TextFind(sess->client.name, item->ptr, -1, 1) < 0) {
		statsCount(&stat_mail_strict_fail);
		return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.0 client " CLIENT_FORMAT " sender <%s> must be sent from %s" ID_MSG(921) "\r\n", CLIENT_INFO(sess), sess->msg.mail->address.string, sess->msg.mail->domain.string, ID_ARG(sess));
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_FREEMAIL */
