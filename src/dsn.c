/*
 * cmd.c
 *
 * Copyright 2006 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#include <com/snert/lib/sys/Time.h>

#define DSN_REPLY_TO							\
"If you believe your message was rejected in error, please send" CRLF	\
"a reply containing this message to our staff for review at:" CRLF	\
CRLF									\
"\t%s" CRLF								\
CRLF

#define DSN_RECIPIENT_LEAD_IN						\
"Your message could not be delivered to the following recipients:" CRLF	\
CRLF

#define DSN_RECIPIENT_LINE						\
"\t<%s>" CRLF

#define DSN_REASON_LEAD_IN						\
CRLF									\
"For the following reason:" CRLF					\
CRLF									\

#define DSN_REASON_LINE							\
"\t%s" CRLF

#define DSN_DIVIDER							\
CRLF									\
"================================================================" CRLF	\
CRLF

/***********************************************************************
 ***
 ***********************************************************************/

#include <com/snert/lib/mail/smtp2.h>

void
sendDSN(Session *sess, Connection *fwd)
{
	Rcpt *rcpt;
	char **line;
	SMTP2 *smtp;

	syslog(LOG_ERR, LOG_MSG(331) "%s rejected message: %s", LOG_ARGS(sess), fwd->route.key, sess->reply);
/*{LOG
A forward host has rejected a message and a DSN has been sent,
}*/

	/* Send a Delivery Status Notification (DSN) to the sender. */
	if (sess->msg.mail->address.length == 0)
		return;

	if ((smtp = smtp2OpenMx(sess->msg.mail->domain.string, optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, 1)) == NULL)
		return;

	if (smtp2Mail(smtp, "") != SMTP_OK)
		goto error1;

	if (smtp2Rcpt(smtp, sess->msg.mail->address.string) != SMTP_OK)
		goto error1;

	if (verb_smtp.option.value)
		syslog(LOG_DEBUG, LOG_MSG(332) "generating DSN to <%s>", LOG_ARGS(sess), sess->msg.mail->address.string);

	TimeStamp(&smtp->start, sess->input, sizeof (sess->input));
	(void) smtp2Printf(smtp, "Date: %s" CRLF, sess->input);
	(void) smtp2Printf(smtp, "To: <%s>" CRLF, sess->msg.mail->address.string);
	(void) smtp2Printf(smtp, "From: \"%s\" <postmaster@%s>" CRLF, _NAME, sess->iface->name);

	if (*optSmtpDsnReplyTo.string != '\0')
		(void) smtp2Printf(smtp, "Reply-To: <%s>" CRLF, optSmtpDsnReplyTo.string);

	(void) smtp2Printf(smtp, "Message-ID: <%s@[%s]>" CRLF, smtp->id_string, smtp->local_ip);
	(void) smtp2Printf(smtp, "Subject: Mail delivery failed." CRLF);
	(void) smtp2Printf(smtp, "MIME-Version: 1.0" CRLF);
	(void) smtp2Printf(smtp, "Content-Type: text/plain" CRLF);
	(void) smtp2Printf(smtp, "Content-Transfer-Encoding: 8bit" CRLF);
	(void) smtp2Printf(smtp, "Auto-Submitted: auto-generated (failure)" CRLF);
	(void) smtp2Printf(smtp, "Precedence: first-class" CRLF);
	(void) smtp2Printf(smtp, "Priority: normal" CRLF);
	(void) smtp2Print(smtp, CRLF, 2);

	if (*optSmtpDsnReplyTo.string != '\0')
		(void) smtp2Printf(smtp, DSN_REPLY_TO, optSmtpDsnReplyTo.string);

	(void) smtp2Printf(smtp, "Message %s" CRLF, sess->msg.id);
	(void) smtp2Printf(smtp, DSN_RECIPIENT_LEAD_IN);

	for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next)
		(void) smtp2Printf(smtp, DSN_RECIPIENT_LINE, rcpt->rcpt->address.string);

	(void) smtp2Printf(smtp, DSN_REASON_LEAD_IN);

	if (fwd->reply == NULL) {
		(void) smtp2Printf(smtp, DSN_REASON_LINE, "(unknown)");
	} else {
		for (line = fwd->reply; *line != NULL; line++)
			(void) smtp2Printf(smtp, DSN_REASON_LINE, *line);
	}

	(void) smtp2Printf(smtp, DSN_DIVIDER);

	/* Send the original message headers. */
	sess->msg.chunk0[sess->msg.eoh] = '\0';
	(void) smtp2Print(smtp, sess->msg.chunk0, sess->msg.eoh);

	if (smtp2Dot(smtp) != SMTP_OK)
		goto error1;

	statsCount(&stat_dsn_sent);
error1:
	smtp2Close(smtp);
}
