/*
 * cmd.c
 *
 * Copyright 2006, 2009 by Anthony Howe. All rights reserved.
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

	/*** TODO add support for Errors-To: header ***/

	if ((smtp = smtp2OpenMx(sess->msg.mail->domain.string, optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, 1)) == NULL)
		return;

	if (smtp2Mail(smtp, "") != SMTP_OK)
		goto error1;

	if (smtp2Rcpt(smtp, sess->msg.mail->address.string) != SMTP_OK)
		goto error1;

	if (1 < verb_smtp.option.value)
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
	/* RFC 3464 DSN Format */
	(void) smtp2Printf(smtp, "Content-Type: multipart/report; report-type=delivery-status; boundary=\"--=_%s\"" CRLF, sess->msg.id);
	(void) smtp2Printf(smtp, "Auto-Submitted: auto-generated (failure)" CRLF);
	(void) smtp2Printf(smtp, "Precedence: first-class" CRLF);
	(void) smtp2Printf(smtp, "Priority: normal" CRLF);
	(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);

	(void) smtp2Printf(smtp, "This is a multi-part message in MIME format." CRLF);

	/* Human readable section. */
	(void) smtp2Printf(smtp, "----=_%s" CRLF, sess->msg.id);
	(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);

	if (*optSmtpDsnReplyTo.string != '\0')
		(void) smtp2Printf(smtp, DSN_REPLY_TO, optSmtpDsnReplyTo.string);

#ifdef OLD
	(void) smtp2Printf(smtp, "Message %s" CRLF, sess->msg.id);

	(void) smtp2Printf(smtp, DSN_RECIPIENT_LEAD_IN);

	for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next)
		(void) smtp2Printf(smtp, DSN_RECIPIENT_LINE, rcpt->rcpt->address.string);
#endif
	(void) smtp2Printf(smtp, DSN_REASON_LEAD_IN);

	if (fwd->reply == NULL) {
		(void) smtp2Printf(smtp, DSN_REASON_LINE, "(unknown)");
	} else {
		for (line = fwd->reply; *line != NULL; line++)
			(void) smtp2Printf(smtp, DSN_REASON_LINE, *line);
	}

	/* Machine readable section. */
	(void) smtp2Printf(smtp, "----=_%s" CRLF, sess->msg.id);
	(void) smtp2Printf(smtp, "Content-Type: message/delivery-status" CRLF);
	(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);

	(void) smtp2Printf(smtp, "Reporting-MTA: dns; %s" CRLF, sess->iface->name);
	(void) smtp2Printf(smtp, "Received-From-MTA: dns; %s" CRLF, sess->client.name);
	(void) smtp2Printf(smtp, "X-Reporting-Envelope-Id: %s (%s)" CRLF, sess->msg.id, sess->long_id);
	(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);

	for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
		(void) smtp2Printf(smtp, "Final-Recipient: rfc822; %s" CRLF, rcpt->rcpt->address.string);
		(void) smtp2Printf(smtp, "Action: failed" CRLF);
		(void) smtp2Printf(smtp, "Status: %c.0.0" CRLF, SMTP_IS_TEMP(fwd->smtp_code) ? '4' : '5');
		(void) smtp2Printf(smtp, "Diagnostic-Code: smtp; %d" CRLF, fwd->smtp_code);
		(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);
	}

	/* Send the original message headers. */
	(void) smtp2Printf(smtp, "----=_%s" CRLF, sess->msg.id);
	(void) smtp2Printf(smtp, "Content-Type: text/rfc822-headers" CRLF);
	(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);

	sess->msg.chunk0[sess->msg.eoh] = '\0';
	(void) smtp2Print(smtp, (char *) sess->msg.chunk0, sess->msg.eoh);

	(void) smtp2Print(smtp, CRLF, CRLF_LENGTH);
	(void) smtp2Printf(smtp, "----=_%s--" CRLF, sess->msg.id);

	if (smtp2Dot(smtp) != SMTP_OK)
		goto error1;

	statsCount(&stat_dsn_sent);
error1:
	smtp2Close(smtp);
}
