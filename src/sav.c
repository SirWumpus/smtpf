/*
 * sav.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_SAV

#include "smtpf.h"

#include <com/snert/lib/crc/Luhn.h>
#include <com/snert/lib/mail/MailSpan.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_call_back[] =
  "When set, performs sender address verification using a call-back to\n"
"# one of the sender's MX hosts. Note that this form of test is very\n"
"# unpopular with large mail services for a variety of reasons such\n"
"# as resource consumption and that it can be abused for proxied\n"
"# dictionary harvesting attacks. Use of this test could result in\n"
"# black listing of your host by those services. Use with care.\n"
"#"
;

static const char usage_call_back_pass_grey[] =
  "If the call-back returns a pass result, then skip grey-listing.\n"
"#"
;

Option optCallBack		= { "call-back", 		"-", 		usage_call_back };
Option optCallBackPassGrey	= { "call-back-pass-grey",	"-",		usage_call_back_pass_grey };

static const char usage_call_back_strict_greeting[] =
  "During a call-back, require that the first word of the 220 response\n"
"# is a FQDN, otherwise fail the call-back. See RFC 2821 section 4.2\n"
"# grammar for greeting and section 4.3.1 paragraph 3.\n"
"#"
;
Option optCallBackStrictGreeting	= { "call-back-strict-greeting",	"-",		usage_call_back_strict_greeting };

static const char usage_call_back_uri_greeting[] =
  "During a call-back, URI BL test the FQDN host name given by the 220\n"
"# response. The call-back fails if the host name is listed.\n"
"#"
;
Option optCallBackUriGreeting	= { "call-back-uri-greeting",	"-",		usage_call_back_uri_greeting };

Stats stat_call_back_made	= { STATS_TABLE_DATA, "call-back-made" };
Stats stat_call_back_skip	= { STATS_TABLE_DATA, "call-back-skip" };
Stats stat_call_back_cache	= { STATS_TABLE_DATA, "call-back-cache" };
Stats stat_call_back_accept	= { STATS_TABLE_DATA, "call-back-accept" };
Stats stat_call_back_reject	= { STATS_TABLE_DATA, "call-back-reject" };
Stats stat_call_back_tempfail	= { STATS_TABLE_DATA, "call-back-tempfail" };

Stats stat_rfc2821_strict_greeting	= { STATS_TABLE_DATA, "call-back-strict-greeting" };
Stats stat_uri_call_back_greeting	= { STATS_TABLE_DATA, "call-back-uri-greeting" };

Verbose verb_sav		= { { "sav", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

int
savRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_sav);

	optionsRegister(&optCallBack, 			0);
	optionsRegister(&optCallBackPassGrey, 		0);
	optionsRegister(&optCallBackStrictGreeting,	0);
	optionsRegister(&optCallBackUriGreeting,	0);

	(void) statsRegister(&stat_call_back_made);
	(void) statsRegister(&stat_call_back_skip);
	(void) statsRegister(&stat_call_back_cache);
	(void) statsRegister(&stat_call_back_accept);
	(void) statsRegister(&stat_call_back_reject);
	(void) statsRegister(&stat_call_back_tempfail);
	(void) statsRegister(&stat_rfc2821_strict_greeting);
	(void) statsRegister(&stat_uri_call_back_greeting);

	return SMTPF_CONTINUE;
}

int
savInit(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}

int
savData(Session *sess, va_list ignore)
{
	URI *uri;
	long span;
	int offset;
	Connection *callback;
	int rc, domain_cached;
	mcc_row sender, domain;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(571) "savData()", LOG_ARGS(sess));

	rc = SMTPF_CONTINUE;

	if (!optCallBack.value)
		goto error0;

	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_HAS_AUTH|CLIENT_IS_GREY)
	|| sess->msg.mail->address.length == 0 || sess->msg.mail->domain.length == 0) {
		(void) TextCopy(sess->reply, sizeof (sess->reply), "null sender, white, auth, or relay, skipping");
		goto error1;
	}

	if (TextInsensitiveCompare(sess->msg.mail->localLeft.string, "postmaster") == 0) {
		(void) TextCopy(sess->reply, sizeof (sess->reply), "postmaster, skipping");
		goto error1;
	}

	/* Does the sender's domain blindly accept all recipients? */
	MEMSET(&domain, 0, sizeof (domain));
	domain.key_size = (unsigned short) snprintf((char *) domain.key_data, sizeof (domain.key_data), SAV_CACHE_TAG "%s", sess->msg.mail->domain.string);

	if ((domain_cached = mccGetRow(mcc, &domain)) == MCC_OK) {
		domain.key_data[domain.key_size] = '\0';
		domain.value_data[domain.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), domain.key_data, domain.value_data, FILE_LINENO);

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), domain.key_data, domain.value_data, FILE_LINENO);
		if (mccPutRow(mcc, &domain) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), domain.key_data, domain.value_data, FILE_LINENO);

		domain.value_data[domain.value_size] = '\0';

		if (SMTP_ISS_OK(domain.value_data)) {
			(void) TextCopy(sess->reply, sizeof (sess->reply), "dumb mail host, skipping");
			statsCount(&stat_call_back_skip);
			goto error1;
		}
	}

	if ((callback = connectionAlloc()) == NULL) {
		(void) TextCopy(sess->reply, sizeof (sess->reply), "out of memory");
		goto error1;
	}

	/* Have we previously seen this sender? */
	sender.key_size = (unsigned short) snprintf((char *) sender.key_data, sizeof (sender.key_data), SAV_CACHE_TAG "%s", sess->msg.mail->address.string);
	TextLower((char *) sender.key_data, -1);

	if (mccGetRow(mcc, &sender) == MCC_OK) {
		sender.value_data[sender.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), sender.key_data, sender.value_data, FILE_LINENO);

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), sender.key_data, sender.value_data, FILE_LINENO);
		if (mccPutRow(mcc, &sender) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), sender.key_data, sender.value_data, FILE_LINENO);

		statsCount(&stat_call_back_cache);
		sender.value_data[sender.value_size] = '\0';

		rc = sender.value_data[0] - '0';
		if (optCallBackPassGrey.value && rc == SMTPF_CONTINUE)
			rc = SMTPF_SKIP_NEXT;

		(void) TextCopy(sess->reply, sizeof (sess->reply), "cached");
		goto error3;
	}

	callback->route.key = strdup(sess->msg.mail->domain.string);

	/* Open connection for call-back. */
	if ((callback->mx = mxConnect(sess, sess->msg.mail->domain.string, IS_IP_RESTRICTED|IS_IP_LAN)) == NULL) {
		(void) TextCopy(sess->reply, sizeof (sess->reply), "connection error");
		rc = sess->smtp_code / 100;
		goto error3;
	}

	statsCount(&stat_call_back_made);

	/* Get welcome message from MX. */
	if (mxCommand(sess, callback, NULL, 220)) {
		rc = sess->smtp_code / 100;
		goto error3;
	}

	/* Extract FQDN from first word of 220 response. */
	offset = smtpGetReplyCodes(callback->reply[0], NULL, 0);
	span = MailSpanDomainName(callback->reply[0]+offset, 1);

	/* Accept IP-domain-literal eg. "[123.45.67.89]" as FQDN, but not a bare IP.
	 * Accept "domain.tld" as FQDN, but not the root domain eg. "some-name." or "."
	 */
	if (optCallBackStrictGreeting.value && span <= 0) {
		rc = SMTPF_REJECT;
		statsCount(&stat_rfc2821_strict_greeting);
		(void) TextCopy(sess->reply, sizeof (sess->reply), "220 response missing FQDN host name");
		syslog(LOG_DEBUG, LOG_MSG(829) "%s", LOG_ARGS(sess), sess->reply);
/*{LOG
See <a href="summary.html#opt_rfc2821_strict_greeting">rfc2821-strict-greeting</a> option.
}*/
		goto error3;
	}

	if (optCallBackUriGreeting.value && 0 < span && (uri = uriParse2(callback->reply[0]+offset, span, 2)) != NULL) {
		rc = uriblTestURI(sess, uri, 0);
		free(uri);

		if (rc == SMTPF_REJECT) {
			statsCount(&stat_uri_call_back_greeting);
			(void) TextCopy(sess->reply, sizeof (sess->reply), "220 response hostname URI BL listed");
			syslog(LOG_ERR, LOG_MSG(830) "%s", LOG_ARGS(sess), sess->reply);
/*{LOG
See <a href="summary.html#opt_uri_call_back_greeting">uri-call-back-greeting</a> option.
}*/
			goto error3;
		}
	}

	(void) snprintf(sess->input, sizeof (sess->input), "HELO %s\r\n", sess->iface->name);
	if (mxCommand(sess, callback, sess->input, 250)) {
		rc = sess->smtp_code / 100;
		goto error3;
	}

	(void) snprintf(sess->input, sizeof (sess->input), "MAIL FROM:<postmaster@%s>\r\n", sess->iface->name);
	if (mxCommand(sess, callback, sess->input, 250)) {
		rc = sess->smtp_code / 100;
		goto error3;
	}

	(void) snprintf(sess->input, sizeof (sess->input), "RCPT TO:<%s>\r\n", sess->msg.mail->address.string);
	(void) mxCommand(sess, callback, sess->input, 250);
	rc = sess->smtp_code / 100;

	if (rc == SMTPF_ACCEPT) {
		rc = optCallBackPassGrey.value ? SMTPF_SKIP_NEXT : SMTPF_CONTINUE;
	}

	sender.hits = 0;
	sender.created = time(NULL);
	sender.value_data[0] = rc + '0';
	sender.value_data[1] = '\0';
	sender.value_size = 1;

	/* If the sender address was accepted and domain's MX status
	 * hasn't been cached, then perform the false address test.
	 */
	if (rc != SMTPF_REJECT && domain_cached == MCC_NOT_FOUND) {
		/* Generate a false address, which is the local-part
		 * reversed plus a LUHN check digit appended.
		 */
		long length;
		char false_rcpt[SMTP_LOCAL_PART_LENGTH];

#ifdef CALL_BACK_RSET
		if (mxCommand(sess, callback, "RSET\r\n", 250))
			goto skip_false_rcpt;

		(void) snprintf(sess->input, sizeof (sess->input), "MAIL FROM:<postmaster@%s>\r\n", optInterfaceName.string);
		if (mxCommand(sess, callback, sess->input, 250)) {
			goto skip_false_rcpt;
#endif
		length = TextCopy(false_rcpt, sizeof (false_rcpt), sess->msg.mail->localLeft.string);
		TextReverse(false_rcpt, length);
		if (sizeof (false_rcpt) <= length)
			length = sizeof (false_rcpt)-2;
		false_rcpt[length++] = LuhnGenerate(false_rcpt) + '0';
		false_rcpt[length] = '\0';

		(void) snprintf(
			sess->input, sizeof (sess->input), "RCPT TO:<%s@%s>\r\n",
			false_rcpt, sess->msg.mail->domain.string
		);

		(void) mxCommand(sess, callback, sess->input, 250);

		/* Assume for an I/O error that the call-back MX dropped the
		 * connection and that the sender test result is still good.
		 *
		 * ovh.net drop the connection following a RSET after a bad
		 * RCPT TO: command.
		 *
		 * sappi.com (mxlogic.net) drop the connection following the
		 * second MAIL FROM: command after a bad RCPT TO: command.
		 */

#ifdef OLD_SMTP_ERROR_CODES
		if (sess->smtp_error & SMTP_ERROR_IO_MASK) {
#else
		if (SMTP_IS_ERROR(sess->smtp_code)) {
#endif
#ifdef CALL_BACK_RSET
skip_false_rcpt:
#endif
			domain.value_data[0] = SMTPF_REJECT + '0';
		} else {
			domain.value_data[0] = sess->smtp_code / 100 + '0';
		}

		if (SMTP_IS_TEMP(sess->smtp_code)) {
			/* Assume 4xx for false recipient is a grey-list
			 * response, add a temp.fail entry to the grey
			 * listing cache to optimise the sav/grey-list
			 * throughput on our end.
			 */
			(void) TextCopy(sess->reply, sizeof (sess->reply), "dumb mail host inconclusive");
			sender.value_data[0] = SMTPF_TEMPFAIL + '0';
			rc = SMTPF_TEMPFAIL;
		} else {
			domain.hits = 0;
			domain.value_size = 1;
			domain.value_data[1] = '\0';
			domain.created = time(NULL);
			sender.expires = domain.created + cacheGetTTL(sess->smtp_code / 100);

			domain.key_size = (unsigned short) snprintf((char *) domain.key_data, sizeof (domain.key_data), SAV_CACHE_TAG "%s", sess->msg.mail->domain.string);

			if (verb_cache.option.value)
				syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), domain.key_data, domain.value_data, FILE_LINENO);
			if (mccPutRow(mcc, &domain) == MCC_ERROR)
				syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), domain.key_data, domain.value_data, FILE_LINENO);

			if (SMTP_IS_OK(sess->smtp_code)) {
				(void) TextCopy(sess->reply, sizeof (sess->reply), "dumb mail host found");
				rc = SMTPF_CONTINUE;
				goto error2;
			} else {
				(void) TextCopy(sess->reply, sizeof (sess->reply), "not a dumb mail host");
			}

			/* rc = sender.value_data[0] - '0'; */
		}
	}

	/* Cache the sender call-back result. */
	sender.expires = sender.created + cacheGetTTL(rc);

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), sender.key_data, sender.value_data, FILE_LINENO);
	if (mccPutRow(mcc, &sender) == MCC_ERROR)
		syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), sender.key_data, sender.value_data, FILE_LINENO);
error3:
	if (rc == SMTPF_REJECT || rc == SMTPF_TEMPFAIL) {
		statsCount(rc == SMTPF_REJECT ? &stat_call_back_reject : &stat_call_back_tempfail);
		(void) replySetFmt(sess, rc, "%d %d.7.0 sender <%s> verification failed" ID_MSG(572) "\r\n", rc == SMTPF_TEMPFAIL ? 451 : 550, rc, sess->msg.mail->address.string, ID_ARG(sess));
/*{REPLY
A call-back to the sender's MX failed to validate their address.
See <a href="summary.html#opt_call_back">call-back</a> option.
}*/
	} else {
		statsCount(&stat_call_back_accept);
	}
error2:
	connectionFree(callback);
error1:
	syslog(LOG_INFO, LOG_MSG(573) "call-back mail=<%s> rc=%d reply=\"%s\"", LOG_ARGS(sess), sess->msg.mail->address.string, rc, sess->reply);
/*{LOG
A summary of call-back results.
}*/
error0:
	return rc;
}

#endif /* FILTER_SAV */
