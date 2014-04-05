/*
 * click.c
 *
 * Copyright 2008, 2009 by Anthony Howe. All rights reserved.
 */


/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_CLICK
#include "smtpf.h"

#include <ctype.h>
#include <limits.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/util/md5.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define CLICK_STRING		"CLICK-"
#define CLICK_PREFIX_LENGTH	44	/* CLICK-ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm */
#define CLICK_STRING_LENGTH	(CLICK_PREFIX_LENGTH+SMTP_PATH_LENGTH)
#define CLICK_PRINTF_FORMAT	CLICK_STRING "%.6s%.32s"

#define CLICK_MAILTO_FORMAT	" White list by sending mail to <%s@%s>\r\n"
#define CLICK_HTTP_FORMAT	" White list via %s?h=%s&c=%s\r\n"

static const char usage_click_url[] =
  "Specify either an empty string, \"mailto\", or an http URL. If set to\n"
"# \"mailto\", then reject messages are appended with a special mail address\n"
"# that a sender can mail in order to get temporarily white listed. If set\n"
"# to an http: URL, then reject messages are appended with the given URL\n"
"# suffixed with query string parameters. Clicking on the link can then\n"
"# validate and white list a sender. Otherwise set to empty string to\n"
"# disable this facility.\n"
"#"
;

static const char usage_click_secret[] =
  "Specify a phrase used to generate and validate a click challenge. Be\n"
"# sure to quote the string if it contains white space.\n"
"#"
;

static const char usage_click_ttl[] =
  "Time-to-live in seconds for click challenge links.\n"
"#"
;

Option optClickUrl		= { "click-url",		"",		usage_click_url };
Option optClickSecret		= { "click-secret",		"",		usage_click_secret };
Option optClickTTL		= { "click-ttl",		"90000",	usage_click_ttl };

Stats stat_click_accept		= { STATS_TABLE_MAIL, "click-accept" };
Stats stat_click_pass		= { STATS_TABLE_RCPT, "click-pass" };
Stats stat_click_fail		= { STATS_TABLE_RCPT, "click-fail" };
Stats stat_click_ttl		= { STATS_TABLE_RCPT, "click-ttl" };

typedef struct {
	char reply[SMTP_REPLY_LINE_LENGTH+1];
} Click;

static FilterContext click_context;

/***********************************************************************
 ***
 ***********************************************************************/

static long
clickMakeKey(Session *sess, ParsePath *email, char *buffer, size_t size)
{
	long length;

	length  = TextCopy(buffer, size, CLICK_CACHE_TAG);
	length += addPtrOrIpSuffix(sess, buffer+length, size-length);
	buffer[length++] = ',';
	length += TextCopy(buffer+length, size-length, email->address.string);

	return length;
}

static int
clickMakeHash(Session *sess, time_t when, char *key, size_t length, char *buffer, size_t size)
{
	int i;
	md5_state_t md5;
	unsigned char digest[16];
	static const char hex_digit[] = "0123456789abcdef";

	(void) TextCopy(buffer, size, CLICK_STRING);
	time62Encode(when, buffer + sizeof (CLICK_STRING)-1);

	md5_init(&md5);
	md5_append(&md5, (md5_byte_t *) key, length);

	/* Encode the date the message was sent. This used to be
	 * the time_t binary value of `when'. However, the time_t
	 * type can be signed or unsigend 32 or 64-bits long. Newer
	 * systems appear to be moving towards signed 64-bit. This
	 * can cause problems when trying to compare CLICK strings
	 * generated by a system using a time_t with a different size.
	 *
	 * To resolve this, we now use the ASCII encoded 62-year
	 * cycle of the timestamp. For our purposes that is more
	 * than sufficient resolution and portable.
	 */
	md5_append(&md5, (md5_byte_t *) buffer + sizeof (CLICK_STRING)-1, TIME62_BUFFER_SIZE);

	/* Factor in our secret phrase. */
	md5_append(&md5, (md5_byte_t *) optClickSecret.string, optClickSecret.length);

	/* That's all folks. */
	md5_finish(&md5, (md5_byte_t *) digest);

	/* Convert digest into a readable string. */
	for (i = 0; i < 16; i++) {
		buffer[sizeof (CLICK_STRING)-1+6+(i << 1)] = hex_digit[(digest[i] >> 4) & 0x0F];
		buffer[sizeof (CLICK_STRING)-1+6+(i << 1) + 1] = hex_digit[digest[i] & 0x0F];
	}

	buffer[CLICK_PREFIX_LENGTH] = '\0';

	return CLICK_PREFIX_LENGTH;

}

int
clickRegister(Session *null, va_list ignore)
{
	optionsRegister(&optClickSecret, 0);
	optionsRegister(&optClickTTL, 0);
	optionsRegister(&optClickUrl, 0);

	(void) statsRegister(&stat_click_accept);
	(void) statsRegister(&stat_click_pass);
	(void) statsRegister(&stat_click_fail);
	(void) statsRegister(&stat_click_ttl);

	click_context = filterRegisterContext(sizeof (Click));

	return SMTPF_CONTINUE;
}

int
clickInit(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}

int
clickMail(Session *sess, va_list args)
{
	int rc, length;
	mcc_row row;
	ParsePath *mail;
	mcc_handle *mcc = SESS_GET_MCC(sess);

	rc = SMTPF_CONTINUE;

	LOG_TRACE(sess, 241, clickMail);

	mail = va_arg(args, ParsePath *);
	if (*optClickUrl.string == '\0' || mail->address.length <= 0)
		return SMTPF_CONTINUE;

	length = clickMakeKey(sess, mail, (char *)MCC_PTR_K(&row), MCC_DATA_SIZE);
	MCC_SET_K_SIZE(&row, length);

	if (mccGetRow(mcc, &row) == MCC_OK) {
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), LOG_CACHE_GET(&row), FILE_LINENO);

		/* Touch */
		rc = *MCC_PTR_V(&row) - '0';
		row.ttl = cacheGetTTL(rc);
		row.expires = time(NULL) + row.ttl;

		sess->msg.bw_state = rc;

		if (rc == SMTPF_ACCEPT) {
			if (verb_info.option.value)
				syslog(LOG_INFO, LOG_MSG(242) "host " CLIENT_FORMAT " sender <%s> white listed", LOG_ARGS(sess), CLIENT_INFO(sess), sess->msg.mail->address.string);
/*{LOG
A cached click white-list entry was found.
See the <a href="summary.html#opt_click_secret">Click</a> family of options.
}*/
			statsCount(&stat_click_accept);
			MAIL_SET(sess, MAIL_IS_WHITE);
			MSG_SET(sess, MSG_OK);

			/* Clear any previously delayed rejection. When
			 * there are two or more RCPTs, then subsequent
			 * RCPTs would see the delayed rejection via
			 * accessRcpt, unless the rejection is dismissed.
			 */
			replyDelayFree(sess);
		}

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), LOG_CACHE_PUT(&row), FILE_LINENO);
		if (mccPutRow(mcc, &row) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), LOG_CACHE_PUT_ERROR(&row), FILE_LINENO);
	}

	return rc;
}

int
clickRcpt(Session *sess, va_list args)
{
	int length;
	mcc_row row;
	ParsePath *rcpt;
	time_t when, now;
	char buffer[CLICK_PREFIX_LENGTH+1];
	mcc_handle *mcc = SESS_GET_MCC(sess);

	LOG_TRACE(sess, 243, clickRcpt);

	if (tolower(*optClickUrl.string) != 'm')
		return SMTPF_CONTINUE;

	rcpt = va_arg(args, ParsePath *);

	/* Is this message a CLICK- recipient? */
	if (TextInsensitiveStartsWith(rcpt->address.string, CLICK_STRING) <= 0)
		return SMTPF_CONTINUE;

	/* Pick off the timestamp. */
	when = time62Decode(rcpt->address.string + sizeof (CLICK_STRING)-1);

	/* Check if it has expired. */
	if (when + optClickTTL.value < time(NULL)) {
		statsCount(&stat_click_ttl);
		return replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> expired" ID_MSG(244), rcpt->address.string, ID_ARG(sess));
/*{REPLY
}*/
	}

	/* Build the cache key and local-part hash. */
	MEMSET(&row, 0, sizeof (row));
	length = clickMakeKey(sess, sess->msg.mail, (char *)MCC_PTR_K(&row), MCC_DATA_SIZE);
	(void) clickMakeHash(sess, when, (char *)MCC_PTR_K(&row), length, buffer, sizeof (buffer));
	MCC_SET_K_SIZE(&row, length);

	/* Validate the hash. Note that we check against address.string
	 * which has maintained the case of the original address, while
	 * localLeft.string will have been converted to lower case.
	 */
	if (strncmp(rcpt->address.string, buffer, CLICK_PREFIX_LENGTH) != 0) {
		statsCount(&stat_click_fail);
		return replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> invalid" ID_MSG(245), rcpt->address.string, ID_ARG(sess));
/*{REPLY
}*/
	}

	/* Sender has replied to the special recipient.
	 * Add a white list entry to the cache.
	 */
	(void) time(&now);
	statsCount(&stat_click_pass);
	row.ttl = cacheGetTTL(SMTPF_ACCEPT);
	row.expires = now + row.ttl;
	row.created = now;

	*MCC_PTR_V(&row) = SMTPF_ACCEPT + '0';
	MCC_SET_V_SIZE(&row, 1);

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), LOG_CACHE_PUT(&row), FILE_LINENO);
	if (mccPutRow(mcc, &row) == MCC_ERROR)
		syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), LOG_CACHE_PUT_ERROR(&row), FILE_LINENO);

	/* Discard messages addressed to the special recipient. */
	MSG_SET(sess, MSG_DISCARD);
	return sess->msg.bw_state = SMTPF_DISCARD;
}

char *
clickUrlEncode(const char *string)
{
	size_t length;
	char *out, *op;
	static char uri_unreserved[] = "-_.~";
	static const char hex_digit[] = "0123456789ABCDEF";

	length = strlen(string);
	if ((out = malloc(length * 3 + 1)) == NULL)
		return NULL;

	for (op = out ; *string != '\0'; string++) {
		if (isalnum(*string) || strchr(uri_unreserved, *string) != NULL) {
			*op++ = *string;
		} else {
			*op++ = '%';
			*op++ = hex_digit[(*string >> 4) & 0x0F];
			*op++ = hex_digit[*string & 0x0F];
		}
	}
	*op = '\0';

	return out;
}

int
clickReplyLog(Session *sess, va_list args)
{
	int len;
	time_t now;
	mcc_row row;
	Click *click;
	const char **reply;
	unsigned char *c_arg;
	size_t *reply_length;

	LOG_TRACE(sess, 246, clickReplyLog);

	if (*optClickUrl.string == '\0' || sess->msg.mail == NULL
	|| CLIENT_ANY_SET(sess, CLIENT_IS_LOCAL_BLACK|CLIENT_IS_GREY|CLIENT_IS_WHITE)
	|| MSG_ANY_SET(sess, MSG_OK|MSG_OK_AV|MSG_DISCARD|MSG_TRAP|MSG_POLICY)
	|| MAIL_ANY_SET(sess, MAIL_IS_LOCAL_BLACK|MAIL_IS_WHITE)
	|| RCPT_ANY_SET(sess, RCPT_IS_LOCAL_BLACK|RCPT_IS_WHITE|RCPT_FAILED)
	)
		return SMTPF_CONTINUE;

	reply = va_arg(args, const char **);
	reply_length = va_arg(args, size_t *);

	if (!SMTP_ISS_PERM(*reply))
		return SMTPF_CONTINUE;

	click = filterGetContext(sess, click_context);

	/* Generate the hash used for the local-part. */
	now = time(NULL);
	len = clickMakeKey(sess, sess->msg.mail, (char *)MCC_PTR_K(&row), MCC_DATA_SIZE);
	(void) clickMakeHash(sess, now, (char *)MCC_PTR_K(&row), len, sess->reply, sizeof (sess->reply));
	MCC_PTR_K(&row)[len] = '\0';
	MCC_SET_K_SIZE(&row, len);

	/*** We're assuming the rejection message is a single
	 *** line terminated by CRLF.
	 ***/

	(void) TextCopy(click->reply, sizeof (click->reply), *reply);

	switch (*optClickUrl.string) {
	case 'm':
		/* The mailto: link is less reliable as a spambot could
		 * easily parse and react to the challenge in an automated
		 * manner.
		 */
		len = snprintf(
			click->reply+(*reply_length-2), sizeof (click->reply)-(*reply_length-2),
			CLICK_MAILTO_FORMAT, sess->reply, sess->iface->name
		);
		break;
	case 'h':
		/* The http: link is more reliable as the CGI can be design
		 * to present some form of CAPTCHA to validate the sender
		 * before white listing.
		 */
		if ((c_arg = (unsigned char *) clickUrlEncode((char *)MCC_PTR_K(&row))) == NULL)
			c_arg = MCC_PTR_K(&row);
		len = snprintf(
			click->reply+(*reply_length-2), sizeof (click->reply)-(*reply_length-2),
			CLICK_HTTP_FORMAT, optClickUrl.string,
			sess->reply + sizeof (CLICK_STRING)-1,
			c_arg
		);
		if (c_arg != MCC_PTR_K(&row))
			free(c_arg);
		break;
	default:
		return SMTPF_CONTINUE;
	}

	if (*reply_length + len - 2 < sizeof (click->reply)) {
		*reply = (const char *) click->reply;
		*reply_length += len - 2;
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_CLICK */
