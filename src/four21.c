/*
 * four21.c
 *
 * Copyright 2007 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_FOUR21

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_421_unknown_ip[] =
  "Test unknown client IP addresses by sending 421 for the banner and\n"
"# observer if they properly QUIT or incorrect disconnect. Subsequent\n"
"# connections by an IP that disconnected will be rejected.\n"
"#"
;

Option opt421UnknownIp			= { "_four21-unknown-ip",	"-", usage_421_unknown_ip };

Stats stat_421_unknown_ip_bad		= { STATS_TABLE_CONNECT, "_four21-unknown-ip-bad" };
Stats stat_421_unknown_ip_good		= { STATS_TABLE_CONNECT, "_four21-unknown-ip-good" };
Stats stat_421_unknown_ip_reject	= { STATS_TABLE_CONNECT, "_four21-unknown-ip-reject" };

/***********************************************************************
 ***
 ***********************************************************************/

int
four21Register(Session *sess, va_list ignore)
{
	optionsRegister(&opt421UnknownIp,		0);

	(void) statsRegister(&stat_421_unknown_ip_bad);
	(void) statsRegister(&stat_421_unknown_ip_good);
	(void) statsRegister(&stat_421_unknown_ip_reject);

	return SMTPF_CONTINUE;
}

static long
four21MakeKey(Session *sess, char *buffer, size_t size)
{
	long length;

	length  = TextCopy(buffer, size, FOUR21_CACHE_TAG);
	length += addPtrOrIpSuffix(sess, buffer+length, size-length);

	return length;
}

int
four21CacheUpdate(Session *sess, int set_smtpf_code)
{
	int rc;
	mcc_row row;

	row.hits = 0;
	row.value_size = 1;

#ifdef OLD
	row.key_size = (unsigned short) snprintf(row.key_data, sizeof (row.key_data), FOUR21_CACHE_TAG "%s", sess->client.addr);
#else
	row.key_size = (unsigned short) four21MakeKey(sess, row.key_data, sizeof (row.key_data));
#endif

	switch (mccGetRow(mcc, &row)) {
	case MCC_OK:
		/* We already have a record for this IP. */
		row.key_data[row.key_size] = '\0';
		row.value_data[row.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		rc = row.value_data[0] - '0';
		if (rc != SMTPF_TEMPFAIL)
			return rc;
		break;

	case MCC_ERROR:
		syslog(LOG_ERR, log_cache_get_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);
		return SMTPF_CONTINUE;

	default:
		/* We've not seen seen this record before. */
		row.created = time(NULL);
		rc = SMTPF_TEMPFAIL;
	}

	if (set_smtpf_code != SMTPF_UNKNOWN)
		rc = set_smtpf_code;

	row.expires = time(NULL) + cacheGetTTL(rc);
	row.value_data[0] = rc + '0';
	row.value_data[1] = '\0';

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
	if (mccPutRow(mcc, &row) == MCC_ERROR) {
		syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		rc = SMTPF_CONTINUE;
	}

	return rc;
}

int
four21Connect(Session *sess, va_list ignore)
{
	int rc;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(362) "four21Connect", LOG_ARGS(sess));

	if (!opt421UnknownIp.value || CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY))
		return SMTPF_CONTINUE;

	/* Check if this IP had been seen before. If it has not, then
	 * 421 the connection and observe if they send a clean QUIT,
	 * pipeline, or disconnect. If the latter two occur, then the
	 * IP is auto-blacklisted.
	 */
	switch (four21CacheUpdate(sess, SMTPF_UNKNOWN)) {
	case SMTPF_TEMPFAIL:
		rc = replyPushFmt(sess, SMTPF_TEMPFAIL, "421 4.4.0 client " CLIENT_FORMAT " unknown" ID_MSG(363) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
The Four21 module is experimental and is only present at select test sites.
See <a href="summary.html#opt_four21_unknown_ip">four21-unknown-ip</a> option.
<p>
This is a RFC 2821 conformance test. Check if the connecting client IP
that has never been seen before. If it has not, then 421 the connection
and observe if they send a clean QUIT (as specified in RFC 2821),
pipeline, or disconnect. If the latter two occur, then the IP is auto-blacklisted.
</p>
}*/
		sess->state = stateSink;
		break;
	case SMTPF_REJECT:
		/* Burn baby! Burn! */
		rc = replyPushFmt(sess, SMTPF_DROP, "554 5.4.0 client " CLIENT_FORMAT " \"No soup for you!\"" ID_MSG(364) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
The Four21 module is experimental and only present at select test sites.

This response (a reference to the Sienfeld Soup Nazi episode) is the
reply given if the client IP failed the 421 test and was subsequently
auto-blacklisted.

See <a href="summary.html#opt_four21_unknown_ip">four21-unknown-ip</a> option.
}*/
		statsCount(&stat_421_unknown_ip_reject);
		break;
	default:
		rc = SMTPF_CONTINUE;
	}

	return rc;
}

int
four21Close(Session *sess, va_list ignore)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(365) "four21Close", LOG_ARGS(sess));

	if (opt421UnknownIp.value && CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)) {
		if (CLIENT_ANY_SET(sess, CLIENT_HAS_QUIT)) {
			/* Clean QUIT. */
			(void) four21CacheUpdate(sess, SMTPF_CONTINUE);
			statsCount(&stat_421_unknown_ip_good);
		} else {
			(void) four21CacheUpdate(sess, SMTPF_REJECT);
			statsCount(&stat_421_unknown_ip_bad);
		}
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_FOUR21 */
