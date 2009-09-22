/*
 * grey.c
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

#ifdef FILTER_GREY

#include "smtpf.h"

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
# include <stdint.h>
# endif
#endif

#include <ctype.h>
#include <com/snert/lib/mail/mime.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/util/setBitWord.h>
#include <com/snert/lib/sys/Time.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_grey_key[] =
  "A comma separated list of what composes the grey-list key: ip,\n"
"# ptr, helo, mail, rcpt. The ptr element is the PTR record for the\n"
"# connecting client minus the first label, so if host.example.com is\n"
"# the returned PTR value, then example.com is the value used. If there\n"
"# is no PTR record found or the client IP appears to be a dynamic IP,\n"
"# then the client IP address is used. Specify the empty string to \n"
"# disable grey-listing.\n"
"#"
;

static const char usage_grey_temp_fail_period[] =
  "This is the amount of time in seconds a correspondent's grey-list\n"
"# record will be temporarily rejected before being upgraded to a pass.\n"
"#\n"
"# The tags Grey-Connect: and Grey-To: can be used in the access-map to\n"
"# override this option. If a key is found, then the value is processed\n"
"# as a pattern list and the result returned. An integer, in place of an\n"
"# action word, specifies the number of seconds to temporarily reject\n"
"# a client. If several Grey-Connect: and Grey-To: keys are found then\n"
"# the minimum value is used. Specify zero (0) seconds to disable grey\n"
"# listing.\n"
"#"
;

static const char usage_grey_temp_fail_ttl[] =
  "Cache time-to-live in seconds to retain grey-list record that are\n"
"# in the temporary rejection state.\n"
"#"
;

Option optGreyKey		= { "grey-key",			"ptr,mail,rcpt",	usage_grey_key };
Option optGreyTempFailPeriod	= { "grey-temp-fail-period",	"600",			usage_grey_temp_fail_period };
Option optGreyTempFailTTL	= { "grey-temp-fail-ttl",	"90000",		usage_grey_temp_fail_ttl };

static const char usage_grey_content[] =
  "Content based grey listing. After all other content filters have passed\n"
"# over a message and when the grey-list key tuple has not been previously\n"
"# seen, we store a hash for the message and temporarily reject it, and\n"
"# grey-list at DATA until the grey-temp-fail-period expires. If the same\n"
"# message returns and matches the previously stored hash, then update the\n"
"# grey-list record to a pass. All other messages from the matching grey-list\n"
"# key tuple are temporarily rejected until the previously hashed message is\n"
"# sent again.\n"
"#"
;

Option optGreyContent		= { "grey-content",		"-",			usage_grey_content };

static const char usage_grey_content_save[] =
  "When set, save the DATA content that is hashed to a file in the\n"
"# save-dir directory. Intended for testing and diagnosis.\n"
"#"
;
Option optGreyContentSave	= { "grey-content-save",	"-",			usage_grey_content_save };

Option optGreyReportHeader = { "grey-report-header",	"X-Grey-Report", "The name of the grey report header. Empty string to disable." };


#if defined(ENABLE_GREY_TO_BLACK) && defined(ENABLE_PRUNED_STATS)
Stats stat_grey_upgrade		= { STATS_TABLE_DATA, "grey-upgrade" };
Stats stat_grey_downgrade	= { STATS_TABLE_DATA, "grey-downgrade" };
#endif
Stats stat_grey_accept		= { STATS_TABLE_DATA, "grey-continue" };
Stats stat_grey_tempfail	= { STATS_TABLE_DATA, "grey-tempfail" };
Stats stat_grey_reject		= { STATS_TABLE_DATA, "grey-reject" };

Stats stat_grey_content		= { STATS_TABLE_MSG, "grey-content" };
Stats stat_grey_hash_mismatch	= { STATS_TABLE_MSG, "grey-hash-mismatch" };
Stats stat_grey_hash_replaced	= { STATS_TABLE_MSG, "grey-hash-replaced" };

# if defined(ENABLE_GREY_DNSBL_RESET) && defined(ENABLE_PRUNED_STATS)
Stats stat_grey_dnsbl_reset	= { STATS_TABLE_RCPT, "grey-dnsbl-reset" };
Stats stat_grey_pass_dnsbl_hit	= { STATS_TABLE_RCPT, "grey-pass-dnsbl-hit" };
Stats stat_grey_uribl_reset	= { STATS_TABLE_MSG, "grey-uribl-reset" };
Stats stat_grey_pass_uribl_hit	= { STATS_TABLE_MSG, "grey-pass-uribl-hit" };
#endif

Verbose verb_grey = { { "grey", "-", "" } };


struct bitword grey_key_words[] = {
	{ GREY_TUPLE_IP, 	"ip" },
	{ GREY_TUPLE_PTR, 	"ptr" },
	{ GREY_TUPLE_PTRN, 	"ptrn" },
	{ GREY_TUPLE_P0F, 	"p0f" },
	{ GREY_TUPLE_HELO, 	"helo" },
	{ GREY_TUPLE_MAIL, 	"mail" },
	{ GREY_TUPLE_RCPT, 	"rcpt" },
	{ 0, 			NULL }
};

#define ACCESS_CONNECT		"grey-connect:"
#define ACCESS_FROM		"grey-from:"
#define ACCESS_TO		"grey-to:"

enum {
	STATE_TEXT,
	STATE_CONTENT,
	STATE_HTML_START,
	STATE_HTML_TAG,
};

typedef struct {
	FILE *fp;
	long period;
	char digest[33];
	md5_state_t md5;
	int skip_mime_part;
	Mime *mime;
	int state;
#ifdef OFF
#ifdef ENABLE_GREY_DNSBL_RESET
	int dnsbl_reset;
#endif
#endif
} Grey;

static FilterContext grey_context;
static pthread_mutex_t grey_mutex;

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef ENABLE_GREY_TO_BLACK
/* NOT USED, KEPT IN CASE WE CHOOSE TO REVISE IT */

#define GREY_SQL_DOWNGRADE_old	\
"REPLACE INTO mcc (k,d,c,t,e)"	\
" SELECT grey_key_to_host(k),'5',strftime('%s', 'now'),strftime('%s', 'now'),strftime('%s', 'now')+?2" \
" FROM mcc WHERE e<=?1 AND k LIKE 'grey:%' AND substr(d,0,1)='4';"

#define GREY_SQL_DOWNGRADE	\
"REPLACE INTO mcc (k,d,c,t,e)"	\
" SELECT grey_key_to_host(k),'5',strftime('%s', 'now'),strftime('%s', 'now'),strftime('%s', 'now')+?2" \
" FROM mcc WHERE e<=?1 AND substr(k,0,5) = 'grey:' AND substr(d,0,1)='4';"

static sqlite3_stmt *grey_sql_downgrade;

static void
grey_key_to_host(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	int span;
	char *old_key, *new_key;

	if (argc < 1 || SQLITE_NULL == sqlite3_value_type(argv[0]))
		return;

	/* Are we using grey keys we can convert to grey host? */
	if ((optGreyKey.value & (GREY_TUPLE_PTR|GREY_TUPLE_PTRN|GREY_TUPLE_IP)) == 0)
		return;

	/* Get the grey key. */
	old_key = (char *) sqlite3_value_text(argv[0]);

	/* Make sure it is grey: record. */
	if (old_key == NULL || TextSensitiveStartsWith(old_key, "grey:") < 0)
		return;

	/* Make sure it hasn't already bee chopped. */
	span = strcspn(old_key, ",");
	if (old_key[span] == '\0')
		return;

	if ((new_key = sqlite3_malloc(span+1)) == NULL) {
		sqlite3_result_error_nomem(context);
		return;
	}

	/* Convert the grey key into a grey host. */
#ifdef ENABLE_PRUNED_STATS
	statsCount(&stat_grey_downgrade);
#endif
	memcpy(new_key, old_key, span);
	new_key[span] = '\0';

	if (verb_grey.option.value)
		syslog(LOG_DEBUG, LOG_NUM(377) "converting %s to %s", old_key, new_key);

	sqlite3_result_text(context, new_key, span, sqlite3_free);
}

int
grey_cache_prepare(mcc_handle *mcc)
{
	if (sqlite3_create_function(mcc->db, "grey_key_to_host", 1, SQLITE_UTF8, NULL, grey_key_to_host, NULL, NULL) != SQLITE_OK) {
		syslog(LOG_ERR, LOG_NUM(378) "sql=%s create error: %s %s", mcc->path, "grey_key_to_host", sqlite3_errmsg(mcc->db));
		return -1;
	}

	if (sqlite3_prepare_v2(mcc->db, GREY_SQL_DOWNGRADE, -1, &grey_sql_downgrade, NULL) != SQLITE_OK) {
		syslog(LOG_ERR, LOG_NUM(379) "sql=%s statement error: %s %s", mcc->path, GREY_SQL_DOWNGRADE, sqlite3_errmsg(mcc->db));
		return -1;
	}

	return 0;
}

void
grey_cache_finalize(mcc_handle *mcc)
{
	if (grey_sql_downgrade != NULL) {
		sqlite3_finalize(grey_sql_downgrade);
		grey_sql_downgrade = NULL;
	}
}

mcc_extra grey_cache_extra = { grey_cache_prepare, grey_cache_finalize };

int
greyGc(Session *null, va_list args)
{
	int rc;
	time_t *when;
	mcc_handle *mcc;

	LOG_TRACE0(375, greyGc);

	mcc = va_arg(args, mcc_handle *);
	when = va_arg(args, time_t *);

	rc = SMTPF_UNKNOWN;

	if (mcc == NULL || when == NULL)
		goto error0;

	if (mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &mcc->mutex))
		goto error0;
	if (sqlite3_bind_int(grey_sql_downgrade, 1, (int)(uint32_t) *when) != SQLITE_OK)
		goto error1;
	if (sqlite3_bind_int(grey_sql_downgrade, 2, (int)(uint32_t) optCacheRejectTTL.value) != SQLITE_OK)
		goto error1;
	if (mccSqlStep(mcc, grey_sql_downgrade, GREY_SQL_DOWNGRADE) == SQLITE_DONE)
		rc = SMTPF_CONTINUE;
error1:
	(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &mcc->mutex);
error0:
	return rc;
}

#endif /* ENABLE_GREY_TO_BLACK */

static sqlite3_stmt *grey_sql_expire;

#define GREY_SQL_EXPIRE \
"SELECT count(*) FROM mcc WHERE e <= strftime('%s','now') AND substr(k,0,4)='grey' AND substr(d,0,1)='4';"

int
greyGcPrepare(mcc_context *mcc, void *data)
{
	if (sqlite3_prepare_v2(mcc->db, GREY_SQL_EXPIRE, -1, &grey_sql_expire, NULL) != SQLITE_OK) {
		syslog(LOG_ERR, LOG_NUM(908) "sql=%s statement error: %s %s", mcc->path, GREY_SQL_EXPIRE, sqlite3_errmsg(mcc->db));
		return -1;
	}

	return 0;
}

int
greyGcFinalise(mcc_context *mcc, void *data)
{
	if (grey_sql_expire != NULL) {
		(void) sqlite3_finalize(grey_sql_expire);
		grey_sql_expire = NULL;
	}

	return 0;
}

Stats stat_grey_temp_expire = { STATS_TABLE_GENERAL, "grey-temp-expire" };

int
greyGcExpire(mcc_context *mcc, void *data)
{
	int count;

	LOG_TRACE0(000, greyGcExpire);

	if (mccSqlStep(mcc, grey_sql_expire, GREY_SQL_EXPIRE) == SQLITE_ROW) {
		count = sqlite3_column_int(grey_sql_expire, 0);
		statsAddValue(&stat_grey_temp_expire, (unsigned long) count);
		syslog(LOG_INFO, LOG_NUM(910) "greyGcExpire count=%d", count);
		(void) sqlite3_reset(grey_sql_expire);
	}

	return 0;
}

mcc_hooks grey_cache_hooks = {
	NULL,
	greyGcExpire,
	greyGcPrepare,
	greyGcFinalise,
	NULL,
	NULL
};

/***********************************************************************
 ***
 ***********************************************************************/

static void
greyHashChar(Grey *grey, unsigned char ch)
{
	if (!isspace(ch)) {
		if (grey->fp != NULL)
			(void) fputc(ch, grey->fp);
		md5_append(&grey->md5, (md5_byte_t *) &ch, 1);
	}
}

static void
greyHashLine(Mime *m)
{
	unsigned char *decode;
	Grey *grey = m->mime_data;

	if (grey->skip_mime_part || (m->is_multipart && m->mime_part_number == 0))
		return;

	for (decode = m->decode.buffer; *decode != '\0'; decode++) {
		switch (grey->state) {
		case STATE_HTML_TAG:
			if (*decode == '>')
				grey->state = STATE_CONTENT;
			continue;

		case STATE_HTML_START:
			if (*decode == '!') {
				grey->state = STATE_HTML_TAG;
			} else {
				grey->state = STATE_CONTENT;
				greyHashChar(grey, '<');
				decode--;
			}
			continue;

		case STATE_CONTENT:
			if (*decode == '<') {
				grey->state = STATE_HTML_START;
				break;
			}
			/*@fallthrough@*/

		case STATE_TEXT:
			greyHashChar(grey, *decode);
		}
	}
}

static void
greyMimeResetPart(Mime *m)
{
	Grey *grey = m->mime_data;

	grey->skip_mime_part = 0;
	grey->state = STATE_TEXT;
}

static void
greyMimeHeader(Mime *m)
{
	Grey *grey = m->mime_data;

	if (TextMatch((char *) m->source.buffer, "Content-Type:*text/html*", m->source.length, 1))
		grey->state = STATE_CONTENT;
	else if (TextMatch((char *) m->source.buffer, "Content-Type:*application/ms-tnef*", m->source.length, 1))
		grey->skip_mime_part = 1;
}

static int
greyMimeInit(Grey *grey)
{
	grey->state = STATE_TEXT;
	grey->skip_mime_part = 0;

	if ((grey->mime = mimeCreate(grey)) == NULL)
		return -1;

	grey->mime->mime_header = greyMimeHeader;
	grey->mime->mime_source_flush = greyHashLine;
	grey->mime->mime_body_finish = greyMimeResetPart;

	return 0;
}

void
greyInitOptions(void)
{
	optGreyKey.value = setBitWord2(grey_key_words, optGreyKey.string, OPTION_LIST_DELIMS, 0);
	optGreyTempFailTTL.value = strtol(optGreyTempFailTTL.string, NULL, 0);
	optGreyTempFailPeriod.value = strtol(optGreyTempFailPeriod.string, NULL, 0);
}

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
greyAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&grey_mutex);
}

void
greyAtForkParent(void)
{
	(void) pthread_mutex_unlock(&grey_mutex);
}

void
greyAtForkChild(void)
{
	(void) pthread_mutex_unlock(&grey_mutex);
	(void) pthread_mutex_destroy(&grey_mutex);
}
#endif

int
greyRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_grey);

	optionsRegister(&optGreyContent,		0);
	optionsRegister(&optGreyContentSave,		0);
	optionsRegister(&optGreyKey, 			0);
	optionsRegister(&optGreyTempFailPeriod, 	0);
	optionsRegister(&optGreyTempFailTTL, 		0);
	optionsRegister(&optGreyReportHeader,		0);

	(void) statsRegister(&stat_grey_accept);
	(void) statsRegister(&stat_grey_tempfail);
	(void) statsRegister(&stat_grey_reject);
#if defined(ENABLE_GREY_TO_BLACK) && defined(ENABLE_PRUNED_STATS)
	(void) statsRegister(&stat_grey_upgrade);
	(void) statsRegister(&stat_grey_downgrade);
#endif
	(void) statsRegister(&stat_grey_content);
	(void) statsRegister(&stat_grey_hash_mismatch);
	(void) statsRegister(&stat_grey_hash_replaced);
# if defined(ENABLE_GREY_DNSBL_RESET) && defined(ENABLE_PRUNED_STATS)
	(void) statsRegister(&stat_grey_dnsbl_reset);
	(void) statsRegister(&stat_grey_pass_dnsbl_hit);
	(void) statsRegister(&stat_grey_uribl_reset);
	(void) statsRegister(&stat_grey_pass_uribl_hit);
# endif
	(void) statsRegister(&stat_grey_temp_expire);

	grey_context = filterRegisterContext(sizeof (Grey));

	return SMTPF_CONTINUE;
}

int
greyInit(Session *null, va_list ignore)
{
	(void) pthread_mutex_init(&grey_mutex, NULL);
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(greyAtForkPrepare, greyAtForkParent, greyAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	greyInitOptions();

	return SMTPF_CONTINUE;
}

int
greyFini(Session *null, va_list ignore)
{
	(void) pthread_mutex_destroy(&grey_mutex);
	return SMTPF_CONTINUE;
}

void
digestToString(unsigned char digest[16], char digest_string[33])
{
	int i;
	static const char hex_digit[] = "0123456789abcdef";

	for (i = 0; i < 16; i++) {
		digest_string[i << 1] = hex_digit[(digest[i] >> 4) & 0x0F];
		digest_string[(i << 1) + 1] = hex_digit[digest[i] & 0x0F];
	}
	digest_string[32] = '\0';
}

static int
greyHeader(Session *sess, mcc_row *row, time_t *now)
{
	char *hdr, timestamp[40];
	unsigned long age, h, m, s;

	if ((hdr = malloc(SMTP_TEXT_LINE_LENGTH)) == NULL)
		return SMTPF_CONTINUE;

	age = s = (unsigned long) (*now - row->created);
	h = s / 3600;
	s -= h * 3600;
	m = s / 60;
	s -= m * 60;

	(void) TimeStamp((time_t *) &row->created, timestamp, sizeof (timestamp));
	(void) snprintf(hdr, SMTP_TEXT_LINE_LENGTH, "%s: age=%lu (%.2lu:%.2lu:%.2lu) hits=%u key=%s at=\"%s\"\r\n", optGreyReportHeader.string, age, h, m, s, row->hits, row->key_data, timestamp);

	if (VectorAdd(sess->msg.headers, hdr))
		free(hdr);

	return SMTPF_CONTINUE;
}

static int
greyCacheUpdate(Session *sess, Grey *grey, char *key, long *delay, int at_dot)
{
	int ret, rc;
	time_t now;
	char *first_comma;
	mcc_row row, id_row;
	unsigned short key_size;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(380) "greyCacheUpdate(key=%s, at_dot=%d)", LOG_ARGS(sess), key, at_dot);

	ret = MCC_ERROR;
	now = time(NULL);
	first_comma = NULL;
	rc = SMTPF_CONTINUE;
	MEMSET(&row, 0, sizeof (row));
	row.value_data[0] = rc + '0';
	key_size = (unsigned short) TextCopy((char *) row.key_data, sizeof row.key_data, key);

	if (mutex_lock(SESS_ID, FILE_LINENO, &grey_mutex))
		goto error0;

	/* As an optimisation, when we upgrade a grey-listed
	 * entry from temp.fail to continue, then we know that
	 * host or mail server pool implements a retry queue
	 * so we simply record the host and skip further grey
	 * listing of them.
	 *
	 * First look for a host entry such as:
	 *
	 *	grey:ptr.domain.com
	 *	grey:123.45.67.89
	 *	grey:2001:0db8:0000:0000:0000:0000:1234:5678
	 */
	if ((optGreyKey.value & (GREY_TUPLE_PTR|GREY_TUPLE_PTRN|GREY_TUPLE_IP)) && (first_comma = strchr(key, ',')) != NULL) {
		/* Chop the key at the first comma. This will
		 * leave the PTR or IP address portion of the
		 * key as generated by greyMakeKey().
		 */
		row.key_size = (unsigned short) (first_comma - key);
		*first_comma = '\0';

		/* Find the grey host record to replace the
		 * grey key record.
		 */
		ret = mccGetRow(mcc, &row);

		/* Restore the grey key name in case we need
		 * to delete, create, or update.
		 */
		row.key_size = (unsigned short) key_size;
		*first_comma = ',';

		/* Did we find a grey host record? */
		if (ret == MCC_OK) {
			/* Then delete the grey key record. */
			if (verb_cache.option.value)
				syslog(LOG_DEBUG, log_cache_delete, LOG_ARGS(sess), row.key_data, FILE_LINENO);
			if (mccDeleteRow(mcc, &row) == MCC_ERROR)
				syslog(LOG_ERR, log_cache_delete_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);

			/* Restore the grey host record. */
			row.key_size = (unsigned short) (first_comma - key);
			*first_comma = '\0';
		}
	}

	/* Find the grey key record if there is no grey host record. */
	if (ret != MCC_OK) {
		row.key_size = (unsigned short) key_size;
		ret = mccGetRow(mcc, &row);
	}

	switch (ret) {
	case MCC_OK:
		row.key_data[row.key_size] = '\0';
		row.value_data[row.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		break;
	case MCC_ERROR:
		syslog(LOG_ERR, log_cache_get_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);
		goto error1;
	default:
		/* We've not seen seen this tuple before. */
		row.created = now;
		row.expires = now + optGreyTempFailTTL.value;
		row.value_data[0] = SMTPF_TEMPFAIL + '0';
		row.value_data[1] = '\0';
		row.value_size = 1;
		row.hits = 0;

		/* When grey-content is applied; a temp.fail record is added
		 * for each recipient at DATA, but the MD5 hash is not added
		 * until the final dot. Therefore between DATA and dot, there
		 * will be a period where the grey list record exists, but is
		 * incomplete.
		 *
		 * This is not wrong since it means grey-listing comes into
		 * play as soon as the record is created, preventing other
		 * messages from being accepted until the MD5 is appended,
		 * temp.fail period ends, and the original message returns.
		 */
	}

	rc = row.value_data[0] - '0';

	/* For an new or existing grey-list record without a digest,
	 * append the current message's digest.
	 */
	if (at_dot && row.value_size == 1) {
		row.value_size = 67;
		row.expires = now + optGreyTempFailTTL.value;

		/* First message hash. */
		row.value_data[1] = ' ';
		(void) TextCopy((char *) row.value_data+2, sizeof (row.value_data)-2, grey->digest);

		/* Last message hash. */
		row.value_data[34] = ' ';
		(void) TextCopy((char *) row.value_data+35, sizeof (row.value_data)-35, grey->digest);

		if (sess->msg.msg_id != NULL) {
			/* Exchange is a piece of crap. The MD5 of first message body
			 * does not match the MD5 of the second and and subsequent
			 * message retries. Exchange appears to change the MIME
			 * boundary, possible QP, and spacing, and might add also
			 * message disclaimers, essentially fucking with any attempt
			 * to hash the first message body.
			 *
			 * The only constant is that the message-id is the same: so
			 * we cache the message-id of the first attempt. On the second
			 * attempt of the message with the same message-id, we replace
			 * the first MD5 hash with the value of the second message
			 * attempt, discard the message-id from the cache, and temp.
			 * fail one more time. The third retry the message should thus
			 * subsequently pass grey-content.
			 */
			MEMSET(&id_row, 0, sizeof (id_row));
			id_row.created = now;
			row.expires = now + cacheGetTTL(rc);
			id_row.key_size = (unsigned short) snprintf((char *) id_row.key_data, sizeof (id_row.key_data), "grey-msgid:%s", sess->msg.msg_id);
			while (isspace(id_row.key_data[id_row.key_size-1]))
				id_row.key_size--;
			id_row.value_data[0] = row.value_data[0];
			id_row.value_size = 1;

			(void) mccPutRow(mcc, &id_row);
		}
	}

	/* Is the tuple still being temporarily blocked? */
	switch (rc) {
	case SMTPF_DROP:
	case SMTPF_TEMPFAIL:
		if (row.created + grey->period <= now) {
			/* Add the header always in the event that the
			 * grey-content hash matches and the message
			 * is accepted.
			 */
			if (!at_dot && *optGreyReportHeader.string != '\0')
				(void) greyHeader(sess, &row, &now);

			if (optGreyContent.value && !at_dot) {
				/* Wait until greyDot() to update the record.*/
				rc = SMTPF_CONTINUE;
				goto error1;
			}

			/* Check if this is the first or last message seen. */
			if (at_dot
			&& row.value_size == 67
			&& strncmp((char *) row.value_data+2, grey->digest, 32) != 0
			&& strncmp((char *) row.value_data+35, grey->digest, 32) != 0
			) {
				/* Exchange is a piece of crap. See note above. */
				if (sess->msg.msg_id != NULL) {
					MEMSET(&id_row, 0, sizeof (id_row));
					id_row.key_size = (unsigned short) snprintf((char *) id_row.key_data, sizeof (id_row.key_data), "grey-msgid:%s", sess->msg.msg_id);
					while (isspace(id_row.key_data[id_row.key_size-1]))
						id_row.key_size--;

					if (mccGetRow(mcc, &id_row) == MCC_OK) {
						/* Remove cached grey-msgid: row. */
						(void) mccDeleteRow(mcc, &id_row);

						if (verb_info.option.value)
							syslog(LOG_INFO, LOG_MSG(000) "grey content hash replaced msg-id=%s key={%s} value={%s} hash=%s", LOG_ARGS(sess), sess->msg.msg_id, key, row.value_data, grey->digest);

						/* Replace the first seen message hash. */
						row.value_data[1] = ' ';
						row.created = now;
						row.expires = now + optGreyTempFailTTL.value;
						(void) TextCopy((char *) row.value_data+2, sizeof (row.value_data)-2, grey->digest);

						statsCount(&stat_grey_hash_replaced);
						if (delay != NULL)
							*delay = row.created + grey->period  - now;
						break;
					}
				}

				/* Keep returning temp.fail until we see a
				 * previously hashed message come back.
				 */
				if (verb_grey.option.value)
					syslog(LOG_DEBUG, LOG_MSG(381) "grey content hash mismatch key={%s} value={%s} hash=%s", LOG_ARGS(sess), key, row.value_data, grey->digest);
				MSG_SET(sess, MSG_GREY_HASH_MISMATCH);
				statsCount(&stat_grey_hash_mismatch);
				*delay = -1;

				/* Replace the last message seen hash with
				 * the hash for this message.
				 */
				(void) TextCopy((char *) row.value_data+35, sizeof (row.value_data)-35, grey->digest);
				break;
			}

			if (verb_grey.option.value)
				syslog(LOG_DEBUG, LOG_MSG(382) "grey pass key={%s} age=%lu", LOG_ARGS(sess), key, (unsigned long)(now - row.created));

			/* As an optimisation, when we upgrade a grey-listed
			 * entry from temp.fail to continue, then we know that
			 * host or mail server pool implements a retry queue
			 * so we simply record the host and skip further grey
			 * listing of them.
			 */
			if (first_comma != NULL) {
				/* Chop the key at the first comma. This will
				 * leave the PTR or IP address portion of the
				 * key as generated by greyMakeKey().
				 */
				*first_comma = '\0';
				row.key_size = (unsigned short) (first_comma - key);
			}

			/* Upgrade from temp.fail to accept once block time expires. */
			row.created = now;
			row.expires = now + optCacheAcceptTTL.value;

			/* Add the grey age and hits to the record value. */
			row.value_size = snprintf((char *) row.value_data, sizeof (row.value_data), "%c %lu %u", SMTPF_CONTINUE + '0', (unsigned long)(now - row.created), row.hits);
			if (sizeof (row.value_data) <= row.value_size) {
				row.value_data[1] = '\0';
				row.value_size = 1;
			}

#if defined(ENABLE_GREY_TO_BLACK) && defined(ENABLE_PRUNED_STATS)
			statsCount(&stat_grey_upgrade);
#endif
			rc = SMTPF_CONTINUE;
			row.hits = 0;
		} else if (delay != NULL) {
			*delay = row.created + grey->period  - now;
		}
		break;

	default:
		row.expires = now + cacheGetTTL(rc);
		break;
	}

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
	if (mccPutRow(mcc, &row) == MCC_ERROR) {
		syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		row.value_data[0] = SMTPF_CONTINUE + '0';
		rc = SMTPF_CONTINUE;
	}

	if (optGreyContent.value && !at_dot && row.created == now)
		rc = SMTPF_CONTINUE;
error1:
	(void) mutex_unlock(SESS_ID, FILE_LINENO, &grey_mutex);
error0:
	return rc;
}

long
greyPtrSuffix(Session *sess, char *buffer, long size)
{
	char *first_dot;
	long tld_offset;

	if ((first_dot = strchr(sess->client.name, '.')) == NULL)
		return 0;

	/* Consider when the PTR for [89.234.6.38]
	 * is pcspecialist.co.uk, which is both a
	 * domain name and a host.
	 */
	tld_offset = indexValidTLD(sess->client.name);
	if (first_dot+1 == &sess->client.name[tld_offset] || strchr(++first_dot, '.') == NULL)
		first_dot = sess->client.name;

	return snprintf(buffer, size, "%s", first_dot);
}

/*
 * Convert and compact numbers in a PTR to single hash signs.
 */
long
greyPtrNSuffix(Session *sess, char *buffer, long size)
{
	int length;
	long offset;
	char *scan, *digit, *stop;

	/* Consider when the PTR for [89.234.6.38]
	 * is pcspecialist.co.uk, which is both a
	 * domain name and a host.
	 */
	offset = indexValidTLD(sess->client.name);
	offset = strlrcspn(sess->client.name, offset-1, ".");
	length = snprintf(buffer, size, "%s", sess->client.name);

	/* Convert and compact numbers to a single hash sign. */
	for (scan = buffer, stop = &buffer[offset - (0 < offset)]; scan < stop; scan++) {
		if (isdigit(*scan)) {
			*scan++ = '#';
			for (digit = scan; isdigit(*digit); digit++)
				;
			memmove(scan, digit, length - (digit - buffer) +1);
			length -= digit - scan;
		}
	}

	return length;
}

long
greyMakeKey(Session *sess, long grey_key, ParsePath *rcpt, char *buffer, size_t size)
{
	int i;
	long length, n;

	length = TextCopy(buffer, size, GREY_CACHE_TAG);

	for (i = GREY_TUPLE_IP; i <= GREY_TUPLE_RCPT; i <<= 1) {
		switch (grey_key & i) {
		case GREY_TUPLE_PTR:
		case GREY_TUPLE_PTRN:
			if (CLIENT_NOT_SET(sess, CLIENT_IS_IP_IN_PTR|CLIENT_IS_PTR_MULTIDOMAIN)
			&& (CLIENT_NOT_SET(sess, CLIENT_NO_PTR) || CLIENT_ANY_SET(sess, CLIENT_IS_HELO_HOSTNAME))
#ifdef FILTER_SPF
			&& sess->msg.spf_mail != SPF_FAIL
			&& sess->msg.spf_mail != SPF_SOFTFAIL
#endif
			&& (
			     ((grey_key & GREY_TUPLE_PTR) && 0 < (n = greyPtrSuffix(sess, buffer+length, size-length)))
			     || 0 < (n = greyPtrNSuffix(sess, buffer+length, size-length))
			   )
			) {
				length += n;
				length += snprintf(buffer + length, size - length, ",");
				break;
			}
			/*@fallthrough@*/
		case GREY_TUPLE_IP:
			length += snprintf(buffer + length, size - length, "%s,", sess->client.addr);
			break;

		case GREY_TUPLE_P0F:
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
{
			P0F *data = filterGetContext(sess, p0f_context);

			if (data->p_response.magic != QUERY_MAGIC
			|| data->p_response.type != RESP_OK
			|| *data->p_response.genre == '\0')
				length += snprintf(buffer + length, size - length, "(unknown),");
			else
				length += snprintf(buffer + length, size - length, "%s,", data->p_response.genre);
}
#endif
			break;
		case GREY_TUPLE_HELO:
			length += snprintf(buffer + length, size - length, "%s,", sess->client.helo);
			break;
		case GREY_TUPLE_MAIL:
			length += snprintf(buffer + length, size - length, "%s@%s,", sess->msg.mail->localLeft.string, sess->msg.mail->domain.string);
			break;
		case GREY_TUPLE_RCPT:
			if (rcpt != NULL)
				length += snprintf(buffer + length, size - length, "%s@%s,", rcpt->localLeft.string, rcpt->domain.string);
			break;
		}

		/* Check for key overflow. */
		if (size <= length) {
			length = size-1;
			buffer[length] = '\0';
			syslog(LOG_ERR, LOG_MSG(383) "greyMakeKey() overflow caught, key={%s} truncated", LOG_ARGS(sess), buffer);
/*{LOG
}*/
			break;
		}
	}

	if (0 < length && buffer[length-1] == ',')
		buffer[--length] = '\0';

	TextLower(buffer, -1);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(384) "grey-key=%s", LOG_ARGS(sess), buffer);

	return length;
}

#ifdef ENABLE_GREY_DNSBL_RESET
int
greyRcpt(Session *sess, va_list args)
{
	Grey *grey;
	mcc_row row;
	ParsePath *rcpt;

	LOG_TRACE(sess, 385, greyRcpt);
	grey = filterGetContext(sess, grey_context);

	/* Have we already reset the grey temp. fail key this session? */
#ifdef OFF
	if (CLIENT_NOT_SET(sess, CLIENT_IS_BLACK) || grey->dnsbl_reset)
#else
	if (CLIENT_NOT_SET(sess, CLIENT_IS_BLACK))
#endif
		return SMTPF_CONTINUE;

	if (CLIENT_ALL_SET(sess, CLIENT_PASSED_GREY|CLIENT_IS_BLACK))
		/* Client host IP was blacklisted after passing grey-listing. */
#if defined(ENABLE_PRUNED_STATS)
		statsCount(&stat_grey_pass_dnsbl_hit);
#else
		;
#endif

	else if (!mutex_lock(SESS_ID, FILE_LINENO, &grey_mutex)) {
		rcpt = va_arg(args, ParsePath *);
		row.key_size = greyMakeKey(sess, optGreyKey.value, rcpt, (char *) row.key_data, sizeof (row.key_data));

		/* Does the temp. fail key exist? */
		if (mccGetRow(mcc, &row) == MCC_OK && row.value_data[0] - '0' == SMTPF_TEMPFAIL) {
			if (verb_cache.option.value)
				syslog(LOG_DEBUG, log_cache_delete, LOG_ARGS(sess), row.key_data, FILE_LINENO);
			/* Then delete the grey temp. fail key. The
			 * assumption is that a host on a DNS / URI BL
			 * is a bad actor and any temp. fail period in
			 * progress can be removed, forcing the host
			 * to retry later.
			 *
			 * For hosts that have passed grey-listing or
			 * grey-content, we leave the record untouched
			 * since it could be a legit server that has
			 * had a temporary misconfiguration or infection.
			 */
#if defined(ENABLE_PRUNED_STATS)
			statsCount(&stat_grey_dnsbl_reset);
#endif
			if (mccDeleteRow(mcc, &row) == MCC_ERROR)
				syslog(LOG_ERR, log_cache_delete_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);
#ifdef OFF
			grey->dnsbl_reset = 1;
#endif
		}
		(void) mutex_unlock(SESS_ID, FILE_LINENO, &grey_mutex);
	}

	return SMTPF_CONTINUE;
}
#endif

int
greyData(Session *sess, va_list args)
{
	int rc;
	Grey *grey;
	Rcpt *rcpt;
	long delay;
	char *value;
	Connection *fwd;
	char tuple[SMTP_DOMAIN_LENGTH + SMTP_DOMAIN_LENGTH + SMTP_PATH_LENGTH + SMTP_PATH_LENGTH];

	LOG_TRACE(sess, 386, greyData);
	grey = filterGetContext(sess, grey_context);

	if (optGreyKey.value == 0 || CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_HAS_AUTH|CLIENT_IS_2ND_MX|CLIENT_IS_GREY)) {
		grey->period = 0;
		return SMTPF_CONTINUE;
	}

	grey->period = optGreyTempFailPeriod.value;
	md5_init(&grey->md5);
	grey->mime = NULL;
	grey->fp = NULL;

	if (accessClient(sess, ACCESS_CONNECT, sess->client.name, sess->client.addr, NULL, &value, 1) != SMDB_ACCESS_NOT_FOUND) {
		grey->period = strtol(value, NULL, 10);
		free(value);
	}

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
		for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
			if (accessEmail(sess, ACCESS_TO, rcpt->rcpt->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
				delay = strtol(value, NULL, 10);
				if (delay < grey->period)
					grey->period = delay;
				free(value);
			}
		}
	}

	if (grey->period <= 0) {
		CLIENT_SET(sess, CLIENT_IS_GREY_EXEMPT);
		return SMTPF_CONTINUE;
	}

	greyMimeInit(grey);

	if (optGreyKey.value & GREY_TUPLE_RCPT) {
		rc = SMTPF_CONTINUE;

		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
				(void) greyMakeKey(sess, optGreyKey.value, rcpt->rcpt, tuple, sizeof (tuple));
				if ((rc = greyCacheUpdate(sess, grey, tuple, &delay, 0)) == SMTPF_CONTINUE)
					goto break_outer_loop;
			}
		}
break_outer_loop:
		;
	} else {
		(void) greyMakeKey(sess, optGreyKey.value, NULL, tuple, sizeof (tuple));
		rc = greyCacheUpdate(sess, grey, tuple, &delay, 0);
	}

	switch (rc) {
	case SMTPF_CONTINUE:
		statsCount(&stat_grey_accept);
		break;
	case SMTPF_TEMPFAIL:
		statsCount(&stat_grey_tempfail);
		if (verb_info.option.value) {
			syslog(LOG_INFO, LOG_MSG(387) "grey listed {%s} for %ld seconds", LOG_ARGS(sess), tuple, delay);
/*{LOG
See <a href="summary.html#opt_grey_key">grey-key</a>,
<a href="summary.html#opt_grey_content">grey-content</a>,
and <a href="summary.html#opt_grey_temp_fail_period">grey-temp-fail-period</a> options.
}*/
		}

		/* It has been observed that some spammers remain connected
		 * and repeatedly attempt to send a message for the same
		 * sender-recipient pair or even different pairs. When
		 * grey-key uses ip or ptr elements, then we know that the
		 * connection will be repeated temp.failed until the
		 * grey-temp-fail-period, so force a drop in order to force
		 * the client that they implement a retry queue.
		 *
		 * The options smtp-drop-after and/or smtpf-reject-delay
		 * would eventually catch this abuse, but this is a time
		 * and resource saving measure.
		 */
		if (optGreyKey.value & (GREY_TUPLE_PTR|GREY_TUPLE_PTRN|GREY_TUPLE_IP))
			rc = SMTPF_DROP;

		/* See http://lists.puremagic.com/pipermail/greylist-users/2004-September/000766.html
		 * about use of 451 vs 450.
		 */
		(void) replyPushFmt(sess, rc, msg_451_try_again, ID_ARG(sess));
		break;

	default:
#ifdef ENABLE_GREY_TO_BLACK
		(void) replyPushFmt(sess, rc, "550 5.7.1 " CLIENT_FORMAT " failed grey listing" ID_MSG(388) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
#else
		syslog(LOG_WARN, LOG_MSG(937) "WARNING grey list {%s} rc=%d unexpected, check cache", LOG_ARGS(sess), tuple, rc);
		rc = SMTPF_CONTINUE;
#endif
		statsCount(&stat_grey_reject);
		break;
	}

	return rc;
}

int
greyRset(Session *sess, va_list ignore)
{
	Grey *grey;

	LOG_TRACE(sess, 389, greyRset);
	grey = filterGetContext(sess, grey_context);

	if (grey->fp != NULL) {
		(void) fclose(grey->fp);
		grey->fp = NULL;
	}

	mimeFree(grey->mime);
	grey->mime = NULL;

	return SMTPF_CONTINUE;
}

int
greyHeaders(Session *sess, va_list args)
{
	Grey *grey;

	LOG_TRACE(sess, 390, greyHeaders);
	grey = filterGetContext(sess, grey_context);

	if (optGreyContentSave.value && *optSaveDir.string != '\0') {
		(void) snprintf(sess->input, sizeof (sess->input), "%s/%s.grey", optSaveDir.string, sess->msg.id);
		if ((grey->fp = fopen(sess->input, "wb")) != NULL)
			cliFdCloseOnExec(fileno(grey->fp), 1);
	}

	return SMTPF_CONTINUE;
}

int
greyContent(Session *sess, va_list args)
{
	long size;
	Grey *grey;
	unsigned char *chunk;

	grey = filterGetContext(sess, grey_context);
	if (!optGreyContent.value || grey->period <= 0)
		return SMTPF_CONTINUE;

	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(391) "greyContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	/* Be sure to scan the original message headers in order
	 * correctly parse a MIME message.
	 */
	if (chunk == sess->msg.chunk0 + sess->msg.eoh) {
		chunk = sess->msg.chunk0;
		size += sess->msg.eoh;
	}

	for ( ; 0 < size; size--, chunk++) {
		if (mimeNextCh(grey->mime, *chunk))
			break;
	}

#ifdef FILTER_GREY_CONTENT_SHORTCUT
	/* As an optimisation concerning spamd, when we see the
	 * final dot in a chunk, then call dot handler immediately,
	 * instead of in the dot handler phase. So if the entire
	 * message fits in the first chunk, we can avoid connecting
	 * to spamd entirely, which is last in filter_content_table.
	 */
	if (sess->msg.seen_final_dot)
		return greyDot(sess, NULL);
#endif

	return SMTPF_CONTINUE;
}

int
greyDot(Session *sess, va_list ignore)
{
	int rc;
	Grey *grey;
	Rcpt *rcpt;
	long delay;
	Connection *fwd;
	uint8_t digest[16];
	char tuple[SMTP_DOMAIN_LENGTH + SMTP_DOMAIN_LENGTH + SMTP_PATH_LENGTH + SMTP_PATH_LENGTH];

	LOG_TRACE(sess, 392, greyDot);
	grey = filterGetContext(sess, grey_context);

	if (!optGreyContent.value)
		return SMTPF_CONTINUE;

#ifdef ENABLE_GREY_DNSBL_RESET
	if (MSG_ANY_SET(sess, MSG_IS_URIBL|MSG_IS_DNSBL)) {
		if (CLIENT_ALL_SET(sess, CLIENT_PASSED_GREY))
			/* URI was blacklisted after passing grey-listing. */
#if defined(ENABLE_PRUNED_STATS)
			statsCount(&stat_grey_pass_uribl_hit);
#else
			;
#endif

		else if (!mutex_lock(SESS_ID, FILE_LINENO, &grey_mutex)) {
			mcc_row row;

			if (optGreyKey.value & GREY_TUPLE_RCPT) {
				for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
					for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
						row.key_size = greyMakeKey(sess, optGreyKey.value, rcpt->rcpt, (char *) row.key_data, sizeof (row.key_data));

						/* Does the temp. fail key exist? */
						if (mccGetRow(mcc, &row) == MCC_OK && row.value_data[0] - '0' == SMTPF_TEMPFAIL) {
							if (verb_cache.option.value)
								syslog(LOG_DEBUG, log_cache_delete, LOG_ARGS(sess), row.key_data, FILE_LINENO);
#if defined(ENABLE_PRUNED_STATS)
							statsCount(&stat_grey_uribl_reset);
#endif
							if (mccDeleteRow(mcc, &row) == MCC_ERROR)
								syslog(LOG_ERR, log_cache_delete_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);
						}
					}
				}
			} else {
				row.key_size = greyMakeKey(sess, optGreyKey.value, NULL, (char *) row.key_data, sizeof (row.key_data));

				/* Does the temp. fail key exist? */
				if (mccGetRow(mcc, &row) == MCC_OK && row.value_data[0] - '0' == SMTPF_TEMPFAIL) {
					if (verb_cache.option.value)
						syslog(LOG_DEBUG, log_cache_delete, LOG_ARGS(sess), row.key_data, FILE_LINENO);
#if defined(ENABLE_PRUNED_STATS)
					statsCount(&stat_grey_uribl_reset);
#endif
					if (mccDeleteRow(mcc, &row) == MCC_ERROR)
						syslog(LOG_ERR, log_cache_delete_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);
				}
			}

			(void) mutex_unlock(SESS_ID, FILE_LINENO, &grey_mutex);
		}
	}
#endif
	if (grey->period <= 0)
		return SMTPF_CONTINUE;

	md5_finish(&grey->md5, (md5_byte_t *) digest);
	digestToString(digest, grey->digest);

	if (optGreyKey.value & GREY_TUPLE_RCPT) {
		rc = SMTPF_CONTINUE;

		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
				(void) greyMakeKey(sess, optGreyKey.value, rcpt->rcpt, tuple, sizeof (tuple));
				if ((rc = greyCacheUpdate(sess, grey, tuple, &delay, 1)) == SMTPF_CONTINUE)
					goto break_outer_loop;
			}
		}
break_outer_loop:
		;
	} else {
		(void) greyMakeKey(sess, optGreyKey.value, NULL, tuple, sizeof (tuple));
		rc = greyCacheUpdate(sess, grey, tuple, &delay, 1);
	}

	if (rc == SMTPF_TEMPFAIL) {
		MSG_SET(sess, MSG_GREY_CONTENT);
		statsCount(&stat_grey_content);
		if (verb_info.option.value) {
			if (delay <= 0) {
				syslog(LOG_INFO, LOG_MSG(393) "grey-content message mismatch", LOG_ARGS(sess));
/*{LOG
See <a href="summary.html#opt_grey_content">grey-content</a> option.
}*/
			} else {
				syslog(LOG_INFO, LOG_MSG(394) "grey-content listed {%s} for %ld seconds", LOG_ARGS(sess), tuple, delay);
/*{LOG
See <a href="summary.html#opt_grey_content">grey-content</a>
and <a href="summary.html#opt_grey_temp_fail_period">grey-temp-fail-period</a> options.
}*/
			}
		}

		/* It has been observed that some spammers remain connected
		 * and repeatedly attempt to send a message for the same
		 * sender-recipient pair or even different pairs. When
		 * grey-key uses ip or ptr elements, then we know that the
		 * connection will be repeated temp.failed until the
		 * grey-temp-fail-period, so force a drop in order to force
		 * the client that they implement a retry queue.
		 *
		 * The options smtp-drop-after and/or smtpf-reject-delay
		 * would eventually catch this abuse, but this is a time
		 * and resource saving measure.
		 */
		if (0 < delay && optGreyKey.value & (GREY_TUPLE_PTR|GREY_TUPLE_PTRN|GREY_TUPLE_IP))
			rc = SMTPF_DROP;

		/* This is contrary to the the Evan Harris article
		 * http://lists.puremagic.com/pipermail/greylist-users/2004-September/000766.html
		 *
		 * We've observed problems with Exchange machines when
		 * grey-listing at final dot. They appear to try the newest
		 * messages first and if a 451 is issued they won't try any
		 * subsequent messages destined for the same recipient
		 * during the same SMTP session, essentially causing
		 * grey-content messages to be forever temp.failed and to
		 * eventually expire from their retry queue. Since 450
		 * appeared to have a different effect, we try that instead
		 * to see if they pass those older messages, in particualr
		 * the original first message, in the same session.
		 */
		(void) replyPushFmt(sess, rc, delay <= 0 ? msg_450_try_again : msg_451_try_again, ID_ARG(sess));
	}

	(void) greyRset(sess, ignore);

	return rc;
}

int
greyClose(Session *sess, va_list ignore)
{
	return greyRset(sess, ignore);
}

#endif /* FILTER_GREY */
