/*
 * dupmsg.c
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_DUPMSG

#include "smtpf.h"

#include <ctype.h>
#include <com/snert/lib/util/md5.h>

extern void digestToString(unsigned char digest[16], char digest_string[33]);

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_dupmsg_ttl[] =
  "Time-to-live in seconds for duplicate message tracking records. These\n"
"# records are created in the event that there was an I/O error while\n"
"# sending a 250 message accepted reply and have successfully relayed the\n"
"# message to the forward host(s). The tracking record is used to discard\n"
"# future retries of the same message and so avoid duplicates.\n"
"#"
;

static const char usage_dupmsg_track_all[] =
  "When set, we track all messages received and reject any duplicates\n"
"# messages that arrive again. This can prevent some types of spam from\n"
"# being sent repeatedly, however it will greatly increase the size of\n"
"# the cache on high volume systems and so should be used with care.\n"
"#"
;

Option optDupMsgTTL		= { "dupmsg-ttl",	"90000",	usage_dupmsg_ttl };
Option optDupMsgTrackAll	= { "dupmsg-track-all",	"-",		usage_dupmsg_track_all };


Stats stat_dupmsg_cached	= { STATS_TABLE_MSG, "dupmsg-cached" };
Stats stat_dupmsg_hit		= { STATS_TABLE_MSG, "dupmsg-hit" };

typedef struct {
	int smtp_code;
	md5_state_t md5;
	uint8_t digest[16];
	char digest_string[33];
	char original_msg_id[SMTP_PATH_LENGTH+1];
} DupMsg;

static FilterContext dupmsg_context;
static Verbose verb_dupmsg	= { { "dupmsg", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

SmtpfCode
dupmsgRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_dupmsg);
	optionsRegister(&optDupMsgTTL, 0);
	optionsRegister(&optDupMsgTrackAll, 0);

	(void) statsRegister(&stat_dupmsg_cached);
	(void) statsRegister(&stat_dupmsg_hit);

	dupmsg_context = filterRegisterContext(sizeof (DupMsg));

	return SMTPF_CONTINUE;
}

SmtpfCode
dupmsgRset(Session *sess, va_list ignore)
{
	DupMsg *ctx;
	mcc_row row;
	ParsePath *first_rcpt;
	SmtpfCode smtpf_code = SMTPF_UNKNOWN;

	LOG_TRACE(sess, 333, dupmsgRset);

	ctx = filterGetContext(sess, dupmsg_context);

	/* We had an IO error while sending the 250 reply accepting the
	 * message, or in getting the next command (QUIT, RSET, MAIL)
	 * after having sent the reply. In the latter case, we can't
	 * really be sure that the client actually received and/or read
	 * the reply, so we assume failure.
	 *
	 * Since we have now accepted the message even though the client
	 * has disappeared, we keep track of the message in the event the
	 * client retries resending the message again, in which case we
	 * want to accept and discard the message so that the client will
	 * remove it from their queue.
	 */
	if (CLIENT_ANY_SET(sess, CLIENT_IO_ERROR) && SMTP_IS_OK(ctx->smtp_code))
		smtpf_code = SMTPF_DISCARD;

	/* When +dupmsg-track-all, only record the details of messages
	 * that were accepted. Mesages that were rejected, temp.failed,
	 * or discarded, there is no point in saving this information.
	 */
	else if (optDupMsgTrackAll.value && SMTP_IS_OK(ctx->smtp_code) && CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS))
		smtpf_code = SMTPF_REJECT;

	first_rcpt = rcptFindFirstValid(sess);

	if (smtpf_code != SMTPF_UNKNOWN && first_rcpt != NULL) {
		MEMSET(&row, 0, sizeof (row));
		row.hits = 0;
		row.created = time(NULL);
		row.expires = row.created + optDupMsgTTL.value;
		row.key_size = snprintf(
			(char *) row.key_data, sizeof (row.key_data), DUPMSG_CACHE_TAG "%s,%s",
			ctx->digest_string, first_rcpt->address.string
		);
		row.value_size = snprintf((char *) row.value_data, sizeof (row.value_data), "%d %s", smtpf_code, sess->long_id);

		if (verb_dupmsg.option.value) {
			syslog(
				LOG_DEBUG, LOG_MSG(334) "key=%s msg-id=%s IO-error=%s smtp-code=%d smtpf-code=%s",
				LOG_ARGS(sess), row.key_data, TextEmpty(ctx->original_msg_id),
				CLIENT_ANY_SET(sess, CLIENT_IO_ERROR) ? "yes" : "no",
				ctx->smtp_code, SMTPF_CODE_NAME(smtpf_code)
			);
		}

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		if (mccPutRow(mcc, &row) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);

		statsCount(&stat_dupmsg_cached);
	}

	md5_init(&ctx->md5);
	ctx->smtp_code = 0;
	*ctx->digest_string = '\0';
	*ctx->original_msg_id = '\0';

	return SMTPF_CONTINUE;
}

SmtpfCode
dupmsgHeaders(Session *sess, va_list args)
{
	DupMsg *ctx;
	Vector headers;
	char **hdr, *msgid;

	LOG_TRACE(sess, 335, dupmsgHeaders);
	ctx = filterGetContext(sess, dupmsg_context);

	if (*ctx->original_msg_id != '\0')
		return SMTPF_CONTINUE;

	headers = va_arg(args, Vector);
	for (hdr = (char **) VectorBase(headers); *hdr != NULL; hdr++) {
		if (0 < TextInsensitiveStartsWith(*hdr, "Message-ID:") && (msgid = strchr(*hdr, '<')) != NULL) {
			(void) TextCopy(ctx->original_msg_id, sizeof (ctx->original_msg_id), msgid);
			ctx->original_msg_id[strcspn(ctx->original_msg_id, " \r\n")] = '\0';
			break;
		}
	}

	return SMTPF_CONTINUE;
}

SmtpfCode
dupmsgContent(Session *sess, va_list args)
{
	DupMsg *ctx;
	size_t size;
	unsigned char *chunk;

	LOG_TRACE(sess, 338, dupmsgContent);

	/* Build MD5 for the message body only. Ignore
	 * the headers, which can change with retries.
	 */
	ctx = filterGetContext(sess, dupmsg_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);
	md5_append(&ctx->md5, (md5_byte_t *) chunk, size);

	return SMTPF_CONTINUE;
}

SmtpfCode
dupmsgDot(Session *sess, va_list ignore)
{
	mcc_row row;
	DupMsg *ctx;
	SmtpfCode rc;
	ParsePath *first_rcpt;

	LOG_TRACE(sess, 000, dupmsgDot);

	if (optDupMsgTTL.value <= 0)
		return SMTPF_CONTINUE;

	if ((first_rcpt = rcptFindFirstValid(sess)) == NULL)
		return SMTPF_CONTINUE;

	ctx = filterGetContext(sess, dupmsg_context);

	/* When available add the Message-ID to the MD5 of the
	 * message body. Adding the Message-ID when present to
	 * the MD5 helps distinguish between templated status
	 * messages that are in fact different only by time sent
	 * and Message-ID.
	 *
	 * The MD5 and the first recipient are then used as a
	 * cache key. The first recipient is included to deal
	 * with MTAs that do envelope spliting and send multiple
	 * copies of the same message to different recipients.
	 *
	 * The first recipient could have been made part of the
	 * MD5, but having it visible in the cache key is useful
	 * for debugging and monitoring.
	 */
	md5_append(&ctx->md5, (md5_byte_t *) ctx->original_msg_id, strlen(ctx->original_msg_id));
	md5_finish(&ctx->md5, (md5_byte_t *) ctx->digest);
	digestToString(ctx->digest, ctx->digest_string);

	rc = SMTPF_CONTINUE;
	MEMSET(&row, 0, sizeof (row));
	row.key_size = snprintf(
		(char *) row.key_data, sizeof (row.key_data), DUPMSG_CACHE_TAG "%s,%s",
		ctx->digest_string, first_rcpt->address.string
	);

	/* Have we seen this message / recipient pair before? */
	if (mccGetRow(mcc, &row) == MCC_OK) {
		row.value_data[row.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);

		/* We've seen this message before. Discard this message
		 * to avoid sending a duplicate to the recipients. Or
		 * reject this message if dupmsg-track-all is set.
		 */
		rc = row.value_data[0] - '0';

		if (verb_info.option.value) {
			syslog(LOG_INFO, LOG_MSG(337) "%s duplicate key=%s previous session=%s", LOG_ARGS(sess), SMTPF_CODE_NAME(rc), row.key_data, row.value_data+2);
/*{LOG
@PACKAGE_NAME@ tracks what messages have already been seen and discards any
message that have prevously been processed. This can occur when the client
connection disappears between the time we relay the end-of-message to the
forward host(s) and the client receiving an SMTP reply. When the client
disconnects, it will assume a 421 response and rety sending the message
later. Mean while if the forward hosts accepted the message the first time,
then these retries can result in duplicate messages being received.
See the <a href="summary.html#opt_dupmsg_ttl">dupmsg-ttl</a> option.
}*/
		}

		if (rc == SMTPF_REJECT) {
			/* Set immediate reply now to take advantage of the
			 * replyContent and replyDot filter table short-circuit.
			 */
			(void) replyPushFmt(sess, SMTPF_REJECT, "550 5.3.4 duplicate message rejected" ID_MSG(340) "\r\n", ID_ARG(sess));
		}

		statsCount(&stat_dupmsg_hit);
		MSG_SET(sess, MSG_DISCARD);
	}

	return rc;
}

SmtpfCode
dupmsgReplyLog(Session *sess, va_list args)
{
	DupMsg *ctx;
	const char **reply;

	LOG_TRACE(sess, 341, dupmsgReplyLog);

	reply = va_arg(args, const char **);
	ctx = filterGetContext(sess, dupmsg_context);

	/* Remember the SMTP reply sent at dot if we have a message header. */
	if (*ctx->digest_string != '\0' && isdigit(**reply)) {
		if (verb_dupmsg.option.value)
			syslog(LOG_DEBUG, LOG_MSG(342) "remember smtp-code=%c", LOG_ARGS(sess), **reply);
		ctx->smtp_code = strtol(*reply, NULL, 0);
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_DUPMSG */
