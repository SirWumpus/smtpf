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

#include  <ctype.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_dupmsg_ttl[] =
  "Time-to-live in seconds for duplicate message tracking records. These\n"
"# records are created in the event that there was an I/O error while\n"
"# sending a 250 message accepted reply and have successfully relayed the\n"
"# message to the forward host(s), in which case record the message ID in\n"
"# order accept and discard future retries of the same message and so avoid\n"
"# duplicates.\n"
"#"
;

static const char usage_dupmsg_track_all[] =
  "When set, we track all Message-ID received and reject any duplicates\n"
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
	int smtpf_code;
	char original_msg_id[SMTP_PATH_LENGTH+1];
} DupMsg;

static FilterContext dupmsg_context;
static Verbose verb_dupmsg	= { { "dupmsg", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

int
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

int
dupmsgRset(Session *sess, va_list ignore)
{
	DupMsg *ctx;
	mcc_row row;
	ParsePath *first_rcpt;
	int smtpf_code = SMTPF_UNKNOWN;

	LOG_TRACE(sess, 333, dupmsgRset);

	ctx = filterGetContext(sess, dupmsg_context);

	/* We had an IO error while sending the 250 reply accepting the
	 * message, or in getting the next command (QUIT, RSET, MAIL)
	 * after having sent the reply. In the latter case, we can't
	 * really be sure that the client actually received and/or read
	 * the reply, so we assume failure.
	 *
	 * Since we have now accepted the message even though the client
	 * has disappeared, we keep track of the original message ID in
	 * the event the client retries resending the message again, in
	 * which case we want to accept and discard the message so that
	 * the client will remove it from their queue.
	 */
	if (CLIENT_ANY_SET(sess, CLIENT_IO_ERROR) && SMTP_IS_OK(ctx->smtp_code))
		smtpf_code = SMTPF_DISCARD;

	/* When +dupmsg-track-all, only record the Message-ID of messages
	 * that were accepted. Mesages that were rejected, temp.failed, or
	 * discarded, there is no point in recording the message-id.
	 */
	else if (optDupMsgTrackAll.value && SMTP_IS_OK(ctx->smtp_code) && CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS))
		smtpf_code = SMTPF_REJECT;

	if (verb_dupmsg.option.value)
		syslog(LOG_DEBUG, LOG_MSG(334) "message-id=%s IO-error=%s smtp-code=%d smtpf-code=%s", LOG_ARGS(sess), ctx->original_msg_id, CLIENT_ANY_SET(sess, CLIENT_IO_ERROR) ? "yes" : "no", ctx->smtp_code, SMTPF_CODE_NAME(smtpf_code));

	first_rcpt = rcptFindFirstValid(sess);

	if (smtpf_code != SMTPF_UNKNOWN && *ctx->original_msg_id != '\0' && first_rcpt != NULL) {
		MEMSET(&row, 0, sizeof (row));
		row.hits = 0;
		row.created = time(NULL);
		row.expires = row.created + optDupMsgTTL.value;
		row.key_size = snprintf(
			row.key_data, sizeof (row.key_data), DUPMSG_CACHE_TAG "%s%s",
			ctx->original_msg_id, first_rcpt->address.string
		);
		row.value_size = snprintf(row.value_data, sizeof (row.value_data), "%d %s", smtpf_code, sess->long_id);

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		if (mccPutRow(mcc, &row) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);

		statsCount(&stat_dupmsg_cached);
	}

	ctx->smtpf_code = SMTPF_CONTINUE;
	*ctx->original_msg_id = '\0';
	ctx->smtp_code = 0;

	return SMTPF_CONTINUE;
}

int
dupmsgHeaders(Session *sess, va_list args)
{
	int rc;
	long i;
	char *hdr;
	DupMsg *ctx;
	mcc_row row;
	size_t length;
	ParsePath *first_rcpt;
	Vector headers = va_arg(args, Vector);

	LOG_TRACE(sess, 335, dupmsgHeaders);
	ctx = filterGetContext(sess, dupmsg_context);

	/* Find and record the ORIGINAL message header. */
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (TextMatch(hdr, "Message-ID:*", -1, 1)) {
			if ((hdr = strchr(hdr, '<')) != NULL) {
				length = TextCopy(ctx->original_msg_id, sizeof (ctx->original_msg_id), hdr);
				ctx->original_msg_id[strcspn(ctx->original_msg_id, " \r\n")] = '\0';

				if (verb_dupmsg.option.value)
					syslog(LOG_DEBUG, LOG_MSG(336) "found original message-id=%s", LOG_ARGS(sess), ctx->original_msg_id);
			}
			break;
		}
	}

	if (optDupMsgTTL.value <= 0 || *ctx->original_msg_id == '\0')
		return SMTPF_CONTINUE;

	if ((first_rcpt = rcptFindFirstValid(sess)) == NULL)
		return SMTPF_CONTINUE;

	rc = SMTPF_CONTINUE;
	row.key_size = snprintf(
		row.key_data, sizeof (row.key_data), DUPMSG_CACHE_TAG "%s%s",
		ctx->original_msg_id, first_rcpt->address.string
	);

	/* Have we seen this message before? */
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
			syslog(LOG_INFO, LOG_MSG(337) "%s duplicate Message-Id=%s previous session=%s", LOG_ARGS(sess), SMTPF_CODE_NAME(rc), ctx->original_msg_id, row.value_data+2);
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

	ctx->smtpf_code = rc;

	return rc;
}

int
dupmsgContent(Session *sess, va_list args)
{
	DupMsg *ctx;

	LOG_TRACE(sess, 338, dupmsgContent);
	ctx = filterGetContext(sess, dupmsg_context);

	return ctx->smtpf_code;
}

int
dupmsgDot(Session *sess, va_list ignore)
{
	return dupmsgContent(sess, ignore);
}

int
dupmsgReplyLog(Session *sess, va_list args)
{
	DupMsg *ctx;
	const char **reply;
/*	size_t *reply_length; */

	LOG_TRACE(sess, 341, dupmsgReplyLog);

	reply = va_arg(args, const char **);
/*	reply_length = va_arg(args, size_t *); */
	ctx = filterGetContext(sess, dupmsg_context);

	/* Remember the SMTP reply sent at dot if we have a message header. */
	if (*ctx->original_msg_id != '\0' && isdigit(**reply)) {
		if (verb_dupmsg.option.value)
			syslog(LOG_DEBUG, LOG_MSG(342) "remember smtp-code=%c", LOG_ARGS(sess), **reply);
		ctx->smtp_code = strtol(*reply, NULL, 0);
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_DUPMSG */
