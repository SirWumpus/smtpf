/*
 * siq.c
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

#ifdef FILTER_SIQ

#include "smtpf.h"

/***********************************************************************
 ***
 ***********************************************************************/

#define SIQ_REPORT		"SIQ-Report:"

static const char usage_siq_servers[] =
  "Semi-colon separated list of SIQ server host[:port] addresses."
;

Option optSiqScoreReject	= { "siq-score-reject",		"-1",		"Reject on or below this score, between 0 and 99; -1 to disable." };
Option optSiqScoreTag		= { "siq-score-tag",		"50",		"Tag the subject on or below this score, between 0 and 99; -1 to disable." };
Option optSiqServers		= { "siq-servers",		"",		 usage_siq_servers };
Option optSiqSubjectTag		= { "siq-subject-tag",		"[SPAM]",	"Subject tag to preprend for messages identified as suspect." };

#ifdef NOT_USED_YET
Option optSiqScoreDiscard	= { "siq-score-discard",	"-1",		"Discard on or below this score, between 0 and 99; -1 to disable." };
Option optSiqSubjectScore	= { "siq-subject-score",	 "-",		"Append the score to the subject tag." };
#endif

Stats stat_siq_query_cache	= { STATS_TABLE_MAIL, "siq-query-cache" };
Stats stat_siq_query_made	= { STATS_TABLE_MAIL, "siq-query-made" };
Stats stat_siq_score_reject	= { STATS_TABLE_MAIL, "siq-score-reject" };
Stats stat_siq_score_tag	= { STATS_TABLE_MAIL, "siq-score-tag" };

Verbose verb_siq = { { "siq", "-", "" } };

#define SIQ_UNDEFINED				(-127)
#define SIQ_FLAG_ML				0x40
#define SIQ_FLAG_HL				0x80

typedef struct {
	char flags;				/*  +0 */
	signed char score;			/*  +1 */
	signed char score_ip;			/*  +2 */
	signed char score_rel;			/*  +3 */
	signed char score_domain;		/*  +4 */
	signed char confidence;			/*  +5 */
	unsigned short ttl;			/*  +6 */
	char text[82];				/*  +8 */
						/*  +90 */
} SIQ_compact;

static Vector servers;
static char wordNo[] = "NO";
static char wordYes[] = "YES";
static char wordUnknown[] = "UNKNOWN";

static FilterContext siq_context;

/***********************************************************************
 ***
 ***********************************************************************/

int
siqRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_siq);

	optionsRegister(&optSiqScoreReject, 		0);
	optionsRegister(&optSiqScoreTag, 		0);
	optionsRegister(&optSiqServers, 		0);
	optionsRegister(&optSiqSubjectTag, 		0);

	(void) statsRegister(&stat_siq_query_cache);
	(void) statsRegister(&stat_siq_query_made);
	(void) statsRegister(&stat_siq_score_reject);
	(void) statsRegister(&stat_siq_score_tag);

	siq_context = filterRegisterContext(sizeof (SIQ_compact));

	return SMTPF_CONTINUE;
}

int
siqInit(Session *null, va_list ignore)
{
	servers = TextSplit(optSiqServers.string, OPTION_LIST_DELIMS, 0);

#ifdef NOT_USED_YET
	if (optSiqScoreDiscard.value < -1 || 99 < optSiqScoreDiscard.value) {
		syslog(LOG_ERR, LOG_NUM(608) "siq-score-discard number must -1 to disable, or 0..99");
/*{NEXT}*/
		exit(1);
	}
#endif
	if (optSiqScoreReject.value < -1 || 99 < optSiqScoreReject.value) {
		syslog(LOG_ERR, LOG_NUM(609) "siq-score-reject number must -1 to disable, or 0..99");
/*{NEXT}*/
		exit(1);
	}

	if (optSiqScoreTag.value < -1 || 99 < optSiqScoreTag.value) {
		syslog(LOG_ERR, LOG_NUM(610) "siq-score-tag number must -1 to disable, or 0..99");
/*{NEXT}*/
		exit(1);
	}

	return SMTPF_CONTINUE;
}

int
siqFini(Session *null, va_list ignore)
{
	VectorDestroy(servers);
	return SMTPF_CONTINUE;
}

int
siqRset(Session *sess, va_list ignore)
{
	SIQ_compact *siq_ctx = filterGetContext(sess, siq_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(611) "siqRset()", LOG_ARGS(sess));

	siq_ctx->score = SIQ_UNDEFINED;

	return SMTPF_CONTINUE;
}

int
siqData(Session *sess, va_list ignore)
{
	SIQ siq;
	long length;
	mcc_row cached;
	const char *error = NULL;
	SIQ_compact *siq_ctx = filterGetContext(sess, siq_context);
	mcc_handle *mcc = SESS_GET_MCC(sess);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(612) "siqData()", LOG_ARGS(sess));

	if (VectorLength(servers) <= 0
	|| sess->msg.mail->domain.length == 0
	|| CLIENT_ANY_SET(sess, CLIENT_HOLY_TRINITY))
		return SMTPF_CONTINUE;

	MEMSET(&cached, 0, sizeof (cached));
	mccSetKey(&cached, SIQ_CACHE_TAG "%s,%s", sess->client.addr, sess->msg.mail->domain.string);
	TextLower(MCC_PTR_K(&cached), MCC_GET_K_SIZE(&cached));

	/* Look for a locally cached copy. */
	if (mccGetRow(mcc, &cached) != MCC_OK) {
		statsCount(&stat_siq_query_made);

		error = siqGetScoreA(
			&siq, sess->client.addr, sess->client.helo,
			sess->msg.mail->domain.string, (char **) VectorBase(servers)
		);

		cached.ttl = siq_ctx->ttl;
		cached.expires = time(NULL) + cached.ttl;

		siq_ctx->flags = 0;
		if (siq.hl)
			siq_ctx->flags |= SIQ_FLAG_HL;
		if (siq.ml)
			siq_ctx->flags |= SIQ_FLAG_ML;

		siq_ctx->score = (char) siq.score;
		siq_ctx->score_ip = (char) siq.score_ip;
		siq_ctx->score_rel = (char) siq.score_rel;
		siq_ctx->score_domain = (char) siq.score_domain;
		siq_ctx->confidence = (char) siq.confidence;
		siq_ctx->ttl = (unsigned short) siq.ttl;

		length = TextCopy(siq_ctx->text, sizeof (siq_ctx->text), siq.text);
		if (sizeof (siq_ctx->text) <= length)
			length = sizeof (siq_ctx->text) - 1;

		MCC_SET_V_SIZE(&cached, sizeof (*siq_ctx) - sizeof (siq_ctx->text) + length);
		(void) memcpy(MCC_PTR_V(&cached), siq_ctx, MCC_GET_V_SIZE(&cached));

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), LOG_CACHE_PUT(&cached), "(mixed)", FILE_LINENO);
		if (mccPutRow(mcc, &cached) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), LOG_CACHE_PUT_ERROR(&cached), "(mixed)", FILE_LINENO);
	} else {
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), LOG_CACHE_PUT(&cached), "(mixed)", FILE_LINENO);
		statsCount(&stat_siq_query_cache);
	}

	if (error == NULL) {
		if (verb_siq.option.value) {
			syslog(
				LOG_DEBUG, LOG_MSG(613) "siq query: qt=0 ip=%s dn=%s hl=%d ml=%d", LOG_ARGS(sess),
				sess->client.addr, sess->msg.mail->domain.string,
				(siq_ctx->flags & SIQ_FLAG_HL) == SIQ_FLAG_HL,
				(siq_ctx->flags & SIQ_FLAG_ML) == SIQ_FLAG_ML
			);
			syslog(
				LOG_DEBUG, LOG_MSG(614) "siq score-ip=%d score-dn=%d score-rel=%d", LOG_ARGS(sess),
				siq_ctx->score_ip, siq_ctx->score_domain, siq_ctx->score_rel
			);
		}

		syslog(
			LOG_INFO, LOG_MSG(615) "siq score=%d confidence=%d ttl=%u text='%.83s'", LOG_ARGS(sess),
			siq_ctx->score, siq_ctx->confidence, siq_ctx->ttl, siq_ctx->text
		);
/*{NEXT}*/
	} else {
		syslog(LOG_ERR, LOG_MSG(616) "%s", LOG_ARGS(sess), error);
/*{NEXT}*/
	}

	if (siq_ctx->score == RESPONSE_TEMPFAIL) {
		return replyPushFmt(sess, SMTPF_TEMPFAIL, msg_451_try_again, ID_ARG(sess));
	}

	if (0 <= siq_ctx->score) {
		if (siq_ctx->score <= optSiqScoreReject.value) {
			statsCount(&stat_siq_score_reject);
			return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 message rejected, SIQ score %d too low" ID_MSG(617) "\r\n", siq_ctx->score, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_siq_score_reject">siq-score-reject</a> option.
}*/
		}
#ifdef NOT_USED_YET
		if (siq_ctx->score <= optSiqScoreDiscard.value) {
			syslog(LOG_INFO, LOG_MSG(618) "siq-score=%d less than %ld, discarding message", LOG_ARGS(sess), siq_ctx->score, optSiqScoreDiscard.value);
/*{LOG
See <a href="summary.html#opt_siq_score_reject">siq-score-reject</a>,
<a href="summary.html#opt_siq_score_tag">siq-score-tag</a>, and
<a href="summary.html#opt_siq_servers">siq-servers</a> options.
}*/
			statsCount(&stat_siq_score_discard);
			return SMTPF_DISCARD;
		}
#endif
	}

	return SMTPF_CONTINUE;
}

int
siqHeaders(Session *sess, va_list args)
{
	char *hdr, *pass, *text;
	SIQ_compact *siq_ctx = filterGetContext(sess, siq_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(619) "siqHeaders", LOG_ARGS(sess));

	if (siq_ctx->score == SIQ_UNDEFINED || (hdr = malloc(SMTP_TEXT_LINE_LENGTH)) == NULL)
		return SMTPF_CONTINUE;

	text = siq_ctx->text;

	if (siq_ctx->score < 0) {
		pass = wordUnknown;
		text = wordUnknown;
	} else if (optSiqScoreTag.value < siq_ctx->score) {
		pass = wordYes;
	} else {
		pass = wordNo;
		MSG_SET(sess, MSG_TAGGED);
		statsCount(&stat_siq_score_tag);
		headerAddPrefix(sess, "Subject", optSiqSubjectTag.string);
	}

	(void) snprintf(
		hdr, SMTP_TEXT_LINE_LENGTH,
		SIQ_REPORT " pass=%s ip=%s dn=%s hl=%d ml=%d score=%d text='%s'\r\n",
		pass, sess->client.addr, sess->msg.mail->domain.string,
		(siq_ctx->flags & SIQ_FLAG_HL) == SIQ_FLAG_HL,
		(siq_ctx->flags & SIQ_FLAG_ML) == SIQ_FLAG_ML,
		siq_ctx->score, text
	);

	if (VectorAdd(sess->msg.headers, hdr))
		free(hdr);

	return SMTPF_CONTINUE;
}

#endif /* FILTER_SIQ */
