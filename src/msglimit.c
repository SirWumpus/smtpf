/*
 * msglimit.c
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

#ifdef FILTER_MSG_LIMIT

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define ACCESS_CONNECT		"msg-limit-connect:"
#define ACCESS_FROM		"msg-limit-from:"
#define ACCESS_TO		"msg-limit-to:"

static const char usage_msg_limit_tags[] =
  "Message Limit Controls\n"
"#\n"
"# The tags Msg-Limit-Connect:, Msg-Limit-From:, and Msg-Limit-To:\n"
"# can be used in the access-map.\n"
"#\n"
"# If a key is found, then the value is processed as a pattern list\n"
"# and the result returned. A message limit is specified in place of\n"
"# an action and has the following format:\n"
"#\n"
"#\tmessages '/' time [unit]\n"
"#\n"
"# which is the number of messages per time interval. The time unit\n"
"# specifier can be one of week, day, hour, minute, or seconds (note\n"
"# only the first letter is significant). Specify a negative number\n"
"# for messages to disable a limit.\n"
"#\n"
"# When there are multiple message limits possible, then the limit\n"
"# applied, in order of precedence is: Msg-Limit-To:, Msg-Limit-From:,\n"
"# and Msg-Limit-Connect.\n"
"#\n"
;

Option optMsgLimitTags 		= { "", NULL, usage_msg_limit_tags };

Stats stat_message_limit	= { STATS_TABLE_MSG, "message-limit" };

typedef struct {
	long messages;
	long seconds;
	int unit;
	long count;
} MsgLimit;

typedef struct {
	MsgLimit client;
	MsgLimit msg;
} MsgLimitContext;

static FilterContext msglimit_context;
static pthread_mutex_t msglimit_mutex;

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
msgLimitAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&msglimit_mutex);
}

void
msgLimitAtForkParent(void)
{
	(void) pthread_mutex_unlock(&msglimit_mutex);
}

void
msgLimitAtForkChild(void)
{
	(void) pthread_mutex_unlock(&msglimit_mutex);
	(void) pthread_mutex_destroy(&msglimit_mutex);
}
#endif

int
msgLimitRegister(Session *sess, va_list ignore)
{
	optionsRegister(&optMsgLimitTags, 		0);

	(void) statsRegister(&stat_message_limit);

	msglimit_context = filterRegisterContext(sizeof (MsgLimitContext));

	return SMTPF_CONTINUE;
}

int
msgLimitInit(Session *null, va_list ignore)
{
	(void) pthread_mutex_init(&msglimit_mutex, NULL);
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(msgLimitAtForkPrepare, msgLimitAtForkParent, msgLimitAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	return SMTPF_CONTINUE;
}

int
msgLimitFini(Session *null, va_list ignore)
{
	(void) pthread_mutex_destroy(&msglimit_mutex);
	return SMTPF_CONTINUE;
}

static void
msgLimitCacheUpdate(Session *sess, MsgLimit *limit, const char *key)
{
	time_t now;
	long value;
	mcc_row row;

	if (mutex_lock(SESS_ID, FILE_LINENO, &msglimit_mutex))
		goto error0;

	value = 0;
	now = time(NULL);
	limit->count = -1;
	MEMSET(&row, 0, sizeof (row));
	row.key_size = snprintf(row.key_data, sizeof (row.key_data), MSG_LIMIT_CACHE_TAG "%s", key);
	TextLower(row.key_data, -1);

	switch (mccGetRow(mcc, &row)) {
	case MCC_OK:
		row.key_data[row.key_size] = '\0';
		row.value_data[row.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		row.value_data[row.value_size] = '\0';
		value = strtol(row.value_data, NULL, 10);
		break;
	case MCC_ERROR:
		syslog(LOG_ERR, log_cache_get_error, LOG_ARGS(sess), row.key_data, FILE_LINENO);
		goto error1;
	default:
		/* We've not seen seen this tuple before. */
		row.expires = 0;
		row.created = now;
		row.hits = 0;
		value = 0;
	}

	if (row.expires <= now) {
		row.expires = now + limit->seconds;
		value = 0;
	}

	limit->count = ++value;
	row.value_size = (unsigned char ) snprintf(row.value_data, sizeof (row.value_data), "%ld", value);

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
	if (mccPutRow(mcc, &row) == MCC_ERROR)
		syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
error1:
	(void) mutex_unlock(SESS_ID, FILE_LINENO, &msglimit_mutex);
error0:
	;
}

static void
msgLimitParse(const char *specifier, MsgLimit *limit)
{
	int unit = 's';
	char *next, *stop;
	long messages = 0, seconds = 1, number;

	number = strtol(specifier, &stop, 10);
	if (specifier < stop)
		messages = number;

	if (0 <= messages && *stop == '/') {
		next = stop + 1;
		number = strtol(next, &stop, 10);
		if (next < stop)
			seconds = number;
		if (*stop != '\0')
			unit = *stop;
	}

	switch (unit) {
	case 'w': seconds *= 7;
	case 'd': seconds *= 24;
	case 'h': seconds *= 60;
	case 'm': seconds *= 60;
	}

	limit->messages = messages;
	limit->seconds = seconds;
	limit->unit = unit;
	limit->count = 0;
}

static int
msgLimitReply(Session *sess, MsgLimit *limit, const char *who)
{
	long units;
	const char *word;

	if (limit->messages < limit->count) {
		units = limit->seconds;

		switch (limit->unit) {
		case 'w': word = "week";   units /= (7 * 86400); break;
		case 'd': word = "day";    units /= 86400;       break;
		case 'h': word = "hour";   units /= 3600;        break;
		case 'm': word = "minute"; units /= 60;          break;
		default:  word = "second";
		}

		statsCount(&stat_message_limit);
		return replyPushFmt(sess, SMTPF_TEMPFAIL, "451 4.7.1 %s has exceeded %ld message%s per %ld %s%s" ID_MSG(475) "\r\n",
			who, limit->messages, limit->messages == 1 ? "" : "s",
			units, word, units == 1 ? "" : "s", ID_ARG(sess)
		);
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_msg_limit"><span class="tag">Msg-Limit-Connect:</span></a>,
<a href="access-map.html#tag_msg_limit"><span class="tag">Msg-Limit-From:</span></a>,
<a href="access-map.html#tag_msg_limit"><span class="tag">Msg-Limit-To:</span></a> tags.
}*/
	}

	return SMTPF_CONTINUE;
}

int
msgLimitConnect(Session *sess, va_list ignore)
{
	char *value;
	MsgLimitContext *limit = filterGetContext(sess, msglimit_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(476) "msgLimitConnect()", LOG_ARGS(sess));

	if (accessClient(sess, ACCESS_CONNECT, sess->client.name, sess->client.addr, NULL, &value, 1) != SMDB_ACCESS_NOT_FOUND) {
		msgLimitParse(value, &limit->client);
		free(value);
	} else {
		limit->client.unit = 0;
	}

	return SMTPF_CONTINUE;
}

int
msgLimitMail(Session *sess, va_list args)
{
	char *value;
	MsgLimitContext *limit = filterGetContext(sess, msglimit_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(477) "msgLimitMail()", LOG_ARGS(sess));

	if (0 < sess->msg.mail->address.length && accessEmail(sess, ACCESS_FROM, sess->msg.mail->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		msgLimitParse(value, &limit->msg);
		free(value);
	} else {
		limit->msg.unit = 0;
	}

	return SMTPF_CONTINUE;
}

int
msgLimitRcpt(Session *sess, va_list args)
{
	char *value;
	ParsePath *rcpt;
	MsgLimit limit_rcpt;
	MsgLimitContext *limit = filterGetContext(sess, msglimit_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(478) "msgLimitRcpt()", LOG_ARGS(sess));

	rcpt = va_arg(args, ParsePath *);

	if (accessEmail(sess, ACCESS_TO, rcpt->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		msgLimitParse(value, &limit_rcpt);
		msgLimitCacheUpdate(sess, &limit_rcpt, rcpt->address.string);
		free(value);
	} else {
		limit_rcpt.unit = 0;
	}

	/* Update the client and sender counter based on number of recipients,
	 * instead of number of actually sent messages.
	 */
	if (limit->client.unit != 0)
		msgLimitCacheUpdate(sess, &limit->client, sess->client.addr);

	if (limit->msg.unit != 0)
		msgLimitCacheUpdate(sess, &limit->msg, sess->msg.mail->address.string);

	/*** The following represents the precedence from highest to lowest. ***/

	if (limit_rcpt.unit != 0)
		return msgLimitReply(sess, &limit_rcpt, rcpt->address.string);

	if (limit->msg.unit != 0)
		return msgLimitReply(sess, &limit->msg, sess->msg.mail->address.string);

	if (limit->client.unit != 0)
		return msgLimitReply(sess, &limit->client, sess->client.addr);

	return SMTPF_CONTINUE;
}

#endif /* FILTER_MSG_LIMIT */
