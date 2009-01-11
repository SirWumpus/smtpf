/*
 * null.c
 *
 * Copyright 2007 by Anthony Howe. All rights reserved.
 */

/*
 * Must be a power of two.
 */
#ifndef HASH_TABLE_SIZE
#define HASH_TABLE_SIZE		(4 * 1024)
#endif

#ifndef MAX_LINEAR_PROBE
#define MAX_LINEAR_PROBE	16
#endif

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_NULL
#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define ACCESS_TAG 		"null-rate-to:"

static const char usage_null_rate_tag[]=
  "Null Sender Rate Control\n"
"#\n"
"# The tag Null-Rate-To: can be used in the access-map.\n"
"#\n"
"# If a key is found, then the value is processed as a pattern list\n"
"# and the result returned. An integer, in place of an action word,\n"
"# specifies the number of DSN/MDN messages per minute allowed. Specify\n"
"# -1 to disable the limit.\n"
"#\n"
;

Option optNullRateTag		= { "",	NULL, usage_null_rate_tag };

Stats stat_null_rate_to		= { STATS_TABLE_RCPT, "null-rate-to" };

#define NULL_TICK		6		/* seconds per tick */
#define	NULL_INTERVALS		10		/* ticks per minute */
#define NULL_WINDOW_SIZE	60		/* one minute window */

typedef struct {
	unsigned long ticks;
	unsigned long count;
} NullInterval;

typedef struct {
	char *rcpt;
	time_t touched;
	NullInterval intervals[NULL_INTERVALS];
} NullHash;

static NullHash rcpts[HASH_TABLE_SIZE];
static pthread_mutex_t null_mutex;

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
nullAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&null_mutex);
}

void
nullAtForkParent(void)
{
	(void) pthread_mutex_unlock(&null_mutex);
}

void
nullAtForkChild(void)
{
	(void) pthread_mutex_unlock(&null_mutex);
	(void) pthread_mutex_destroy(&null_mutex);
}
#endif

int
nullRegister(Session *sess, va_list ignore)
{
	optionsRegister(&optNullRateTag,		0);

	(void) statsRegister(&stat_null_rate_to);

	return SMTPF_CONTINUE;
}

int
nullInit(Session *null, va_list ignore)
{
	(void) pthread_mutex_init(&null_mutex, NULL);
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(nullAtForkPrepare, nullAtForkParent, nullAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	return SMTPF_CONTINUE;
}

int
nullFini(Session *nul, va_list ignore)
{
	int i;
	NullHash *entry;

	(void) pthread_mutex_destroy(&null_mutex);

	for (i = 0, entry = rcpts; i < HASH_TABLE_SIZE; i++, entry++) {
		if (entry->rcpt != NULL)
			free(entry->rcpt);
	}

	return SMTPF_CONTINUE;
}

static unsigned long
nullUpdate(Session *sess, NullInterval *intervals, unsigned long ticks)
{
	int i;
	NullInterval *interval;
	unsigned long count = 0;

	/* Update the current interval. */
	interval = &intervals[ticks % NULL_INTERVALS];
	if (interval->ticks != ticks) {
		interval->ticks = ticks;
		interval->count = 0;
	}
	interval->count++;

	/* Sum the counts within this window. */
	interval = intervals;
	for (i = 0; i < NULL_INTERVALS; i++) {
		if (ticks - NULL_INTERVALS <= interval->ticks && interval->ticks <= ticks)
			count += interval->count;
		interval++;
	}

	return count;
}

int
nullRcpt(Session *sess, va_list args)
{
	int i;
	long limit;
	time_t now;
	char *key, *value;
	NullHash *entry, *oldest;
	unsigned long hash, rate;
	ParsePath *rcpt = va_arg(args, ParsePath *);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(504) "nullRcpt", LOG_ARGS(sess));

	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS) || 0 < sess->msg.mail->address.length)
		return SMTPF_CONTINUE;

	/* Find the client specific connection rate limit. */
	key = value = NULL;
	if (accessEmail(sess, ACCESS_TAG, rcpt->address.string, &key, &value) == SMDB_ACCESS_NOT_FOUND)
		return SMTPF_CONTINUE;

	limit = strtol(value, NULL, 10);
	free(value);
	if (limit < 0 || mutex_lock(SESS_ID, FILE_LINENO, &null_mutex)) {
		free(key);
		return SMTPF_CONTINUE;
	}

	/* Find a hash table entry for this client. */
	hash = djb_hash_index(key, strlen(key), HASH_TABLE_SIZE);
	oldest = &rcpts[hash];

	for (i = 0; i < MAX_LINEAR_PROBE; i++) {
		entry = &rcpts[(hash + i) & (HASH_TABLE_SIZE-1)];

		if (entry->touched < oldest->touched)
			oldest = entry;

		if (entry->rcpt != NULL && strcmp(entry->rcpt, key) == 0)
			break;
	}

	/* If we didn't find the RCPT within the linear probe
	 * distance, then overwrite the oldest hash entry. Note
	 * that we take the risk of two or more RCPTs repeatedly
	 * cancelling out each other's entry. Shit happens on
	 * a full moon.
	 */
	if (MAX_LINEAR_PROBE <= i) {
		entry = oldest;
		free(entry->rcpt);
		entry->rcpt = key;
		memset(entry->intervals, 0, sizeof (entry->intervals));
	}

	/* Parse the RCPT's N messages per minute. We've
	 * opted to fix the rate limit window size at 60
	 * seconds in 6 second intervals. Not being able to
	 * specify the window size globally or per RCPT was
	 * an intentional design decision.
	 */
	now = time(NULL);
	entry->touched = now;
	rate = nullUpdate(sess, entry->intervals, now / NULL_TICK);

	(void) mutex_unlock(SESS_ID, FILE_LINENO, &null_mutex);

	if (limit < rate) {
		(void) replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 null-sender messages %ld for <%s> exceed %ld/60s" ID_MSG(505) "\r\n", rate, rcpt->address.string, limit, ID_ARG(sess));
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_null_rate_to"><span class="tag">Null-Rate-To:</span></a> tag.
}*/
		statsCount(&stat_null_rate_to);
		return SMTPF_REJECT;
	}

	return SMTPF_CONTINUE;
}

# ifdef FILTER_NULL_DEFER
int
nullRateRcpt(Session *sess, ...)
{
	int rc;
	va_list args;

	va_start(args, sess);
	rc = nullRcpt(sess, args);
	va_end(args);

	return rc;
}

int
nullData(Session *sess, va_list args)
{
	int rc;
	Rcpt *rcpt;
	Connection * fwd;

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
		for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
			if ((rc = nullRateRcpt(sess, rcpt->rcpt)) != SMTPF_CONTINUE)
				return rc;
		}
	}

	return SMTPF_CONTINUE;
}
# endif

#endif /* FILTER_NULL */
