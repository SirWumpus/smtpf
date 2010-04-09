/*
 * memhash.c
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
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

#include <com/snert/lib/version.h>

#include <limits.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define RATE_TICK		6		/* seconds per tick */
#define	RATE_INTERVALS		10		/* ticks per minute */
#define RATE_WINDOW_SIZE	60		/* one minute window */

typedef struct {
	unsigned long ticks;
	unsigned long count;
} RateInterval;

typedef struct {
	RateInterval intervals[RATE_INTERVALS];
	unsigned char ipv6[IPV6_BYTE_LENGTH];
	time_t touched;
} RateHash;

static Verbose verb_rate	= { { "rate", "-", "" } };

volatile unsigned long connections_per_second;
RateInterval cpm_intervals[RATE_INTERVALS];

static RateHash clients[HASH_TABLE_SIZE];
static pthread_mutex_t rate_mutex;
static time_t last_connection;

/*
 * D.J. Bernstien Hash version 2 (+ replaced by ^).
 */
unsigned long
djb_hash_index(unsigned char *buffer, unsigned long size, unsigned long table_size)
{
	unsigned long hash = 5381;

	while (0 < size--)
		hash = ((hash << 5) + hash) ^ *buffer++;

	return hash & (table_size-1);
}

int
rateInit(Session *null, va_list ignore)
{
	(void) pthread_mutex_init(&rate_mutex, NULL);
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(rateAtForkPrepare, rateAtForkParent, rateAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	return SMTPF_CONTINUE;
}

int
rateFini(Session *nul, va_list ignore)
{
	(void) pthread_mutex_destroy(&rate_mutex);
	return SMTPF_CONTINUE;
}

static unsigned long
rateUpdate(Session *sess, RateInterval *intervals, unsigned long ticks)
{
	int i;
	RateInterval *interval;
	unsigned long connections = 0;

	/* Update the current interval. */
	interval = &intervals[ticks % RATE_INTERVALS];
	if (interval->ticks != ticks) {
		interval->ticks = ticks;
		interval->count = 0;
	}
	interval->count++;

	/* Sum the number of connections within this window. */
	interval = intervals;
	for (i = 0; i < RATE_INTERVALS; i++) {
		if (ticks - RATE_INTERVALS <= interval->ticks && interval->ticks <= ticks)
			connections += interval->count;
		interval++;
	}

	return connections;
}

int
rateConnect(Session *sess, va_list ignore)
{
	int i, rc;
	time_t now;
	char *value;
	long client_limit;
	RateHash *entry, *oldest;
	unsigned long hash, client_rate;

	LOG_TRACE(sess, 520, rateConnect);

	if (CLIENT_ANY_SET(sess, CLIENT_HOLY_TRINITY))
		return SMTPF_CONTINUE;

	/* Find the client specific connection rate limit. */
	if (accessClient(sess, ACCESS_TAG, sess->client.name, sess->client.addr, NULL, &value, 1) == ACCESS_NOT_FOUND)
		return SMTPF_CONTINUE;
	client_limit = strtol(value, NULL, 10);
	free(value);

	rc = SMTPF_CONTINUE;

	if (0 < client_limit) {
		/* Find a hash table entry for this client. */
		hash = djb_hash_index(sess->client.ipv6, sizeof (sess->client.ipv6), HASH_TABLE_SIZE);
		oldest = &clients[hash];

		if (mutex_lock(SESS_ID, FILE_LINENO, &rate_mutex))
			return SMTPF_CONTINUE;

		for (i = 0; i < MAX_LINEAR_PROBE; i++) {
			entry = &clients[(hash + i) & (HASH_TABLE_SIZE-1)];

			if (entry->touched < oldest->touched)
				oldest = entry;

			if (memcmp(sess->client.ipv6, entry->ipv6, sizeof (entry->ipv6)) == 0)
				break;
		}

		/* If we didn't find the client within the linear probe
		 * distance, then overwrite the oldest hash entry. Note
		 * that we take the risk of two or more IPs repeatedly
		 * cancelling out each other's entry. Shit happens on
		 * a full moon.
		 */
		if (MAX_LINEAR_PROBE <= i) {
			entry = oldest;
			memset(entry->intervals, 0, sizeof (entry->intervals));
			memcpy(entry->ipv6, sess->client.ipv6, sizeof (entry->ipv6));
		}

		/* Parse the client's N connections per minute. We've
		 * opted for to fix the rate limit window size at 60
		 * seconds in 6 second intervals. Not being able to
		 * specify the window size globally or per client was
		 * an intentional design decision.
		 */
		now = time(NULL);
		client_rate = rateUpdate(sess, entry->intervals, now / RATE_TICK);
		entry->touched = now;

		(void) mutex_unlock(SESS_ID, FILE_LINENO, &rate_mutex);

		if (client_limit < client_rate) {
			if (verb_rate.option.value)
				syslog(LOG_DEBUG, LOG_MSG(521) "client " CLIENT_FORMAT " connections %ld exceed %ld/60s", LOG_ARGS(sess), CLIENT_INFO(sess), client_rate, client_limit);
			rc = replyPushFmt(sess, optRateDrop.value ? SMTPF_DROP : SMTPF_TEMPFAIL, "421 4.4.5 client " CLIENT_FORMAT " connections %ld exceed %ld/60s" ID_MSG(522) "\r\n", CLIENT_INFO(sess), client_rate, client_limit, ID_ARG(sess));
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_rate_connect"><span class="tag">Rate-Connect:</span></a> tag.
}*/
			CLIENT_SET(sess, CLIENT_RATE_LIMIT);
			statsCount(&stat_rate_client);
			if (!optRateDrop.value)
				sess->state = stateSink;
		}
	}

	return rc;
}
