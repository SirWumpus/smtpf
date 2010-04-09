/*
 * concurrent.c
 *
 * Copyright 2006 by Anthony Howe. All rights reserved.
 */

/*
 * Must be a power of two.
 */
#ifndef HASH_TABLE_SIZE
#define HASH_TABLE_SIZE		(16 * 1024)
#endif

#ifndef MAX_LINEAR_PROBE
#define MAX_LINEAR_PROBE	24
#endif

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_CONCURRENT
#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define ACCESS_TAG 		"concurrent-connect:"

#define USAGE_CONCURRENT_TAG						\
  "Concurrent Connection Control\n"					\
"#\n"									\
"# The tag Concurrent-Connect: can be used in the access-map.\n"	\
"#\n"									\
"# If a key is found, then the value is processed as a pattern list\n"	\
"# and the result returned. A positive integer value is specified in\n"\
"# place of an action and is the maximum number of concurrent\n"	\
"# connections permitted at any one time.\n"				\
"#\n"

Option optConcurrentTag	= { "",	NULL, USAGE_CONCURRENT_TAG };

static const char usage_concurrent_drop[] =
  "When a client exceeds per-client concurrency limits, send a 421 reply\n"
"# and if this option is set, drop the connection, otherwise wait for the\n"
"# the client to send the QUIT command.\n"
"#"
;

Option optConcurrentDrop	= { "concurrent-drop",		"+",	usage_concurrent_drop };

typedef struct {
	unsigned char ipv6[IPV6_BYTE_LENGTH];
	int count;
} ConcurrentHash;

static ConcurrentHash clients[HASH_TABLE_SIZE];
static pthread_mutex_t concurrent_mutex;

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
concurrentAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&concurrent_mutex);
}

void
concurrentAtForkParent(void)
{
	(void) pthread_mutex_unlock(&concurrent_mutex);
}

void
concurrentAtForkChild(void)
{
	(void) pthread_mutex_unlock(&concurrent_mutex);
	(void) pthread_mutex_destroy(&concurrent_mutex);
}
#endif

int
concurrentRegister(Session *null, va_list ignore)
{
	optionsRegister(&optConcurrentTag, 		0);
	optionsRegister(&optConcurrentDrop,		0);

	(void) statsRegister(&stat_concurrent);

	return SMTPF_CONTINUE;
}

int
concurrentInit(Session *null, va_list ignore)
{
	(void) pthread_mutex_init(&concurrent_mutex, NULL);

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(concurrentAtForkPrepare, concurrentAtForkParent, concurrentAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	return SMTPF_CONTINUE;
}

int
concurrentFini(Session *null, va_list ignore)
{
	(void) pthread_mutex_destroy(&concurrent_mutex);
	return SMTPF_CONTINUE;
}

static int
concurrentCacheUpdate(Session *sess, long add)
{
	int i, rc;
	unsigned long hash;
	ConcurrentHash *entry, *oldest;

	if (sess->max_concurrent <= 0)
		return 0;

	if (mutex_lock(SESS_ID, FILE_LINENO, &concurrent_mutex))
		return 0;

	hash = djb_hash_index(sess->client.ipv6, sizeof (sess->client.ipv6), HASH_TABLE_SIZE);
	oldest = &clients[hash];

	for (i = 0; i < MAX_LINEAR_PROBE; i++) {
		entry = &clients[(hash + i) & (HASH_TABLE_SIZE-1)];

		if (entry->count <= 0)
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
		entry->count = 0;
		memcpy(entry->ipv6, sess->client.ipv6, sizeof (entry->ipv6));
	}

	entry->count += add;
	rc = (sess->max_concurrent < entry->count);

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, LOG_MSG(327) "concurrency update key={%s} value={%d} add=%ld", LOG_ARGS(sess), sess->client.addr, entry->count, add);

	(void) mutex_unlock(SESS_ID, FILE_LINENO, &concurrent_mutex);

	if (rc) {
		CLIENT_SET(sess, CLIENT_CONCURRENCY_LIMIT);
		statsCount(&stat_concurrent);
	}

	return rc;
}

int
concurrentConnect(Session *sess, va_list ignore)
{
	char *value;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(328) "concurrentConnect()", LOG_ARGS(sess));

	if (CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY)
	&& accessClient(sess, ACCESS_TAG, sess->client.name, sess->client.addr, NULL, &value, 1) != ACCESS_NOT_FOUND) {
		sess->max_concurrent = strtol(value, NULL, 10);
		free(value);

		if (concurrentCacheUpdate(sess, 1)) {
			int rc = replyPushFmt(sess, optConcurrentDrop.value ? SMTPF_DROP : SMTPF_TEMPFAIL, "421 4.7.1 client " CLIENT_FORMAT " too many concurrent connections, max=%ld" ID_MSG(329) "\r\n", CLIENT_INFO(sess), sess->max_concurrent, ID_ARG(sess));
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_concurrent_connect"><span class="tag">Concurrent-Connect:</span></a> tag.
}*/
			if (!optConcurrentDrop.value)
				sess->state = stateSink;
			return rc;
		}
	} else {
		sess->max_concurrent = -1;
	}

	return SMTPF_CONTINUE;
}

int
concurrentClose(Session *sess, va_list ignore)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(330) "concurrentClose()", LOG_ARGS(sess));

	(void) concurrentCacheUpdate(sess, -1);
	return SMTPF_CONTINUE;
}

#endif /* FILTER_CONCURRENT */
