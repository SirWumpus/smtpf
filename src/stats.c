/*
 * stats.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

/*
 * Must be a power of two.
 */
#ifndef HASH_TABLE_SIZE
#define HASH_TABLE_SIZE		(4 * 1024)
#endif

/*
 * Max. string length for values.
 */
#ifndef STATS_DOMAIN_VALUE_SIZE
#define STATS_DOMAIN_VALUE_SIZE	(sizeof (time_t)*2 + 1 + (sizeof (uint32_t)*2 + sizeof (uint32_t)*2 + 2) * 31)
#endif

#ifndef STATS_BUFFER_SIZE
#define STATS_BUFFER_SIZE	(4 * 1024)
#endif

#ifndef HTTP_LINE_BUFFER_SIZE
#define HTTP_LINE_BUFFER_SIZE	(1024)
#endif

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#include <ctype.h>
#include <limits.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/b64.h>
#include <com/snert/lib/util/Token.h>
#include <com/snert/lib/sys/Time.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define STATS_DIRECT_SAVE

static const char usage_stats_map[] =
  "stats-map=\n"
"#\n"
"# This option specifies the cache type and path used to record\n"
"# hourly statistic counters. Specify the empty string to disable.\n"
"# This file is updated according to the cache-gc-interval. Note that\n"
"# it is the responsibility of the data gatherer process to expire\n"
"# old entries from this file, otherwise it will grow indefinitely.\n"
"#\n"
"# The following map methods are supported:\n"
"#\n"
"#   file!/path/map.txt\t\t\tr/w file, memory hash\n"
"#   text!/path/map.txt\t\t\tr/o text file, memory hash\n"
#ifdef HAVE_DB_H
"#   db!/path/map.db\t\t\tBerkeley DB hash format\n"
"#   db!btree!/path/map.db\t\tBerkeley DB btree format\n"
#endif
#ifdef HAVE_SQLITE3_H
"#   sql!/path/database\t\t\tan SQLite database\n"
#endif
"#   socketmap!host:port\t\t\tSendmail style socket-map\n"
"#   socketmap!/path/local/socket\tSendmail style socket-map\n"
"#   socketmap!123.45.67.89:port\t\tSendmail style socket-map\n"
"#   socketmap![2001:0DB8::1234]:port\tSendmail style socket-map\n"
"#\n"
"# If port is omitted, the default is 7953.\n"
"#\n"
"# The stats-map contains key-value pairs. The key is the current\n"
"# hour specified as \"YYYYMMDDHH\" and the value is a white space\n"
"# separated list of hex values, the first three being the version,\n"
"# process start time in seconds from the epoch, and the last update\n"
"# time in seconds from the epoch followed by the counters (see STAT).\n"
"#\n"
#if defined(HAVE_SQLITE3_H)
"#stats-map=sql!" CACHE_DIR "/stats.sq3"
#elif defined(HAVE_DB_H)
"#stats-map=db!" CACHE_DIR "/stats.db"
#else
"#stats-map=file!" CACHE_DIR "/stats.txt"
#endif
;

Option optStatsMap = { "stats-map", "",	usage_stats_map };

static const char usage_stats_http_post[] =
  "Specify an HTTP URL used to gather statistic data each garabage\n"
"# collection run. Specify the empty string to disable. The data sent\n"
"# has the same format as the STAT command output. Runtime, hourly, and\n"
"# 60 minute window data including route stats are all sent.\n"
"#"
;

Option optStatsHttpPost = { "stats-http-post", "",	usage_stats_http_post };

Option optStatsHttpRealm	= { "stats-http-realm",	"", "HTTP realm for restricted access." };
Option optStatsHttpUser		= { "stats-http-user",	"", "HTTP user name for restricted access." };
Option optStatsHttpPass		= { "stats-http-pass",	"", "HTTP password for restricted access." };

#define STATS_SCANF_FORMAT	"%lx %lx %lu"
#define STATS_SCANF_DOT(v)	(long *) &(v).created, (long *) &(v).touched, &(v).count
#define STATS_SCANF_ARROW(v)	(long *) &(v)->created, (long *) &(v)->touched, &(v)->count

#define STATS_PRINTF_FORMAT	"%lx %lx %lu"
#define STATS_PRINTF_DOT(v)	(long) (v).created, (long) (v).touched, (v).count
#define STATS_PRINTF_ARROW(v)	(long) (v)->created, (long) (v)->touched, (v)->count

/*
 * $processed = $val['CLIENTS'] - $val['admin-commands'] - ($val['grey-tempfail']+$val['grey-continue']) + $val['MESSAGES'];
 * $graph[$key]['accepted'] = $val['msg-accept'];
 * $graph[$key]['rejected'] = $processed - $val['msg-accept'];
 * $graph[$key]['total-kb'] = $val['total-KB'];
 */

#ifdef HAVE_GETLOADAVG
Stats stat_high_load_avg_1		= { STATS_TABLE_GENERAL, "high-load-avg-1", 1 };
Stats stat_high_load_avg_5		= { STATS_TABLE_GENERAL, "high-load-avg-5", 1 };
Stats stat_high_load_avg_15		= { STATS_TABLE_GENERAL, "high-load-avg-15", 1 };

Stats stat_load_avg_1			= { STATS_TABLE_GENERAL, "load-avg-1", 1 };
Stats stat_load_avg_5			= { STATS_TABLE_GENERAL, "load-avg-5", 1 };
Stats stat_load_avg_15			= { STATS_TABLE_GENERAL, "load-avg-15", 1 };

# ifdef LOW_LOAD_AVG
Stats stat_low_load_avg_1		= { STATS_TABLE_GENERAL, "low-load-avg-1", 1 };
Stats stat_low_load_avg_5		= { STATS_TABLE_GENERAL, "low-load-avg-5", 1 };
Stats stat_low_load_avg_15		= { STATS_TABLE_GENERAL, "low-load-avg-15", 1 };
# endif
#endif

Stats stat_high_connections		= { STATS_TABLE_GENERAL, "high-connections", 1 };
Stats stat_high_connections_per_second	= { STATS_TABLE_GENERAL, "high-connections-per-second", 1 };
Stats stat_high_connections_per_minute	= { STATS_TABLE_GENERAL, "high-connections-per-minute", 1 };
Stats stat_high_session_time		= { STATS_TABLE_GENERAL, "high-session-time", 1 };
Stats stat_connections_per_minute	= { STATS_TABLE_GENERAL, "connections-per-minute", 1 };
Stats stat_total_kb			= { STATS_TABLE_GENERAL, "total-KB" };

Stats stat_connect_count		= { STATS_TABLE_CONNECT, "CLIENTS" };
Stats stat_connect_dropped		= { STATS_TABLE_CONNECT, "dropped" };
Stats stat_clean_quit			= { STATS_TABLE_CONNECT, "clean-quit" };
Stats stat_client_io_error		= { STATS_TABLE_CONNECT, "client-io-error" };
Stats stat_client_pipelining_seen	= { STATS_TABLE_CONNECT, "client-pipelining-seen" };
Stats stat_client_timeout		= { STATS_TABLE_CONNECT, "client-timeout" };
Stats stat_client_is_2nd_mx		= { STATS_TABLE_CONNECT, "client-is-2nd-mx" };
Stats stat_server_io_error		= { STATS_TABLE_CONNECT, "server-io-error" };
Stats stat_admin_commands		= { STATS_TABLE_CONNECT, "admin-commands" };
Stats stat_auth_pass			= { STATS_TABLE_CONNECT, "auth-pass" };
Stats stat_auth_fail			= { STATS_TABLE_CONNECT, "auth-fail" };
Stats stat_concurrent			= { STATS_TABLE_CONNECT, "concurrent" };
Stats stat_connect_lan			= { STATS_TABLE_CONNECT, "connect-lan" };
Stats stat_connect_localhost		= { STATS_TABLE_CONNECT, "connect-localhost" };
Stats stat_connect_relay		= { STATS_TABLE_CONNECT, "connect-relay" };
Stats stat_ehlo_no_helo			= { STATS_TABLE_CONNECT, "ehlo-no-helo"};
Stats stat_helo_schizophrenic		= { STATS_TABLE_CONNECT, "helo-schizophrenic" };
Stats stat_rfc2821_command_length	= { STATS_TABLE_CONNECT, "rfc2821-command-length" };
Stats stat_smtp_command_non_ascii	= { STATS_TABLE_CONNECT, "smtp-command-non-ascii" };
Stats stat_smtp_drop_after		= { STATS_TABLE_CONNECT, "smtp-drop-after" };
Stats stat_smtp_drop_unknown		= { STATS_TABLE_CONNECT, "smtp-drop-unknown" };
#ifdef ENABLE_PRUNED_STATS
Stats stat_smtp_enable_esmtp		= { STATS_TABLE_CONNECT, "smtp-enable-esmtp" };
#endif
Stats stat_quit_after_ehlo		= { STATS_TABLE_CONNECT, "quit-after-ehlo" };
Stats stat_quit_after_helo		= { STATS_TABLE_CONNECT, "quit-after-helo" };

Stats stat_mail_count			= { STATS_TABLE_MAIL, "MAIL" };
Stats stat_null_sender			= { STATS_TABLE_MAIL, "null-sender" };
Stats stat_mail_drop			= { STATS_TABLE_MAIL, "mail-drop" };
Stats stat_mail_parse			= { STATS_TABLE_MAIL, "mail-parse" };
Stats stat_mail_reject			= { STATS_TABLE_MAIL, "mail-reject" };
Stats stat_mail_tempfail		= { STATS_TABLE_MAIL, "mail-tempfail" };

Stats stat_rcpt_count			= { STATS_TABLE_RCPT, "RCPT" };
Stats stat_rcpt_drop			= { STATS_TABLE_RCPT, "rcpt-drop" };
Stats stat_rcpt_parse			= { STATS_TABLE_RCPT, "rcpt-parse" };
Stats stat_rcpt_reject			= { STATS_TABLE_RCPT, "rcpt-reject" };
Stats stat_rcpt_tempfail		= { STATS_TABLE_RCPT, "rcpt-tempfail" };
Stats stat_rcpt_relay_denied		= { STATS_TABLE_RCPT, "rcpt-relay-denied" };
Stats stat_rcpt_unknown			= { STATS_TABLE_RCPT, "rcpt-unknown" };
Stats stat_quit_after_rcpt		= { STATS_TABLE_RCPT, "quit-after-rcpt" };
Stats stat_msg_queue			= { STATS_TABLE_RCPT, "msg-queue" };

Stats stat_forward_helo_tempfail	= { STATS_TABLE_RCPT, "forward-helo-tempfail" };
Stats stat_forward_helo_reject		= { STATS_TABLE_RCPT, "forward-helo-reject" };
Stats stat_forward_mail_tempfail	= { STATS_TABLE_RCPT, "forward-mail-tempfail" };
Stats stat_forward_mail_reject		= { STATS_TABLE_RCPT, "forward-mail-reject" };
Stats stat_forward_rcpt_tempfail	= { STATS_TABLE_RCPT, "forward-rcpt-tempfail" };
Stats stat_forward_rcpt_reject		= { STATS_TABLE_RCPT, "forward-rcpt-reject" };

Stats stat_data_count			= { STATS_TABLE_DATA, "DATA" };
Stats stat_data_accept			= { STATS_TABLE_DATA, "data-accept" };
Stats stat_data_drop			= { STATS_TABLE_DATA, "data-drop" };
Stats stat_data_reject			= { STATS_TABLE_DATA, "data-reject" };
Stats stat_data_tempfail		= { STATS_TABLE_DATA, "data-tempfail" };
Stats stat_data_354			= { STATS_TABLE_DATA, "data-354" };

Stats stat_msg_count			= { STATS_TABLE_MSG, "MESSAGES" };
Stats stat_msg_accept			= { STATS_TABLE_MSG, "msg-accept" };
Stats stat_msg_discard			= { STATS_TABLE_MSG, "msg-discard" };
Stats stat_msg_drop			= { STATS_TABLE_MSG, "msg-drop" };
Stats stat_msg_reject			= { STATS_TABLE_MSG, "msg-reject" };
Stats stat_msg_tempfail			= { STATS_TABLE_MSG, "msg-tempfail" };
Stats stat_dsn_sent			= { STATS_TABLE_MSG, "dsn-sent" };
Stats stat_line_length			= { STATS_TABLE_MSG, "line-length" };
Stats stat_strict_dot			= { STATS_TABLE_MSG, "strict-dot" };
Stats stat_disconnect_after_dot		= { STATS_TABLE_MSG, "disconnect-after-dot" };
Stats stat_virus_infected		= { STATS_TABLE_MSG, "virus-infected" };


Vector stats;
time_t start_time;
int stats_table_indices[STATS_TABLE_SIZE];

Verbose verb_stats = { { "stats", "-", "" } };

static kvm *stats_map;
static int stats_current_hour;
static pthread_mutex_t stats_mutex;
static char buffer[STATS_BUFFER_SIZE];

/***********************************************************************
 ***
 ***********************************************************************/

static unsigned long
parse_hex(char *start, char **stop)
{
	unsigned long hex;
	hex = strtol(start, stop, 16);
	*stop += strspn(*stop, " \t");
	return hex;
}

static char *
parse_name(char *start, char **stop)
{
	start += strspn(start, " \t");
	*stop = start + strcspn(start, " \t");

	return start;
}

/***********************************************************************
 *** Stats by Domain
 ***********************************************************************/

#define STATS_ROUTE_TAG		ROUTE_TAG

typedef struct route_hash {
	char *route;
	size_t length;
	uint32_t accept;
	uint32_t reject;
	uint32_t volume;
	struct route_hash *next;
} RouteStat;

static RouteStat *routes[HASH_TABLE_SIZE];
static pthread_mutex_t routes_mutex;

static int
statsRouteUpdate(Session *sess, const char *route, int smtpf_code)
{
	int rc = -1;
	RouteStat *entry;
	unsigned long hash;

	if (route == NULL || *route == '\0' || mutex_lock(SESS_ID, FILE_LINENO, &routes_mutex))
		goto error0;

	/* Only hash the stuff after the route: tag. */
	hash = djb_hash_index((unsigned char *) route+sizeof(STATS_ROUTE_TAG)-1, strlen(route)-sizeof(STATS_ROUTE_TAG)+1, HASH_TABLE_SIZE);

	for (entry = routes[hash]; entry != NULL; entry = entry->next) {
		if (strcmp(entry->route+sizeof(STATS_ROUTE_TAG)-1, route+sizeof(STATS_ROUTE_TAG)-1) == 0)
			break;
	}

	if (entry == NULL) {
		if ((entry = calloc(1, sizeof (*entry))) == NULL) {
			syslog(LOG_ERR, log_oom, FILE_LINENO);
			goto error1;
		}

		entry->length = /* sizeof(STATS_ROUTE_TAG)-1 +*/ strlen(route);
		if ((entry->route = malloc(entry->length+1)) == NULL) {
			syslog(LOG_ERR, log_oom, FILE_LINENO);
			free(entry);
			goto error1;
		}

		(void) snprintf(entry->route, entry->length+1, /* STATS_ROUTE_TAG */ "%s", route);
		entry->next = routes[hash];
		routes[hash] = entry;
	}

	if (verb_stats.option.value)
		syslog(LOG_DEBUG, LOG_MSG(704) "route stats before %s %u:%u:%u", LOG_ARGS(sess), entry->route, entry->accept, entry->reject, entry->volume);

	/* We don't count temp.fail of messages, since the message
	 * will either be counted as an accept or a reject eventually.
	 * One case we cannot properly count is when a message is
	 * temp.failed until expired from a sender's retry queue.
	 *
	 * If we attempt to count temp.fails the numbers would be
	 * large and possibly misleading when presented to the
	 * postmaster/client/user, therefore better to punt on the
	 * issue.
	 *
	 * We can still count volume though, even for temp.fail
	 * (see grey-content).
	 */
	switch (smtpf_code) {
	case SMTPF_ACCEPT:
	case SMTPF_CONTINUE:
		/* _MESSAGES_ accepted. */
		entry->accept++;
		break;

	case SMTPF_DROP:
	case SMTPF_REJECT:
		/* _MESSAGES_ rejected. */
		entry->reject++;
		break;
	}

	entry->volume += sess->msg.length / 1024 + 1;

	if (verb_stats.option.value)
		syslog(LOG_DEBUG, LOG_MSG(705) "route stats after %s %u:%u:%u", LOG_ARGS(sess), entry->route, entry->accept, entry->reject, entry->volume);

	rc = 0;
error1:
	(void) mutex_unlock(SESS_ID, FILE_LINENO, &routes_mutex);
error0:
	return rc;
}

void
statsRoute(Session *sess, int smtpf_code)
{
        char *key;
	Connection *fwd;

	if (stats_map == NULL)
		return;

	/* Is the sender one of ours that we need to tally? */
        if (sess->msg.mail != NULL
        && smdbAccessMail(routeGetMap(sess), ROUTE_TAG, sess->msg.mail->address.string, &key, NULL) != SMDB_ACCESS_NOT_FOUND) {
		statsRouteUpdate(sess, key, smtpf_code);
		free(key);
	}

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
		/* We have a route without any recipients, which
		 * can only occur if there was an error.
		 *
		 * Or we have an I/O error when forwarding. A DSN
		 * will have been sent explaining failure to
		 * deliver.
		 */
#ifdef OLD_SMTP_ERROR_CODES
		if (fwd->rcpt_count == 0 || (fwd->smtp_error & SMTP_ERROR_IO_MASK)) {
#else
		if (fwd->rcpt_count == 0 || fwd->smtp_code == SMTP_ERROR_IO) {
#endif
			statsRouteUpdate(sess, fwd->route.key, SMTPF_REJECT);
			continue;
		}

		/* We either have a clear end-of-message result
		 * (SMTPF_DROP or SMTPF_REJECT) or the message
		 * was abandoned (SMTPF_UNKNOWN default) even
		 * though there are recipients for the route,
		 * probably because of a delayed reject/drop
		 * reported at RCPT time.
		 */
		statsRouteUpdate(sess, fwd->route.key, smtpf_code);
	}
}

/*
 * New record with 30 ratios (not 31). The day-of-year field will be replaced
 * and a
 */
static const char stats_domain_zero[] = "-1 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0 0:0:0";

static void
statsRouteSave(RouteStat *list)
{
	time_t now;
	char *last_ratio;
	struct tm time_now;
	kvm_data key, value;
	int span, day_of_year;
	RouteStat *entry, current;
	static char output[STATS_DOMAIN_VALUE_SIZE];

	now = time(NULL);
	localtime_r(&now, &time_now);

	(void) stats_map->begin(stats_map);

	for (entry = list; entry != NULL; entry = entry->next) {
		if (entry->accept + entry->reject == 0)
			continue;

		key.data = entry->route;
		key.size = entry->length;

		switch (stats_map->get(stats_map, &key, &value)) {
		case KVM_OK:
			break;

		case KVM_NOT_FOUND:
			value.data = (unsigned char *) stats_domain_zero;
			value.size = sizeof (stats_domain_zero)-1;
			break;

		default:
			syslog(LOG_ERR, LOG_NUM(706) "stats-map get key={%s} failed", key.data);
/*{NEXT}*/
			continue;
		}

		(void) sscanf(value.data, "%d %x:%x:%x%n", &day_of_year, &current.accept, &current.reject, &current.volume, &span);

		if (verb_stats.option.value)
			syslog(LOG_DEBUG, LOG_NUM(707) "route stat get %s %d %u:%u:%u", entry->route, day_of_year, current.accept, current.reject, current.volume);

		if (day_of_year != time_now.tm_yday) {
			/* It is a different day from the last update,
			 * discard the 31st ratio.
			 *
			 * span covers the day-of-year only and we
			 * truncate the last ratio.
			 */
			span = strcspn(value.data, " ");

			if (value.data != (unsigned char *) stats_domain_zero) {
				/* Find last ratio and remove it. */
				last_ratio = strrchr(value.data, ' ');
				*last_ratio = '\0';
			}
		} else {
			/* Same day, update first ratio only.
			 *
			 * span covers the day-of-year and the first ratio.
			 *
			 * Tally the day's running total ignoring overflow.
			 * Can you overflow an unsigned 32-bit in one day?
			 */
			entry->accept += current.accept;
			entry->reject += current.reject;
			entry->volume += current.volume;
		}

		/* Build a new record: day-of-year, first ratio, previous 30 days. */
		value.size = snprintf(
			output, sizeof (output), "%d %x:%x:%x%s",
			time_now.tm_yday, entry->accept, entry->reject,
			entry->volume, value.data+span
		);
		if (sizeof (output) <= value.size) {
			value.size = sizeof (output)-1;
			syslog(LOG_ERR, LOG_NUM(708) "stats-map key={%s} value={%s} truncated", key.data, value.data);
/*{NEXT}*/
		}
		if (value.data != (unsigned char *) stats_domain_zero)
			free(value.data);
		value.data = output;

		(void) stats_map->put(stats_map, &key, &value);

		if (verb_stats.option.value)
			syslog(LOG_DEBUG, LOG_NUM(709) "route stat put %s %d %u:%u:%u", entry->route, time_now.tm_yday, entry->accept, entry->reject, entry->volume);

		entry->accept = 0;
		entry->reject = 0;
		entry->volume = 0;
	}

	(void) stats_map->commit(stats_map);
}

static void
statsRouteListFree(RouteStat *entry)
{
	RouteStat *next;

	for ( ; entry != NULL; entry = next) {
		next = entry->next;
		free(entry->route);
		free(entry);
	}
}

static void
statsRouteFini(void)
{
	int i;

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		statsRouteListFree(routes[i]);

	pthread_mutex_destroy(&routes_mutex);
}

static RouteStat *
statsRouteCopy(void)
{
	int i;
	RouteStat *entry, *copy, *list = NULL;

	if (mutex_lock(SESS_ID_ZERO, FILE_LINENO, &routes_mutex))
		return NULL;

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		for (entry = routes[i]; entry != NULL; entry = entry->next) {
			if ((copy = malloc(sizeof (*copy))) == NULL)
				continue;

			*copy = *entry;

			entry->accept = 0;
			entry->reject = 0;
			entry->volume = 0;

			if ((copy->route = strdup(entry->route)) == NULL) {
				free(copy);
				continue;
			}

			copy->next = list;
			list = copy;
		}
	}

	(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &routes_mutex);

	return list;
}

/***********************************************************************
 ***
 ***********************************************************************/

void
human_units(unsigned long value, unsigned long *out, const char **unit)
{
	char *u = "B";

	if (1024 < value) {
		value /= 1024;
		u = "KB";
	}
	if (1024 < value) {
		value /= 1024;
		u = "MB";
	}
	if (1024 < value) {
		value /= 1024;
		u = "GB";
	}

	*out = value;
	*unit = u;
}

static unsigned long *
statsHourlyCopy(void)
{
	long i;
	Stats *stat;
	unsigned long *copy;

	if ((copy = malloc(VectorLength(stats) * sizeof (*copy))) != NULL) {
		for (i = 0; i < VectorLength(stats); i++) {
			stat = VectorGet(stats, i);
			copy[i] = stat->hourly;
		}
	}

	return copy;
}

static void
statsHourlyReset(void)
{
	int i;
	time_t now;
	Stats *stat;
	struct tm time_now;

	/* In case the hour has change since the last update,
	 * count the stats against the previous hour before
	 * reseting stats_hourly[]. Due to how the cache gc
	 * happens, this might not be precisely on or near
	 * the hour.
	 */

	(void) time(&now);
	localtime_r(&now, &time_now);

	if (stats_current_hour != time_now.tm_hour) {
		for (i = 0; i < VectorLength(stats); i++) {
			stat = VectorGet(stats, i);
			stat->hourly = 0;
		}
		stats_current_hour = time_now.tm_hour;
	}
}

static void
statsNameSave(void)
{
	int i, len;
	Stats *stat;
	kvm_data key, value;
	static int first_time = 1;

	if (first_time) {
		/* Save the list of stats names in Vector order for
		 * when we restart we can reload the hourly stats.
		 */
		key.data = "fields:" _VERSION;
		key.size = sizeof ("fields:" _VERSION)-1;

		len = snprintf(buffer, sizeof (buffer), "version start-time touch-time");

		value.size = len;
		value.data = buffer;

		for (i = 0; i < VectorLength(stats); i++) {
			if ((stat = VectorGet(stats, i)) == NULL)
				continue;

			len = snprintf(buffer+value.size, sizeof (buffer)-value.size, " %s", stat->name);

			if (sizeof (buffer)-value.size <= len) {
				syslog(LOG_ERR, LOG_NUM(710) "statsSave() field name buffer overflow caught");
/*{NEXT}*/
				exit(1);
			}

			value.size += len;
		}

		(void) stats_map->put(stats_map, &key, &value);
		first_time = 0;
	}
}

static void
statsHourlySave(unsigned long *table, size_t length)
{
	time_t now;
	int i, len;
	char date_hour[12];
	struct tm time_now;
	kvm_data key, value;

	(void) time(&now);
	key.data = date_hour;
	localtime_r(&now, &time_now);
	time_now.tm_hour = stats_current_hour;
	key.size = strftime(date_hour, sizeof (date_hour), "%Y%m%d%H", &time_now);

	len = snprintf(buffer, sizeof (buffer), _VERSION " %lx %lx", (unsigned long) start_time, (unsigned long) now);

	value.size = len;
	value.data = buffer;
	for (i = 0; i < length; i++) {
		len = snprintf(buffer+value.size, sizeof (buffer)-value.size, " %lx", table[i]);

		if (sizeof (buffer)-value.size <= len) {
			syslog(LOG_ERR, LOG_NUM(711) "statsSave() buffer overflow caught");
/*{NEXT}*/
			break;
		}

		value.size += len;
	}

	(void) stats_map->put(stats_map, &key, &value);
}

static int
statsHttpPostChunk(Socket2 *socket, char *buffer, int size)
{
	int length;
	char chunk_size[20];

	length = snprintf(chunk_size, sizeof (chunk_size), "%X" CRLF, size);

	if (socketWrite(socket, chunk_size, length) == SOCKET_ERROR)
		return -1;

	if (socketWrite(socket, buffer, size) == SOCKET_ERROR)
		return -1;

	return socketWrite(socket, CRLF, sizeof (CRLF)-1) == SOCKET_ERROR ? -1 : 0;
}

static void
statsHttpPost(void)
{
	URI *uri;
	int length;
	Socket2 *socket;
	char buffer[HTTP_LINE_BUFFER_SIZE];

	int i, j;
	Stats **base;
	unsigned long counter;
	sqlite3_int64 mem_use;
	const char *units, *question_mark, *query;

	if (*optStatsHttpPost.string == '\0' || (uri = uriParse(optStatsHttpPost.string, -1)) == NULL)
		goto error0;

	if (TextInsensitiveCompare(uri->scheme, "http") != 0)
		goto error1;

	if (socketOpenClient(uri->host, 80, optHttpTimeout.value, NULL, &socket) == SOCKET_ERROR)
		goto error1;

	if (uri->query == NULL) {
		question_mark = query = "";
	} else {
		question_mark = "?";
		query = uri->query;
	}

	length = snprintf(
		buffer, sizeof (buffer),
		"POST %s%s%s HTTP/1.1" CRLF
		"Host: %s:%d" CRLF
		"Transfer-Encoding: chunked" CRLF
		"Content-Type: application/x-www-form-urlencoded" CRLF,
		uri->path, question_mark, query, uri->host, uriGetSchemePort(uri)
	);

	if (*optStatsHttpUser.string == '\0') {
		B64 b64;
		size_t cred_length, encoded_length;
		char credentials[256], encoded[512];

		cred_length = snprintf(credentials, sizeof (credentials), "%s:%s", optStatsHttpUser.string, optStatsHttpPass.string);

		b64Init();
		b64Reset(&b64);
		encoded_length = 0;
		b64EncodeBuffer(&b64, credentials, cred_length, encoded, sizeof (encoded), &encoded_length);
		b64EncodeFinish(&b64, encoded, sizeof (encoded), &encoded_length, 0);

		length += snprintf(buffer+length, sizeof (buffer)-length, "Authorization: Basic %s" CRLF, encoded);
	}

	length += TextCopy(buffer+length, sizeof (buffer)-length, CRLF);

	if (sizeof (buffer) <= length) {
		syslog(LOG_ERR, LOG_NUM(878) "stats-http-post request buffer overflow");
		*optStatsHttpPost.string = '\0';
		goto error2;
	}

	if (socketWrite(socket, buffer, length) == SOCKET_ERROR)
		goto error2;


	length = snprintf(
		buffer, sizeof (buffer),
		_NAME"="_VERSION
		"&start-time=0x%lx"
		"&age=%lu"
		"&active-connections=%u",
		(unsigned long) start_time,
		(unsigned long) (time(NULL) - start_time),
		server.connections
	);
	if (statsHttpPostChunk(socket, buffer, length))
		goto error2;

	mem_use = sqlite3_memory_used();
	human_units((unsigned long) mem_use, &counter, &units);
	length = snprintf(buffer, sizeof (buffer), "&sqlite-memory=%s%lu%s", ULONG_MAX == counter ? ">" : "", counter, units);
	if (statsHttpPostChunk(socket, buffer, length))
		goto error2;

	mem_use = sqlite3_memory_highwater(0);
	human_units((unsigned long) mem_use, &counter, &units);
	length = snprintf(buffer, sizeof (buffer), "&sqlite-high-memory=%s%lu%s", ULONG_MAX == counter ? ">" : "", counter, units);
	if (statsHttpPostChunk(socket, buffer, length))
		goto error2;

	base = (Stats **) VectorBase(stats);
	for (i = 0; base[i] != NULL; i++) {
		unsigned long counter_hour, counter_win;
		double pct, divisor, pct_hour, divisor_hour, pct_win, divisor_win;

		if (i < stats_table_indices[STATS_TABLE_CONNECT])
			j = i;
		else if (i < stats_table_indices[STATS_TABLE_MAIL])
			j = stats_table_indices[STATS_TABLE_CONNECT];
		else if (i < stats_table_indices[STATS_TABLE_RCPT])
			j = stats_table_indices[STATS_TABLE_MAIL];
		else if (i < stats_table_indices[STATS_TABLE_DATA])
			j = stats_table_indices[STATS_TABLE_RCPT];
		else if (i < stats_table_indices[STATS_TABLE_MSG])
			j = stats_table_indices[STATS_TABLE_DATA];
		else
			j = stats_table_indices[STATS_TABLE_MSG];

		counter_hour = statsGetHourly(base[i]);
		divisor_hour = (double) statsGetHourly(base[j]);
		pct_hour = 0.0;
		if (0 < divisor_hour)
			pct_hour = 100.0 * (double) counter_hour / divisor_hour;

		counter_win = statsGetWindow(base[i]);
		divisor_win = (double) statsGetWindow(base[j]);
		pct_win = 0.0;
		if (0 < divisor_win)
			pct_win = 100.0 * (double) counter_win / divisor_win;

		counter = statsGetRuntime(base[i]);
		divisor = (double) statsGetRuntime(base[j]);
		pct = 0.0;
		if (0 < divisor)
			pct = 100.0 * (double) counter / divisor;

		length = snprintf(buffer, sizeof (buffer), "&%s=%lu%%20%.2f%%25%%3B%lu%%20%.2f%%25%%3B%lu%%20%.2f%%25", base[i]->name, counter, pct, counter_hour, pct_hour, counter_win, pct_win);
		if (statsHttpPostChunk(socket, buffer, length))
			goto error2;
	}

	/* End chunked data. */
	if (statsHttpPostChunk(socket, buffer, 0))
		goto error2;

	/* Read response line. */
	socketSetNonBlocking(socket, 1);
	socketSetTimeout(socket, optHttpTimeout.value / 2);

	if (0 < (length = socketReadLine(socket, buffer, sizeof (buffer)))) {
		char *result = strchr(buffer, ' ');
		if (result != NULL && result[1] != '2')
			syslog(LOG_ERR, LOG_NUM(879) "stats-http-post error: %s", result+1);
	}

	/* Ignore remainder of response. */
	while (0 < (length = socketReadLine(socket, buffer, sizeof (buffer))))
		;
error2:
	socketSetLinger(socket, 0);
	socketClose(socket);
error1:
	free(uri);
error0:
	;
}

/*
 * Called by statsFini() and cacheGcThread(), therefore subject to the
 * cache-gc-interval.
 */
void
statsSave(void)
{
	RouteStat *routes;
	unsigned long *hourly;

	/* Note that on exit, we want to save the stats regardless of
	 * whether another thread has the mutex or not, otherwise we
	 * might get forever stuck on the mutex, who's owner thread
	 * has gone away before unlocking it.
	 */
	if (stats_map != NULL) {
		statsHttpPost();

		/* Lock mutex and make in memory working copies. */
		statsLock();
		hourly = statsHourlyCopy();
		routes = statsRouteCopy();
		statsHourlyReset();

		/* Release mutex and use working copies to update database. */
		statsUnlock();
		statsNameSave();
		statsRouteSave(routes);
		statsHourlySave(hourly, VectorLength(stats));

		free(hourly);
		statsRouteListFree(routes);
#ifdef STATS_SYNC
		(void) stats_map->sync(stats_map);
#endif
	}
}

void
statsLoad(void)
{
	int i;
	time_t now;
	Stats *stat;
	struct tm time_now;
	unsigned long counter;
	kvm_data key, value, fields;
	char key_data[20], *next_counter, *name, *next_name;

	if (stats_map == NULL)
		return;

	now = time(NULL);
	key.data = key_data;
	localtime_r(&now, &time_now);
	stats_current_hour = time_now.tm_hour;
	key.size = strftime(key_data, sizeof (key_data), "%Y%m%d%H", &time_now);

	if (stats_map->get(stats_map, &key, &value) == KVM_OK) {
		/* Get values version. */
		name = parse_name(value.data, &next_counter);
		if (*next_counter != '\0')
			*next_counter++ = '\0';

		/* Skip values start_time, and touch time. */
		(void) parse_name(next_counter, &next_counter);
		(void) parse_name(next_counter, &next_counter);

		/* Find matching fields lists. */
		key.size = snprintf(key_data, sizeof (key_data), "fields:%s", value.data);
		if (stats_map->get(stats_map, &key, &fields) == KVM_OK)	{
			/* Skip field names: version, start-time, touch-time. */
			(void) parse_name(fields.data, &next_name);
			(void) parse_name(next_name, &next_name);
			(void) parse_name(next_name, &next_name);

			/* For each stat field name... */
			while (*next_name != '\0') {
				name = parse_name(next_name, &next_name);
				if (*next_name != '\0')
					*next_name++ = '\0';

				counter = parse_hex(next_counter, &next_counter);

				/* Restore the stats structure hourly counter. */
				for (i = 0; i < VectorLength(stats); i++) {
					stat = VectorGet(stats, i);
					if (strcmp(stat->name, name) == 0) {
						stat->hourly = counter;
						break;
					}
				}
			}
			free(fields.data);
		}
		free(value.data);
	}
}

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
statsAtForkPrepare(void)
{
	if (stats_map != NULL) {
		/* Take care to maintaine nesting order. */
		pthread_mutex_lock(&stats_mutex);
		pthread_mutex_lock(&routes_mutex);
		kvmAtForkPrepare(stats_map);
	}
}

void
statsAtForkParent(void)
{
	if (stats_map != NULL) {
		/* Take care to maintaine nesting order. */
		kvmAtForkParent(stats_map);
		pthread_mutex_unlock(&routes_mutex);
		pthread_mutex_unlock(&stats_mutex);
	}
}

void
statsAtForkChild(void)
{
	if (stats_map != NULL) {
		/* Take care to maintaine nesting order. */
		kvmAtForkChild(stats_map);
		stats_map->close(stats_map);
		stats_map = NULL;

		pthread_mutex_unlock(&routes_mutex);
		(void) pthread_mutex_destroy(&routes_mutex);

		pthread_mutex_unlock(&stats_mutex);
		(void) pthread_mutex_destroy(&stats_mutex);
	}
}

#endif

void
statsDumpList(void)
{
	int i;
	Stats **base;

	base = (Stats **) VectorBase(stats);

	for (i = 0; base[i] != NULL; i++) {
		syslog(LOG_DEBUG, LOG_NUM(712) "stat=%d:%s", i, base[i]->name);
	}

	for (i = 0; i < STATS_TABLE_SIZE; i++) {
		syslog(LOG_DEBUG, LOG_NUM(713) "stat-table=%d:%d", i, stats_table_indices[i]);
	}
}

int
statsRegister0(Session *sess, va_list ignore)
{
	int i;

	verboseRegister(&verb_stats);
	optionsRegister(&optStatsMap, 1);
	optionsRegister(&optStatsHttpPost, 0);
	optionsRegister(&optStatsHttpUser, 0);
	optionsRegister(&optStatsHttpPass, 0);

	VectorDestroy(stats);
	for (i = 0; i < STATS_TABLE_SIZE; i++)
		stats_table_indices[i] = 0;

	if ((stats = VectorCreate(100)) == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}

	/* This stats have no module. */

	/*** General ***********************************************************/

	(void) statsRegister(&stat_route_accounts);
	(void) statsRegister(&stat_route_addresses);
	(void) statsRegister(&stat_route_domains);
	(void) statsRegister(&stat_route_unique_domains);

#ifdef HAVE_GETLOADAVG
	(void) statsRegister(&stat_high_load_avg_1);
	(void) statsRegister(&stat_high_load_avg_5);
	(void) statsRegister(&stat_high_load_avg_15);
	(void) statsRegister(&stat_load_avg_1);
	(void) statsRegister(&stat_load_avg_5);
	(void) statsRegister(&stat_load_avg_15);
# ifdef LOW_LOAD_AVG
	(void) statsRegister(&stat_low_load_avg_1);
	(void) statsRegister(&stat_low_load_avg_5);
	(void) statsRegister(&stat_low_load_avg_15);
# endif
#endif
	(void) statsRegister(&stat_high_connections);
	(void) statsRegister(&stat_high_connections_per_second);
	(void) statsRegister(&stat_high_connections_per_minute);
	(void) statsRegister(&stat_high_session_time);
	(void) statsRegister(&stat_connections_per_minute);
	(void) statsRegister(&stat_total_kb);

	/*** Connection ********************************************************/

	(void) statsRegister(&stat_connect_count);
	(void) statsRegister(&stat_connect_dropped);
	(void) statsRegister(&stat_clean_quit);
	(void) statsRegister(&stat_client_io_error);
	(void) statsRegister(&stat_client_timeout);
	(void) statsRegister(&stat_client_is_2nd_mx);
	(void) statsRegister(&stat_client_pipelining_seen);
	(void) statsRegister(&stat_server_io_error);
	(void) statsRegister(&stat_admin_commands);
	(void) statsRegister(&stat_auth_pass);
	(void) statsRegister(&stat_auth_fail);
	(void) statsRegister(&stat_ehlo_no_helo);
	(void) statsRegister(&stat_helo_schizophrenic);
	(void) statsRegister(&stat_rfc2821_command_length);
	(void) statsRegister(&stat_smtp_command_non_ascii);
	(void) statsRegister(&stat_smtp_drop_after);
	(void) statsRegister(&stat_smtp_drop_unknown);
#ifdef ENABLE_PRUNED_STATS
	(void) statsRegister(&stat_smtp_enable_esmtp);
#endif
	/*** MAIL **************************************************************/

	(void) statsRegister(&stat_mail_count);
	(void) statsRegister(&stat_mail_drop);
	(void) statsRegister(&stat_mail_parse);
	(void) statsRegister(&stat_mail_reject);
	(void) statsRegister(&stat_mail_tempfail);
	(void) statsRegister(&stat_null_sender);

	/*** RCPT **************************************************************/

	(void) statsRegister(&stat_rcpt_count);
	(void) statsRegister(&stat_rcpt_drop);
	(void) statsRegister(&stat_rcpt_parse);
	(void) statsRegister(&stat_rcpt_reject);
	(void) statsRegister(&stat_rcpt_tempfail);
	(void) statsRegister(&stat_rcpt_relay_denied);
	(void) statsRegister(&stat_rcpt_unknown);
	(void) statsRegister(&stat_msg_queue);
	(void) statsRegister(&stat_quit_after_ehlo);
	(void) statsRegister(&stat_quit_after_helo);
	(void) statsRegister(&stat_quit_after_rcpt);

	(void) statsRegister(&stat_forward_helo_tempfail);
	(void) statsRegister(&stat_forward_helo_reject);
	(void) statsRegister(&stat_forward_mail_tempfail);
	(void) statsRegister(&stat_forward_mail_reject);
	(void) statsRegister(&stat_forward_rcpt_tempfail);
	(void) statsRegister(&stat_forward_rcpt_reject);

	/*** DATA **************************************************************/

	(void) statsRegister(&stat_data_count);
	(void) statsRegister(&stat_data_accept);
	(void) statsRegister(&stat_data_drop);
	(void) statsRegister(&stat_data_reject);
	(void) statsRegister(&stat_data_tempfail);
	(void) statsRegister(&stat_data_354);

	/*** Message ***********************************************************/

	(void) statsRegister(&stat_msg_count);
	(void) statsRegister(&stat_msg_accept);
	(void) statsRegister(&stat_msg_discard);
	(void) statsRegister(&stat_msg_drop);
	(void) statsRegister(&stat_msg_reject);
	(void) statsRegister(&stat_msg_tempfail);
	(void) statsRegister(&stat_dsn_sent);
	(void) statsRegister(&stat_disconnect_after_dot);
	(void) statsRegister(&stat_line_length);
	(void) statsRegister(&stat_strict_dot);
	(void) statsRegister(&stat_virus_infected);

	/*** End ***************************************************************/

	return SMTPF_CONTINUE;
}

void
statsInit(void)
{
	int length;
	const char *file;

	(void) pthread_mutex_init(&stats_mutex, NULL);
	(void) pthread_mutex_init(&routes_mutex, NULL);
	(void) time(&start_time);

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(statsAtForkPrepare, statsAtForkParent, statsAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif

	if (*optStatsMap.string != '\0') {
		if ((stats_map = kvmOpen("stats", optStatsMap.string, 0)) == NULL) {
			syslog(LOG_ERR, LOG_NUM(714) "stats-map=%s open error: %s (%d)", optStatsMap.string, strerror(errno), errno);
/*{LOG
See <a href="summary.html#opt_stats_map">stats-map</a> option.
}*/
			exit(1);
		}

		if ((file = stats_map->filepath(stats_map)) != NULL) {
			char journal[PATH_MAX];

			if (chownByName(file, optRunUser.string, optRunGroup.string))
				exit(1);
			if (chmodByName(file, 0664))
				exit(1);
			length = snprintf(journal, sizeof (journal), "%s-journal", file);
			if (sizeof (journal) <= length) {
				syslog(LOG_ERR, log_overflow, SESSION_ID_ZERO, FILE_LINENO, sizeof (journal), length);
				exit(1);
			}
			(void) chownByName(journal, optRunUser.string, optRunGroup.string);
		}
	}
}

void
statsFini(void)
{
	statsSave();
	if (stats_map != NULL) {
		stats_map->close(stats_map);
		stats_map = NULL;
	}
	statsLock();
	statsRouteFini();
	statsUnlock();
	(void) pthread_mutex_destroy(&stats_mutex);
}

int
statsRegister(Stats *stat)
{
	STATS_TABLE table = stat->table;

	/* Append the stat to the end of this section, ie. insert the
	 * stat before the next section.
	 */
	if (VectorInsert(stats, stats_table_indices[table+1], stat))
		return -1;

	/* Update the offsets of the table sections that follow. */
	for (table++; table < STATS_TABLE_SIZE; table++)
		stats_table_indices[table]++;

	return 0;
}

/***********************************************************************
 ***
 ***********************************************************************/

static StatsInterval *
stats_get_interval(Stats *stat, unsigned long ticks)
{
	StatsInterval *interval;

	/* Update the current interval. */
	interval = &stat->intervals[ticks % STATS_INTERVALS];
	if (interval->ticks != ticks) {
		interval->ticks = ticks;
		interval->count = 0;
	}

	return interval;
}

static void
stats_set_interval(Stats *stat, unsigned long ticks, unsigned long value)
{
	stats_get_interval(stat, ticks)->count = value;
}

static void
stats_add_interval(Stats *stat, unsigned long ticks, unsigned long value)
{
	stats_get_interval(stat, ticks)->count += value;
}

unsigned long
stats_get_sum_window(Stats *stat)
{
	int i;
	unsigned long ticks;
	unsigned long counter;
	StatsInterval *interval;

	counter = 0;
	ticks = time(NULL) / STATS_TICK;

	/* Sum the number of hits within this window. */
	interval = stat->intervals;
	for (i = 0; i < STATS_INTERVALS; i++) {
		if (ticks - STATS_INTERVALS <= interval->ticks && interval->ticks <= ticks)
			counter += interval->count;
		interval++;
	}

	return counter;
}

unsigned long
stats_get_max_window(Stats *stat)
{
	int i;
	unsigned long max;
	unsigned long ticks;
	StatsInterval *interval;

	max = 0;
	ticks = time(NULL) / STATS_TICK;

	/* Sum the number of hits within this window. */
	interval = stat->intervals;
	for (i = 0; i < STATS_INTERVALS; i++) {
		if (ticks - STATS_INTERVALS <= interval->ticks && interval->ticks <= ticks && max < interval->count)
			max = interval->count;
		interval++;
	}

	return max;
}

void
stats_set_window(Stats *stat, unsigned long value)
{
	stats_set_interval(stat, time(NULL) / STATS_TICK, value);
}

void
stats_add_window(Stats *stat, unsigned long value)
{
	stats_add_interval(stat, time(NULL) / STATS_TICK, value);
}

static unsigned long
stats_get_value(unsigned long *valuep)
{
	unsigned long count = 0;

	if (!mutex_lock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex)) {
		count = *valuep;
		(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
	}

	return count;
}

void
statsLock(void)
{
	(void) mutex_lock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
}

void
statsUnlock(void)
{
	(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
}

void
statsGet(Stats *stat, Stats *out)
{
	if (!mutex_lock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex)) {
		*out = *stat;
		(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
	} else {
		memset(out, 0, sizeof (*out));
	}
}

unsigned long
statsGetHourly(Stats *stat)
{
	return stats_get_value(&stat->hourly);
}

unsigned long
statsGetRuntime(Stats *stat)
{
	return stats_get_value(&stat->runtime);
}

unsigned long
statsGetWindow(Stats *stat)
{
	unsigned long count = 0;

	if (!mutex_lock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex)) {
		if (stat->is_max_of_intervals)
			count = stats_get_max_window(stat);
		else
			count = stats_get_sum_window(stat);
		(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
	}

	return count;
}

void
statsSetValue(Stats *stat, unsigned long value)
{
	if (server.running && !mutex_lock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex)) {
		stat->hourly = value;
		stat->runtime = value;
//		(void) stats_set_interval(stat, time(NULL) / STATS_TICK, value);
		(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
	}
}

void
statsAddValue(Stats *stat, unsigned long value)
{
	if (server.running && !mutex_lock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex)) {
		stat->hourly += value;
		stat->runtime += value;
		stats_add_interval(stat, time(NULL) / STATS_TICK, value);
		(void) mutex_unlock(SESS_ID_ZERO, FILE_LINENO, &stats_mutex);
	}
}

void
statsCount(Stats *stat)
{
	statsAddValue(stat, 1);
}

void
statsSetHighWater(Stats *stat, unsigned long value, int log)
{
	statsLock();
	if (stat->hourly < value) {
		if (log)
			syslog(LOG_INFO, LOG_NUM(715) "hourly %s was=%lu now=%lu", stat->name, (unsigned long) stat->hourly, value);
		stat->hourly = value;
	}
	if (stat->runtime < value) {
		if (log) {
			syslog(LOG_INFO, LOG_NUM(716) "runtime %s was=%lu now=%lu", stat->name, (unsigned long) stat->runtime, value);
/*{LOG
Logging of change in high water marks.
See <a hrfe="runtime.html#runtime_config">STAT</a> command.
}*/
		}
		stat->runtime = value;
	}
	if (stats_get_max_window(stat) < value)
		stats_set_window(stat, value);
	statsUnlock();
}

#ifdef NOT_USED_YET
void
statsSetLowWater(Stats *stat, unsigned long value, int log)
{
	statsLock();
	if (value < stat->hourly) {
		if (log)
			syslog(LOG_INFO, LOG_NUM(880) "hourly %s was=%lu now=%lu", stat->name, (unsigned long) stat->hourly, value);
		stat->hourly = value;
	}
	if (value < stat->runtime) {
		if (log) {
			syslog(LOG_INFO, LOG_NUM(881) "runtime %s was=%lu now=%lu", stat->name, (unsigned long) stat->runtime, value);
/*{LOG
Not used at this time.
}*/
		}
		stat->runtime = value;
	}
	if (value < stats_get_max_window(stat))
		stats_set_window(stat, value);
	statsUnlock();
}
#endif

void
statsGetLoadAvg(void)
{
#ifdef HAVE_GETLOADAVG
	double avg[3];

	if (getloadavg(avg, 3) != -1) {
		/* Convert double to 3 decimals place into an integer. */
		statsSetValue(&stat_load_avg_1, (unsigned long)(avg[0] * 1000));
		statsSetValue(&stat_load_avg_5, (unsigned long)(avg[1] * 1000));
		statsSetValue(&stat_load_avg_15, (unsigned long)(avg[2] * 1000));

# ifdef LOW_LOAD_AVG
		statsSetLowWater(&stat_low_load_avg_1, (unsigned long)(avg[0] * 1000), 0);
		statsSetLowWater(&stat_low_load_avg_5, (unsigned long)(avg[1] * 1000), 0);
		statsSetLowWater(&stat_low_load_avg_15, (unsigned long)(avg[2] * 1000), 0);
# endif
		statsSetHighWater(&stat_high_load_avg_1, (unsigned long)(avg[0] * 1000), verb_info.option.value);
		statsSetHighWater(&stat_high_load_avg_5, (unsigned long)(avg[1] * 1000), verb_info.option.value);
		statsSetHighWater(&stat_high_load_avg_15, (unsigned long)(avg[2] * 1000), verb_info.option.value);
	}
#endif
}

int
statsCommand(Session *sess)
{
	int i, j;
	Stats **base;
	Reply *reply;
	char stamp[40];
	struct tm local;
	unsigned long counter;
	sqlite3_int64 mem_use;
	const char *type, *units;
	unsigned long age, d, h, m, s;
	static const char hourly[] = "hourly";
	static const char window[] = "window";
	static const char runtime[] = "runtime";

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST|CLIENT_IS_LAN))
		return cmdUnknown(sess);

	statsCount(&stat_admin_commands);
	statsGetLoadAvg();

	switch (toupper(sess->input[sizeof ("STAT")-1 + strspn(sess->input + sizeof ("STAT")-1, " ")])) {
	case 'H': type = hourly; break;
	case 'W': type = window; break;
	default:  type = runtime; break;
	}

	reply = replyFmt(SMTPF_CONTINUE, "214-2.0.0 " _NAME "/" _VERSION "" CRLF);
	if (reply == NULL)
		replyInternalError(sess, FILE_LINENO);

	age = s = (unsigned long) (time(NULL) - start_time);
	d = s / 86400;
	s -= d * 86400;
	h = s / 3600;
	s -= h * 3600;
	m = s / 60;
	s -= m * 60;

	(void) localtime_r(&start_time, &local);
	(void) getRFC2821DateTime(&local, stamp, sizeof (stamp));
	reply = replyAppendFmt(reply, "214-2.0.0 start-time=%s" CRLF, stamp);
	reply = replyAppendFmt(reply, "214-2.0.0 age=%lu (%.2lu %.2lu:%.2lu:%.2lu)" CRLF, age, d, h, m, s);
	reply = replyAppendFmt(reply, "214-2.0.0 active-connections=%lu" CRLF, server.connections);

	mem_use = sqlite3_memory_used();
	human_units((unsigned long) mem_use, &counter, &units);
	reply = replyAppendFmt(reply, "214-2.0.0 sqlite-memory=%s%lu%s" CRLF, ULONG_MAX == counter ? ">" : "", counter, units);

	mem_use = sqlite3_memory_highwater(0);
	human_units((unsigned long) mem_use, &counter, &units);
	reply = replyAppendFmt(reply, "214-2.0.0 sqlite-high-memory=%s%lu%s" CRLF, ULONG_MAX == counter ? ">" : "", counter, units);

	base = (Stats **) VectorBase(stats);
	for (i = 0; base[i] != NULL; i++) {
		unsigned long counter_hour, counter_win;
		double pct, divisor, pct_hour, divisor_hour, pct_win, divisor_win;

		if (i < stats_table_indices[STATS_TABLE_CONNECT])
			j = i;
		else if (i < stats_table_indices[STATS_TABLE_MAIL])
			j = stats_table_indices[STATS_TABLE_CONNECT];
		else if (i < stats_table_indices[STATS_TABLE_RCPT])
			j = stats_table_indices[STATS_TABLE_MAIL];
		else if (i < stats_table_indices[STATS_TABLE_DATA])
			j = stats_table_indices[STATS_TABLE_RCPT];
		else if (i < stats_table_indices[STATS_TABLE_MSG])
			j = stats_table_indices[STATS_TABLE_DATA];
		else
			j = stats_table_indices[STATS_TABLE_MSG];

		counter_hour = statsGetHourly(base[i]);
		divisor_hour = (double) statsGetHourly(base[j]);
		pct_hour = 0.0;
		if (0 < divisor_hour)
			pct_hour = 100.0 * (double) counter_hour / divisor_hour;

		counter_win = statsGetWindow(base[i]);
		divisor_win = (double) statsGetWindow(base[j]);
		pct_win = 0.0;
		if (0 < divisor_win)
			pct_win = 100.0 * (double) counter_win / divisor_win;

		counter = statsGetRuntime(base[i]);
		divisor = (double) statsGetRuntime(base[j]);
		pct = 0.0;
		if (0 < divisor)
			pct = 100.0 * (double) counter / divisor;

		reply = replyAppendFmt(reply, "214-2.0.0 %.3d %s=%lu %.2f%%; %lu %.2f%%; %lu %.2f%%" CRLF, i, base[i]->name, counter, pct, counter_hour, pct_hour, counter_win, pct_win);
	}

	reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));

	return replyPush(sess, reply);
}

