/*
 * cache.c
 *
 * Copyright 2006, 2010 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#include <com/snert/lib/sys/Time.h>

/***********************************************************************
 *** Common Options
 ***********************************************************************/

static const char usage_cache_accept_ttl[] =
  "Cache time-to-live in seconds for positive results. A record will\n"
"# be maintained as long as there is regular activity.\n"
"#"
;

static const char usage_cache_reject_ttl[] =
  "Cache time-to-live in seconds for reject results.\n"
"#"
;

static const char usage_cache_tempfail_ttl[] =
  "Cache time-to-live in seconds for temporary failure results.\n"
"#"
;

/*
static const char usage_cache_ttl[] =
  "Cache time-to-live in seconds for long term cache records without\n"
"# a more specific TTL value. A record will be maintained as long as\n"
"# there is regular activity. Used for passed grey-list records and\n"
"# successfully validated recipients, etc.\n"
"#"
;
*/

static const char usage_cache_gc_interval[] =
  "Cache garbage collection interval in seconds.\n"
"#"
;

Option optCacheAcceptTTL	= { "cache-accept-ttl",		"604800",	usage_cache_accept_ttl };
Option optCacheRejectTTL	= { "cache-reject-ttl",		"604800",	usage_cache_reject_ttl };
Option optCacheTempFailTTL	= { "cache-temp-fail-ttl",	"7200",		usage_cache_tempfail_ttl };
Option optCacheGcInterval	= { "cache-gc-interval", 	"300",		usage_cache_gc_interval };

#ifdef NO_LONGER_USED
static const char usage_cache_on_corrupt[] =
  "Action taken if cache corruption is detected. Set to one of: exit,\n"
"# rename, or replace. This is intended for debugging.\n"
"#"
;

Option optCacheOnCorrupt	= { "cache-on-corrupt",		"replace",	usage_cache_on_corrupt };

static const char usage_cache_sync_mode[] =
  "Cache synchronisation mode. Set to one of: off, normal, or full. The\n"
"# normal and full modes improve reliability at the sake of speed.\n"
"#"
;

Option optCacheSyncMode		= { "cache-sync-mode",		"off",		usage_cache_sync_mode };
#endif


Verbose verb_cache		= { { "cache",		"-", "" } };

/***********************************************************************
 *** Multicast Cache API
 ***********************************************************************/

#include <ctype.h>
#include <com/snert/lib/mail/smtp2.h>

static const char usage_cache_path[] =
  "The file path of the SQLite3 cache. The directory containing the\n"
"# cache must be read-writable by the process so that SQLite3 can\n"
"# create journal files as required.\n"
"#"
;

static const char usage_cache_multicast_ip[] =
  "The Multicast Cache facility provides the ability to share cache\n"
"# updates between two or more machines on the same network segment.\n"
"# The multicast group can be an IPv4 or IPv6 address plus an optional\n"
"# port. For IPv4, RFC 3171 reserves 232/8 for one-to-many applications.\n"
"# RFC 3513 outlines multicast IPv6 assignment and it is recommended to\n"
"# use something within FF12/16 for link-local. To disable the multicast\n"
"# cache updates, specify the empty string.\n"
"#"
;

static const char usage_cache_unicast_domain[] =
  "The Unicast Cache facility provides the ability to broadcast cache\n"
"# updates to a set of remote hosts beyond the local network segment.\n"
"# The specified domain is used to obtain the list of MX hosts that\n"
"# are assumed to be participating in cache updates. To disable the\n"
"# unicast cache updates, specify the empty string.\n"
"#"
;

static const char usage_cache_secret[] =
  "The Multicast & Unicast Cache facility broadcasts UDP packets in the\n"
"# clear on the link-local network segment or direct to a set of hosts.\n"
"# In order to identify valid broadcasts, each participating machine\n"
"# must have the same shared secret used to generate and validate the\n"
"# cache updates.\n"
"#"
;

static const char usage_cache_unicast_hosts[] =
  "The Unicast Cache facility provides the ability to broadcast cache\n"
"# updates to a set of remote hosts beyond the local network segment.\n"
"# A semi-colon separated list of host names and/or IP addresses with\n"
"# optional colon separated port numbers. cache-unicast-domain and this\n"
"# option are mutually exclusive.\n"
"#"
;

Option optCachePath		= { "cache-path",		CACHE_DIR "/cache.sq3",	usage_cache_path };
Option optCacheMulticastIp	= { "cache-multicast-ip",	"",			usage_cache_multicast_ip };
Option optCacheMulticastPort	= { "cache-multicast-port",	QUOTE(CACHE_MULTICAST_PORT),	"The listener port for multicast cache updates." };
Option optCacheMulticastTTL	= { "cache-multicast-ttl",	"1",			"The multicast TTL value to be applied to broadcast packets." };
Option optCacheSecret		= { "cache-secret",		"",			usage_cache_secret };
Option optCacheUnicastDomain	= { "cache-unicast-domain",	"",			usage_cache_unicast_domain };
Option optCacheUnicastHosts	= { "cache-unicast-hosts",	"",			usage_cache_unicast_hosts };
Option optCacheUnicastPort	= { "cache-unicast-port",	QUOTE(CACHE_UNICAST_PORT),	"The listener port for unicast cache updates." };

static const char usage_cache_hosts[] =
  "The Multicast & Unicast Cache facility broadcasts UDP packets to one\n"   
"# or more multicast group IPs and/or unicast hosts. Specify a list of\n"
"# host names, IPv4, and/or IPv6 addresses. Specify the empty string to\n"
"# disable.\n"
"#"
;
Option opt_cache_hosts		= { "cache-hosts",		"",			usage_cache_hosts };

static const char usage_cache_port[] =
  "The listener port for Multicast & Unicast Cache UDP broadcasts.\n"
"#"
;
Option opt_cache_port		= { "cache-port",		QUOTE(CACHE_PORT),	usage_cache_port };

/***********************************************************************
 ***
 ***********************************************************************/

long
cacheGetTTL(SmtpfCode code)
{
	switch (code) {
	default:
	case SMTPF_ACCEPT:
	case SMTPF_CONTINUE:
		return optCacheAcceptTTL.value;
	case SMTPF_REJECT:
		return optCacheRejectTTL.value;
	case SMTPF_TEMPFAIL:
		return optCacheTempFailTTL.value;
	}

	return 0;
}

Timer *gc_timer;

static void
cacheGcThread(Timer *timer)
{
	mcc_handle *mcc;
#ifdef REPLACED_BY_MCC_START_GC
	time_t now;
#endif
	TIMER_DECLARE(section);
	TIMER_DECLARE(overall);

	if (verb_timers.option.value) {
		TIMER_START(overall);
		TIMER_START(section);
	}

#ifdef REPLACED_BY_MCC_START_GC
	if (verb_cache.option.value)
		syslog(LOG_DEBUG, LOG_NUM(165) "garbage collecting cache");

	/* Reset the timer period in case the option was updated. */
	timer->period.tv_sec = optCacheGcInterval.value;

	(void) time(&now);
	(void) filterRun(NULL, filter_cache_gc_table, timer->data, &now);

	if (verb_timers.option.value) {
		TIMER_DIFF(section);
		if (TIMER_GE_CONST(diff_section, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_NUM(166) "cache gc time-elapsed=" TIMER_FORMAT, TIMER_FORMAT_ARG(diff_section));
		TIMER_START(section);
	}
#endif
	if (verb_cache.option.value)
		syslog(LOG_DEBUG, LOG_NUM(167) "updating stats");

	statsGetLoadAvg();
	statsSave();

	if (verb_timers.option.value) {
		TIMER_DIFF(section);
		if (TIMER_GE_CONST(diff_section, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_NUM(168) "statsSave time-elapsed=" TIMER_FORMAT, TIMER_FORMAT_ARG(diff_section));
		TIMER_START(section);
	}

	if ((mcc = mccCreate()) != NULL) {
		lickeyHasExpired();
		lickeySendWarning(mcc);
		mccDestroy(mcc);
	}

	if (verb_timers.option.value) {
		TIMER_DIFF(section);
		if (TIMER_GE_CONST(diff_section, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_NUM(170) "lickey expire time-elapsed=" TIMER_FORMAT, TIMER_FORMAT_ARG(diff_section));

		TIMER_DIFF(overall);
		if (TIMER_GE_CONST(diff_overall, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_NUM(171) "gc time-elapsed=" TIMER_FORMAT, TIMER_FORMAT_ARG(diff_overall));
	}

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, LOG_NUM(169) "gc run done");
}

void
cacheGcStart(void)
{
	CLOCK period = { 0, 0 };

	period.tv_sec = optCacheGcInterval.value;

	if (mccStartGc(optCacheGcInterval.value)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}

	if ((gc_timer = timerCreate(cacheGcThread, NULL, NULL, &period, 32 * 1024)) == NULL) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
}

void
cacheFini(void)
{
	if (gc_timer != NULL) {
		timerFree(gc_timer);
	}
	mccFini();
}

int
cacheRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_cache);

	optionsRegister(&optCacheAcceptTTL, 0);
	optionsRegister(&optCacheGcInterval, 0);
	optionsRegister(&opt_cache_hosts, 1);
	optionsRegister(&opt_cache_port, 1);
	optionsRegister(&optCacheMulticastTTL, 1);
#ifdef NO_LONGER_USED
	optionsRegister(&optCacheOnCorrupt, 1);
#endif
	optionsRegister(&optCachePath, 1);
	optionsRegister(&optCacheRejectTTL, 0);
	optionsRegister(&optCacheSecret, 0);
#ifdef NO_LONGER_USED
	optionsRegister(&optCacheSyncMode, 1);
#endif
	optionsRegister(&optCacheTempFailTTL, 0);

	return SMTPF_CONTINUE;
}

static void
cache_loadavg_process(mcc_context *mcc, mcc_key_hook *hook, const char *ip, mcc_row *row)
{
	char buffer[128], *uptime, *clients, *arv, *of, *cap;

	MCC_PTR_V(row)[MCC_GET_V_SIZE(row)] = '\0';
	uptime = strchr((char *) MCC_PTR_V(row), ' ');
	*uptime++ = '\0';
	clients = strchr(uptime, ' ');
	*clients++ = '\0';
	arv = strchr(clients, ' ');
	*arv++ = '\0';

	if ((of = strchr(arv, ' ')) != NULL) {
		*of++ = '\0';

		if ((cap = strchr(of, ' ')) != NULL)
			*cap++ = '\0';
		else
			cap = "";
	} else {
		of = cap = "";
	}

	(void) snprintf(
		buffer, sizeof (buffer),
		"la=" MCC_FMT_V " ut=%s tc=%s arv=%s of=%s cap=%s",
		MCC_FMT_V_ARG(row), uptime, clients, arv, of, cap
	);

	mccNotesUpdate(ip, "la=", buffer);
}

static mcc_key_hook cache_loadavg_hook = {
	NULL,
	"__loadavg", sizeof ("__loadavg")-1,
	cache_loadavg_process,
	NULL
};

void
cacheInit(void)
{
	char buffer[1024];

#ifdef SEE_VERBOSE_INIT
	verboseRegister(&verb_cache);
	mccSetDebug(verb_cache.option.value);
#endif

#ifdef NO_LONGER_USED
	switch (tolower(optCacheOnCorrupt.string[0])) {
	case 'e':
		mccSetOnCorrupt(MCC_ON_CORRUPT_EXIT);
		break;
	case 'r':
		switch (tolower(optCacheOnCorrupt.string[0])) {
		case 'n':
			mccSetOnCorrupt(MCC_ON_CORRUPT_RENAME);
			break;
		case 'p':
			mccSetOnCorrupt(MCC_ON_CORRUPT_REPLACE);
			break;
		}
	}
#endif
	if (mccInit(optCachePath.string, &grey_cache_hooks) == MCC_ERROR) {
		syslog(LOG_ERR, LOG_NUM(172) "cache-path=%s open error: %s (%d)", optCachePath.string, strerror(errno), errno);
/*{LOG
The cache database could not be opened. Check the <code>cache.sq3</code> file <a href="install.html#unix_permissions">permissions &amp; ownership</a>
}*/
		exit(1);
	}

#ifdef NO_LONGER_USED
	if (mccSetSyncByName(mcc, optCacheSyncMode.string) != MCC_OK) {
		syslog(LOG_ERR, LOG_NUM(173) "cache-sync-mode=%s error", optCacheSyncMode.string);
/*{LOG
An invalid value was specified for this option.
}*/
		exit(1);
	}
#endif
	mccRegisterKey(&cache_loadavg_hook);

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(mccAtForkPrepare, mccAtForkParent, mccAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	if (pathSetPermsByName(optCachePath.string, optRunUser.string, optRunGroup.string, 0664) && errno != ENOENT)
		exit(1);

	snprintf(buffer, sizeof (buffer), "%s-journal", optCachePath.string);
	(void) pathSetPermsByName(buffer, optRunUser.string, optRunGroup.string, 0664);

	if (*optCacheSecret.string != '\0')
		(void) mccSetSecret(optCacheSecret.string);

	if (*opt_cache_hosts.string != '\0') {
		Vector unicast_list;

		if ((unicast_list = TextSplit(opt_cache_hosts.string, OPTION_LIST_DELIMS, 0)) == NULL) {
			syslog(LOG_ERR, LOG_NUM(176) "cache-hosts error: %s (%d)", strerror(errno), errno);
/*{NEXT}*/
			exit(1);
		}

		if (mccStartListener((const char **) VectorBase(unicast_list), opt_cache_port.value)) {
			syslog(LOG_ERR, LOG_NUM(177) "cache-hosts error: %s (%d)", strerror(errno), errno);
/*{LOG
An error in parsing the option or starting the cache listener thread.
See <a href="summary.html#opt_cache_hosts">cache-hosts</a>.
}*/
			VectorDestroy(unicast_list);
			exit(1);
		}

		VectorDestroy(unicast_list);

		if (mccSetMulticastTTL(optCacheMulticastTTL.value))
			exit(1);
	}
}

int
cacheGc(Session *null, va_list args)
{
	time_t *now;
	mcc_handle *mcc;

	LOG_TRACE0(176, cacheGc);

	mcc = va_arg(args, mcc_handle *);
	now = va_arg(args, time_t *);

	(void) mccExpireRows(mcc, now);

	return SMTPF_CONTINUE;
}

void
cacheGetTime(uint32_t *seconds, char *buffer, size_t size)
{
	struct tm local;
	time_t timestamp;

	/* Convert 32-bit timestamp to possibly 64-bit time_t. */
	timestamp = (time_t) *seconds;
	(void) localtime_r(&timestamp, &local);
	(void) getRFC2821DateTime(&local, buffer, size);
}

int
cacheCommand(Session *sess)
{
	time_t now;
	Reply *reply;
	Vector active;
	unsigned long ticks;
	int key_len, value_len;
	char *cmd, *key, *value;
	mcc_active_host **cache;
	mcc_row old_row, new_row;
	char cstamp[TIME_STAMP_MIN_SIZE], estamp[TIME_STAMP_MIN_SIZE];
	mcc_handle *mcc = ((Worker *) sess->session->worker->data)->mcc;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
		return cmdUnknown(sess);

	reply = NULL;
	statsCount(&stat_admin_commands);

	/* Format of commands:
	 *
	 *	CACHE G[ET] key
	 *	CACHE P[UT] key value
	 *	CACHE D[ELETE] key
	 */

	/* Find start of command. */
	cmd = sess->input + sizeof ("CACHE")-1 + strspn(sess->input + sizeof ("CACHE")-1, " ");

	/* Find start and length of key. */
	key = cmd + strcspn(cmd, " ");
	key += strspn(key, " ");
	key_len = strcspn(key, " ");
	value_len = strspn(key + key_len, " ");
	key[key_len] = '\0';

	mccSetKey(&new_row, "%s", key);

	/* Find start and length of value. */
	value = key + key_len + value_len;
	if (*value != '\0') 
		mccSetValue(&new_row, "%s", value);

	switch (toupper(*cmd)) {
	default:
		reply = replyFmt(SMTPF_REJECT, "214-2.0.0 CACHE ACTIVE\r\n");
		reply = replyAppendFmt(reply,  "214-2.0.0 CACHE GET key\r\n");
		reply = replyAppendFmt(reply,  "214-2.0.0 CACHE PUT key value\r\n");
		reply = replyAppendFmt(reply,  "214-2.0.0 CACHE DELETE key\r\n");
		reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));
		goto error0;

	case 'A': /* ACTIVE */
		if ((active = mccGetActive()) == NULL) {
			reply = replyFmt(SMTPF_REJECT, "510 5.0.0 ACTIVE error\r\n");
			break;
		}

		(void) time(&now);
		reply = replyMsg(SMTPF_CONTINUE, "", 0);
		for (cache = (mcc_active_host **) VectorBase(active); *cache != NULL; cache++) {
			long td;
			mcc_string *notes;

			td = 0;
			notes = mccNotesFind((*cache)->notes, "td=");
			if (notes != NULL)
				td = strtol(strstr(notes->string, "td=")+sizeof("td=")-1, NULL, 10);

			ticks = (*cache)->touched / MCC_TICK;

			reply = replyAppendFmt(
				reply,
				"211-2.0.0 ip=%s age=%lu ppm=%lu max-ppm=%lu",
				(*cache)->ip,
				(unsigned long) (now - (*cache)->touched) - td,
				mccGetRate((*cache)->intervals, ticks),
				(*cache)->max_ppm
			);

			/* Append the notes to the reply line and truncate if necessary. */
			for (notes = (*cache)->notes; notes != NULL; notes = notes->next)
				reply = replyAppendFmt(reply, " %s", notes->string);
			if (SMTP_REPLY_LINE_LENGTH-2 <= reply->length)
				reply->string[SMTP_REPLY_LINE_LENGTH-2] = '\0';

			reply = replyAppendFmt(reply, "\r\n", reply->string);
		}

		reply = replyAppendFmt(reply, "211 2.0.0 end\r\n");
		VectorDestroy(active);
		break;

	case 'G': /* GET */
	case 'P': /* PUT */
	case 'D': /* DELETE */
		switch (mccGetKey(mcc, MCC_PTR_K(&new_row), MCC_GET_K_SIZE(&new_row), &old_row)) {
		case MCC_OK:
			/* Create a blank reply. */
			reply = replyMsg(SMTPF_CONTINUE, "", 0);

			cacheGetTime(&old_row.created, cstamp, sizeof (cstamp));
			cacheGetTime(&old_row.expires, estamp, sizeof (estamp));

			/* Append a reply that might be longer than
			 * SMTP_REPLY_LINE_LENGTH bytes. Not fond of
			 * breaking SMTP limits, but this command
			 * would only be used by non-SMTP clients
			 * which will allow for larger reply strings.
			 */
			reply = replyAppendFmt(
				reply,
				"211 2.0.0 k=\"%.*s\" d=\"%.*s\" t=%lu c=0x%lx (%s) e=0x%lx (%s)\r\n",
				LOG_CACHE_GET(&old_row), old_row.ttl, 
				(long) old_row.created, cstamp,
				(long) old_row.expires, estamp
			);
			break;

		case MCC_ERROR:
			reply = replyFmt(SMTPF_REJECT, "510 5.0.0 GET error\r\n");
			goto error0;

		case MCC_NOT_FOUND:
			reply = replyFmt(SMTPF_CONTINUE, "210 2.0.0 key not found\r\n");
			if (toupper(*cmd) == 'G')
				goto error0;
		}
		break;
	}

	switch (toupper(*cmd)) {
	case 'P': /* PUT */
		new_row.ttl = cacheGetTTL(*MCC_PTR_V(&new_row)-'0');
		new_row.expires = time(NULL) + new_row.ttl;
		new_row.created = old_row.created;

		switch (mccPutRow(mcc, &new_row)) {
		case MCC_OK:
			free(reply);

			/* Create a blank reply. */
			reply = replyMsg(SMTPF_CONTINUE, "", 0);

			cacheGetTime(&new_row.created, cstamp, sizeof (cstamp));
			cacheGetTime(&new_row.expires, estamp, sizeof (estamp));

			/* Append a reply that might be longer than
			 * SMTP_REPLY_LINE_LENGTH bytes. Not fond of
			 * breaking SMTP limits, but this command
			 * would only be used by non-SMTP clients
			 * which will allow for larger reply strings.
			 */
			reply = replyFmt(
				SMTPF_CONTINUE,
				"211 2.0.0 k=\"%.*s\" d=\"%.*s\" t=%lu c=0x%lx (%s) e=0x%lx (%s)\r\n",
				LOG_CACHE_GET(&new_row), new_row.ttl, 
				(long) new_row.created, cstamp,
				(long) new_row.expires, estamp
			);
			break;
		case MCC_ERROR:
			reply = replyFmt(SMTPF_REJECT, "510 5.0.0 PUT error\r\n");
			break;
		}
		break;

	case 'D': /* DELETE */
		if (mccDeleteRow(mcc, &new_row) == MCC_ERROR) {
			free(reply);
			reply = replyFmt(SMTPF_REJECT, "510 5.0.0 DELETE error\r\n");
			break;
		}
		break;
	}
error0:
	if (reply == NULL)
		replyInternalError(sess, FILE_LINENO);
	return replyPush(sess, reply);
}

