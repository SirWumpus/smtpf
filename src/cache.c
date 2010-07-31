/*
 * cache.c
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

mcc_handle *mcc;

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

#define PHONE_HOME
#ifdef PHONE_HOME
/*** REMOVAL OF THIS CODE IS IN VIOLATION
 *** OF THE TERMS OF THE SOFTWARE LICENSE.
 ***/
void *
licenseControl(void *data)
{
	FILE *fp;
	char *host;
	SMTP2 *smtp;
	mcc_row row;
	ssize_t nbytes;
	mcc_handle *mcc = data;
	char timestamp[40];
	int days = 31;

	if ((host = strchr(PHONE_HOME_MAIL, '@')) == NULL)
		goto error0;

	MEMSET(&row, 0, sizeof (row));
	row.key_size = snprintf((char *) row.key_data, sizeof (row.key_data), "rcpt:%s", PHONE_HOME_MAIL);

	if (mccGetRow(mcc, &row) == MCC_OK)
		goto error0;

	/* Try to connect directly. */
	if ((smtp = smtp2OpenMx(++host, optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, 0)) == NULL) {
		Vector hosts;
		char **table;

		/* Find the local route to queue on. */
		if ((hosts = routeGetLocalHosts()) == NULL)
			goto error0;

		/* Try to connect to one of the local routes. */
		for (table = (char **) VectorBase(hosts); *table != NULL; table++) {
			if ((smtp = smtp2Open(*table, optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, 0)) != NULL)
				break;
		}

		VectorDestroy(hosts);

		if (smtp == NULL)
			goto error1;
	}

	if (smtp2Mail(smtp, "") != SMTP_OK || smtp2Rcpt(smtp, PHONE_HOME_MAIL) != SMTP_OK) {
		(void) smtp2Rset(smtp);
		if (smtp2Mail(smtp, "") != SMTP_OK)
			goto error2;
		if (smtp2Rcpt(smtp, PHONE_HOME_MAIL) != SMTP_OK)
			goto error2;
	}

	/* Build message headers. */
	TimeStamp(&smtp->start, timestamp, sizeof (timestamp));
	(void) smtp2Printf(smtp, "Date: %s\r\n", timestamp);
	(void) smtp2Printf(smtp, "To: \"SnertSoft\" <%s>\r\n", PHONE_HOME_MAIL);
	(void) smtp2Printf(smtp, "From: \"%s\" <%s>\r\n", lickeyClientName.string, lickeyClientMail.string);
	(void) smtp2Printf(smtp, "Subject: %s %s-%s\r\n", lickeyClientName.string, _NAME, _VERSION);
	(void) smtp2Printf(smtp, "Message-ID: <%s@[%s]>\r\n", smtp->id_string, smtp->local_ip);
	(void) smtp2Printf(smtp, "Priority: normal\r\n");
	(void) smtp2Printf(smtp, "User-Agent: " _NAME "-" _VERSION "\r\n");
	(void) smtp2Printf(smtp, "\r\n");

	/* Get copy of lickey.txt. */
	if ((fp = fopen(optLicenseKeyFile.string, "r")) == NULL)
		goto error2;

	while (0 < (nbytes = fread(smtp->text, 1, sizeof (smtp->text), fp)))
		(void) smtp2Print(smtp, smtp->text, nbytes);

	if (ferror(fp))
		goto error3;

	if (smtp2Dot(smtp) != SMTP_OK)
		goto error3;

	/* Success. No follow-up for a year. */
	days = 365;
error3:
	fclose(fp);
error2:
	smtp2Close(smtp);
error1:
	/* Remember that this message has been sent. */
	row.hits = 0;
	row.created = time(NULL);
	row.expires = row.created + days * 86400;
	row.key_size = snprintf((char *) row.key_data, sizeof (row.key_data), "rcpt:%s", PHONE_HOME_MAIL);
	row.value_size = (unsigned char) snprintf((char *) row.value_data, sizeof (row.value_data), "%d", SMTPF_ACCEPT);
	(void) mccPutRowLocal(mcc, &row, 0);
error0:
	return NULL;
}
#endif

#ifdef OLD_GC_THREAD
pthread_t gc_thread;
static int gc_thread_created;
static int cache_is_gc_running;

int
cacheIsGcRunning(void)
{
	return cache_is_gc_running;
}

/*
 * This is an independent timer thread used to garbadge collect
 * expired cache records and periodically save statistic counters.
 */
static void *
cache_gc_thread(void *data)
{
	time_t now, when;
	mcc_handle *mcc = data;

	for (when = time(NULL);	; ) {
		if (when <= (now = time(NULL))) {
			TIMER_DECLARE(section);
			TIMER_DECLARE(overall);

			cache_is_gc_running = 1;

			if (verb_timers.option.value) {
				TIMER_START(overall);
				TIMER_START(section);
			}

			if (verb_cache.option.value)
				syslog(LOG_DEBUG, LOG_NUM(165) "garbage collecting cache");

			(void) filterRun(NULL, filter_cache_gc_table, mcc, &now);

			/* Reset the time now in case of a long gc run. */
			when = now + optCacheGcInterval.value;

			if (verb_timers.option.value) {
				TIMER_DIFF(section);
				if (TIMER_GE_CONST(diff_section, 1, 0) || 1 < verb_timers.option.value)
					syslog(LOG_DEBUG, LOG_NUM(166) "cache gc time-elapsed=" TIMER_FORMAT, TIMER_FORMAT_ARG(diff_section));
				TIMER_START(section);
			}

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
#ifdef PHONE_HOME
			/*** REMOVAL OF THIS CODE IS IN VIOLATION
			 *** OF THE TERMS OF THE SOFTWARE LICENSE.
			 ***/
			(void) licenseControl(data);
#endif
			cache_is_gc_running = 0;

			lickeyHasExpired();
			lickeySendWarning();

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
		pthreadSleep(when - now, 0);
	}

	freeThreadData();
#ifdef __WIN32__
	pthread_exit(NULL);
#endif
	return NULL;
}

void
cacheGcStart(void)
{
	int rc;
	pthread_attr_t *pthread_attr_ptr = NULL;

#if defined(HAVE_PTHREAD_ATTR_INIT)
{
	pthread_attr_t pthread_attr;

	if (pthread_attr_init(&pthread_attr)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}

# if defined(HAVE_PTHREAD_ATTR_SETSCOPE)
	(void) pthread_attr_setscope(&pthread_attr, PTHREAD_SCOPE_SYSTEM);
# endif
# if defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	(void) pthread_attr_setstacksize(&pthread_attr, THREAD_STACK_SIZE);
# endif
	pthread_attr_ptr = &pthread_attr;
}
#endif
	rc = pthread_create(&gc_thread, pthread_attr_ptr, cache_gc_thread, (void *) mcc);

#if defined(HAVE_PTHREAD_ATTR_INIT)
	if (pthread_attr_ptr != NULL)
		(void) pthread_attr_destroy(pthread_attr_ptr);
#endif
	if (rc != 0) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "gc thread start", strerror(errno), errno);
		exit(1);
	}

	pthread_detach(gc_thread);
	gc_thread_created = 1;
}

void
cacheFini(void)
{
	if (gc_thread_created)
		pthread_cancel(gc_thread);
	mccDestroy(mcc);
}

#else
Timer *gc_timer;

static void
cacheGcThread(Timer *timer)
{
	time_t now;
	TIMER_DECLARE(section);
	TIMER_DECLARE(overall);

	if (verb_timers.option.value) {
		TIMER_START(overall);
		TIMER_START(section);
	}

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, LOG_NUM(165) "garbage collecting cache");

	/* Reset the timer period in case the option was updated. */
	timer->period.tv_sec = optCacheGcInterval.value;

	(void) time(&now);
	(void) filterRun(NULL, filter_cache_gc_table, mcc, &now);

	if (verb_timers.option.value) {
		TIMER_DIFF(section);
		if (TIMER_GE_CONST(diff_section, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_NUM(166) "cache gc time-elapsed=" TIMER_FORMAT, TIMER_FORMAT_ARG(diff_section));
		TIMER_START(section);
	}

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
#ifdef PHONE_HOME
	/*** REMOVAL OF THIS CODE IS IN VIOLATION
	 *** OF THE TERMS OF THE SOFTWARE LICENSE.
	 ***/
	(void) licenseControl(mcc);
#endif
	lickeyHasExpired();
	lickeySendWarning();

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

	if ((gc_timer = timerCreate(cacheGcThread, NULL, &period, 32 * 1024)) == NULL) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
}

void
cacheFini(void)
{
	timerFree(gc_timer);
	mccDestroy(mcc);
}

#endif


#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
cacheAtForkPrepare(void)
{
	mccAtForkPrepare(mcc);
}

void
cacheAtForkParent(void)
{
	mccAtForkParent(mcc);
}

void
cacheAtForkChild(void)
{
	mccAtForkChild(mcc);
}
#endif

int
cacheRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_cache);

	optionsRegister(&optCacheAcceptTTL, 0);
	optionsRegister(&optCacheGcInterval, 0);
	optionsRegister(&optCacheMulticastIp, 1);
	optionsRegister(&optCacheMulticastPort, 1);
	optionsRegister(&optCacheMulticastTTL, 1);
	optionsRegister(&optCacheOnCorrupt, 1);
	optionsRegister(&optCachePath, 1);
	optionsRegister(&optCacheRejectTTL, 0);
	optionsRegister(&optCacheSecret, 0);
	optionsRegister(&optCacheSyncMode, 1);
	optionsRegister(&optCacheTempFailTTL, 0);
#if !defined(ENABLE_PDQ)
	optionsRegister(&optCacheUnicastDomain, 1);
#endif
	optionsRegister(&optCacheUnicastHosts, 1);
	optionsRegister(&optCacheUnicastPort, 1);

	return SMTPF_CONTINUE;
}

static void
cache_loadavg_process(mcc_context *mcc, mcc_key_hook *hook, const char *ip, mcc_row *row)
{
	char buffer[128], *uptime, *clients, *arv, *of, *cap;

	row->value_data[row->value_size] = '\0';
	uptime = strchr((char *) row->value_data, ' ');
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
		"la=%s ut=%s tc=%s arv=%s of=%s cap=%s td=%ld",
		row->value_data, uptime, clients, arv, of, cap,
		(long) (time(NULL) - (time_t) row->touched)
	);

	mccNotesUpdate(mcc, ip, "la=", buffer);
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

	if ((mcc = mccCreate(optCachePath.string, 0, &grey_cache_hooks)) == NULL) {
		syslog(LOG_ERR, LOG_NUM(172) "cache-path=%s open error: %s (%d)", optCachePath.string, strerror(errno), errno);
/*{LOG
The cache database could not be opened. Check the <code>cache.sq3</code> file <a href="install.html#unix_permissions">permissions &amp; ownership</a>
}*/
		exit(1);
	}

	if (mccSetSyncByName(mcc, optCacheSyncMode.string) != MCC_OK) {
		syslog(LOG_ERR, LOG_NUM(173) "cache-sync-mode=%s error", optCacheSyncMode.string);
/*{LOG
An invalid value was specified for this option.
}*/
		exit(1);
	}

	mccRegisterKey(mcc, &cache_loadavg_hook);

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(cacheAtForkPrepare, cacheAtForkParent, cacheAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	if (pathSetPermsByName(optCachePath.string, optRunUser.string, optRunGroup.string, 0664))
		exit(1);

	snprintf(buffer, sizeof (buffer), "%s-journal", optCachePath.string);
	(void) pathSetPermsByName(buffer, optRunUser.string, optRunGroup.string, 0664);

	if (*optCacheSecret.string != '\0')
		(void) mccSetSecret(mcc, optCacheSecret.string);

	if (*optCacheMulticastIp.string != '\0') {
		if (mccStartMulticast(mcc, optCacheMulticastIp.string, optCacheMulticastPort.value))
			exit(1);
		if (mccSetMulticastTTL(mcc, optCacheMulticastTTL.value))
			exit(1);
	}

#if !defined(ENABLE_PDQ)
	if (*optCacheUnicastDomain.string != '\0' && *optCacheUnicastHosts.string != '\0') {
		syslog(LOG_ERR, LOG_NUM(174) "cache-unicast-domain and cache-unicast-hosts are mutually exclusive options");
/*{LOG
Check the @PACKAGE_NAME@.cf file. Specify either
<a href="summary.html#opt_cache_unicast_domain">cache-unicast-domain</a> or
<a href="summary.html#opt_cache_unicast_hosts">cache-unicast-hosts</a>, but
not both.
}*/
		exit(1);
	} else if (*optCacheUnicastDomain.string != '\0' && mccStartUnicastDomain(mcc, optCacheUnicastDomain.string, optCacheUnicastPort.value)) {
		syslog(LOG_ERR, LOG_NUM(175) "cache-unicast-domain error: %s (%d)", strerror(errno), errno);
/*{NEXT}*/
		exit(1);
	} else
#endif
	if (*optCacheUnicastHosts.string != '\0') {
		Vector unicast_list;

		if ((unicast_list = TextSplit(optCacheUnicastHosts.string, OPTION_LIST_DELIMS, 0)) == NULL) {
			syslog(LOG_ERR, LOG_NUM(176) "cache-unicast-hosts error: %s (%d)", strerror(errno), errno);
/*{NEXT}*/
			exit(1);
		}

		if (mccStartUnicast(mcc, (const char **) VectorBase(unicast_list), optCacheUnicastPort.value)) {
			syslog(LOG_ERR, LOG_NUM(177) "cache-unicast-hosts error: %s (%d)", strerror(errno), errno);
/*{LOG
An error in parsing the option or starting the unicast cache listener thread.
See <a href="summary.html#opt_cache_unicast_domain">cache-unicast-domain</a> or <a href="summary.html#opt_cache_unicast_hosts">cache-unicast-hosts</a>.
}*/
			VectorDestroy(unicast_list);
			exit(1);
		}

		VectorDestroy(unicast_list);
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
	char cstamp[40], tstamp[40], estamp[40];

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
	new_row.key_size = TextCopy((char *) new_row.key_data, sizeof (new_row.key_data), key);

	/* Find start and length of value. */
	value = key + key_len + value_len;
	if (*value != '\0') {
		value_len = strlen(value);
		value[value_len] = '\0';
		new_row.value_size = TextCopy((char *) new_row.value_data, sizeof (new_row.value_data), value);
	}

	switch (toupper(*cmd)) {
	default:
		reply = replyFmt(SMTPF_REJECT, "214-2.0.0 CACHE ACTIVE\r\n");
		reply = replyAppendFmt(reply,  "214-2.0.0 CACHE GET key\r\n");
		reply = replyAppendFmt(reply,  "214-2.0.0 CACHE PUT key value\r\n");
		reply = replyAppendFmt(reply,  "214-2.0.0 CACHE DELETE key\r\n");
		reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));
		goto error0;

	case 'A': /* ACTIVE */
		if ((active = mccGetActive(mcc)) == NULL) {
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
		switch (mccGetKey(mcc, new_row.key_data, new_row.key_size, &old_row)) {
		case MCC_OK:
			old_row.key_data[old_row.key_size] = '\0';
			old_row.value_data[old_row.value_size] = '\0';

			/* Create a blank reply. */
			reply = replyMsg(SMTPF_CONTINUE, "", 0);

			cacheGetTime(&old_row.created, cstamp, sizeof (cstamp));
			cacheGetTime(&old_row.touched, tstamp, sizeof (tstamp));
			cacheGetTime(&old_row.expires, estamp, sizeof (estamp));

			/* Append a reply that might be longer than
			 * SMTP_REPLY_LINE_LENGTH bytes. Not fond of
			 * breaking SMTP limits, but this command
			 * would only be used by non-SMTP clients
			 * which will allow for larger reply strings.
			 */
			reply = replyAppendFmt(
				reply,
				"211 2.0.0 k=\"%s\" d=\"%s\" h=%lu c=0x%lx (%s) t=0x%lx (%s) e=0x%lx (%s)\r\n",
				old_row.key_data, old_row.value_data,
				old_row.hits,
				(long) old_row.created, cstamp,
				(long) old_row.touched, tstamp,
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

			old_row.hits = 0;
			old_row.created = time(NULL);
			old_row.touched = old_row.created;
		}
		break;
	}

	switch (toupper(*cmd)) {
	case 'P': /* PUT */
		new_row.hits = old_row.hits;
		new_row.created = old_row.created;
		new_row.touched = old_row.touched;
		new_row.expires = new_row.touched + cacheGetTTL(*new_row.value_data-'0');

		switch (mccPutRow(mcc, &new_row)) {
		case MCC_OK:
			free(reply);

			/* Create a blank reply. */
			reply = replyMsg(SMTPF_CONTINUE, "", 0);

			cacheGetTime(&new_row.created, cstamp, sizeof (cstamp));
			cacheGetTime(&new_row.touched, tstamp, sizeof (tstamp));
			cacheGetTime(&new_row.expires, estamp, sizeof (estamp));

			/* Append a reply that might be longer than
			 * SMTP_REPLY_LINE_LENGTH bytes. Not fond of
			 * breaking SMTP limits, but this command
			 * would only be used by non-SMTP clients
			 * which will allow for larger reply strings.
			 */
			reply = replyFmt(
				SMTPF_CONTINUE,
				"211 2.0.0 k=\"%s\" d=\"%s\" h=%lu c=0x%lx (%s) t=0x%lx (%s) e=0x%lx (%s)\r\n",
				new_row.key_data, new_row.value_data,
				new_row.hits,
				(long) new_row.created, cstamp,
				(long) new_row.touched, tstamp,
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

