/*
 * lickey.c
 *
 * Copyright 2006 by Anthony Howe. All rights reserved.
 */

#ifndef LICKEY_1ST_WARNING
#define LICKEY_1ST_WARNING	30
#endif

#ifndef LICKEY_2ND_WARNING
#define LICKEY_2ND_WARNING	5
#endif

#ifndef LICKEY_LAST_WARNING
#define LICKEY_LAST_WARNING	1
#endif

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#include <com/snert/lib/io/Log.h>
#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/sys/process.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/util/convertDate.h>
#include <com/snert/lib/mail/smtp2.h>

#ifdef __WIN32__
/*
 * _PLATFORM might be "CYGWIN", but we really mean Windows.
 */
# undef _PLATFORM
# define _PLATFORM	"Windows"

# include <ws2tcpip.h>
#endif

/***********************************************************************
 ***
 ***********************************************************************/

int output_all_fields;

/* Any default value that is an empty string "", is required to be set.
 * For historical reasons, values with "?", while optional were still
 * included in the hashing. In order to introduce new optional fields
 * without having to issue new license keys, any value of "~" is ignored
 * unless otherwise set differently.
 *
 * This can only be changed on a major version upgrade..
 */
Option lickeyClientName 	= { "client-name",	"",		"Name of licensed client." };
Option lickeyClientMail 	= { "client-mail",	"",		"Mail address of licensed client." };
Option lickeyComments		= { "comment",		"?",		"Single line of remarks, notes, info." };
Option lickeyCorePerIpList	= { "core-per-ip-list",	"",		"Comma separated list of number of cores/IP." };
Option lickeyDateIssued		= { "date-issued",	"?",		"Date license was issued." };
Option lickeyDateExpires	= { "date-expires",	"",		"Date license will expire. Empty string for unlimited." };
Option lickeyHwMachine		= { "hw-machine",	"?",		"The machine class." };
Option lickeyHwModel		= { "hw-model",		"?",		"The machine model." };
Option lickeyHwProduct		= { "hw-product",	"?",		"The product name of the machine." };
Option lickeyHwVendor		= { "hw-vendor",	"?",		"The vendor name for this machine." };
Option lickeyHwVersion		= { "hw-version",	"?",		"The version or revision of this machine." };
Option lickeyHwSerialNo		= { "hw-serialno",	"?",		"The serial number of the machine." };
Option lickeyHwUuid		= { "hw-uuid",		"~",		"The universal unique id of the machine." };
Option lickeyProcessName	= { "process-name",	_NAME,		"Process name of software licensed." };
Option lickeyProcessVersion	= { "process-version",	_VERSION,	"Version of licensed software." };
Option lickeyGeneratedBy	= { "generated-by",	"",		"Who issued the license key." };
Option lickeyKeycode		= { "keycode",		"",		"Hex string" /* " of concatenated index octet pairs." */ };
Option lickeyHash		= { "hash",		"?",		"Hex string of license hash." };
Option lickeyMaxDomains		= { "max-domains",	"?",		"Maximum number of domains license will allow." };
Option lickeyResellerName	= { "reseller-name",	"?",		"Name of vendor." };
Option lickeyResellerMail	= { "reseller-mail",	"~",		"Mail address of vendor." };
Option lickeySupportMail	= { "support-mail",	"~",		"Mail address of technical support." };
Option lickeyPlatform		= { "platform",		"~",		"OS platform" };
#ifdef ENABLE_LINT
Option lickeyLint		= { "lint",		"~",		"Set to 1 to allow lint option." };
#endif
Option lickeyHttpRealm		= { "http-realm",	"~",		"HTTP realm for restricted access." };
Option lickeyHttpUser		= { "http-user",	"~",		"HTTP user name for restricted access." };
Option lickeyHttpPass		= { "http-pass",	"~",		"HTTP password for restricted access." };


Option *lickeyTable[] = {
	&lickeyClientName,
	&lickeyClientMail,
	&lickeyCorePerIpList,
	&lickeyComments,
	&lickeyDateIssued,
	&lickeyDateExpires,
	&lickeyHwMachine,
	&lickeyHwModel,
	&lickeyHwProduct,
	&lickeyHwSerialNo,
	&lickeyHwUuid,
	&lickeyHwVendor,
	&lickeyHwVersion,
	&lickeyProcessName,
	&lickeyProcessVersion,
	&lickeyGeneratedBy,
	&lickeyKeycode,
	&lickeyHash,
	&lickeyMaxDomains,
	&lickeyResellerName,
	&lickeyResellerMail,
	&lickeySupportMail,
	&lickeyPlatform,
#ifdef ENABLE_LINT
	&lickeyLint,
#endif
	&lickeyHttpRealm,
	&lickeyHttpUser,
	&lickeyHttpPass,
	NULL
};

/* Keep original usage messages for license keys.
 */
static Option optRFC2821Syntax = { "rfc2821-syntax", "+", "Strict RFC 2821 grammar for mail addresses." };
extern Option optInterfaceIp;
extern Option optInterfaceName;


/* We keep an independent list of options that won't be affected by
 * additions or deletions to optTable. However, we are still subject
 * to changes in usage description, which would mean any change in
 * a 1.0 usage text, requires keeping the old copy at hand for use
 * with lickey.
 *
 * Deal with that problem when it comes up.
 */
Option *lickeyOptTable[] = {
	&optSyntax,

	&optAccessMap,
	&optAuthDelayChecks,
	&optCacheAcceptTTL,
	&optCacheGcInterval,
	&optCacheMulticastIp,
	&optCacheMulticastPort,
	&optCachePath,
	&optCacheRejectTTL,
	&optCacheSecret,
	&optCacheTempFailTTL,
	&optCacheUnicastDomain,
	&optCacheUnicastPort,
	&optClientIpInPtr,
	&optClientIsMx,
	&optClientPtrRequired,
	&optDaemon,
	&optFile,
	&optHeloClaimsUs,
	&optHeloIpMismatch,
	&optHelp,
	&optIdleRetestTimer,
	&optInterfaceIp,
	&optInterfaceName,
	&optLicenseKeyFile,
	&optOneRcptPerNull,
	&optQuit,
	&optRejectPercentRelay,
	&optRejectQuotedAtSign,
	&optRejectUnknownTLD,
	&optRejectUucpRoute,
	&optRelayReply,
	&optMailRequireMx,
	&optRestart,
	&optRFC2606SpecialDomains,
	&optRFC2821DomainLength,
	&optRFC2821LineLength,
	&optRFC2821LiteralPlus,
	&optRFC2821LocalLength,
	&optRFC2821StrictDot,
	&optRFC2821StrictHelo,
	&optRFC2821Syntax,
	&optRFC28227bitHeaders,
	&optRouteMap,
	&optRunGroup,
	&optRunJailed,
	&optRunOpenFileLimit,
	&optRunPidFile,
	&optRunUser,
	&optRunWorkDir,
	&optService,
	&optSmtpCommandPause,
	&optSmtpCommandTimeout,
	&optSmtpConnectTimeout,
	&optSmtpDataLineTimeout,
	&optSmtpDropAfter,
	&optSmtpDropUnknown,
	&optSmtpDsnReplyTo,
	&optSmtpEnableEsmtp,
	&optSmtpGreetPause,
	&optSmtpRejectDelay,
	&optSmtpRejectFile,
	&optSmtpServerQueue,
	&optSmtpWelcomeFile,
	&optStatsMap,

	NULL
};

Option *cmdOptTable[] = {
	&optFile,
	NULL
};

Stats stat_route_accounts	= { STATS_TABLE_GENERAL, "route-accounts", 1 };
Stats stat_route_addresses	= { STATS_TABLE_GENERAL, "route-addresses", 1 };
Stats stat_route_domains	= { STATS_TABLE_GENERAL, "route-domains", 1 };

/***********************************************************************
 ***
 ***********************************************************************/

static void *
lickeyMailWarning(void *data)
{
	Mail *mail;
	int days, flags;
	Option **opt, *o;
	char timestamp[40], sender[SMTP_PATH_LENGTH],  host[DOMAIN_STRING_LENGTH];

	/* This is a NO-NO, but I'm too lazy to allocate memory for an int. */
	days = (int) data;

	flags = SMTP_FLAG_TRY_ALL;
	if (verb_info.option.value)
		flags |= SMTP_FLAG_LOG;
	if (verb_smtp.option.value)
		flags |= SMTP_FLAG_DEBUG;

	if ((mail = mailOpen(optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, flags)) == NULL)
		goto error0;

	networkGetMyName(host);
	(void) snprintf(sender, sizeof (sender), "%s@%s", lickeyProcessName.string, host);
	if (mailMail(mail, sender) != SMTP_OK)
		goto error1;

	/* If all of these fail then all the DATA commands SHOULD fail. */
	(void) mailRcpt(mail, lickeyClientMail.string);
	(void) mailRcpt(mail, lickeySupportMail.string);
	(void) mailRcpt(mail, lickeyResellerMail.string);

	if (mailData(mail) != SMTP_WAITING)
		goto error1;

	TimeStamp(&mail->list->start, timestamp, sizeof (timestamp));

	(void) mailPrintf(mail, "Date: %s\r\n", timestamp);
	(void) mailPrintf(mail, "From: \"%s\" <%s>\r\n", lickeyClientName.string, lickeyClientMail.string);
	(void) mailPrintf(mail, "Sender: \"%s\" <%s>\r\n", lickeyProcessName.string, sender);
	(void) mailPrintf(mail, "Subject: %s license key expires in less than %d day%s\r\n", _NAME, days, days <= 1 ? "" : "s");
	(void) mailPrintf(mail, "Message-ID: <%s@[%s]>\r\n", mail->list->id_string, mail->list->local_ip);
	(void) mailPrintf(mail, "Priority: normal\r\n");
	(void) mailPrintf(mail, "User-Agent: lickey-" _VERSION "\r\n");
	(void) mailPrintf(mail, "\r\n");

	(void) mailPrintf(
		mail, "%s, your license key for %s-%s expires in less than %d day%s.\r\n",
		lickeyClientName.string, _NAME, _VERSION,
		days, days <= 1 ? "" : "s"
	);
	(void) mailPrintf(mail, "\r\n");
	(void) mailPrintf(mail, "----license key----\r\n");

	for (opt = lickeyTable; *opt != NULL; opt++) {
		o = *opt;
		if (o->string[0] != '?' && o->string[1] != '\0')
			(void) mailPrintf(mail, "%s=\"%s\"\r\n", o->name, o->string);
	}

	(void) mailPrintf(mail, "-------------------\r\n");
	(void) mailDot(mail);
error1:
	mailClose(mail);
error0:
	freeThreadData();
	return NULL;
}

void
lickeySendWarning(void)
{
	int days;
	char *mail;
	mcc_row row;
	pthread_t thread;
	time_t expire, now;
#if defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	pthread_attr_t thread_attr;
#endif

	if (lickeyDateExpires.string == NULL || *lickeyDateExpires.string == '\0')
		return;

	(void) convertDate(lickeyDateExpires.string, &expire, NULL);
	now = time(NULL);

	if (expire <= now + (LICKEY_LAST_WARNING * 86400))
		days = LICKEY_LAST_WARNING;
	else if (expire <= now + (LICKEY_2ND_WARNING * 86400))
		days = LICKEY_2ND_WARNING;
	else if (expire <= now + (LICKEY_1ST_WARNING * 86400))
		days = LICKEY_1ST_WARNING;
	else
		return;

	/* As we get close to the end start nagging. */
	if (days <= LICKEY_2ND_WARNING)
		syslog(LOG_WARN, LOG_NUM(395) "%s-%s license key expires in less than %d day%s", _NAME, _VERSION, days, days <= 1 ? "" : "s");

	if (lickeyClientMail.string != NULL && strchr(lickeyClientMail.string, '@') != NULL)
		mail = lickeyClientMail.string;
	else if (lickeyResellerMail.string != NULL && strchr(lickeyResellerMail.string, '@') != NULL)
		mail = lickeyResellerMail.string;
	else if (lickeySupportMail.string != NULL && strchr(lickeySupportMail.string, '@') != NULL)
		mail = lickeySupportMail.string;
	else {
		syslog(LOG_ERR, log_internal, SESSION_ID_ZERO, FILE_LINENO, "missing address", strerror(errno), errno);
		return;
	}

	row.key_size = snprintf(row.key_data, sizeof (row.key_data), "lickey:%s", mail);

	/* Check if the most recent warning has been sent. */
	if (mccGetRow(mcc, &row) == MCC_OK
	&& strtol(row.value_data, NULL, 10) <= days)
		return;

#if defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	(void) pthread_attr_init(&thread_attr);
	pthread_attr_setstacksize(&thread_attr, THREAD_STACK_SIZE);

	if (pthread_create(&thread, &thread_attr, lickeyMailWarning, (void *) days)) {
		syslog(LOG_ERR, log_internal, SESSION_ID_ZERO, FILE_LINENO, "pthread_create", strerror(errno), errno);
		return;
	}

	(void) pthread_attr_destroy(&thread_attr);
#else
	if (pthread_create(&thread, NULL, lickeyMailWarning, (void *) days)) {
		syslog(LOG_ERR, log_internal, SESSION_ID_ZERO, FILE_LINENO, "pthread_create", strerror(errno), errno);
		return;
	}
#endif
	pthread_detach(thread);

	/* Remember that this message has been sent. */
	row.hits = 0;
	row.created = time(NULL);
	row.expires = row.created + (days+1) * 86400;
	row.key_size = snprintf(row.key_data, sizeof (row.key_data), "lickey:%s", mail);
	row.value_size = (unsigned char) snprintf(row.value_data, sizeof (row.value_data), "%d", days);
	(void) mccPutRowLocal(mcc, &row, 1);
}

static const char hex_digit[] = "0123456789ABCDEF";

static void
lickeyHashParms(md5_state_t *md5)
{
	Option **opt, *o;

	for (opt = lickeyTable; *opt != NULL; opt++) {
		o = *opt;

		/* Any default value that is an empty string is required. */
		if (o != &lickeyDateExpires && *o->string == '\0' && !output_all_fields) {
			syslog(LOG_ERR, LOG_NUM(396) "license key %s must be set", o->name);
/*{NEXT}*/
			exit(3);
		}

		/* For historical reasons, values with "?", while optional
		 * were still included in the hashing. In order to introduce
		 * new optional fields without having to issue new license
		 * keys, any value of "~" is ignored.
		 */
		if (o != &lickeyHash && *o->string != '~')
			md5_append(md5, (md5_byte_t *) o->string, strlen(o->string));
	}
}

/*
 * The shared secret is derived from words within option descriptions.
 * The keycode is a hex string of concatenated index octet pairs. The
 * first octet is an option index, ignoring options without descriptions,
 * The second octet is the word index of space only separated words
 * found in the description. If an index is larger that the number of
 * options or words, then wrap to the beginning and continue.
 */
static void
lickeyHashKey(md5_state_t *md5)
{
	Option **opt;
	int m, n, span;
	const char *list, *word, *key;

	for (key = lickeyKeycode.string; *key != '\0'; key += 4) {
		/* Find option description to use. */
		m = (qpHexDigit(key[0]) << 4) | qpHexDigit(key[1]);
		for (list = NULL, opt = lickeyOptTable; 0 <= m; opt++) {
			if (*opt == NULL)
				opt = lickeyOptTable;

			if ((list = (*opt)->usage) != NULL)
				m--;
		}

		/* Find word within description. */
		word = list;
		n = (qpHexDigit(key[2]) << 4) | qpHexDigit(key[3]);
		for (span = 0; 1 < n; n--) {
			word = &word[strcspn(word, " ")];
			word = &word[strspn(word, " ")];
			if (*word == '\0')
				word = list;
		}
		span = strcspn(word, " ");

#ifdef DUMP
printf("list=[%s] word=%.10s span=%d\n", list, word, span);
#endif
		md5_append(md5, (md5_byte_t *) word, span);
	}
}


/*
 * This is an independent timer thread used to check for
 * license key expiration.
 */
void
lickeyHasExpired(void)
{
	time_t when, now;

	now = time(NULL);

	if (lickeyDateIssued.string != NULL && *lickeyDateIssued.string != '\0') {
		(void) convertDate(lickeyDateIssued.string, &when, NULL);
		if (now < when) {
			syslog(LOG_ERR, LOG_NUM(397) "license key date-issued is in the future, please check your system clock");
/*{NEXT}*/
			exit(3);
		}
	}

	if (lickeyDateExpires.string != NULL && *lickeyDateExpires.string != '\0') {
		(void) convertDate(lickeyDateExpires.string, &when, NULL);

		if (when <= now) {
			syslog(LOG_ERR, LOG_NUM(398) "license key has expired");
/*{NEXT}*/
			exit(3);
		}
	}
}

#if defined(__OpenBSD__) && defined(HAVE_SYS_SYSCTL_H)
void
lickeyCheckSysCtlString(Option *opt, int mib0, int mib1)
{
	char *string;

	if (*opt->string != '\0' && *opt->string != '?' && *opt->string != '~') {
		if ((string = getSysCtlString(mib0, mib1)) == NULL) {
			syslog(LOG_ERR, LOG_NUM(399) "license key %s error: %s (%d)", opt->name, strerror(errno), errno);
/*{NEXT}*/
			exit(3);
		}

		if (strcmp(opt->string, string) != 0) {
			syslog(LOG_ERR, LOG_NUM(400) "license key %s mismatch", opt->name);
/*{NEXT}*/
			exit(3);
		}

		free(string);
	}
}
#endif

static int
lickeyIsValid(const char *ip)
{
	int i;
	long cores;
	md5_state_t md5;
	const char *their_digest, *word;
	unsigned char our_digest[16], their_ip[IPV6_BYTE_LENGTH], our_ip[IPV6_BYTE_LENGTH];

	/* Check if the key has been tampered with. */
	md5_init(&md5);
	lickeyHashParms(&md5);
	lickeyHashKey(&md5);
	md5_finish(&md5, (md5_byte_t *) our_digest);

	their_digest = lickeyHash.string;

	/* Compare our expected result with the supplied digest. */
	for (i = 0; i < 16; i++) {
		if (*their_digest++ != hex_digit[(our_digest[i] >> 4) & 0x0F])
			break;
		if (*their_digest++ != hex_digit[our_digest[i] & 0x0F])
			break;
	}

	if (i < 16) {
		syslog(LOG_ERR, LOG_NUM(401) "license key invalid");
/*{NEXT}*/
		exit(3);
	}

	/* Get the major version number. */
	i = strtol(lickeyProcessVersion.string, NULL, 10);
	if (
#if _MAJOR == 2
/* 1.0 first sold in June 2007. 2.0 started beta
 * mid-September 2007, within 6 months of 1.0.
 * 2.1 released July 2008.
 */
	   (i != _MAJOR && i != _MAJOR-1)
#else
	   (i != _MAJOR)
#endif
	|| strcmp(_NAME, lickeyProcessName.string) != 0) {
		syslog(LOG_ERR, LOG_NUM(402) "license key not for %s/%s", _NAME, _VERSION);
/*{NEXT}*/
		exit(3);
	}

	if (*lickeyPlatform.string != '~' && strcmp(_PLATFORM, lickeyPlatform.string) != 0) {
		syslog(LOG_ERR, LOG_NUM(403) "license key not for %s", _PLATFORM);
/*{NEXT}*/
		exit(3);
	}

	lickeyHasExpired();

	if (parseIPv6(ip, our_ip) <= 0) {
		syslog(LOG_ERR, LOG_NUM(404) "invalid license key IP address [%s]", ip);
/*{NEXT}*/
		exit(3);
	}

	cores = 0;
	for (word = lickeyCorePerIpList.string; *word != '\0'; word += strspn(word, ", ")) {
		cores = strtol(word, (char **) &word, 10);

		if (*word != '/') {
			syslog(LOG_ERR, LOG_NUM(405) "lickey syntax error: %s", lickeyCorePerIpList.string);
/*{NEXT}*/
			exit(3);
		}

		if (0 < cores && 0 < parseIPv6(word+1, their_ip)) {
			if (memcmp(their_ip, our_ip, sizeof (our_ip)) == 0)
				break;

			/* For demo license we use local-host or this-host. */
			if (isReservedIPv6(their_ip, IS_IP_THIS_HOST|IS_IP_LOCALHOST))
				break;
		}

		/* Find end of core/ip pair. */
		word += strcspn(word, ", ");
	}

	if (*word == '\0') {
		syslog(LOG_ERR, LOG_NUM(406) "not licensed for IP [%s]", ip);
/*{NEXT}*/
		return 0;
	}

	if (cores <= 0 || cores < sysGetCpuCount()) {
		syslog(LOG_ERR, LOG_NUM(407) "IP [%s] not licensed for %ld cores (max. %ld)", ip, sysGetCpuCount(), cores);
/*{NEXT}*/
		exit(3);
	}

#if defined(__OpenBSD__) && defined(HAVE_SYS_SYSCTL_H)
{
# ifdef HW_MACHINE
	lickeyCheckSysCtlString(&lickeyHwMachine, CTL_HW, HW_MACHINE);
# endif
# ifdef HW_MODEL
	lickeyCheckSysCtlString(&lickeyHwModel, CTL_HW, HW_MODEL);
# endif
# ifdef HW_VENDOR
	lickeyCheckSysCtlString(&lickeyHwVendor, CTL_HW, HW_VENDOR);
# endif
# ifdef HW_PRODUCT
	lickeyCheckSysCtlString(&lickeyHwProduct, CTL_HW, HW_PRODUCT);
# endif
# ifdef HW_VERSION
	lickeyCheckSysCtlString(&lickeyHwVersion, CTL_HW, HW_VERSION);
# endif
# ifdef HW_SERIALNO
	lickeyCheckSysCtlString(&lickeyHwSerialNo, CTL_HW, HW_SERIALNO);
# endif
# ifdef HW_UUID
	lickeyCheckSysCtlString(&lickeyHwUuid, CTL_HW, HW_UUID);
# endif
}
#endif

	syslog(LOG_INFO, LOG_NUM(408) "found valid licensed IP [%s]", ip);
/*{NEXT}*/

	return 1;
}

int
lickeyLoadFile(const char *file)
{
	optionInit(lickeyTable, NULL);

	if (optionFile(file, lickeyTable, NULL)) {
		syslog(LOG_ERR, LOG_NUM(409) "license key \"%s\" load error: %s (%d)", TextNull(file), strerror(errno), errno);
/*{NEXT}*/
		return(3);
	}

	return 0;
}

int
lickeyLoadString(const char *string)
{
	optionInit(lickeyTable, NULL);
	(void) optionString(string, lickeyTable, NULL);
	return 0;
}

void
lickeyRouteCount(void)
{
	RouteCount rcount;
	unsigned long route_count;

	if (routeGetRouteCount(&rcount)) {
		syslog(LOG_ERR, LOG_NUM(410) "route count error");
/*{NEXT}*/
		exit(1);
	}

	/* max-domains is a bit of a misnomer, should have been called
	 * max-routes, but it is easier for people to think in terms of
	 * domains and in the majority of cases routing is by-domain.
	 *
	 * However, our logic counts all route: records, regardless of
	 * type, towards the license's max-domains since the same amount
	 * of work is necessary to route by-domain as by-address or
	 * by-account. Also the greater the number of route: records
	 * typically corresponds to the greater the size and complexity
	 * of mail site and thus greater demands for support.
	 */
	route_count = rcount.domains + rcount.addresses + rcount.accounts;

	if (0 < lickeyMaxDomains.value && lickeyMaxDomains.value <= route_count) {
		syslog(LOG_ERR, LOG_NUM(411) "route-map entries=%lu exceeds license key max-domains=%ld", route_count, lickeyMaxDomains.value);
/*{NEXT}*/
		exit(3);
	}

	stat_route_accounts.runtime = rcount.accounts;
	stat_route_addresses.runtime = rcount.addresses;
	stat_route_domains.runtime = rcount.domains;
}

/*
 *
 */
void
lickeyInit(Vector interfaces)
{
	long i;
	BoundIp *iface;
	char ip[IPV6_STRING_LENGTH];

	if (interfaces == NULL) {
		/* Interfaces have to "ready" before we can check
		 * the license against the IP addresses.
		 */
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(3);
	}

	if (lickeyLoadFile(optLicenseKeyFile.string))
		exit(3);

	/* For each interface we have to lookup all its IPv4 and/or
	 * IPv6 addresses and test them against the license key to
	 * find one that matches.
	 */
	for (i = 0; i < VectorLength(interfaces); i++) {
		if ((iface = VectorGet(interfaces, i)) == NULL)
			continue;

#if defined(HAVE_GETADDRINFO)
{
		struct addrinfo *answers, *ai, hints;

		memset(&hints, 0, sizeof (hints));
		hints.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(iface->name, NULL, &hints, &answers)) {
			syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
			continue;
		}

		for (ai = answers; ai != NULL; ai = ai->ai_next) {
			if (socketAddressFormatIp(ai->ai_addr, 0, ip, sizeof (ip)) <= 0)
				continue;
			if (lickeyIsValid(ip)) {
				freeaddrinfo(answers);
				return;
			}
		}

		freeaddrinfo(answers);
}
#elif defined(HAVE_GETHOSTBYNAME2)
{
		char **addr;
		struct hostent *hosts;

		if ((hosts = gethostbyname2(iface->name, iface->socket->address.sa.sa_family)) == NULL)
			continue;

		for (addr = hosts->h_addr_list; *addr != NULL; addr++) {
			if (formatIP(*addr, hosts->h_length, 0, ip, sizeof (ip)) <= 0)
				continue;
			if (lickeyIsValid(ip))
				return;
		}
}
#elif defined(HAVE_GETHOSTBYNAME)
{
		char **addr;
		struct hostent *hosts;

		if ((hosts = gethostbyname(iface->name)) == NULL)
			continue;

		for (addr = hosts->h_addr_list; *addr != NULL; addr++) {
			if (formatIP(*addr, hosts->h_length, 0, ip, sizeof (ip)) <= 0)
				continue;
			if (lickeyIsValid(ip))
				return;
		}
}
#else
# error "lickeyInit requires getaddrinfo, gethostbyname2, or gethostbyname"
#endif
	}

	exit(3);
}

#ifdef TEST
#include <stdio.h>
#include <stdlib.h>

#include <com/snert/lib/net/network.h>
#include <com/snert/lib/util/getopt.h>

static char usage[] =
"usage: lickey [-i ip][smtpf options] file.txt\n"
"       lickey -g [-fk][-e days] [arguments...] [file.txt] >new.txt\n"
"\n"
"-e days\t\tnumber of days before the license key expires, 0 unlimited\n"
"-f\t\twrite all possible lickey fields and usage\n"
"-g\t\tgenerate a license using info from arguments and/or file.txt\n"
"-i ip\t\tthe IP to validate against\n"
"-k\t\tkeep previously generated keycode\n"
"\n"
"Without any options, the file.txt is validated.\n"
"\n"
LIBSNERT_COPYRIGHT "\n"
;

static char host_ip[IPV6_STRING_LENGTH];
static char host_name[DOMAIN_STRING_LENGTH];

#if ! defined(__MINGW32__)
void
syslog(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (logFile == NULL)
		vsyslog(level, fmt, args);
	else
		LogV(level, fmt, args);
	va_end(args);
}
#endif

/***********************************************************************
 *** CGI Support Routines
 ***********************************************************************/

struct cgi {
	int port;
	int is_nph;
	const char *content_length;
	const char *document_root;
	const char *path_translated;
	const char *query_string;
	const char *remote_addr;
	const char *request_method;
	const char *script_name;
	const char *server_name;
	const char *server_port;
};

char *(*_GET)[2];
char *(*_POST)[2];
struct cgi _SERVER;
const char localhost[] = "127.0.0.1";

/**
 * @param tp
 *	A pointer to pointer of char. Decoded bytes from the source
 *	string are copied to this destination. The destination buffer
 *	must be as large as the source. The copied string is '\0'
 *	terminated and the pointer passed back points to next byte
 *	after the terminating '\0'.
 *
 * @param sp
 * 	A pointer to pointer of char. The URL encoded bytes are copied
 *	from this source buffer to the destination. The copying stops
 *	after an equals-sign, ampersand, or on a terminating '\0' and
 *	this pointer is passed back.
 */
void
cgiUrlDecode(char **tp, const char **sp)
{
	int hex;
	char *t;
	const char *s;

	for (t = *tp, s = *sp; *s != '\0'; t++, s++) {
		switch (*s) {
		case '=':
		case '&':
			s++;
			break;
		case '+':
			*t = ' ';
			continue;
		case '%':
			if (sscanf(s+1, "%2x", &hex) == 1) {
				*t = (char) hex;
				s += 2;
				continue;
			}
			/*@fallthrough@*/
		default:
			*t = *s;
			continue;
		}
		break;
	}

	/* Terminate decoded string. */
	*t = '\0';

	/* Pass back the next unprocessed location.
	 * For the source '\0' byte, we stop on that.
	 */
	*tp = t+1;
	*sp = s;
}

/**
 * @param urlencoded
 *	A URL encoded string such as the query string portion of an HTTP
 *	request or HTML form data ie. application/x-www-form-urlencoded.
 *
 * @return
 *	A pointer to array 2 of pointer to char. The first column of the
 *	table are the field names and the second column their associated
 *	values. The array is NULL terminated. The array pointer returned
 *	must be released with a single call to free().
 */
char *(*cgiParseForm(const char *urlencoded))[2]
{
	int nfields, i;
	const char *s;
	char *t, *(*out)[2];

	if (urlencoded == NULL)
		return NULL;

	nfields = 1;
	for (s = urlencoded; *s != '\0'; s++) {
		if (*s == '&')
			nfields++;
	}

	if ((out = malloc((nfields + 1) * sizeof (*out) + strlen(urlencoded) + 1)) == NULL)
		return NULL;

	s = urlencoded;
	t = (char *) &out[nfields+1];

	for (i = 0; i < nfields; i++) {
		out[i][0] = t;
		cgiUrlDecode(&t, &s);

		out[i][1] = t;
		if (s[-1] == '=')
			cgiUrlDecode(&t, &s);
		else
			*t++ = '\0';
	}

	out[i][0] = NULL;
	out[i][1] = NULL;

	return out;
}

int
cgiFindFormEntry(char *(*array)[2], char *prefix)
{
	int i;
	long plength = strlen(prefix);

	if (array == NULL)
		return -1;

	for (i = 0; array[i][0] != NULL; i++) {
		if (strncmp(array[i][0], prefix, plength) == 0)
			return i;
	}

	return -1;
}

void
cgiSendV(int code, const char *response, const char *fmt, va_list args)
{
	printf("%s %d %s\r\n", _SERVER.is_nph ? "HTTP/1.1" : "Status:", code, response);
	printf("Content-Type: text/plain\r\n");
	printf("\r\n");
	if (fmt != NULL) {
		printf("%d %s\r\n", code, response);
		vprintf(fmt, args);
	}
}

void
cgiSendOk(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	cgiSendV(200, "OK", fmt, args);
	va_end(args);
}

void
cgiSendNoContent()
{
	cgiSendV(204, "No Content", NULL, NULL);
	exit(EXIT_SUCCESS);
}

void
cgiSendSeeOther(int terminate, const char *url, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printf("%s 303 See Other\r\n",  _SERVER.is_nph ? "HTTP/1.1" : "Status:");
	printf("Content-Type: text/plain\r\n");
	printf("Location: %s\r\n", url);
	printf("\r\n");
	if (fmt != NULL)
		vprintf(fmt, args);
	printf("\r\n");
	if (terminate)
		exit(EXIT_SUCCESS);
	va_end(args);
}

void
cgiSendBadRequest(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	cgiSendV(400, "Bad Request", fmt, args);
	exit(EXIT_SUCCESS);
	va_end(args);
}

void
cgiSendInternalServerError(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	LogV(LOG_DEBUG, fmt, args);
	cgiSendV(500, "Internal Server Error", fmt, args);
	exit(EXIT_SUCCESS);

	va_end(args);
}

void
cgiSetOptions(char *(*array)[2], Option *table[])
{
	int argi;
	Option **opt, *o;

	for (opt = table; *opt != NULL; opt++) {
		o = *opt;

		if (0 <= (argi = cgiFindFormEntry(array, (char *) o->name))) {
			if (o->initial != o->string)
				free(o->string);
			o->string = strdup(array[argi][1]);
		}
	}
}

int
cgiInit(void)
{
	_SERVER.content_length = getenv("CONTENT_LENGTH");
	_SERVER.document_root = getenv("DOCUMENT_ROOT");
	_SERVER.path_translated = getenv("PATH_TRANSLATED");
	_SERVER.query_string = getenv("QUERY_STRING");
	_SERVER.remote_addr = getenv("REMOTE_ADDR");
	_SERVER.request_method = getenv("REQUEST_METHOD");
	_SERVER.script_name = getenv("SCRIPT_NAME");
	_SERVER.server_name = getenv("SERVER_NAME");
	_SERVER.server_port = getenv("SERVER_PORT");

	_SERVER.is_nph = _SERVER.script_name == NULL || strstr(_SERVER.script_name, "nph-") != NULL;

	_GET = cgiParseForm(_SERVER.query_string);

	if (_SERVER.document_root != NULL)
		(void) chdir(_SERVER.document_root);

	if (_SERVER.script_name == NULL)
		_SERVER.script_name = "/" _NAME;

	if (_SERVER.remote_addr == NULL)
		_SERVER.remote_addr = localhost;

	if (_SERVER.server_name == NULL)
		_SERVER.server_name = localhost;

	if (_SERVER.server_port == NULL)
		_SERVER.server_port = "80";

	_SERVER.port = strtol(_SERVER.server_port, NULL, 10);

	if (_SERVER.request_method != NULL && strcmp(_SERVER.request_method, "POST") == 0) {
		char *post_input;
		ssize_t content_length, length, n;

		if (_SERVER.content_length == NULL) {
			cgiSendBadRequest("Missing content.");
			return -1;
		}

		content_length = strtol(_SERVER.content_length, NULL, 10);

		if ((post_input = malloc(content_length+1)) == NULL) {
			cgiSendInternalServerError("Out of memory.");
			return -1;
		}

		for (length = 0; length < content_length; length += n) {
			if ((n = read(0, post_input + length, (size_t) (content_length-length))) < 0) {
				cgiSendInternalServerError("Content read error.");
				return -1;
			}
		}
		post_input[length] = '\0';

		if ((_POST = cgiParseForm(post_input)) == NULL) {
			cgiSendInternalServerError("Form POST parse error.\n");
			return -1;
		}

		free(post_input);
	}

	return 0;
}

/***********************************************************************
 ***
 ***********************************************************************/

pthread_attr_t thread_attr;

void
atExitCleanUp(void)
{
	/* Do nothing (yet). */
}

#ifdef __WIN32__
void
freeThreadData(void)
{
	/* Do nothing (yet). */
}
#endif

void
signalInit(Server *srv)
{
	/* Do nothing (yet). */
}

void
signalFini(Server *srv)
{
	/* Do nothing (yet). */
}

void *
signalThread(void *data)
{
	/* Do nothing (yet). */
	return NULL;
}

int
dropPrivilages(void)
{
	/* Do nothing (yet). */
	return 0;
}

int
chownByName(const char *path, const char *user, const char *group)
{
	/* Do nothing (yet). */
	return 0;
}

int
chmodByName(const char *path, mode_t mode)
{
	/* Do nothing (yet). */
	return 0;
}

#ifdef ENABLE_LICENSE_CONTROL
/*** REMOVAL OF THIS CODE IS IN VIOLATION
 *** OF THE TERMS OF THE SOFTWARE LICENSE.
 ***/
static void *
license_control(void *data)
{
	SMTP2 *smtp;
	Option **opt, *o;
	char timestamp[40], sender[SMTP_PATH_LENGTH], host[DOMAIN_STRING_LENGTH];

	if ((smtp = smtp2OpenMx(PHONE_HOME_DOMAIN, optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, 0)) != NULL) {
		networkGetMyName(host);
		smtp->timeout = optSmtpCommandTimeout.value;
		(void) snprintf(sender, sizeof (sender), "%s@%s", optRunUser.string, host);
		if (smtp2Mail(smtp, sender) != SMTP_OK || smtp2Rcpt(smtp, PHONE_HOME_MAIL) != SMTP_OK) {
			(void) smtp2Rset(smtp);
			if (smtp2Mail(smtp, "") != SMTP_OK)
				goto error1;
			if (smtp2Rcpt(smtp, PHONE_HOME_MAIL) != SMTP_OK)
				goto error1;
		}

		TimeStamp(&smtp->start, timestamp, sizeof (timestamp));
		(void) smtp2Printf(smtp, "Date: %s\r\n", timestamp);
		(void) smtp2Printf(smtp, "To: \"SnertSoft\" <%s>\r\n", PHONE_HOME_MAIL);
		(void) smtp2Printf(smtp, "From: \"%s\" <%s>\r\n", lickeyClientName.string, lickeyClientMail.string);
		(void) smtp2Printf(smtp, "Sender: \"lickey\" <%s>\r\n", sender);
		(void) smtp2Printf(smtp, "Subject: lickey for %s %s-%s\r\n", lickeyClientName.string, lickeyProcessName.string, lickeyProcessVersion.string);
		(void) smtp2Printf(smtp, "Message-ID: <%s@[%s]>\r\n", smtp->id_string, smtp->local_ip);
		(void) smtp2Printf(smtp, "Priority: normal\r\n");
		(void) smtp2Printf(smtp, "User-Agent: lickey-" _VERSION "\r\n");
		(void) smtp2Printf(smtp, "\r\n");

		for (opt = lickeyTable; *opt != NULL; opt++) {
			o = *opt;
			if (o->string[0] != '?' && o->string[1] != '\0')
				(void) smtp2Printf(smtp, "%s=\"%s\"\r\n", o->name, o->string);
		}

		(void) smtp2Dot(smtp);
error1:
		smtp2Close(smtp);
	}

	freeThreadData();

	return NULL;
}
#endif

void
lickeyMake(int argc, char **argv, unsigned long seconds, int keep_keycode)
{
	int m, n;
	time_t now;
	char buffer[65];
	md5_state_t md5;
	Option **opt, *o;
#ifdef ENABLE_LICENSE_CONTROL
	pthread_t thread;
#endif
	unsigned char digest[16];

	optionInit(lickeyTable, NULL);
	n = optionArrayL(argc, argv, lickeyTable, NULL);

	if (n < argc) {
		optionInit(lickeyTable, NULL);
		if (optionFile(argv[n], lickeyTable, NULL)) {
			syslog(LOG_ERR, LOG_NUM(412) "%s load error: %s (%d)", argv[n], strerror(errno), errno);
/*{LOG
The <a href="summary.html#opt_lickey_file">lickey-file</a> option is a
required option and must be the absolute path of the license key file.
}*/
			exit(1);
		}
		(void) optionArrayL(argc, argv, lickeyTable, NULL);
	}

	if (lickeyKeycode.string == NULL || *lickeyKeycode.string == '\0' || !keep_keycode) {
		/* Generate the secret key indices. */
		for (m = 0; m < 32; m++) {
			n = rand() % 256;
			buffer[(m << 1)] = hex_digit[(n >> 4) & 0x0F];
			buffer[(m << 1) + 1] = hex_digit[n & 0x0F];
		}
		buffer[64] = '\0';
		lickeyKeycode.string = strdup(buffer);
	}

	now = time(NULL);
	TimeStamp(&now, buffer, sizeof (buffer));
	lickeyDateIssued.string = strdup(buffer);

	if (0 < seconds) {
		now += seconds;
		TimeStamp(&now, buffer, sizeof (buffer));
		lickeyDateExpires.string = strdup(buffer);
	} else {
		lickeyDateExpires.string = (char *) lickeyDateExpires.initial;
	}

#ifdef ENABLE_DEFAULT_PLATFORM
	if (lickeyPlatform.initial == lickeyPlatform.string) {
		lickeyPlatform.initial = _PLATFORM;
		lickeyPlatform.string = (char *) lickeyPlatform.initial;
	}
#endif

	md5_init(&md5);
	lickeyHashParms(&md5);
	lickeyHashKey(&md5);
	md5_finish(&md5, (md5_byte_t *) digest);

	for (m = 0; m < 16; m++) {
		buffer[(m << 1)] = hex_digit[(digest[m] >> 4) & 0x0F];
		buffer[(m << 1) + 1] = hex_digit[digest[m] & 0x0F];
	}
	buffer[32] = '\0';

	lickeyHash.string = strdup(buffer);

#ifdef ENABLE_LICENSE_CONTROL
	(void) pthread_create(&thread, NULL, license_control, NULL);
#endif
	if (output_all_fields) {
		optionUsageL(lickeyTable, NULL);
	} else {
		for (opt = lickeyTable; *opt != NULL; opt++) {
			o = *opt;
			if (!((o->string[0] == '?' || o->string[0] == '~') && o->string[1] == '\0'))
				printf("%s=\"%s\"\r\n", o->name, o->string);
		}
	}

#ifdef ENABLE_LICENSE_CONTROL
	pthread_join(thread, NULL);
#endif
}

int
main(int argc, char **argv)
{
	unsigned long days = 0;
	int ch, argi, generate_mode = 0, cgi_mode = 0, keep_keycode = 0, usage_dump = 0;

	LogOpen("(standard error)");
	LogSetProgramName("lickey");
	LogSetLevel(LOG_DEBUG);

	if (getenv("GATEWAY_INTERFACE") == NULL) {
		while ((ch = getopt(argc, argv, "e:fgi:kR:u")) != -1) {
			switch (ch) {
			case 'R':
				optRouteMap.string = strdup(optarg);
				break;
			case 'f':
				output_all_fields = 1;
				break;
			case 'e':
				days = (unsigned long) strtol(optarg, NULL, 10);
				days *= 86400;
				break;
			case 'g':
				generate_mode = 1;
				break;
			case 'i':
				(void) TextCopy(host_ip, sizeof (host_ip), optarg);
				break;
			case 'k':
				keep_keycode = 1;
				break;
			case 'u':
				usage_dump = 1;
				break;
			default:
				(void) fprintf(stderr, usage);
				return 2;
			}
		}

		if (!usage_dump && !generate_mode && argc < optind + 1) {
			if (output_all_fields)
				optionUsage(lickeyTable);
			else
				(void) fprintf(stderr, usage);
			return 2;
		}
	} else {
		cgiInit();
		cgi_mode = 1;
		cgiSetOptions(_POST, lickeyTable);

		if (0 <= (argi = cgiFindFormEntry(_POST, "f")))
			output_all_fields = _POST[argi][1][0] == '1';
		if (0 <= (argi = cgiFindFormEntry(_POST, "g")))
			generate_mode = _POST[argi][1][0] == '1';
		if (0 <= (argi = cgiFindFormEntry(_POST, "e")))
			days = (int) strtol(_POST[argi][1], NULL, 10) * 86400;
		if (0 <= (argi = cgiFindFormEntry(_POST, "i")))
			(void) TextCopy(host_ip, sizeof (host_ip), _POST[argi][1]);

		cgiSendOk(NULL);
	}

	if (host_ip[0] == '\0') {
		socketInit();
		networkGetMyName(host_name);
		networkGetHostIp(host_name, host_ip);
	}

	srand(TextHash(0, host_ip) ^ time(NULL));

	/* Parse command line options looking for a file= option. */
	filterRegister();
	argc -= optind-1;
	argv += optind-1;
	optionInit(cmdOptTable, NULL);
	argi = optionArrayL(argc, argv, cmdOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (optFile.string != NULL && *optFile.string != '\0') {
		/* Do NOT reset this option. */
		optFile.initial = optFile.string;
		optFile.string = NULL;

		optionInit(optTable, NULL);
		(void) optionFile(optFile.string, optTable, NULL);
		(void) optionArrayL(argc, argv, optTable, NULL);
	}

	if (usage_dump) {
		optionUsage(lickeyOptTable);
		return 0;
	}

	if (generate_mode) {
		lickeyMake(argc, argv, days, keep_keycode);
		return 0;
	}

	if (lickeyLoadFile(argv[argi]) || !lickeyIsValid(host_ip))
		return 3;

	routeInit(NULL, NULL);
	lickeyRouteCount();
	routeFini(NULL, NULL);

	return 0;
}
#endif
