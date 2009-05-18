/*
 * rbl.c
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

#ifdef FILTER_RBL

#include "smtpf.h"

#include <com/snert/lib/io/Dns.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/net/dnsList.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_dns_bl[] =
  "A list of IP based DNS BL suffixes to consult, like sbl-xbl.spamhaus.org.\n"
"# Aggregate lists are supported using suffix/mask. Without a /mask, suffix\n"
"# is the same as suffix/0x00FFFFFE.\n"
"#"
;

Option optDnsBL			= { "dns-bl",	"",		usage_dns_bl };

static const char usage_dns_bl_headers[] =
  "A list of mail headers to parse for IP addresses and check against\n"
"# one or more DNS BL. Specify the empty list to disable.\n"
"#"
;
Option optDnsBlHeaders		= { "dns-bl-headers", "",	usage_dns_bl_headers };

Stats stat_dns_bl		= { STATS_TABLE_CONNECT, "dns-bl" };
Stats stat_dns_gl		= { STATS_TABLE_CONNECT, "dns-gl" };
Stats stat_dns_wl		= { STATS_TABLE_CONNECT, "dns-wl" };
Stats stat_idle_retest_timer	= { STATS_TABLE_CONNECT, "idle-retest-timer" };
Stats stat_dns_bl_headers	= { STATS_TABLE_MSG, "dns-bl-headers" };

static Verbose verb_rbl		= { { "rbl", "-", "" } };

int
rblRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_rbl);

	optionsRegister(&optDnsBL, 1);
	optionsRegister(&optDnsGL, 1);
	optionsRegister(&optDnsWL, 1);
	optionsRegister(&optDnsBlHeaders, 0);

	(void) statsRegister(&stat_dns_bl);
	(void) statsRegister(&stat_dns_gl);
	(void) statsRegister(&stat_dns_wl);
	(void) statsRegister(&stat_dns_bl_headers);
	(void) statsRegister(&stat_idle_retest_timer);

	return SMTPF_CONTINUE;
}

void
dnsListSysLog(Session *sess, const char *option, const char *name, const char *list)
{
       if (verb_info.option.value)
	       syslog(LOG_INFO, LOG_MSG(523) "%s found %s %s", LOG_ARGS(sess), option, name, list);
/*{LOG
See <a href="summary.html#opt_dns_bl">dns-bl</a>,
<a href="summary.html#opt_dns_gl">dns-gl</a>,
<a href="summary.html#opt_dns_wl">dns-wl</a>,
<a href="summary.html#opt_ns_bl">ns-bl</a>,
<a href="summary.html#opt_uri_bl">uri-bl</a>,
and
<a href="summary.html#opt_uri_dnl_bl">uri-dns-bl</a>
options.
}*/
}

static DnsList *dns_bl;

int
rblInit(Session *null, va_list ignore)
{
	dns_bl = dnsListCreate(optDnsBL.string);
	return SMTPF_CONTINUE;
}

int
rblFini(Session *null, va_list ignore)
{
	dnsListFree(dns_bl);
	return SMTPF_CONTINUE;
}

int
rblConnect(Session *sess, va_list ignore)
{
	const char *list_name = NULL;

	LOG_TRACE(sess, 524, rblConnect);

	if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)) {
		if ((list_name = dnsListQueryName(dns_bl, sess->pdq, NULL, sess->client.addr)) != NULL) {
			statsCount(&stat_dns_bl);
			CLIENT_SET(sess, CLIENT_IS_BLACK);
			dnsListSysLog(sess, "dns-bl", sess->client.addr, list_name);
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 " CLIENT_FORMAT " black listed by %s" ID_MSG(525) "\r\n", CLIENT_INFO(sess), list_name, ID_ARG(sess));
		}
	}

	return SMTPF_CONTINUE;
}

static int
rblCheckString(Session *sess, const char *value)
{
	int span;
	char ip[IPV6_STRING_LENGTH];
	const char *list_name = NULL;

	for ( ; *value != '\0'; value++) {
		if (0 < (span = spanIP(value))) {
			memcpy(ip, value, span);
			ip[span] = '\0';

			if (verb_rbl.option.value)
				syslog(LOG_DEBUG, LOG_MSG(872) "rblCheckString value=\"%s\"", LOG_ARGS(sess), ip);

			if ((list_name = dnsListQueryName(dns_bl, sess->pdq, NULL, ip)) != NULL) {
				MSG_SET(sess, MSG_IS_DNSBL);
				statsCount(&stat_dns_bl_headers);
				dnsListSysLog(sess, "dns-bl", ip, list_name);
				return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.0 IP [%s] in header black listed by %s" ID_MSG(873) "\r\n", ip, list_name, ID_ARG(sess));
			}

			value += span;
		}
	}

	return SMTPF_CONTINUE;
}

int
rblHeaders(Session *sess, va_list args)
{
	int rc;
	long i, length;
	char *hdr, **table;
	Vector headers, search;

	LOG_TRACE(sess, 874, rblHeaders);

	if (*optDnsBlHeaders.string == '\0' || CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS))
		return SMTPF_CONTINUE;

	if ((search = TextSplit(optDnsBlHeaders.string, ";, ", 0)) == NULL)
		return SMTPF_CONTINUE;

	rc = SMTPF_CONTINUE;
	headers = va_arg(args, Vector);
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		for (table = (char **) VectorBase(search); *table != NULL; table++) {
			if (0 < (length = TextInsensitiveStartsWith(hdr, *table)) && hdr[length] == ':') {
				if (verb_rbl.option.value)
					syslog(LOG_DEBUG, LOG_MSG(875) "rblHeaders hdr=\"%s\"", LOG_ARGS(sess), hdr);

				if ((rc = rblCheckString(sess, hdr + length + 1)) != SMTPF_CONTINUE)
					goto done;
			}
		}
	}
done:
	VectorDestroy(search);

	return rc;
}

int
rblIdle(Session *sess, va_list ignore)
{
	int rc;

	if ((rc = rblConnect(sess, ignore)) != SMTPF_CONTINUE)
		statsCount(&stat_idle_retest_timer);

	return rc;
}

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_dns_wl[] =
  "A list of IP based DNS WL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;

Option optDnsWL			= { "dns-wl",	"",		usage_dns_wl };

static DnsList *dnswl;

int
dnswlInit(Session *null, va_list ignore)
{
	dnswl = dnsListCreate(optDnsWL.string);
	return SMTPF_CONTINUE;
}

int
dnswlFini(Session *null, va_list ignore)
{
	dnsListFree(dnswl);
	return SMTPF_CONTINUE;
}

int
dnswlConnect(Session *sess, va_list ignore)
{
	const char *list_name = NULL;

	LOG_TRACE(sess, 531, dnswlConnect);

	if ((list_name = dnsListQueryName(dnswl, sess->pdq, NULL, sess->client.addr)) != NULL) {
		statsCount(&stat_dns_wl);
		CLIENT_SET(sess, CLIENT_IS_WHITE);
		dnsListSysLog(sess, "dns-wl", sess->client.addr, list_name);
		return sess->client.bw_state = SMTPF_ACCEPT;
	}

	return SMTPF_CONTINUE;
}

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_dns_gl[] =
  "A list of IP based DNS grey-list suffixes to consult. This is similar\n"
"# to dns-wl, but only white lists as far as the data content filters.\n"
"# Intended for use with less reliable DNS white lists. Aggregate lists\n"
"# are supported using suffix/mask. Without a /mask, suffix is the same\n"
"# as suffix/0x00FFFFFE.\n"
"#"
;

Option optDnsGL			= { "dns-gl",	"",		usage_dns_gl };

static DnsList *dnsgl;

int
dnsglInit(Session *null, va_list ignore)
{
	dnsgl = dnsListCreate(optDnsGL.string);
	return SMTPF_CONTINUE;
}

int
dnsglFini(Session *null, va_list ignore)
{
	dnsListFree(dnsgl);
	return SMTPF_CONTINUE;
}

int
dnsglConnect(Session *sess, va_list ignore)
{
	const char *list_name = NULL;

	LOG_TRACE(sess, 534, dnsglConnect);

	if ((list_name = dnsListQueryName(dnsgl, sess->pdq, NULL, sess->client.addr)) != NULL) {
		statsCount(&stat_dns_gl);
		CLIENT_SET(sess, CLIENT_IS_GREY);
		dnsListSysLog(sess, "dns-gl", sess->client.addr, list_name);
		return sess->client.bw_state = SMTPF_GREY;
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_RBL */
