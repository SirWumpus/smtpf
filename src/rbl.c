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

#ifdef ENABLE_PDQ
static DnsList *dns_bl;

void
dnsListFree(void *_list)
{
	DnsList *list = _list;

	if (list != NULL) {
		VectorDestroy(list->suffixes);
		free(list->masks);
		free(list);
	}
}

DnsList *
dnsListCreate(Option *option)
{
	long i;
	DnsList *list;
	char *slash, *suffix;

	if ((list = malloc(sizeof (*list))) == NULL)
		goto error0;

	if ((list->suffixes = TextSplit(option->string, OPTION_LIST_DELIMS, 0)) == NULL)
		goto error1;

	if ((list->masks = calloc(sizeof (*list->masks), VectorLength(list->suffixes))) == NULL)
		goto error1;

	for (i = 0; i < VectorLength(list->suffixes); i++) {
		if ((suffix = VectorGet(list->suffixes, i)) == NULL)
			continue;

		if ((slash = strchr(suffix, '/')) == NULL) {
			list->masks[i] = (unsigned long) ~0L;
		} else {
			list->masks[i] = (unsigned long) strtol(slash+1, NULL, 0);
			*slash = '\0';
		}
	}

	list->option = option;

	return list;
error1:
	dnsListFree(list);
error0:
	return NULL;
}

const char *
dnsListIsListed(Session *sess, DnsList *dnslist, const char *name, PDQ_rr *list)
{
	long i;
	PDQ_A *rr;
	unsigned long bits;
	const char **suffixes;

	suffixes = (const char **) VectorBase(dnslist->suffixes);
	for (rr = (PDQ_A *) list; rr != NULL; rr = (PDQ_A *) rr->rr.next) {
		if (rr->rr.rcode != PDQ_RCODE_OK || rr->rr.type != PDQ_TYPE_A)
			continue;

		if (TextInsensitiveStartsWith(rr->rr.name.string.value, name) < 0)
			continue;

		for (i = 0; suffixes[i] != NULL; i++) {
			if (strstr(rr->rr.name.string.value, suffixes[i]) == NULL)
				continue;

			bits = NET_GET_LONG(rr->address.ip.value + rr->address.ip.offset);

			if ((bits & dnslist->masks[i]) != 0) {
				if (verb_info.option.value) {
					syslog(LOG_INFO, LOG_MSG(523) "%s found %s %s", LOG_ARGS(sess), dnslist->option->name, rr->rr.name.string.value, rr->address.string.value);
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

				return suffixes[i];
			}
		}
	}

	return NULL;
}

const char *
dnsListLookup(Session *sess, DnsList *dnslist, Vector names_seen, const char *name)
{
	PDQ_rr *answers;
	const char *list_name = NULL;
	char buffer[DOMAIN_STRING_LENGTH];

	/* Clear incomplete queries. */
	pdqQueryRemoveAll(sess->pdq);

        if (0 < spanIP(name)) {
		(void) reverseIp(name, buffer, sizeof (buffer), 0);
		name = buffer;
        }

	if (names_seen != NULL) {
		const char **seen;

		/* Check cache of previously tested hosts/domains. */
		for (seen = (const char **) VectorBase(names_seen); *seen != NULL; seen++) {
			if (TextInsensitiveCompare(name, *seen) == 0) {
				if (verb_rbl.option.value)
					syslog(LOG_DEBUG, LOG_MSG(000) "name=%s previously checked", LOG_ARGS(sess), name);
				return NULL;
			}
		}

		(void) VectorAdd(names_seen, strdup(name));
	}

	answers = pdqGetDnsList(
		sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_A, name,
		(const char **) VectorBase(dnslist->suffixes), pdqWait
	);

	if (answers != NULL) {
		list_name = dnsListIsListed(sess, dnslist, name, answers);
		pdqFree(answers);
	}

	return list_name;
}

/**
 * @param dns_list
 *	A pointer to a DnsList.
 *
 * @param pdq
 *	A pointer to PDQ structure to use for the query.
 *
 * @param names_seen
 *	A pointer to vector of previously looked up names. If name
 *	is present in this vector, then the query is skipped and
 *	NULL immiediately returned. The query name will be added
 *	to this vector.	Specify NULL to skip this check.
 *
 * @param name
 *	A host or domain name whos A/AAAA records are first found and
 *	then passed to dnsListQueryName.
 *
 * @return
 *	A C string pointer to a list name in which name is a member.
 *	Otherwise NULL if name was not found in a DNS list.
 */
const char *
dnsListQueryIp(Session *sess, DnsList *dns_list, Vector names_seen, const char *name)
{
	PDQ_rr *rr, *list;
	const char *list_name = NULL;

	list = pdqGet5A(sess->pdq, PDQ_CLASS_IN, name);

	for (rr = list; rr != NULL; rr = rr->next) {
		if (rr->rcode != PDQ_RCODE_OK || (rr->type != PDQ_TYPE_A && rr->type != PDQ_TYPE_AAAA))
			continue;

		/* Some domains specify a 127.0.0.0/8 address for
		 * an A recorded, like "anything.so". The whole
		 * TLD .so for Somalia, is a wild card record that
		 * maps to 127.0.0.2, which typically is a DNSBL
		 * test record that always fails.
		 */
		if (isReservedIPv6(((PDQ_AAAA *) rr)->address.ip.value, IS_IP_LOOPBACK|IS_IP_LOCALHOST))
			continue;

		list_name = dnsListLookup(sess, dns_list, names_seen, ((PDQ_AAAA *) rr)->address.string.value);
		if (list_name != NULL) {
			if (verb_rbl.option.value)
				syslog(LOG_DEBUG, LOG_MSG(000) "%s [%s] listed in %s", LOG_ARGS(sess), name, ((PDQ_AAAA *) rr)->address.string.value, list_name);
			break;
		}
	}

	pdqFree(list);

	return list_name;
}


int
rblInit(Session *null, va_list ignore)
{
	dns_bl = dnsListCreate(&optDnsBL);
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
		if ((list_name = dnsListLookup(sess, dns_bl, NULL, sess->client.addr)) != NULL) {
			statsCount(&stat_dns_bl);
			CLIENT_SET(sess, CLIENT_IS_BLACK);
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

			if ((list_name = dnsListLookup(sess, dns_bl, NULL, ip)) != NULL) {
				MSG_SET(sess, MSG_IS_DNSBL);
				statsCount(&stat_dns_bl_headers);
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

#else

static int
dnsIsIpListed(Session *sess, const char *ip, const char *dns_type, const char *dns_suffix, unsigned long mask)
{
	long length;
	Vector answer;
	DnsEntry *entry;
	char buffer[256];
	unsigned long bits;

	/* Ignore bits 1 and 25..32, since they match 127.0.0.1. */
	mask &= 0x00fffffe;

	if ((length = reverseIp(ip, buffer, sizeof (buffer), 0)) == 0) {
		errno = EINVAL;
		return 0;
	}

	/* But make sure we have a leading dot on the DNSBL suffix. */
	if (*dns_suffix != '.')
		buffer[length++] = '.';

	if (sizeof (buffer) <= TextCopy(buffer+length, sizeof (buffer)-length, (char *) dns_suffix)) {
		errno = EINVAL;
		return 0;
	}

	if (verb_rbl.option.value)
		syslog(LOG_DEBUG, LOG_NUM(526) "lookup %s", buffer);

	answer = NULL;
	if (DnsGet2(DNS_TYPE_A, 1, buffer, &answer, NULL) == DNS_RCODE_OK
	&& (entry = VectorGet(answer, 0)) != NULL && entry->address != NULL) {
		bits = NET_GET_LONG(entry->address + IPV6_OFFSET_IPV4);
		if ((bits & mask) != 0) {
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(527) "%s found %s %s", LOG_ARGS(sess), dns_type, buffer, entry->address_string);
/*{LOG
See <a href="summary.html#opt_dns_bl">dns-bl</a>,
<a href="summary.html#opt_dns_gl">dns-gl</a>,
and <a href="summary.html#opt_dns_wl">dns-wl</a> options.
}*/
			}
			VectorDestroy(answer);
			return 1;
		}
	}

	VectorDestroy(answer);

	return 0;
}

static Vector dnsbl;

int
rblInit(Session *null, va_list ignore)
{
	dnsbl = blCreate(optDnsBL.string);
	return SMTPF_CONTINUE;
}

int
rblFini(Session *null, va_list ignore)
{
	VectorDestroy(dnsbl);
	return SMTPF_CONTINUE;
}

int
rblConnect(Session *sess, va_list ignore)
{
	int i;
	BL *bl;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(528) "rblConnect()", LOG_ARGS(sess));

	if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)) {
		for (i = 0; i < VectorLength(dnsbl); i++) {
			if ((bl = VectorGet(dnsbl, i)) == NULL)
				continue;

			if (verb_rbl.option.value)
				syslog(LOG_DEBUG, LOG_MSG(529) "checking client.addr=%s dnsbl=%s mask=0x%lx", LOG_ARGS(sess), sess->client.addr, bl->suffix, bl->mask);

			if (dnsIsIpListed(sess, sess->client.addr, "dns-bl", bl->suffix, bl->mask)) {
				statsCount(&stat_dns_bl);
				CLIENT_SET(sess, CLIENT_IS_BLACK);
				return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 " CLIENT_FORMAT " black listed by %s" ID_MSG(530) "\r\n", CLIENT_INFO(sess), bl->suffix, ID_ARG(sess));
			}
		}
	}

	return SMTPF_CONTINUE;
}
#endif

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

#ifdef ENABLE_PDQ

static DnsList *dnswl;

int
dnswlInit(Session *null, va_list ignore)
{
	dnswl = dnsListCreate(&optDnsWL);
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

	if ((list_name = dnsListLookup(sess, dnswl, NULL, sess->client.addr)) != NULL) {
		statsCount(&stat_dns_wl);
		CLIENT_SET(sess, CLIENT_IS_WHITE);
		return sess->client.bw_state = SMTPF_ACCEPT;
	}

	return SMTPF_CONTINUE;
}

#else

static Vector dnswl;

int
dnswlInit(Session *null, va_list ignore)
{
	dnswl = blCreate(optDnsWL.string);
	return SMTPF_CONTINUE;
}

int
dnswlFini(Session *null, va_list ignore)
{
	VectorDestroy(dnswl);
	return SMTPF_CONTINUE;
}

int
dnswlConnect(Session *sess, va_list ignore)
{
	int i;
	BL *wl;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(532) "dnswlConnect()", LOG_ARGS(sess));

	for (i = 0; i < VectorLength(dnswl); i++) {
		if ((wl = VectorGet(dnswl, i)) == NULL)
			continue;

		if (verb_rbl.option.value)
			syslog(LOG_DEBUG, LOG_MSG(533) "checking client.addr=%s dnswl=%s mask=0x%lx", LOG_ARGS(sess), sess->client.addr, wl->suffix, wl->mask);

		if (dnsIsIpListed(sess, sess->client.addr, "dns-wl", wl->suffix, wl->mask)) {
			statsCount(&stat_dns_wl);
			CLIENT_SET(sess, CLIENT_IS_WHITE);
			return sess->client.bw_state = SMTPF_ACCEPT;
		}
	}

	return SMTPF_CONTINUE;
}

#endif

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

#ifdef ENABLE_PDQ

static DnsList *dnsgl;

int
dnsglInit(Session *null, va_list ignore)
{
	dnsgl = dnsListCreate(&optDnsGL);
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

	if ((list_name = dnsListLookup(sess, dnsgl, NULL, sess->client.addr)) != NULL) {
		statsCount(&stat_dns_gl);
		CLIENT_SET(sess, CLIENT_IS_GREY);
		return sess->client.bw_state = SMTPF_GREY;
	}

	return SMTPF_CONTINUE;
}

#else

static Vector dnsgl;

int
dnsglInit(Session *null, va_list ignore)
{
	dnsgl = blCreate(optDnsGL.string);
	return SMTPF_CONTINUE;
}

int
dnsglFini(Session *null, va_list ignore)
{
	VectorDestroy(dnsgl);
	return SMTPF_CONTINUE;
}

/*
 * Current definition of dns-gl: by-pass all pre-DATA tests and those that
 * would delay delivery, but apply those tests that *act* on message content;
 * specifically cli, clamd, spamd, uribl.
 *
 * Previous definition of dns-gl: by-pass all pre-DATA tests upto, but not
 * the content filters; specially cli, clamd, spamd, uribl, and grey-content.
 * Note that grey-listing was not by-passed either, though the reasons why
 * are lost in history, possibly related to grey-connect: being available, or
 * might have been a bug.
 */
int
dnsglConnect(Session *sess, va_list ignore)
{
	int i;
	BL *gl;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(535) "dnsglConnect()", LOG_ARGS(sess));

	for (i = 0; i < VectorLength(dnsgl); i++) {
		if ((gl = VectorGet(dnsgl, i)) == NULL)
			continue;

		if (verb_rbl.option.value)
			syslog(LOG_DEBUG, LOG_MSG(536) "checking client.addr=%s dnsgl=%s mask=0x%lx", LOG_ARGS(sess), sess->client.addr, gl->suffix, gl->mask);

		if (dnsIsIpListed(sess, sess->client.addr, "dns-gl", gl->suffix, gl->mask)) {
			statsCount(&stat_dns_gl);
			CLIENT_SET(sess, CLIENT_IS_GREY);
			sess->client.bw_state = SMTPF_GREY;
			return SMTPF_GREY;
		}
	}

	return SMTPF_CONTINUE;
}

#endif

#endif /* FILTER_RBL */
