/*
 * uribl.c
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

#ifdef FILTER_URIBL

#include "smtpf.h"

#include <ctype.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/net/dnsList.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_uri_bl_policy[] =
  "Check if the message contains a black listed URI found by uri-bl\n"
"# or uri-dns-bl. Specify one of none, reject, or discard. When set\n"
"# to none, the test is disabled.\n"
"#"
;
static const char usage_uri_links_policy[] =
  "Test if message contains a broken URL and apply policy if found.\n"
"# Specify one of none, reject, or discard. When set to none, the test\n"
"# is disabled.\n"
"#"
;
static const char usage_uri_bl[] =
  "Extract from text, HTML, and/or MIME encoded messages bodies URIs\n"
"# such as http: and mailto: links, then check one or more URI black\n"
"# lists. Give a list of domain based DNS BL suffixes to consult, like\n"
"# .multi.surbl.org. Aggregate lists are supported using suffix/mask.\n"
"# Without a /mask, suffix is the same as suffix/0x00FFFFFE.\n"
"#\n"
"# The tag Body: can be used in the access-map to white-list domains\n"
"# found within the message, for example w3c.org or google.com.\n"
"#"
;
static const char usage_uri_dns_bl[] =
  "Extract from text, HTML, and/or MIME encoded messages bodies URIs\n"
"# such as http: and mailto: links, then consult one or more IP black\n"
"# lists. Give a list of IP based DNS BL suffixes to consult, like\n"
"# sbl-xbl.spamhaus.org. Aggregate lists are supported using suffix/mask.\n"
"# Without a /mask, suffix is the same as suffix/0x00FFFFFE.\n"
"#\n"
"# The tag Body: can be used in the access-map to white-list domains\n"
"# found within the message, for example w3c.org or google.com.\n"
"#"
;

#ifdef CONFUSING
static const char usage_uri_max_limit[] =
  "Maximum number of URIs that a message may contain before being\n"
"# rejected. Intended as a means to prevent DoS attacks that attempt to\n"
"# flood the URI filter and/or the DNS server with excessive lookups.\n"
"# Specify zero for unlimited.\n"
"#"
;
Option optUriMaxLimit		= { "uri-max-limit",	"0",			usage_uri_max_limit };
#endif

static const char usage_uri_max_test[] =
  "Maximum number of unique URIs to check. Specify zero for unlimited.\n"
"#"
;
static const char usage_uri_sub_domains[] =
  "When querying against name based black lists, like .multi.surbl.org\n"
"# or .black.uribl.com, first test the registered domain, then any \n"
"# sub-domains from right-to-left. Typically sub-domains are not listed\n"
"# on URI black lists.\n"
"#"
;

Option optHttpTimeout		= { "http-timeout",	"60",			"Socket timeout used when testing HTTP links." };
Option optUriBL			= { "uri-bl",		"",			usage_uri_bl };
Option optUriDnsBL		= { "uri-dns-bl",	"",			usage_uri_dns_bl };
Option optUriBlPolicy		= { "uri-bl-policy",	"reject",		usage_uri_bl_policy };
Option optUriLinksPolicy	= { "uri-links-policy",	"none",			usage_uri_links_policy };
Option optUriMaxTest		= { "uri-max-test",	"10",			usage_uri_max_test };
Option optUriSubDomains		= { "uri-sub-domains",	"-",			usage_uri_sub_domains };

static const char usage_uri_valid_soa[] =
  "For each URI found, check that the domain has a valid SOA and reject\n"
"# otherwise.\n"
"#"
;
Option optUriValidSoa		= { "uri-valid-soa",	"-",		usage_uri_valid_soa };

static const char usage_uri_bl_helo[] =
  "Check if the HELO/EHLO argument is black listed using uri-dns-bl\n"
"# and/or uri-bl.\n"
"#"
;

static const char usage_uri_bl_mail[] =
  "Check if the domain of the MAIL FROM: argument is black listed\n"
"# using uri-dns-bl and/or uri-bl.\n"
"#"
;

static const char usage_uri_bl_ptr[] =
  "Check if the PTR result is black listed using uri-dns-bl and/or\n"
"# uri-bl.\n"
"#"
;

static const char usage_uri_bl_headers[] =
  "A list of mail headers to parse for URI and check against one or\n"
"# more URI BL. Specify the empty list to disable.\n"
"#"
;

Option optUriBlHelo		= { "uri-bl-helo",	"-",			usage_uri_bl_helo };
Option optUriBlMail		= { "uri-bl-mail",	"-",			usage_uri_bl_mail };
Option optUriBlPtr		= { "uri-bl-ptr",	"-",			usage_uri_bl_ptr };
Option optUriBlHeaders		= { "uri-bl-headers",	"",			usage_uri_bl_headers };

/* +uri uri=1 general, uri=2 lookup, uri=3 parsing */
Verbose verb_uri		= { { "uri",		"-", "" } };
Verbose verb_mail_bl		= { { "mail-bl",	"-", "" } };


static const char usage_mail_bl[] =
  "A list of MD5 based MAIL BL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;
Option optMailBl		= { "mail-bl",		"",			usage_mail_bl };

static const char usage_mail_bl_headers[] =
  "A list of mail headers to parse for mail addresses and check against\n"
"# one or more MAIL BL. Specify the empty list to disable.\n"
"#"
;
Option optMailBlHeaders		= { "mail-bl-headers",	"From;Reply-To",	usage_mail_bl_headers };

static const char usage_mail_bl_max[] =
  "Maximum number of unique mail addresses to check. Specify zero for\n"
"# unlimited.\n"
"#"
;
Option optMailBlMax		= { "mail-bl-max",	"10",			usage_mail_bl_max };

static const char usage_mail_bl_policy[] =
  "If the message contains a black listed mail address found by mail-bl\n"
"# the apply one of the following policies: none, reject, or discard.\n"
"#"
;
Option optMailBlPolicy		= { "mail-bl-policy",	"reject",		usage_mail_bl_policy };

static const char usage_mail_bl_domains[] =
  "A list of domain glob-like patterns for which to test against mail-bl,\n"
"# typically free mail services. This reduces the load on public BLs.\n"
"# Specify * to test all domains, empty list to disable.\n"
"#"
;
Option optMailBlDomains		= {
	"mail-bl-domains",

	 "gmail.*"
	";hotmail.*"
	";live.*"
	";yahoo.*"
	";aol.*"
	";aim.com"
	";cantv.net"
	";centrum.cz"
	";centrum.sk"
	";googlemail.com"
	";inmail24.com"
	";jmail.co.za"
	";libero.it"
	";luckymail.com"
	";mail2world.com"
	";msn.com"
	";rocketmail.com"
	";she.com"
	";shuf.com"
	";sify.com"
	";terra.es"
	";tiscali.it"
	";tom.com"
	";ubbi.com"
	";virgilio.it"
	";voila.fr"
	";walla.com"
	";wanadoo.fr"
	";windowslive.com"
	";y7mail.com"
	";yeah.net"
	";ymail.com"

	, usage_mail_bl_domains
};

Stats stat_mail_bl_mail		= { STATS_TABLE_MAIL,	"mail-bl-mail" };
Stats stat_mail_bl_hdr		= { STATS_TABLE_MSG,	"mail-bl-hdr" };
Stats stat_mail_bl_body		= { STATS_TABLE_MSG,	"mail-bl-body" };

static const char usage_ns_bl[] =
  "A list of name based NS BL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;
static const char usage_ns_sub_domains[] =
  "When querying against name based black lists, first test the registered\n"
"# domain, then any sub-domains from right-to-left.\n"
"#"
;

Option optNsBL			= { "ns-bl",		"",			usage_ns_bl };
Option optNsSubDomains		= { "ns-sub-domains",	"+",			usage_ns_sub_domains };

Stats stat_ns_bl_ptr		= { STATS_TABLE_CONNECT,"ns-bl-ptr" };
Stats stat_ns_bl_mail		= { STATS_TABLE_MAIL,	"ns-bl-mail" };
Stats stat_ns_bl_uri		= { STATS_TABLE_MSG,	"ns-bl-body" };

static const char usage_uri_require_domain[] =
  "Reject URLs that specify a scheme and refer to a bare IP address.\n"
"#"
;

static const char usage_uri_require_ptr[] =
  "Reject any URI where the host name is missing a PTR record for any\n"
"# of its IP addresses. Specify the minimum number of IP addresses a\n"
"# host must have before applying this test; zero to disable.\n"
"#"
;

static const char usage_uri_ip_in_name[] =
  "For each URI, apply a pattern heuristic to the host's name and reject\n"
"# if it looks like it is composed from it's IP address.\n"
"#"
;

static const char usage_uri_ip_in_ns[] =
  "For each URI, apply a pattern heuristic to the host's NS server names\n"
"# and reject if any look like they are composed from their IP addresses.\n"
"#"
;

static const char usage_uri_reject_unknown[] =
  "Reject any URI host/domain that does not exist.\n"
"#"
;

static const char usage_uri_reject_on_timeout[] =
  "Reject any URI host/domain that times out while looking up DNS A records.\n"
"#"
;

static const char usage_uri_ns_nxdomain[] =
  "Reject if a URI's NS host is in a non-existant domain."
;

#ifndef ENABLE_PDQ
static const char usage_uri_ip_in_ptr[] =
  "For each URI, lookup the host's IP addresses followed by each IP's\n"
"# PTR record. Apply a pattern heuristic to each PTR record and reject\n"
"# if it looks like the PTR is composed from the IP address. Specify the\n"
"# minimum number of IP addresses a host must have before applying this\n"
"# test; zero to disable.\n"
"#"
;

Option optUriIpInPtr		= { "uri-ip-in-ptr",		"0",		usage_uri_ip_in_ptr };
Stats stat_uri_ip_in_ptr	= { STATS_TABLE_MSG, 	"uri-ip-in-ptr"};
#endif

Option optUriIpInName		= { "uri-ip-in-name",		"-",		usage_uri_ip_in_name };
Option optUriIpInNs		= { "_uri-ip-in-ns",		"-",		usage_uri_ip_in_ns };
Option optUriNsNxDomain		= { "_uri-ns-nxdomain",		"-",		usage_uri_ns_nxdomain };
Option optUriRejectUnknown	= { "uri-reject-unknown",	"-",		usage_uri_reject_unknown };
Option optUriRejectOnTimeout	= { "uri-reject-on-timeout",	"-",		usage_uri_reject_on_timeout };
Option optUriRequireDomain	= { "uri-require-domain",	"-",		usage_uri_require_domain };
Option optUriRequirePtr		= { "uri-require-ptr",		"0",		usage_uri_require_ptr };

static const char usage_uri_cite_list[] =
  "When enabled, URI BL based rejection will cite the black list used.\n"
"#"
;

Option optUriCiteList		= { "uri-cite-list",		"+",		usage_uri_cite_list };

#ifdef BEING_CONSIDERED
static const char usage_uri_munge[] =
  "When enabled, URI found in messages will have the dots within the\n"
"# domain name replaced by semi-colons. For URI, such as data:, cid:, and\n"
"# javascript:, they are disabled by replacing the colon by semi-colon.\n"
"#"
;

Option optUriMunge		= { "uri-munge",		"-",		usage_uri_munge };
#endif

Stats stat_uri_bl			= { STATS_TABLE_MSG,	"uri-bl"};
Stats stat_uri_dns_bl			= { STATS_TABLE_MSG,	"uri-dns-bl" };
Stats stat_uri_bl_helo			= { STATS_TABLE_CONNECT,"uri-bl-helo" };
Stats stat_uri_bl_ptr			= { STATS_TABLE_CONNECT,"uri-bl-ptr" };
Stats stat_uri_bl_mail			= { STATS_TABLE_MAIL,	"uri-bl-mail" };
Stats stat_uri_ip_in_name		= { STATS_TABLE_MSG, 	"uri-ip-in-name"};
Stats stat_uri_ip_in_ns			= { STATS_TABLE_MSG, 	"_uri-ip-in-ns"};
Stats stat_uri_links_policy		= { STATS_TABLE_MSG, 	"uri-links-policy"};
#ifdef CONFUSING
Stats stat_uri_max_limit		= { STATS_TABLE_MSG, 	"uri-max-limit"};
#endif
Stats stat_uri_max_test			= { STATS_TABLE_MSG, 	"uri-max-test"};
Stats stat_uri_ns_nxdomain		= { STATS_TABLE_MSG,	"_uri-ns-nxdomain" };
Stats stat_uri_reject_on_timeout	= { STATS_TABLE_MSG, 	"uri-reject-on-timeout"};
Stats stat_uri_reject_unknown		= { STATS_TABLE_MSG, 	"uri-reject-unknown"};
Stats stat_uri_require_domain		= { STATS_TABLE_MSG, 	"uri-require-domain"};
Stats stat_uri_require_ptr		= { STATS_TABLE_MSG, 	"uri-require-ptr"};
Stats stat_uri_valid_soa		= { STATS_TABLE_MSG, 	"uri-valid-soa"};
Stats stat_uri_soa_error		= { STATS_TABLE_MSG, 	"uri-soa-error"};

typedef struct {
	int policy;
	Mime *mime;
	Vector uri_seen;
	Vector uri_ns_seen;
	Vector uri_mail_seen;
#ifdef CONFUSING
	unsigned uri_count;
#endif
	unsigned distinct_uri_tested;
} Uribl;

static FilterContext uribl_context;

/***********************************************************************
 ***
 ***********************************************************************/

static DnsList *ns_bl;
static DnsList *uri_bl;
static DnsList *mail_bl;
static DnsList *uri_dns_bl;
static Vector mail_domains;

int
uriblInit(Session *null, va_list ignore)
{
	LOG_TRACE0(000, uriblInit);

	mail_domains = TextSplit(optMailBlDomains.string, ";, ", 0);

	uri_dns_bl = dnsListCreate(optUriDnsBL.string);
	mail_bl = dnsListCreate(optMailBl.string);
	uri_bl = dnsListCreate(optUriBL.string);
	ns_bl = dnsListCreate(optNsBL.string);

	return SMTPF_CONTINUE;
}

int
uriblFini(Session *null, va_list ignore)
{
	LOG_TRACE0(000, uriblFini);

	dnsListFree(uri_dns_bl);
	dnsListFree(mail_bl);
	dnsListFree(uri_bl);
	dnsListFree(ns_bl);

	return SMTPF_CONTINUE;
}

int
uriCheckIp(Session *sess, const char *host)
{
	PDQ_rr *list, *rr, *plist;
	int rc, missing_ptr, a_count, rcode;
	Uribl *ctx = filterGetContext(sess, uribl_context);

	rc = SMTPF_CONTINUE;

	if (indexValidTLD(host) < 0)
		return SMTPF_CONTINUE;

#ifdef SIMILAR_URI_REQUIRE_DOMAIN
	if (isNxDomain(sess, host)) {
		snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI host %s in non-existant domain" ID_MSG(740), host, ID_ARG(sess));
/*{REPLY
}*/
		ctx->policy = *optUriBlPolicy.string;
		statsCount(&stat_uri_ns_nxdomain);
		rc = SMTPF_REJECT;
		goto error0;
	}
#endif

	if ((optUriIpInNs.value || optUriNsNxDomain.value)
	&& (list = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_NS, host, NULL)) != NULL) {
		for (rr = list; rr != NULL; rr = rr->next) {
			if (rr->rcode != PDQ_RCODE_OK)
				continue;

			if (optUriIpInNs.value && rr->type == PDQ_TYPE_A
			&& isIPv4InClientName(rr->name.string.value, ((PDQ_A *) rr)->address.ip.value+IPV6_OFFSET_IPV4)) {
				snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI domain %s where NS %s contains IP %s in name" ID_MSG(741), host, rr->name.string.value, ((PDQ_A *) rr)->address.string.value, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_ip_in_ns">uri-ip-in-ns</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
				if (0 < verb_uri.option.value)
					syslog(LOG_DEBUG, LOG_MSG(742) "%s", LOG_ARGS(sess), sess->msg.reject);
				ctx->policy = *optUriBlPolicy.string;
				statsCount(&stat_uri_ip_in_ns);
				rc = SMTPF_REJECT;
				goto error0;
			}

			if (optUriNsNxDomain.value && rr->type == PDQ_TYPE_NS
			&& isNxDomain(sess, ((PDQ_NS *) rr)->host.string.value) == SMTPF_REJECT) {
				snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI domain %s where NS %s in non-existant domain" ID_MSG(743), host, ((PDQ_NS *) rr)->host.string.value, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_ns_nxdomain">uri-ns-nxdomain</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
				ctx->policy = *optUriBlPolicy.string;
				statsCount(&stat_uri_ns_nxdomain);
				rc = SMTPF_REJECT;
				goto error0;
			}
		}

		pdqFree(list);
	}

	list = pdqGet5A(sess->pdq, PDQ_CLASS_IN, host);
	rcode = list == NULL ? PDQ_RCODE_ERRNO : list->type;

	if (list == NULL && errno != 0) {
		if (optUriRejectOnTimeout.value && errno == ETIMEDOUT) {
			statsCount(&stat_uri_reject_on_timeout);
			snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI domain %s lookup timeout" ID_MSG(744), host, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_reject_on_timeout">uri-reject-on-timeout</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
			ctx->policy = *optUriBlPolicy.string;
			rc = SMTPF_REJECT;
		}
		goto error0;
	}

	if (rcode != PDQ_RCODE_OK) {
		if (optUriRejectUnknown.value) {
			statsCount(&stat_uri_reject_unknown);
			snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI domain %s does not exist (%s)" ID_MSG(745), host, ID_ARG(sess), pdqRcodeName(rcode));
/*{REPLY
See <a href="summary.html#opt_uri_reject_unknown">uri-reject-unknown</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
			ctx->policy = *optUriBlPolicy.string;
			rc = SMTPF_REJECT;
		}
		goto error0;
	}

	/* Count the number of A records in the result. Remember
	 * the list might include a chain of CNAME records
	 * leading up to the actual A records.
	 */
	a_count = 0;
	for (rr = list; rr != NULL; rr = rr->next) {
		if (rr->type == PDQ_TYPE_A || rr->type == PDQ_TYPE_AAAA)
			a_count++;
	}

	missing_ptr = 0;
	for (rr = list; rr != NULL; rr = rr->next) {
		if (rr->type != PDQ_TYPE_A && rr->type != PDQ_TYPE_AAAA)
			continue;

		/* Do any of the A host names look like dynamic IP addresses?
		 *
		 * Apply this test only if the host has more than one assigned
		 * IP address. This will allow for dyndns hosted web sites by
		 * peasants, but catch fast-flux web sites that tend to have
		 * many IPs assigned.
		 */
		if (optUriIpInName.value && rr->type == PDQ_TYPE_A && 1 < a_count
		&& isIPv4InClientName(rr->name.string.value, ((PDQ_A *) rr)->address.ip.value+IPV6_OFFSET_IPV4)) {
			snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI host %s contains IP %s in %s" ID_MSG(746), host, ((PDQ_A *) rr)->address.string.value, rr->name.string.value, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_ip_in_name">uri-ip-in-name</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
			if (0 < verb_uri.option.value)
				syslog(LOG_DEBUG, LOG_MSG(747) "%s", LOG_ARGS(sess), sess->msg.reject);
			ctx->policy = *optUriBlPolicy.string;
			statsCount(&stat_uri_ip_in_name);
			rc = SMTPF_REJECT;
			goto error0;
		}

		plist = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_PTR, ((PDQ_AAAA *) rr)->address.string.value, NULL);
		rcode = plist == NULL ? PDQ_RCODE_ERRNO : plist->type;
		pdqFree(plist);

		if (rcode != PDQ_RCODE_OK)
			missing_ptr++;
	}

	/* Apply this test only if the host has at least a minimum
	 * web sites by peasants, but catch fast-flux web sites that
	 * tend to have many IPs assigned.
	 */
	if (missing_ptr && 0 < optUriRequirePtr.value && optUriRequirePtr.value <= a_count) {
		snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URL host %s is missing a PTR" ID_MSG(748), host, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_require_ptr">uri-require-ptr</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
		if (0 < verb_uri.option.value)
			syslog(LOG_DEBUG, LOG_MSG(749) "%s", LOG_ARGS(sess), sess->msg.reject);
		ctx->policy = *optUriBlPolicy.string;
		statsCount(&stat_uri_require_ptr);
		rc = SMTPF_REJECT;
	}
error0:
	pdqFree(list);

	return rc;
}

static void
setRejectMessage(Session *sess, const char *name, const char *list_name, int post_data, int msg_flag, Stats *stat)
{
	Uribl *ctx = filterGetContext(sess, uribl_context);

	snprintf(sess->msg.reject, sizeof (sess->msg.reject), "black listed %s by %s" ID_NUM(762), name, list_name);
/*{REPLY
See
<a href="summary.html#opt_ns_bl">ns-bl</a>,
<a href="summary.html#opt_uri_bl">uri-bl</a>,
<a href="summary.html#opt_uri_dns_bl">uri-dns-bl</a>,
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
	ctx->policy = *optUriBlPolicy.string;

	if (post_data) {
		MSG_SET(sess, msg_flag);
		statsCount(stat);
	}
}

int
mailBlLookup(Session *sess, const char *mail, Stats *stat)
{
	const char *list_name;
	Uribl *ctx = filterGetContext(sess, uribl_context);

	if (optMailBlMax.value <= VectorLength(ctx->uri_mail_seen))
		return SMTPF_CONTINUE;

	if ((list_name = dnsListQueryMail(mail_bl, sess->pdq, mail_domains, ctx->uri_mail_seen, mail)) != NULL) {
		statsCount(stat);
		ctx->policy = *optMailBlPolicy.string;
		dnsListSysLog(sess, "mail-bl", mail, list_name);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "550 5.7.1 rejected mail address, <%s> black listed by %s" ID_MSG(940) "\r\n", mail, list_name, ID_ARG(sess));
	}

	return SMTPF_CONTINUE;
}

int
uriblTestURI(Session *sess, URI *uri, int post_data)
{
	long i;
	char *value = NULL;
	URI *origin = NULL;
	int origin_is_different, access, rc = SMTPF_REJECT;
	Uribl *ctx = filterGetContext(sess, uribl_context);
	const char *error, *body_tag, *msg, *host, *list_name;

	if (uri == NULL || ctx->policy != '\0')
		return SMTPF_CONTINUE;

	if (uri->host == NULL || (indexValidTLD(uri->host) <= 0 && spanIP(uri->host) <= 0))
		goto ignore0;

	/* Session cache for previously tested hosts/domains. */
	for (i = 0; i < VectorLength(ctx->uri_seen); i++) {
		if ((host = VectorGet(ctx->uri_seen, i)) == NULL)
			continue;

		if (TextInsensitiveCompare(uri->host, host) == 0)
			goto ignore0;
	}

	/* Number of distinct URI tested. */
	ctx->distinct_uri_tested++;

	/* Be sure to apply the correct access lookup. */
	if (0 < spanIP(uri->host)) {
		access = accessClient(sess, "body:", NULL, body_tag = uri->host, NULL, &value, 1);
	} else if (uriGetSchemePort(uri) == 25) {
		access = accessEmail(sess, "body:", body_tag = uri->uriDecoded, NULL, &value);
	} else {
		access = accessClient(sess, "body:", body_tag = uri->host, NULL, NULL, &value, 1);
	}

	msg = NULL;
	if (value != NULL && (msg = strchr(value, ':')) != NULL)
		msg++;

	switch (access) {
	case SMDB_ACCESS_ERROR:
		break;
	case SMDB_ACCESS_REJECT:
		snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI %s %s" ID_NUM(763), body_tag, msg == NULL ? "black listed" : msg);
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_body"><span class="tag">Body:</span></a> tag.
}*/
		goto error0;
	case SMDB_ACCESS_OK:
		if (verb_info.option.value) {
			syslog(LOG_INFO, LOG_MSG(764) "URI %s %s", LOG_ARGS(sess), body_tag, msg == NULL ? "white listed" : msg);
/*{LOG
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_body"><span class="tag">Body:</span></a> tag.
}*/
		}
		goto ignore1;
	}

	if (post_data && optUriRequireDomain.value && uri->schemeInfo != NULL && 0 < spanIP(uri->host)) {
		snprintf(sess->msg.reject, sizeof (sess->msg.reject), "host is an IP in URL %s" ID_NUM(765), uri->uri);
/*{REPLY
See <a href="summary.html#opt_uri_require_domain">uri-require-domain</a>
and <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a>
options.
}*/
		ctx->policy = *optUriBlPolicy.string;
		statsCount(&stat_uri_require_domain);
		goto error0;
	}

	if (post_data && uriCheckIp(sess, uri->host) != SMTPF_CONTINUE)
		goto error0;

	/* Test and follow redirections so verify that the link returns something valid. */
	if (post_data && *optUriLinksPolicy.string != 'n' && (error = uriHttpOrigin(uri->uri, &origin)) != NULL) {
		if (error == uriErrorNotHttp || error == uriErrorPort)
			goto ignore0;

		snprintf(sess->msg.reject, sizeof (sess->msg.reject), "broken URL \"%s\": %s" ID_NUM(766), uri->uri, error);
/*{REPLY
See <a href="summary.html#opt_uri_links_policy">uri-links-policy</a> option.
}*/
		ctx->policy = *optUriLinksPolicy.string;
		if (post_data)
			statsCount(&stat_uri_links_policy);
		goto error0;
	}

	if (*optUriBlPolicy.string == 'n')
		goto ignore1;

	origin_is_different = origin != NULL && origin->host != NULL && strcmp(uri->host, origin->host) != 0;

	if ((list_name = dnsListQuery(uri_bl, sess->pdq, ctx->uri_seen, optUriSubDomains.value, uri->host)) != NULL) {
		setRejectMessage(sess, uri->host, list_name, post_data, MSG_IS_URIBL, &stat_uri_bl);
		dnsListSysLog(sess, "uri-bl", uri->host, list_name);
		goto error1;
	}
	if (origin_is_different && (list_name = dnsListQuery(uri_bl, sess->pdq, ctx->uri_seen, optUriSubDomains.value, origin->host)) != NULL) {
		setRejectMessage(sess, origin->host, list_name, post_data, MSG_IS_URIBL, &stat_uri_bl);
		dnsListSysLog(sess, "uri-bl", origin->host, list_name);
		goto error1;
	}

	if ((list_name = dnsListQueryIP(uri_dns_bl, sess->pdq, NULL, uri->host)) != NULL) {
		setRejectMessage(sess, uri->host, list_name, post_data, MSG_IS_URIBL, &stat_uri_dns_bl);
		dnsListSysLog(sess, "uri-dns-bl", uri->host, list_name);
		goto error1;
	}
	if (origin_is_different && (list_name = dnsListQueryIP(uri_dns_bl, sess->pdq, NULL, origin->host)) != NULL) {
		setRejectMessage(sess, origin->host, list_name, post_data, MSG_IS_URIBL, &stat_uri_dns_bl);
		dnsListSysLog(sess, "uri-dns-bl", origin->host, list_name);
		goto error1;
	}
ignore1:
	(void) VectorAdd(ctx->uri_seen, strdup(uri->host));
ignore0:
	rc = SMTPF_CONTINUE;
error1:
	free(origin);
error0:
	if (verb_trace.option.value || verb_uri.option.value)
		syslog(LOG_DEBUG, LOG_MSG(767) "uriblTestURI(%lx, \"%s\", %d) rc=%d reply='%s'", LOG_ARGS(sess), (long) sess, uri->uri, post_data, rc, sess->msg.reject);
	free(value);

	return rc;
}

static int
testList(Session *sess, char *query, const char *delim)
{
	URI *uri;
	int i, rc;
	Vector args;
	char *arg, *ptr;

	if (query == NULL)
		return SMTPF_CONTINUE;

	args = TextSplit(query, delim, 0);

	for (rc = SMTPF_CONTINUE, i = 0; rc == SMTPF_CONTINUE && i < VectorLength(args); i++) {
		if ((arg = VectorGet(args, i)) == NULL)
			continue;

		/* Skip leading symbol name and equals sign. */
		for (ptr = arg; *ptr != '\0'; ptr++) {
			if (!isalnum(*ptr) && *ptr != '_') {
				if (*ptr == '=')
					arg = ptr+1;
				break;
			}
		}

		uri = uriParse2(arg, -1, 2);
		rc = uriblTestURI(sess, uri, 1);
		free(uri);
	}

	VectorDestroy(args);

	return rc;
}

int
uriblOptn(Session *null, va_list ignore)
{
	uriSetTimeout(optHttpTimeout.value * 1000);

	if (optUriValidSoa.value == 2) {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, "/tmp");
	}

	return SMTPF_CONTINUE;
}

int
uriRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_uri);

	optionsRegister(&optHttpTimeout, 		0);
	optionsRegister(&optUriBL, 			1);
	optionsRegister(&optUriBlHelo, 			0);
	optionsRegister(&optUriBlHeaders,		0);
	optionsRegister(&optUriBlMail, 			0);
	optionsRegister(&optUriBlPolicy, 		0);
	optionsRegister(&optUriBlPtr, 			0);
	optionsRegister(&optUriCiteList,		0);
	optionsRegister(&optUriDnsBL, 			1);
	optionsRegister(&optUriIpInName,		0);
	optionsRegister(&optUriIpInNs,			0);
#ifndef ENABLE_PDQ
	optionsRegister(&optUriIpInPtr,			0);
#endif
	optionsRegister(&optUriLinksPolicy, 		0);
#ifdef CONFUSING
	optionsRegister(&optUriMaxLimit, 		0);
#endif
	optionsRegister(&optUriMaxTest, 		0);
	optionsRegister(&optUriNsNxDomain, 		0);
	optionsRegister(&optUriRejectOnTimeout,		0);
	optionsRegister(&optUriRejectUnknown,		0);
	optionsRegister(&optUriRequireDomain,		0);
	optionsRegister(&optUriRequirePtr,		0);
	optionsRegister(&optUriSubDomains, 		0);
	optionsRegister(&optUriValidSoa,		0);

	optionsRegister(&optMailBl, 			1);
	optionsRegister(&optMailBlDomains,		1);
	optionsRegister(&optMailBlHeaders, 		0);
	optionsRegister(&optMailBlMax, 			0);
	optionsRegister(&optMailBlPolicy,		0);

	optionsRegister(&optNsBL, 			1);
	optionsRegister(&optNsSubDomains, 		0);

	(void) statsRegister(&stat_mail_bl_mail);
	(void) statsRegister(&stat_mail_bl_hdr);
	(void) statsRegister(&stat_mail_bl_body);

	(void) statsRegister(&stat_ns_bl_ptr);
	(void) statsRegister(&stat_ns_bl_uri);
	(void) statsRegister(&stat_ns_bl_mail);

	(void) statsRegister(&stat_uri_bl_helo);
	(void) statsRegister(&stat_uri_bl_ptr);

	(void) statsRegister(&stat_uri_bl_mail);

	(void) statsRegister(&stat_uri_bl);
	(void) statsRegister(&stat_uri_dns_bl);
	(void) statsRegister(&stat_uri_ip_in_name);
	(void) statsRegister(&stat_uri_ip_in_ns);
#ifndef ENABLE_PDQ
	(void) statsRegister(&stat_uri_ip_in_ptr);
#endif
	(void) statsRegister(&stat_uri_links_policy);
#ifdef CONFUSING
	(void) statsRegister(&stat_uri_max_limit);
#endif
	(void) statsRegister(&stat_uri_max_test);
	(void) statsRegister(&stat_uri_ns_nxdomain);
	(void) statsRegister(&stat_uri_reject_on_timeout);
	(void) statsRegister(&stat_uri_reject_unknown);
	(void) statsRegister(&stat_uri_require_domain);
	(void) statsRegister(&stat_uri_require_ptr);
	(void) statsRegister(&stat_uri_valid_soa);
	(void) statsRegister(&stat_uri_soa_error);

	uribl_context = filterRegisterContext(sizeof (Uribl));

	return SMTPF_CONTINUE;
}

int
uriblConnect(Session *sess, va_list ignore)
{
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 779, uriblConnect);

	ctx->policy = '\0';

	if ((ctx->uri_seen = VectorCreate(10)) != NULL)
		VectorSetDestroyEntry(ctx->uri_seen, free);

	if ((ctx->uri_ns_seen = VectorCreate(10)) != NULL)
		VectorSetDestroyEntry(ctx->uri_ns_seen, free);

	if ((ctx->uri_mail_seen = VectorCreate(10)) != NULL)
		VectorSetDestroyEntry(ctx->uri_mail_seen, free);

	ctx->policy = '\0';

	return SMTPF_CONTINUE;
}

int
uriblData(Session *sess, va_list ignore)
{
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 780, uriblData);

	*sess->msg.reject = '\0';

#ifdef CONFUSED
	ctx->uri_count = 0;
#endif
	ctx->policy = '\0';
	ctx->distinct_uri_tested = 0;
	ctx->mime = uriMimeCreate(0);

	return SMTPF_CONTINUE;
}

static int
uriblNs(Session *sess, const char *host, Stats *stat)
{
	const char *list_name;
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 787, uriblNs);

	if (*optNsBL.string == '\0'|| host == NULL || *host == '\0')
		return SMTPF_CONTINUE;

	if ((list_name = dnsListQueryNs(ns_bl, sess->pdq, ctx->uri_ns_seen, host)) != NULL) {
		setRejectMessage(sess, host, list_name, 0, 0, stat);
		statsCount(stat);
		return SMTPF_REJECT;
	}

	return SMTPF_CONTINUE;
}

static int
uriblCheckUri(Session *sess, URI *uri)
{
	PDQ_valid_soa code;
	int rc = SMTPF_CONTINUE;
	Uribl *ctx = filterGetContext(sess, uribl_context);

	if (uri != NULL && uri->host != NULL
	&& (0 < indexValidTLD(uri->host) || 0 < spanIP(uri->host))
	) {
		if (1 < verb_uri.option.value)
			syslog(LOG_DEBUG, LOG_MSG(892) "uriDecoded=%s", LOG_ARGS(sess), uri->uriDecoded);

#ifdef CONFUSING
		if (0 < optUriMaxLimit.value && optUriMaxLimit.value <= ctx->uri_count++) {
			(void) snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI per message limit exceeded" ID_MSG(781) "\r\n", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_max_limit">uri-max-limit</a> option.
}*/
			statsCount(&stat_uri_max_limit);
			ctx->policy = 'r';
			rc = SMTPF_REJECT;
		} else
#endif
		if (0 < optUriMaxTest.value && optUriMaxTest.value <= ctx->distinct_uri_tested) {
			statsCount(&stat_uri_max_test);
			/* Break out of loop. */
			rc = SMTPF_SKIP_REMAINDER;

			if (0 < verb_uri.option.value) {
				char **host;

				for (host = (char **) VectorBase(ctx->uri_seen); *host != NULL; host++) {
					syslog(LOG_DEBUG, LOG_MSG(918) "uri-max-test host=%s", LOG_ARGS(sess), *host);
				}

				syslog(LOG_DEBUG, LOG_MSG(893) "uri-max-test reached skipping host=%s", LOG_ARGS(sess), uri->host);
			}
		} else if ((rc = uriblTestURI(sess, uri, 1)) == SMTPF_CONTINUE) {
			if (uriblNs(sess, uri->host, &stat_ns_bl_uri) != SMTPF_CONTINUE)
				return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 rejected URI NS, %s" ID_MSG(894) "\r\n", sess->msg.reject, ID_ARG(sess));

			/* Check for redirected URL in query string or path. */
			if (uri->query == NULL) {
				rc = testList(sess, uri->path, "&");
			} else {
				rc = testList(sess, uri->query, "&");
				if (rc == SMTPF_CONTINUE)
					rc = testList(sess, uri->query, "/");
			}
			if (rc == SMTPF_CONTINUE)
				rc = testList(sess, uri->path, "/");

			if (rc == SMTPF_CONTINUE && optUriValidSoa.value
			&& (code = pdqTestSOA(sess->pdq, PDQ_CLASS_IN, uri->host, NULL)) != PDQ_SOA_OK) {
				if (optUriValidSoa.value == 2)
					MSG_SET(sess, MSG_SAVE);

				if (code == PDQ_SOA_MISSING) {
					statsCount(&stat_uri_soa_error);
#ifdef VERSION1
					return replyPushFmt(sess, SMTPF_REJECT, "450 4.7.1 URI %s SOA lookup error" ID_MSG(919) "\r\n", uri->host, ID_ARG(sess));
#else
/* Disable the temporary failure for no SOA. Some DNS
 * servers consistently return SERVFAIL for sites like
 * prc.it and worldsites.mc, while the same query else
 * where (for prc.it) appears to work. Possibly a negative
 * caching problem with some DNS servers.
 */
					return SMTPF_CONTINUE;
#endif
				}

				snprintf(sess->msg.reject, sizeof (sess->msg.reject), "URI %s invalid SOA (%d)" ID_NUM(000), uri->host, code);
				statsCount(&stat_uri_valid_soa);
				ctx->policy = 'r';
				rc = SMTPF_REJECT;
			}
		}

		if (rc == SMTPF_REJECT) {
			/* Set immediate reply now to take advantage of the
			 * replyContent and replyDot filter table short-circuit.
			 */
			(void) replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 rejected content, %s" ID_MSG(895) "\r\n", sess->msg.reject, ID_ARG(sess));
		}
	}

	return rc;
}

static int
uriCheckString(Session *sess, const char *value)
{
	int rc;
	URI *uri;
	Mime *mime;

	if (1 < verb_uri.option.value)
		syslog(LOG_DEBUG, LOG_MSG(896) "uriCheckString value=\"%s\"", LOG_ARGS(sess), value);

	if ((mime = uriMimeCreate(0)) == NULL)
		return SMTPF_CONTINUE;

	mimeHeadersFirst(mime, 0);

	for (rc = SMTPF_CONTINUE; rc == SMTPF_CONTINUE && *value != '\0'; value++) {
		if (mimeNextCh(mime, *value))
			break;

		if ((uri = uriMimeGetUri(mime)) != NULL) {
			rc = uriblCheckUri(sess, uri);
			uriMimeFreeUri(mime);
		}
	}

	uriMimeFree(mime);

	return rc;
}

static int
mailBlCheckString(Session *sess, const char *value)
{
	int rc;
	URI *uri;
	Mime *mime;

	if (1 < verb_uri.option.value)
		syslog(LOG_DEBUG, LOG_MSG(941) "mailBlCheckString value=\"%s\"", LOG_ARGS(sess), value);

	if ((mime = uriMimeCreate(0)) == NULL)
		return SMTPF_CONTINUE;

	mimeHeadersFirst(mime, 0);

	for (rc = SMTPF_CONTINUE; rc == SMTPF_CONTINUE && *value != '\0'; value++) {
		if (mimeNextCh(mime, *value))
			break;

		if ((uri = uriMimeGetUri(mime)) != NULL) {
			rc = mailBlLookup(sess, uri->uriDecoded, &stat_mail_bl_hdr);
			uriMimeFreeUri(mime);
		}
	}

	uriMimeFree(mime);

	return rc;
}

int
uriblHeaders(Session *sess, va_list args)
{
	int rc;
	long i, length;
	char *hdr, **table;
	Vector headers, uri_hdrs, mail_hdrs;
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 897, uriblHeaders);

	/* We run the headers through the URI MIME parser in order to
	 * setup the correct state for MIME boundaries and content
	 * type.
	 */
	headers = va_arg(args, Vector);
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		while (*hdr != '\0') {
			if (mimeNextCh(ctx->mime, *hdr++))
				break;
			uriMimeFreeUri(ctx->mime);
		}
	}

	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS))
		return SMTPF_CONTINUE;

	uri_hdrs = TextSplit(optUriBlHeaders.string, ";, ", 0);
	mail_hdrs = TextSplit(optMailBlHeaders.string, ";, ", 0);

	if (uri_hdrs == NULL && mail_hdrs == NULL)
		return SMTPF_CONTINUE;

	rc = SMTPF_CONTINUE;
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		for (table = (char **) VectorBase(uri_hdrs); *table != NULL; table++) {
			if (0 < (length = TextInsensitiveStartsWith(hdr, *table)) && hdr[length] == ':') {
				if (verb_uri.option.value)
					syslog(LOG_DEBUG, LOG_MSG(898) "uri-bl-headers hdr=\"%s\"", LOG_ARGS(sess), hdr);

				if ((rc = uriCheckString(sess, hdr + length + 1)) != SMTPF_CONTINUE)
					goto done;
			}
		}

		for (table = (char **) VectorBase(mail_hdrs); *table != NULL; table++) {
			if (0 < (length = TextInsensitiveStartsWith(hdr, *table)) && hdr[length] == ':') {
				if (verb_uri.option.value)
					syslog(LOG_DEBUG, LOG_MSG(942) "mail-bl-headers hdr=\"%s\"", LOG_ARGS(sess), hdr);

				if ((rc = mailBlCheckString(sess, hdr + length + 1)) != SMTPF_CONTINUE)
					goto done;
			}
		}
	}
done:
	VectorDestroy(mail_hdrs);
	VectorDestroy(uri_hdrs);

	return rc;
}

int
uriblContent(Session *sess, va_list args)
{
	int rc;
	URI *uri;
	long size;
	unsigned char *stop;
	unsigned char *chunk;
	Uribl *ctx = filterGetContext(sess, uribl_context);

	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(783) "uriblContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	if (ctx->mime == NULL)
		return SMTPF_CONTINUE;

	for (stop = chunk + size; chunk < stop; chunk++) {
		if (mimeNextCh(ctx->mime, *chunk))
			break;

		if ((uri = uriMimeGetUri(ctx->mime)) != NULL) {
			rc = uriblCheckUri(sess, uri);

			if (rc == SMTPF_CONTINUE && uriGetSchemePort(uri) == 25)
				rc = mailBlLookup(sess, uri->uriDecoded, &stat_mail_bl_body);

			uriMimeFreeUri(ctx->mime);

			if (rc == SMTPF_SKIP_REMAINDER)
				break;

			if (rc != SMTPF_CONTINUE) {
				MSG_SET(sess, MSG_POLICY);
				return rc;
			}

			keepAlive(sess);
		}
	}

#ifdef FILTER_URIBL_CONTENT_SHORTCUT
	/* As an optimisation concerning spamd, when we see the
	 * final dot in a chunk, then call dot handler immediately,
	 * instead of in the dot handler phase. So if the entire
	 * message fits in the first chunk, we can avoid connecting
	 * to spamd entirely, which is last in filter_content_table.
	 */
	if (sess->msg.seen_final_dot)
		return uriblDot(sess, NULL);
#endif

	return SMTPF_CONTINUE;
}

int
uriblDot(Session *sess, va_list ignore)
{
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 784, uriblDot);

	if (ctx->policy == 'd') {
		syslog(LOG_ERR, LOG_MSG(785) "discarded: %s", LOG_ARGS(sess), sess->msg.reject);
/*{LOG
See <a href="summary.html#opt_uri_bl_policy">uri-bl-policy</a> option.
}*/
		return SMTPF_DISCARD;
	}

	return SMTPF_CONTINUE;
}

int
uriblRset(Session *sess, va_list ignore)
{
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 899, uriblRset);
	uriMimeFree(ctx->mime);
	ctx->mime = NULL;

	return SMTPF_CONTINUE;
}

int
uriblClose(Session *sess, va_list ignore)
{
	Uribl *ctx = filterGetContext(sess, uribl_context);

	LOG_TRACE(sess, 786, uriblClose);

	VectorDestroy(ctx->uri_mail_seen);
	ctx->uri_mail_seen = NULL;

	VectorDestroy(ctx->uri_ns_seen);
	ctx->uri_ns_seen = NULL;

	VectorDestroy(ctx->uri_seen);
	ctx->uri_seen = NULL;

	uriMimeFree(ctx->mime);
	ctx->mime = NULL;

	return SMTPF_CONTINUE;
}

static int
uriblPtr(Session *sess)
{
	int rc;
	URI *uri;

	LOG_TRACE(sess, 789, uriblPtr);

	if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)) {
		if (optUriBlPtr.value && (uri = uriParse2(sess->client.name, -1, 1)) != NULL) {
			rc = uriblTestURI(sess, uri, 0);
			free(uri);

			if (rc == SMTPF_REJECT) {
				statsCount(&stat_uri_bl_ptr);
				return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 rejected client " CLIENT_FORMAT ", %s" ID_MSG(790) "\r\n", CLIENT_INFO(sess), sess->msg.reject, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_bl_ptr">uri-bl-ptr</a> option.
}*/
			}
		}

		rc = uriblNs(sess, sess->client.name, &stat_ns_bl_ptr);
		if (rc != SMTPF_CONTINUE)
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 rejected PTR NS, %s" ID_MSG(790) "\r\n", sess->msg.reject, ID_ARG(sess));
	}

	return SMTPF_CONTINUE;
}

int
uriblPtrConnect(Session *sess, va_list ignore)
{
	if (optAuthDelayChecks.value)
		return SMTPF_CONTINUE;

	return uriblPtr(sess);
}

int
uriblPtrMail(Session *sess, va_list args)
{
	if (!optAuthDelayChecks.value || CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH))
		return SMTPF_CONTINUE;

	return uriblPtr(sess);
}

static int
uriblHelo(Session *sess)
{
	int rc;
	URI *uri;

	LOG_TRACE(sess, 791, uriblHelo);

	if (optUriBlHelo.value && (uri = uriParse2(sess->client.helo, -1, 1)) != NULL) {
		rc = uriblTestURI(sess, uri, 0);
		free(uri);

		if (rc == SMTPF_REJECT) {
			statsCount(&stat_uri_bl_helo);
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 rejected HELO, %s" ID_MSG(792) "\r\n", sess->msg.reject, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_bl_helo">uri-bl-helo</a> option.
}*/
		}
	}

	return SMTPF_CONTINUE;
}

int
uriblHeloHelo(Session *sess, va_list ignore)
{
	if (optAuthDelayChecks.value)
		return SMTPF_CONTINUE;

	return uriblHelo(sess);
}

int
uriblHeloMail(Session *sess, va_list args)
{
	if (!optAuthDelayChecks.value || CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH))
		return SMTPF_CONTINUE;

	return uriblHelo(sess);
}

int
uriblMailMail(Session *sess, va_list args)
{
	int rc;
	URI *uri;
	ParsePath *mail = va_arg(args, ParsePath *);

	LOG_TRACE(sess, 793, uriblMailMail);

	if ((rc = mailBlLookup(sess, sess->msg.mail->address.string, &stat_mail_bl_mail)) != SMTPF_CONTINUE)
		return rc;

	if (optUriBlMail.value && 0 < mail->address.length && (uri = uriParse2(mail->domain.string, -1, 1)) != NULL) {
		rc = uriblTestURI(sess, uri, 0);
		free(uri);

		if (rc == SMTPF_REJECT) {
			statsCount(&stat_uri_bl_mail);
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_DROP, "550 5.7.1 rejected MAIL FROM, %s" ID_MSG(794) "\r\n", sess->msg.reject, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_uri_bl_mail">uri-bl-mail</a> option.
}*/
		}

		rc = uriblNs(sess, mail->domain.string, &stat_ns_bl_mail);
		if (rc != SMTPF_CONTINUE)
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_DROP, "550 5.7.1 rejected MAIL NS, %s" ID_MSG(900) "\r\n", sess->msg.reject, ID_ARG(sess));
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_URIBL */
