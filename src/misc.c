/*
 * misc.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

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
#include <com/snert/lib/io/Dns.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/util/convertDate.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_client_is_mx[] =
  "Weaken rejects based on client-ptr-required or client-ip-in-ptr\n"
"# until the sender address is known. Check if the connecting client\n"
"# passes SPF or is an MX for the sender and reject if it is not.\n"
"#"
;

static const char usage_client_ip_in_ptr[] =
  "Apply a pattern heuristic to the connected client's PTR record.\n"
"# Reject if it looks like it is composed from the client IP address.\n"
"# See also client-is-mx.\n"
"#"
;

static const char usage_client_ptr_required[] =
  "The connecting client IP address must have a PTR record. See also\n"
"# client-is-mx.\n"
"#"
;

static const char usage_helo_claims_us[] =
  "Drop any host that claims to be from a domain we are responsible\n"
"# for in the HELO/EHLO argument.\n"
"#"
;

static const char usage_helo_ip_mismatch[] =
  "Drop any host that specifies an IP address as the HELO argument\n"
"# that does not correspond to the connecting client's IP, excluding\n"
"# RFC 3330 IP addresses reserved for LANs.\n"
"#"
;

static const char usage_idle_retest_timer[] =
  "Periodically reapply some tests, such as dns-bl, on long running\n"
"# connections. Specify zero (0) to disable.\n"
"#"
;

static const char usage_rfc2821_strict_helo[] =
  "Strict RFC 2821 section 4.1.1.1 HELO argument must be a FQDN or\n"
"# ip-domain literal."
;

static const char usage_one_rcpt_per_null[] =
  "When the sender is MAIL FROM:<>, then there can only be one\n"
"# RCPT TO: specified since the null address is only used to return\n"
"# a Delivery Status Notification or Message Disposition Notification\n"
"# to the original sender and it is not possible to have two or more\n"
"# sender's for one message (in theory).\n"
"#"
;

static const char usage_helo_is_ptr[] =
  "If the HELO argument is the same as the PTR name and the PTR record\n"
"# is an instance of client IP-in-PTR, then reject the HELO command. See\n"
"# also client-is-mx.\n"
"#"
;

static const char usage_mail_retest_client[] =
  "If set, recheck the client IP every message transaction. A client's\n"
"# IP could be black listed locally or by a DNS BL during a message\n"
"# transaction and would be caught starting with the next transaction.\n"
"#"
;

Option optClientIsMx			= { "client-is-mx",		"-",	usage_client_is_mx };
Option optClientIpInPtr			= { "client-ip-in-ptr",		"-",	usage_client_ip_in_ptr };
Option optClientPtrRequired		= { "client-ptr-required",	"-",	usage_client_ptr_required };
Option optHeloClaimsUs			= { "helo-claims-us",		"+",	usage_helo_claims_us };
Option optHeloIpMismatch		= { "helo-ip-mismatch",		"-",	usage_helo_ip_mismatch };
Option optHeloIsPtr			= { "helo-is-ptr",		"-",	usage_helo_is_ptr };
Option optIdleRetestTimer		= { "idle-retest-timer",	"300",	usage_idle_retest_timer };
Option optOneRcptPerNull		= { "one-rcpt-per-null",	"+",	usage_one_rcpt_per_null };

static const char usage_one_domain_per_session[] =
  "If set, only permit mail from one sender domain per session. Mail\n"
"# from other domains will be temporarily rejected.\n"
"#"
;
Option optOneDomainPerSession		= { "one-domain-per-session",	"-",	usage_one_domain_per_session };

Option optMailRequireMx			= { "mail-require-mx",		"+",	"Reject if the sender's domain has no MX record." };
Option optMailRetestClient		= { "mail-retest-client",	"-",	usage_mail_retest_client };
Option optRFC2821StrictHelo		= { "rfc2821-strict-helo", 	"+", 	usage_rfc2821_strict_helo };

/* Keep these for lickey. */
static const char usage_smtp_command_pause[] =
  "SMTP Command Pause\n"
"#\n"
"# Delay SMTP command processing for a given number of milliseconds.\n"
"# If any data is received before the elapsed time, then drop the\n"
"# connection. When set to zero, allow RFC 2920 SMTP PIPELINING.\n"
"#\n"
"# The tag CommandPause: is a connection specific tag that can be used\n"
"# in the access-map. If a key is found, then the value is processed\n"
"# as a pattern list and the result returned. The number of milliseconds\n"
"# to pause is given in place of an action.\n"
"#\n"
;

static const char usage_smtp_greet_pause[] =
  "SMTP Greet Pause\n"
"#\n"
"# Delay the sending of the SMTP welcome message for a given number\n"
"# of milliseconds. If any data is received before the welcome message\n"
"# is sent, then reject the connection.\n"
"#\n"
"# The tag GreetPause: is a connection specific tag that can be used\n"
"# in the access-map. If a key is found, then the value is processed\n"
"# as a pattern list and the result returned. The number of milliseconds\n"
"# to pause is given in place of an action.\n"
"#\n"
;

Option optSmtpCommandPause 		= { "",			 	"0",	usage_smtp_command_pause };
Option optSmtpGreetPause		= { "",				NULL,	usage_smtp_greet_pause };

#ifdef FILTER_MISC

Stats stat_bogus_helo			= { STATS_TABLE_CONNECT, "bogus-helo" };
Stats stat_client_is_mx			= { STATS_TABLE_MAIL, "client-is-mx" };
Stats stat_client_ip_in_ptr		= { STATS_TABLE_CONNECT, "client-ip-in-ptr" };
Stats stat_client_ptr_required		= { STATS_TABLE_CONNECT, "client-ptr-required" };
Stats stat_client_ptr_required_error	= { STATS_TABLE_CONNECT, "client-ptr-required-error" };
Stats stat_helo_claims_us		= { STATS_TABLE_CONNECT, "helo-claims-us" };
Stats stat_helo_ip_mismatch		= { STATS_TABLE_CONNECT, "helo-ip-mismatch" };
Stats stat_helo_is_ptr			= { STATS_TABLE_CONNECT, "helo-is-ptr" };
Stats stat_helo_mail_params		= { STATS_TABLE_MAIL, "helo-mail-params" };
Stats stat_mail_require_mx		= { STATS_TABLE_MAIL, "mail-require-mx" };
Stats stat_mail_require_mx_error	= { STATS_TABLE_MAIL, "mail-require-mx-error" };
Stats stat_one_domain_per_session	= { STATS_TABLE_MAIL, "one-domain-per-session" };
Stats stat_helo_rcpt_params		= { STATS_TABLE_RCPT, "helo-rcpt-params" };
Stats stat_one_rcpt_per_null		= { STATS_TABLE_RCPT, "one-rcpt-per-null" };

Stats stat_smtp_command_pause		= { STATS_TABLE_CONNECT, "smtp-command-pause" };
Stats stat_smtp_greet_pause		= { STATS_TABLE_CONNECT, "smtp-greet-pause" };
Stats stat_rfc2821_strict_helo		= { STATS_TABLE_CONNECT, "rfc2821-strict-helo" };

/***********************************************************************
 ***
 ***********************************************************************/

int
miscInit(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}

static int
noPtr(Session *sess)
{
	LOG_TRACE(sess, 414, noPtr);

	/* client-is-mx softens the impact of client-ptr-required and
	 * client-ip-in-ptr in order to reduce possible false positives
	 * concerning legit mail servers on "dynamic" or residential ADSL.
	 * For example Claus Assmann operates sendmail.org from an ADSL
	 * with a static IP.
	 */
	if (optClientPtrRequired.value
	&& CLIENT_IS_SET(sess, CLIENT_HOLY_TRINITY|CLIENT_IS_MX|CLIENT_NO_PTR, CLIENT_NO_PTR)
#ifdef FILTER_SPF
	&& sess->msg.spf_mail != SPF_PASS
#endif
	) {
		if (CLIENT_ANY_SET(sess, CLIENT_NO_PTR_ERROR)) {
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_TEMPFAIL, "421 4.4.3 PTR record lookup error for [%s]" ID_MSG(415) CRLF, sess->client.addr, ID_ARG(sess));
/*{NEXT}*/
		} else {
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "554 5.7.1 reject [%s] missing PTR record" ID_MSG(416) CRLF, sess->client.addr, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_client_is_mx">client-is-mx</a>
and <a href="summary.html#opt_client_ptr_required">client-ptr-required</a> options.
}*/
		}
	}

	return SMTPF_CONTINUE;
}

int
noPtrConnect(Session *sess, va_list ignore)
{
	if (optAuthDelayChecks.value || optClientIsMx.value)
		return SMTPF_CONTINUE;

	return noPtr(sess);
}

int
noPtrMail(Session *sess, va_list args)
{
	if (!optAuthDelayChecks.value || CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH) || !optClientIsMx.value)
		return SMTPF_CONTINUE;

	return noPtr(sess);
}

static int
ipInPtr(Session *sess)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(417) "ipInPtr", LOG_ARGS(sess));

	/* client-is-mx softens the impact of client-ptr-required and
	 * client-ip-in-ptr in order to reduce possible false positives
	 * concerning legit mail servers on "dynamic" or residential ADSL.
	 * For example Claus Assmann operates sendmail.org from an ADSL
	 * with a static IP.
	 */
	if (optClientIpInPtr.value
#ifdef OLD
	&& CLIENT_NOT_SET(sess, CLIENT_IS_MX)
	&& CLIENT_ANY_SET(sess, CLIENT_IS_IP_IN_PTR)
#else
	&& CLIENT_IS_SET(sess, CLIENT_IS_MX|CLIENT_IS_IP_IN_PTR, CLIENT_IS_IP_IN_PTR)
#endif
#ifdef FILTER_SPF
	&& sess->msg.spf_mail != SPF_PASS
#endif
	) {
		statsCount(&stat_client_ip_in_ptr);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 reject IP in client name " CLIENT_FORMAT " (1)" ID_MSG(418) CRLF, CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_client_is_mx">client-is-mx</a>
and <a href="summary.html#opt_client_ip_in_ptr">client-ip-in-ptr</a> options.
}*/
	}

	return SMTPF_CONTINUE;
}

int
ipInPtrConnect(Session *sess, va_list ignore)
{
	if (optAuthDelayChecks.value || optClientIsMx.value)
		return SMTPF_CONTINUE;

	return ipInPtr(sess);
}

int
ipInPtrMail(Session *sess, va_list args)
{
	if (!optAuthDelayChecks.value || CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH) || !optClientIsMx.value)
		return SMTPF_CONTINUE;

	return ipInPtr(sess);
}

int
idleRetestIdle(Session *sess, va_list ignore)
{
	time_t now;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(421) "idleRetestIdle", LOG_ARGS(sess));

	now = time(NULL);

	if (optMailRetestClient.value && 0 < sess->client.forward_count)
		return SMTPF_CONTINUE;

	if (optIdleRetestTimer.value <= 0
	|| CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)
	|| now < sess->last_test + optIdleRetestTimer.value)
		return SMTPF_SKIP_REMAINDER;

	sess->last_test = now;

	return SMTPF_CONTINUE;
}

int
heloSyntaxHelo(Session *sess, va_list ignore)
{
	char *h, *stop;
	PDQ_rr *r1, *r2;
	size_t helo_length;
	unsigned long number;
	unsigned char helo_ipv6[IPV6_BYTE_LENGTH];

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(422) "heloSyntaxHelo", LOG_ARGS(sess));

	for (h = sess->client.helo; *h != '\0'; h++) {
		switch (*h) {
		case '.': case ':':
		case '-': case '_':
		case '[': case ']':
			break;
		default:
			if (!isalnum(*h)) {
				statsCount(&stat_bogus_helo);
				return replyPushFmt(sess, SMTPF_DROP, "501 5.5.4 invalid HELO %s" ID_MSG(423) CRLF, sess->client.helo, ID_ARG(sess));
/*{REPLY
The HELO or EHLO argument contains include characters in the string.
The set of valid characters are alpha-numerics, hyphen, underscore, square brackets, and dot.
There is no option to turn this test off.
}*/
			}
		}
	}

	helo_length = h - sess->client.helo;

	/* This allows for ip-domain-literal or bare-ip to appear as
	 * the HELO argument.
	 *
	 * TODO consider adding options to reject bare-ip ie. no square
	 * brackets, revisit & research again instances of bare-ip.
	 *
	 * TODO consider adding an option to reject if there is not at
	 * least one dot in the argument.
	 */
	CLIENT_CLEAR(sess, CLIENT_IS_HELO_IP);
	if (parseIPv6(sess->client.helo, helo_ipv6) == helo_length)
		CLIENT_SET(sess, CLIENT_IS_HELO_IP);

	if (CLIENT_NOT_SET(sess, CLIENT_IS_HELO_IP)) {
		/* Check if the HELO argument is a number in octal, decimal,
		 * or hexdecimal that could represent an IP address.
		 */
		number = strtol(sess->client.helo, &stop, 8);
		if (stop - sess->client.helo != helo_length) {
			number = strtol(sess->client.helo, &stop, 10);
			if (stop - sess->client.helo != helo_length)
				number = strtol(sess->client.helo, &stop, 16);
		}

		memset(helo_ipv6, 0, sizeof (helo_ipv6));

		if (stop - sess->client.helo == helo_length) {
			*(unsigned long *)(helo_ipv6+IPV6_OFFSET_IPV4) = htonl(number);
			CLIENT_SET(sess, CLIENT_IS_HELO_IP);
		}

		/* Does the HELO argument have a matching A record that
		 * is the same as the connected client IP address?
		 *
		 * TODO consider merging with is_forged check - looks very similar.
		 */
		r1 = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_A, sess->client.helo, NULL);
		r2 = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_AAAA, sess->client.helo, NULL);
		r1 = pdqListAppend(r1, r2);

		for (r2 = r1; r2 != NULL; r2 = r2->next) {
			if (r2->section != PDQ_SECTION_ANSWER)
				continue;
			if (TextInsensitiveCompare(sess->client.addr, ((PDQ_A *) r2)->address.string.value) == 0) {
				/* When a host has no PTR, but the
				 * HELO arg corresponds to the A/AAAA
				 * record of the client address, then
				 * we can use the HELO arg for the
				 * client.name and subsequently use
				 * it with the grey-list ptr key.
				 *
				 * It also aid with the HELO "claims
				 * to be us" test.
				 */
				if (CLIENT_ANY_SET(sess, CLIENT_NO_PTR))
					TextCopy(sess->client.name, sizeof (sess->client.name), sess->client.helo);
				CLIENT_SET(sess, CLIENT_IS_HELO_HOSTNAME);
				break;
			}
		}

		pdqFree(r1);
	}

	/* If the client connects from a public IP address and HELO's
	 * with a ip-domain-literal, then the client's address must
	 * match the HELO address.
	 */
	if (optHeloIpMismatch.value
	&& CLIENT_IS_SET(sess, CLIENT_IS_LAN|CLIENT_IS_HELO_IP, CLIENT_IS_HELO_IP)
	&& !isReservedIPv6(helo_ipv6, IS_IP_LAN|IS_IP_THIS_NET)
	&& memcmp(sess->client.ipv6, helo_ipv6, sizeof (helo_ipv6)) != 0) {
		statsCount(&stat_helo_ip_mismatch);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 HELO %s does not match client " CLIENT_FORMAT "" ID_MSG(424) CRLF, sess->client.helo, CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_helo_ip_mismatch">helo-ip-mismatch</a> option.
}*/
	}

	if (verb_trace.option.value) {
		syslog(
			LOG_DEBUG,
			LOG_MSG(425) "HELO %s helo-ip=%d helo-hostname=%d ip-in-ptr=%d",
			LOG_ARGS(sess), sess->client.helo,
			CLIENT_ANY_SET(sess, CLIENT_IS_HELO_IP),
			CLIENT_ANY_SET(sess, CLIENT_IS_HELO_HOSTNAME),
			CLIENT_ANY_SET(sess, CLIENT_IS_IP_IN_PTR)
		);
	}

	return SMTPF_CONTINUE;
}

static int
heloTests(Session *sess)
{
	char * dot;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(426) "heloTests", LOG_ARGS(sess));

	if (optRFC2606SpecialDomains.value
	&& CLIENT_NOT_SET(sess, CLIENT_IS_LAN|CLIENT_IS_LOCALHOST)
	&& isReservedTLD(sess->client.helo, IS_TLD_ANY_RESERVED & ~(IS_TLD_LOCAL|IS_TLD_LAN))) {
		statsCount(&stat_bogus_helo);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 HELO %s from RFC2606 reserved domain" ID_MSG(427) CRLF, sess->client.helo, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2606_special_domains">rfc2606-special-domains</a> option.
}*/
	}

	if (optRFC2821StrictHelo.value
	/* Accept IP-domain-literal eg. "[123.45.67.89]" as FQDN, but not a bare IP. */
	&& ((CLIENT_ANY_SET(sess, CLIENT_IS_HELO_IP) && *sess->client.helo != '[')
	/* Accept "domain.tld" as FQDN, but not the root domain eg. "some-name." or "." */
	  || (dot = strchr(sess->client.helo, '.')) == NULL || dot[1] == '\0')) {
		if (CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY)) {
			statsCount(&stat_rfc2821_strict_helo);
			return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 HELO %s argument must be a FQDN or IP-domain literal" ID_MSG(428) CRLF, sess->client.helo, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2821_strict_helo">rfc2821-strict-helo</a> option.
}*/
		}

		/* Report that one of our hosts we're responsible for is misconfigured. */
		if (verb_warn.option.value) {
			syslog(LOG_WARN, LOG_MSG(429) "" CLIENT_FORMAT " HELO %s is not FQDN", LOG_ARGS(sess), CLIENT_INFO(sess), sess->client.helo);
/*{LOG
See <a href="summary.html#opt_rfc2821_strict_helo">rfc2821-strict-helo</a> option.
}*/
		}
	}

	/* When the HELO argument claims to be from a domain we are
	 * responsible for and the connection is not a relay and is
	 * not a server from a domain we're responsible for, then
	 * the client is falsely "claiming to be us".
	 */
#ifdef OLD
	if (optHeloClaimsUs.value
	&& CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY)
	&& (CLIENT_ANY_SET(sess, CLIENT_IS_FORGED) || !routeKnownDomain(sess, sess->client.name))
	&& routeKnownDomain(sess, sess->client.helo)) {
#else
	/* This works when combined with the CLIENT_IS_HELO_HOSTNAME
	 * check / grey-list change that allowed us to use the HELO
	 * arg as the client.name when there was no PTR.
   	 *
   	 * Consider the case of puff.snert.com on a static ADSL IP,
   	 * has not PTR, yet puff.snert.com has an A record that matches
   	 * the connecting IP, and HELO as puff.snert.com; we should be
   	 * allowed to HELO within the snert.com domain as a result.
	 */
	if (optHeloClaimsUs.value
	&& CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY)
	&& routeKnownDomain(sess, sess->client.helo) && !routeKnownDomain(sess, sess->client.name)) {
#endif
		statsCount(&stat_helo_claims_us);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 " CLIENT_FORMAT " claims to be us \"%s\"" ID_MSG(430) CRLF, CLIENT_INFO(sess), sess->client.helo, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_helo_claims_us">helo-claims-us</a> option.
}*/
	}

	return SMTPF_CONTINUE;
}

int
heloTestsHelo(Session *sess, va_list ignore)
{
	if (optAuthDelayChecks.value)
		return SMTPF_CONTINUE;

	return heloTests(sess);
}

int
heloTestsMail(Session *sess, va_list args)
{
	if (!optAuthDelayChecks.value || CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH))
		return SMTPF_CONTINUE;

	return heloTests(sess);
}

static int
heloIsPtr(Session *sess)
{
	LOG_TRACE(sess, 431, heloIsPtr);

	/* client-is-mx softens the impact of helo-is-ptr in order to
	 * reduce possible false positives concerning legit mail servers
	 * on "dynamic" or residential ADSL.
	 */
	if (optHeloIsPtr.value
#ifdef OLD
	&& CLIENT_ANY_SET(sess, CLIENT_IS_IP_IN_PTR)
	&& CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY|CLIENT_IS_MX)
#else
	&& CLIENT_IS_SET(sess, CLIENT_HOLY_TRINITY|CLIENT_IS_MX|CLIENT_IS_IP_IN_PTR, CLIENT_IS_IP_IN_PTR)
#endif
	&& TextInsensitiveCompare(sess->client.name, sess->client.helo) == 0
#ifdef FILTER_SPF
	&& sess->msg.spf_mail != SPF_PASS
#endif
	) {
		statsCount(&stat_helo_is_ptr);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.0 HELO %s equivalent to client IP-in-PTR" ID_MSG(432) CRLF, sess->client.helo, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_helo_is_ptr">helo-is-ptr</a> option.
}*/
	}

	return SMTPF_CONTINUE;
}

int
heloIsPtrHelo(Session *sess, va_list ignore)
{
	if (optClientIsMx.value)
		return SMTPF_CONTINUE;

	return heloIsPtr(sess);
}

int
heloIsPtrRcpt(Session *sess, va_list args)
{
	if (!optClientIsMx.value)
		return SMTPF_CONTINUE;

	return heloIsPtr(sess);
}

int
pdqListAllRcode(PDQ_rr *list, PDQ_class class, PDQ_type type, const char *name, PDQ_rcode rcode)
{
	int count, match;

	for (count = match = 0; list != NULL; list = list->next) {
		if (list->section != PDQ_SECTION_QUERY)
			continue;
		if (class != PDQ_CLASS_ANY && list->class != class)
			continue;
		if (type != PDQ_TYPE_ANY && list->type != type)
			continue;
		if (type == PDQ_TYPE_5A && list->type != PDQ_TYPE_A && list->type != PDQ_TYPE_AAAA)
			continue;

		if (name != NULL && TextInsensitiveCompare(list->name.string.value, name) != 0)
			continue;

		/* Count number of queries returned. */
		count++;

		if (rcode != PDQ_RCODE_ANY && ((PDQ_QUERY *)list)->rcode != rcode)
			continue;

		/* Count number of queries with expected rcode. */
		match++;
	}

	/* Return true if all the queries returned the expected rcode. */
	return count == match;
}

int
mailTestsMail(Session *sess, va_list args)
{
	int rc;
	char *domain;
	PDQ_rr *list, *rr;
	ParsePath *mail = va_arg(args, ParsePath *);
	Vector params_list = va_arg(args, Vector);

	LOG_TRACE(sess, 433, mailTestsMail);

	if ((sess->helo_state == stateHelo && 0 < VectorLength(params_list))
	|| MAIL_ANY_SET(sess, MAIL_IS_BINARYMIME)) {
		statsCount(&stat_helo_mail_params);
		return replyPushFmt(sess, SMTPF_REJECT, "555 5.5.4 invalid or unsupported parameters" ID_MSG(1016) CRLF, ID_ARG(sess));
/*{REPLY
Sender sent a HELO command indicating the older RFC 822 SMTP
standard, yet set MAIL FROM: parameters as though RFC 5321 SMTP
and extensions were in use without knowing what extensions are
supported.
}*/
	}

	if (CLIENT_ANY_SET(sess, CLIENT_HOLY_TRINITY))
		return SMTPF_CONTINUE;

	/* Skip MX related tests for domains we route, because of split
	 * DNS configurations.
	 */
	if (0 < mail->address.length && routeKnownDomain(sess, mail->domain.string))
		return SMTPF_CONTINUE;

	/* We can not reliably check for MX hosts when mail is from the
	 * null sender and the HELO argument refers to an IP address.
	 */
	if (mail->address.length == 0) {
		/*** Q: Should we use the PTR name when available? ***/
		if (0 < spanIP(sess->client.helo))
			return SMTPF_CONTINUE;
		domain = sess->client.helo;
	} else {
		domain = mail->domain.string;
	}

	/* We need the MX records for mail-require-mx and client-is-mx tests. */
	list = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_MX, domain, NULL);

	/* Did we get a result we can use and is it a valid domain? */
	if (list != NULL && ((PDQ_QUERY *)list)->rcode == PDQ_RCODE_UNDEFINED
	&& optMailRequireMx.value && 0 < sess->msg.mail->address.length) {
		pdqFree(list);
		statsCount(&stat_mail_require_mx);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "553 5.1.8 sender <%s> from %s has no MX record" ID_MSG(434) CRLF, mail->address.string, domain, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_mail_require_mx">mail-require-mx</a> option.
}*/
	}

	/* Was there some sort of error? */
	if (list == NULL || ((PDQ_QUERY *)list)->rcode != PDQ_RCODE_OK) {
		int rcode = list == NULL ? PDQ_RCODE_ERRNO : ((PDQ_QUERY *)list)->rcode;

		syslog(LOG_ERR, LOG_MSG(435) "MX %s error %s", LOG_ARGS(sess), domain, pdqRcodeName(rcode));
/*{LOG
The MX record is always fetched and verified regardless of the setting
of <a href="summary.html#opt_client_is_mx">client-is-mx</a> and
<a href="summary.html#opt_mail_require_mx">mail-require-mx</a> options.
}*/
                if (optMailRequireMx.value && 0 < sess->msg.mail->address.length && rcode != PDQ_RCODE_NOT_IMPLEMENTED) {
			pdqFree(list);
                	statsCount(&stat_mail_require_mx_error);
			return replyPushFmt(sess, SMTPF_TEMPFAIL, "451 4.4.3 sender <%s> from %s MX lookup error" ID_MSG(436) CRLF, sess->msg.mail->address.string, domain, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_mail_require_mx">mail-require-mx</a> option.
}*/
		}
	}

	/* Remove impossible to reach MX and A/AAAA records. Retain the
	 * A/AAAA records that return PDQ_RCODE_OK or PDQ_RCODE_SERVER
	 * in order to for mail-require-mx to distinguish between an
	 * empty list due to bogus records and temporary DNS failures.
	 */
	list = pdqListPrune5A(list, IS_IP_RESTRICTED|IS_IP_LAN, 0);
	list = pdqListPruneMatch(list);

	rr = pdqListFindIP(list, PDQ_CLASS_IN, PDQ_TYPE_5A, sess->client.ipv6);
	if (PDQ_RR_IS_VALID(rr)) {
		/* Note we now include the implicit MX 0 rule compared
		 * to early versions. client-is-mx is intended to help
		 * reduce false positives from client-ptr-required and
		 * client-ip-in-ptr; not as a bad host/spam filter.
		 */
		if (verb_info.option.value)
			syslog(LOG_INFO, LOG_MSG(437) CLIENT_FORMAT " is MX for %s", LOG_ARGS(sess), CLIENT_INFO(sess), domain);
/*{LOG
See <a href="summary.html#opt_client_is_mx">client-is-mx</a> option.
}*/
		CLIENT_SET(sess, CLIENT_IS_MX);
		statsCount(&stat_client_is_mx);
	}

	rc = SMTPF_CONTINUE;

	if (optMailRequireMx.value && 0 < mail->address.length) {
		/* Is the MX/A/AAAA list empty?  */
		if (list == NULL) {
			if (verb_warn.option.value) {
				syslog(LOG_WARN, LOG_MSG(438) "empty MX list after pruning", LOG_ARGS(sess));
/*{LOG
The MX list gathered from DNS is pruned to remove hosts that resolve to localhost,
RFC 3330 reserved IP addresses that cannot be reached from the Internet, or
have no A/AAAA record. This message is reported if the MX list is empty after pruning.
}*/
			}

			rc = replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "553 5.1.8 sender <%s> from %s MX invalid" ID_MSG(439) CRLF, sess->msg.mail->address.string, domain, ID_ARG(sess));
/*{REPLY
The MX list gathered from DNS is pruned to remove hosts that resolve to localhost,
RFC 3330 reserved IP addresses that cannot be reached from the Internet, or
have no A/AAAA record. This message is reported if the MX list is empty after pruning.
}*/
		}

		/* Did any of the MX / A / AAAA queries have DNS failures? */
		else if (!pdqListAllRcode(list, PDQ_CLASS_IN, PDQ_TYPE_ANY, NULL, PDQ_RCODE_OK)) {
			if (verb_warn.option.value) {
				syslog(LOG_WARN, LOG_MSG(906) "MX list incomplete...", LOG_ARGS(sess));
#ifdef OFF
				pdqListLog(list);
#endif
/*{LOG
The MX / A / AAAA records gather from DNS failed one or more queries.
See <a href="summary.html#opt_mail_require_mx">mail-require-mx</a> option.
}*/
			}

			rc = replyPushFmt(sess, SMTPF_DELAY|SMTPF_TEMPFAIL, "451 4.1.8 sender <%s> from %s MX lookup error" ID_MSG(907) CRLF, sess->msg.mail->address.string, domain, ID_ARG(sess));
/*{REPLY
The MX / A / AAAA records gather from DNS failed one or more queries.
See <a href="summary.html#opt_mail_require_mx">mail-require-mx</a> option.
}*/
		}
	}

	pdqFree(list);

	return rc;
}

int
rcptTestsRcpt(Session *sess, va_list args)
{
	PDQ_rr *list, *rr;
	ParsePath *rcpt = va_arg(args, ParsePath *);
	Vector params_list = va_arg(args, Vector);

	LOG_TRACE(sess, 440, rcptTestsRcpt);

	if (sess->helo_state == stateHelo && 0 < VectorLength(params_list)) {
		statsCount(&stat_helo_rcpt_params);
		return replyPushFmt(sess, SMTPF_REJECT, "555 5.5.4 invalid or unsupported parameters" ID_MSG(1017) CRLF, ID_ARG(sess));
/*{REPLY
Sender sent a HELO command indicating the older RFC 822 SMTP
standard, yet set RCPT TO: parameters as though RFC 5321 SMTP
and extensions were in use without knowing what extensions are
supported.
}*/
	}

	if (optOneRcptPerNull.value && sess->msg.mail->address.length == 0 && 0 < sess->msg.rcpt_count) {
		statsCount(&stat_one_rcpt_per_null);
		return replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "550 5.7.1 too many recipients for DSN or MDN" ID_MSG(441) CRLF, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_one_rcpt_per_null">one-rcpt-per-null</a> option.
}*/
	}

	if (CLIENT_NOT_SET(sess, CLIENT_IS_2ND_MX)
	&& (list = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_MX, rcpt->domain.string, NULL)) != NULL) {
		for (rr = list; rr != NULL; rr = rr->next) {
			if (rr->section == PDQ_SECTION_QUERY)
				continue;

			if ((rr->type == PDQ_TYPE_A || rr->type == PDQ_TYPE_AAAA)
			&& memcmp(((PDQ_AAAA *) rr)->address.ip.value, sess->client.ipv6, sizeof (sess->client.ipv6)) == 0) {
				statsCount(&stat_client_is_2nd_mx);
				CLIENT_SET(sess, CLIENT_IS_2ND_MX);
				break;
			}
		}

		pdqFree(list);
	}

	return SMTPF_CONTINUE;
}

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_rfc2822_strict_date[] =
  "Check Date, Resent-Date, and Received headers for strict RFC 2822\n"
"# date syntax.\n"
"#"
;

Option optRFC28227bitHeaders		= { "rfc2822-7bit-headers", 	"-", 	"Strict RFC 2822 7-bit ASCII printable message headers." };
Option optRFC2822MinHeaders		= { "rfc2822-min-headers", 	"-", 	"Require RFC 2822 minimum required headers." };
Option optRFC2822StrictDate		= { "rfc2822-strict-date", 	"-", 	usage_rfc2822_strict_date };
Option optRFC2822MissingEOH		= { "rfc2822-missing-eoh", 	"-", 	"Reject messages missing the RFC 2822 end-of-headers line." };

Stats stat_rfc2822_7bit_headers		= { STATS_TABLE_MSG, "rfc2822-7bit-headers" };
Stats stat_rfc2822_min_headers		= { STATS_TABLE_MSG, "rfc2822-min-headers" };
Stats stat_rfc2822_strict_date		= { STATS_TABLE_MSG, "rfc2822-strict-date" };
Stats stat_rfc2822_missing_eoh		= { STATS_TABLE_MSG, "rfc2822-missing-eoh" };

Verbose verb_headers			= { { "headers",		"-", "" } };

static int
is7bitPrintable(int byte)
{
	if (ASCII_SPACE <= byte && byte < ASCII_DEL)
		return 1;

	switch (byte) {
	case ASCII_BS:
	case ASCII_TAB:
	case ASCII_FF:
	case ASCII_CR:
	case ASCII_LF:
		return 1;
	}

	return 0;
}

enum {
	HDR_DATE	= 0x0001,
	HDR_FROM	= 0x0002,
	HDR_FROM_LIST	= 0x0004,
	HDR_SENDER	= 0x0008,
	HDR_MESSAGE_ID	= 0x0010,
};

int
rfc2822Headers(Session *sess, va_list args)
{
	long i;
	char *hdr, *p;
	int hdr_found;
	Vector headers;
	time_t gmt_seconds_since_epoch;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(454) "rfc2822Headers", LOG_ARGS(sess));

        if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS))
                return SMTPF_CONTINUE;

	hdr_found = 0;
	headers = va_arg(args, Vector);
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (verb_headers.option.value)
			syslog(LOG_DEBUG, LOG_MSG(455) "header %s", LOG_ARGS(sess), hdr);

		if (optRFC28227bitHeaders.value) {
			for (p = hdr; *p != '\0'; p++) {
				if (!is7bitPrintable(*p)) {
					statsCount(&stat_rfc2822_7bit_headers);
					return replyPushFmt(sess, SMTPF_REJECT, "554 5.6.0 message headers must be US-ASCII, found 0x%.2X; RFC 2822 section 2.2" ID_MSG(456) CRLF, *(unsigned char *)p, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2822_7bit_headers">rfc2822-7bit-headers</a> option.
}*/
				}
			}
		}

		if (!(hdr_found & HDR_DATE) && TextMatch(hdr, "Date:*", -1, 1)) {
			hdr_found |= HDR_DATE;

			if (optRFC2822StrictDate.value && convertDate(hdr+sizeof ("Date:")-1, &gmt_seconds_since_epoch, NULL)) {
				statsCount(&stat_rfc2822_strict_date);
				return replyPushFmt(sess, SMTPF_REJECT, "554 5.6.0 invalid RFC 2822 date-time in %s header" ID_MSG(457) CRLF, "Date:", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2822_strict_date">rfc2822-strict-date</a> option.
}*/
			}
		}

		else if (!(hdr_found & HDR_FROM) && TextMatch(hdr, "From:*", -1, 1)) {
			hdr_found |= HDR_FROM;

			if (TextMatch(hdr, "From:*@*,*@*", -1, 1))
				hdr_found |= HDR_FROM_LIST;
		}

		else if (!(hdr_found & HDR_SENDER) && TextMatch(hdr, "Sender:*", -1, 1))
			hdr_found |= HDR_SENDER;

		else if (!(hdr_found & HDR_MESSAGE_ID) && TextMatch(hdr, "Message-ID:*", -1, 1)) {
			hdr_found |= HDR_MESSAGE_ID;

			if (optRFC2822MinHeaders.value && !TextMatch(hdr, "Message-ID:*<*@*>*", -1, 1)) {
				statsCount(&stat_rfc2822_min_headers);
				return replyPushFmt(sess, SMTPF_REJECT, "554 5.6.0 invalid RFC 2822 %s header" ID_MSG(458) CRLF, "Message-ID:", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2822_min_headers">rfc2822-min-headers</a> option.
The Message-ID is not correctly formatted according to RFC 2822 grammar.
}*/
			}
		}

		else if (optRFC2822StrictDate.value) {
			if (TextMatch(hdr, "Received:*", -1, 1)
			&& convertDate(hdr + strlrcspn(hdr, strlen(hdr), ";"), &gmt_seconds_since_epoch, NULL)) {
				statsCount(&stat_rfc2822_strict_date);
				return replyPushFmt(sess, SMTPF_REJECT, "554 5.6.0 invalid RFC 2822 date-time in %s header" ID_MSG(459) CRLF, "Received:", ID_ARG(sess));
/*{NEXT}*/
			}

			else if (TextMatch(hdr, "Resent-Date:*", -1, 1)
			&& convertDate(hdr+sizeof ("Resent-Date:")-1, &gmt_seconds_since_epoch, NULL)) {
				statsCount(&stat_rfc2822_strict_date);
				return replyPushFmt(sess, SMTPF_REJECT, "554 5.6.0 invalid RFC 2822 date-time in %s header" ID_MSG(460) CRLF, "Resent-Date:", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2822_strict_date">rfc2822-strict-date</a> option.
}*/
			}
		}
	}

	/* The Date: and From: headers are MUST requirements. However, the
	 * Message-ID: header is only a SHOULD requirement, which we consider
	 * important and common enough to treat as a MUST requirement.
	 *
	 * When the From: header is a list of mailboxes, then the Sender:
	 * header is required.
	 */
	if (optRFC2822MinHeaders.value
	&& ((hdr_found & (HDR_FROM_LIST|HDR_SENDER)) == HDR_FROM_LIST
	 || (hdr_found & (HDR_DATE|HDR_FROM|HDR_MESSAGE_ID)) != (HDR_DATE|HDR_FROM|HDR_MESSAGE_ID))) {
		statsCount(&stat_rfc2822_min_headers);
		if (1 < verb_smtp.option.value)
			syslog(
				LOG_DEBUG, LOG_MSG(461) "missing headers (0x%x)%s%s%s%s", LOG_ARGS(sess),
				hdr_found,
				(hdr_found & HDR_DATE) ? "" : " Date:",
				(hdr_found & HDR_FROM) ? "" : " From:",
				(hdr_found & HDR_MESSAGE_ID) ? "" : " Message-ID:",
				((hdr_found & (HDR_FROM_LIST|HDR_SENDER)) == HDR_FROM_LIST) ? " Sender:" : ""
			);
		return replySetFmt(sess, SMTPF_REJECT, "554 5.6.0 missing RFC 2822 required headers" ID_MSG(462) CRLF, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2822_min_headers">rfc2822-min-headers</a> option.
}*/
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_MISC */

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_smtp_reject_delay[] =
  "When set, exponentially delay the reporting of SMTP temporary and\n"
"# permanent rejects during the SMTP session. After enough rejects\n"
"# the client connection will timeout and be dropped. See also \n"
"# smtp-command-pause and smtp-drop-after.\n"
"#"
;

Option optSmtpRejectDelay 	= { "smtp-reject-delay", 	"-", 		usage_smtp_reject_delay };

Stats stat_smtp_reject_delay	= { STATS_TABLE_CONNECT, "smtp-reject-delay" };

int
smtpReplyLog(Session *sess, va_list args)
{
	int span;
	const char **reply;
	size_t *reply_length;

	LOG_TRACE(sess, 463, smtpReplyLog);

	reply = va_arg(args, const char **);
	reply_length = va_arg(args, size_t *);

	if ((SMTP_ISS_TEMP(*reply) || SMTP_ISS_PERM(*reply))) {
		/* Remember first line of last reply for "end" log line.
		 * Requested by	Steve Freegard for BMX+ interface.
		 */
		free(sess->last_reply);
		span = strcspn(*reply, CRLF);
		if ((sess->last_reply = malloc(span+1)) != NULL)
			(void) TextCopy(sess->last_reply, span+1, *reply);

		/* Note that CLIENT_PASSED_GREY should NOT be applied here.
		 * If a client slips past grey listing and is excluded from
		 * this control, then we'd be open to dictionary attacks
		 * and attempts at address harvesting.
		 */
		if (optSmtpRejectDelay.value && CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS)) {
			if (300 <= sess->client.reject_delay) {
				if (verb_info.option.value)
					syslog(LOG_DEBUG, LOG_NUM(464) "smtp-reject-delay has reached %ld seconds", sess->client.reject_delay);
				statsCount(&stat_smtp_reject_delay);
			}
			pthreadSleep(sess->client.reject_delay, 0);
			sess->client.reject_delay += sess->client.reject_delay;
		}

		sess->client.reject_count++;
	}

	return SMTPF_CONTINUE;
}

/***********************************************************************
 ***
 ***********************************************************************/

int
miscRegister(Session *sess, va_list ignore)
{
#ifdef FILTER_MISC
	verboseRegister(&verb_headers);

	optionsRegister(&optClientIpInPtr, 0);
	optionsRegister(&optClientIsMx, 0);
	optionsRegister(&optClientPtrRequired, 0);
	optionsRegister(&optHeloClaimsUs, 0);
	optionsRegister(&optHeloIpMismatch, 0);
	optionsRegister(&optHeloIsPtr, 0);
	optionsRegister(&optIdleRetestTimer, 0);
	optionsRegister(&optMailRequireMx, 0);
	optionsRegister(&optMailRetestClient, 0);
	optionsRegister(&optOneRcptPerNull, 0);
	optionsRegister(&optOneDomainPerSession, 0);
	optionsRegister(&optRFC28227bitHeaders, 0);
	optionsRegister(&optRFC2822MinHeaders, 0);
	optionsRegister(&optRFC2822MissingEOH, 0);
	optionsRegister(&optRFC2822StrictDate, 0);

	(void) statsRegister(&stat_bogus_helo);
	(void) statsRegister(&stat_client_is_mx);
	(void) statsRegister(&stat_client_ip_in_ptr);
	(void) statsRegister(&stat_client_ptr_required);
	(void) statsRegister(&stat_client_ptr_required_error);
	(void) statsRegister(&stat_helo_claims_us);
	(void) statsRegister(&stat_helo_ip_mismatch);
	(void) statsRegister(&stat_helo_is_ptr);
	(void) statsRegister(&stat_helo_mail_params);
	(void) statsRegister(&stat_mail_require_mx);
	(void) statsRegister(&stat_mail_require_mx_error);
	(void) statsRegister(&stat_helo_rcpt_params);
	(void) statsRegister(&stat_one_domain_per_session);
	(void) statsRegister(&stat_one_rcpt_per_null);
	(void) statsRegister(&stat_rfc2821_strict_helo);
	(void) statsRegister(&stat_rfc2822_7bit_headers);
	(void) statsRegister(&stat_rfc2822_min_headers);
	(void) statsRegister(&stat_rfc2822_missing_eoh);
	(void) statsRegister(&stat_rfc2822_strict_date);
#endif /* FILTER_MISC */

	optionsRegister(&optSmtpRejectDelay, 0);

	(void) statsRegister(&stat_smtp_reject_delay);

	return SMTPF_CONTINUE;
}

Reply *
infoReplyVar(Reply *reply, int columns, const char *prefix, const char *name, const char *value)
{
	Vector list;
	const char **args;

	if (columns <= 0)
		reply = replyAppendFmt(reply, "%s %s=\"%s\"" CRLF, prefix, name, value);
	else if ((list = TextSplit(value, " \t", 0)) != NULL && 0 < VectorLength(list)) {
		args = (const char **) VectorBase(list);

		reply = replyAppendFmt(reply, "%s %s=\"%s", prefix, name, *args);

		for (args++; *args != NULL; args++) {
			/* Line wrap. */
			if (columns <= reply->length % columns + strlen(*args) + 3) {
				reply = replyAppendFmt(reply, CRLF "%s    ", prefix);
			}
			reply = replyAppendFmt(reply, " %s", *args);
		}
		reply = replyAppendFmt(reply, "\"" CRLF);

		VectorDestroy(list);
	}

	return reply;
}

int
infoCommand(Session *sess)
{
	Reply *reply = NULL;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
		return cmdOutOfSequence(sess);

	statsCount(&stat_admin_commands);

#ifdef _NAME
	reply = infoReplyVar(reply, 0, "214-2.0.0", "SMTPF_NAME", _NAME);
#endif
#ifdef _VERSION
	reply = infoReplyVar(reply, 0, "214-2.0.0", "SMTPF_VERSION", _VERSION);
#endif
#ifdef _COPYRIGHT
	reply = infoReplyVar(reply, 0, "214-2.0.0", "SMTPF_COPYRIGHT", _COPYRIGHT);
#endif
	reply = infoReplyVar(reply, 0, "214-2.0.0", "SMTPF_BUILT", smtpf_built);
#ifdef LIBSNERT_VERSION
	reply = infoReplyVar(reply, 0, "214-2.0.0", "LIBSNERT_VERSION", LIBSNERT_VERSION);
#endif
#ifdef LIBSNERT_CONFIGURE
	reply = infoReplyVar(reply, LINE_WRAP, "214-2.0.0", "LIBSNERT_CONFIGURE", LIBSNERT_CONFIGURE);
#endif
	reply = infoReplyVar(reply, 0, "214-2.0.0", "SQLITE3_VERSION", sqlite3_libversion());
#ifdef _CONFIGURE
	reply = infoReplyVar(reply, LINE_WRAP, "214-2.0.0", "SMTPF_CONFIGURE", _CONFIGURE);
#endif
#ifdef _CFLAGS
	reply = infoReplyVar(reply, LINE_WRAP, "214-2.0.0", "CFLAGS", _CFLAGS);
#endif
#ifdef _LDFLAGS
	reply = infoReplyVar(reply, LINE_WRAP, "214-2.0.0", "LDFLAGS", _LDFLAGS);
#endif
#ifdef _LIBS
	reply = infoReplyVar(reply, LINE_WRAP, "214-2.0.0", "LIBS", _LIBS);
#endif
	reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));

	return replyPush(sess, reply);
}

/*
 * @param sess
 *	A session pointer.
 *
 * @param host
 *	A pointer to a C string containing a host / domain name.
 *
 * @return
 *	SMTPF_REJECT if the host and none of its parent domains
 *	upto, but not including, the TLD have an SOA. SMTPF_TEMPFAIL
 *	if there was a DNS lookup error. Otherwise SMTPF_CONTINUE if
 *	the host name or any of its parent domains have an SOA before
 *	the TLD is reached.
 *
 *	Consider:
 *
 *	puff# dig +short ns vocus.com
 *	name.phx.gblx.net.
 *	name.roc.gblx.net.
 *	name.snv.gblx.net.
 *	name.jfk.gblx.net.
 *	name.lon.gblx.net.
 *
 *	puff# dig +short soa vocus.com
 *	gblx.net. dns.gblx.net. 22048 7200 1800 604800 3600
 *
 *	puff# dig +short @gblx.net ns vocus.com
 *	dig: couldn't get address for 'gblx.net': not found
 *
 *	puff# dig +short @gblx.net a gblx.net.
 *	dig: couldn't get address for 'gblx.net': not found
 *
 * ***	[SF] Apperently this is allowed though really weird.
 * ***	From dnsstuff.com
 *
 *	WARN	SOA MNAME Check	WARNING: Your SOA (Start of Authority)
 *	record states that your master (primary) name server is: gblx.net..
 *	However, that server is not listed at the parent servers as one
 *	of your NS records! This is legal, but you should be sure that
 *	you know what you are doing.
 */
int
isNxDomain(Session *sess, const char *host)
{
	PDQ_rr *list;
	int offset, rcode;
	const char *domain, *tld;

	/* Find start of TLD. */
	offset = indexValidTLD(host);

	/* Is it an unknown TLD domain or a TLD without a second level? */
	if (offset <= 0) {
		syslog(LOG_ERR, LOG_MSG(465) "domain %s does not exist", LOG_ARGS(sess), TextNull(host));
/*{LOG
The top level domain is unknown.
}*/
		return SMTPF_REJECT;
	}

	domain = host;
	tld = &host[offset];
	do {
		if (0 < verb_uri.option.value)
			syslog(LOG_DEBUG, LOG_MSG(466) "lookup %s", LOG_ARGS(sess), domain);

		list = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_SOA, domain, NULL);
		rcode = list == NULL ? PDQ_RCODE_ERRNO : ((PDQ_QUERY *)list)->rcode;
		pdqFree(list);

		switch (rcode) {
		case PDQ_RCODE_OK:
			return SMTPF_CONTINUE;

		case PDQ_RCODE_UNDEFINED:
			syslog(LOG_ERR, LOG_MSG(467) "domain %s does not exist", LOG_ARGS(sess), domain);
/*{NEXT}*/
			return SMTPF_REJECT;
		default:
			syslog(LOG_ERR, LOG_MSG(468) "SOA for %s lookup error: %s", LOG_ARGS(sess), domain, pdqRcodeName(rcode));
/*{NEXT}*/
			return SMTPF_TEMPFAIL;
		}

		if ((domain = strchr(domain, '.')) == NULL)
			break;

		domain++;
	} while (domain < tld);

	syslog(LOG_ERR, LOG_MSG(469) "SOA for %s does not exist", LOG_ARGS(sess), host);
/*{LOG
Part of the experimental is-nxdomain family of tests.
Reject a domain if the host and none of its parent domains
upto, but not including, the TLD have an SOA. Temp. fail
if there was a DNS lookup error. Otherwise continue if
the host name or any of its parent domains have an SOA before
the TLD is reached.
}*/

	return SMTPF_REJECT;
}
