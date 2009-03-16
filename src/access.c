/*
 * access.c
 *
 * Copyright 2004, 2008 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#if defined(HAVE_REGEX_H) && ! defined(__MINGW32__)
# include <regex.h>
#endif

#include <com/snert/lib/mail/tlds.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_access_map[] =
  "access-map=\n"
"#\n"
"# The type and location of the read-only access key-value map. The\n"
"# following methods are supported:\n"
"#\n"
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
"# If :port is omitted, the default is 7953.\n"
"#\n"
"# The access-map contains key-value pairs. Lookups are performed\n"
"# from most to least specific, stopping on the first entry found.\n"
"# Keys are case-insensitive.\n"
"#\n"
"# An IPv4 lookup is repeated several times reducing the IP address\n"
"# by one octet from right to left until a match is found.\n"
"#\n"
"#   tag:192.0.2.9\n"
"#   tag:192.0.2\n"
"#   tag:192.0\n"
"#   tag:192\n"
"#\n"
"# An IPv6 lookup is repeated several times reducing the IP address\n"
"# by one 16-bit word from right to left until a match is found.\n"
"#\n"
"#   tag:2001:0DB8:0:0:0:0:1234:5678\n"
"#   tag:2001:0DB8:0:0:0:0:1234\n"
"#   tag:2001:0DB8:0:0:0:0\n"
"#   tag:2001:0DB8:0:0:0\n"
"#   tag:2001:0DB8:0:0\n"
"#   tag:2001:0DB8:0:0\n"
"#   tag:2001:0DB8:0\n"
"#   tag:2001:0DB8\n"
"#   tag:2001\n"
"#\n"
"# A domain lookup is repeated several times reducing the domain by\n"
"# one label from left to right until a match is found.\n"
"#\n"
"#   tag:[ipv6:2001:0DB8::1234:5678]\n"
"#   tag:[192.0.2.9]\n"
"#   tag:sub.domain.tld\n"
"#   tag:domain.tld\n"
"#   tag:tld\n"
"#   tag:\n"
"#\n"
"# An email lookup is similar to a domain lookup; the exact address\n"
"# is tried first, then the address's domain, and finally the local\n"
"# part of the address.\n"
"#\n"
"#   tag:account@sub.domain.tld\n"
"#   tag:sub.domain.tld\n"
"#   tag:domain.tld\n"
"#   tag:tld\n"
"#   tag:account@\n"
"#   tag:\n"
"#\n"
"# The tags Connect:, From:, and To: are used for black-white list\n"
"# lookup by connecting client IP or domain, sender address, and\n"
"# recipient address respectively. Other options may specify other\n"
"# tags.\n"
"#\n"
"# If a key is found, then the value is processed as a pattern list\n"
"# and the result returned. A pattern list is a whitespace separated\n"
"# list of pattern-action pairs followed by an optional default\n"
"# action. The support pattern formats are:\n"
"#\n"
"#   [network/cidr]action\tClassless Inter-Domain Routing\n"
"#   !pattern!action\t\tSimple fast text matching.\n"
"#   /regex/action\t\tExtended Regular Expressions\n"
"#\n"
"# The CIDR will only ever match for IP address related lookups.\n"
"#\n"
"# A !pattern! uses an asterisk (*) for a wildcard, scanning over\n"
"# zero or more characters; a question-mark (?) matches any single\n"
"# character; a backslash followed by any character treats it as a\n"
"# literal (it loses any special meaning).\n"
"#\n"
"#   !abc!\t\texact match for 'abc'\n"
"#   !abc*!\t\tmatch 'abc' at start of string\n"
"#   !*abc!\t\tmatch 'abc' at the end of string\n"
"#   !abc*def!\t\tmatch 'abc' at the start and match 'def'\n"
"#\t\t\tat the end, maybe with stuff in between.\n"
"#   !*abc*def*!\t\tfind 'abc', then find 'def'\n"
"#\n"
"# For black-white lookups, the following actions are recognised:\n"
"# OK (white list), REJECT (black list), DISCARD (accept & discard),\n"
"# SKIP or DUNNO (stop lookup, no result), and NEXT (opposite of\n"
"# SKIP, resume lookup). It is possible to specify an empty action\n"
"# after a pattern, which is treated like SKIP returning an undefined\n"
"# result. Other options may specify other actions.\n"
"#"
;

Option optAccessMap = {
	"access-map",
#if defined(HAVE_SQLITE3_H)
	"sql!" CF_DIR "/access.sq3"
#elif defined(HAVE_DB_H)
	"db!" CF_DIR "/access.db"
#endif
	, usage_access_map
};

static const char usage_access_word_tags[] =
  "Write to standard output access-map action word and valid tag mapping.\n"
"#"
;
Option optAccessWordTags	= { "access-word-tags",		NULL,		usage_access_word_tags };

static const char usage_access_tag_words[] =
  "Write to standard output access-map action tag and valid word mapping.\n"
"#"
;
Option optAccessTagWords	= { "access-tag-words",		NULL,		usage_access_tag_words };

Option optRejectPercentRelay 	= { "reject-percent-relay", 	"+", 		"Reject occurrences of % relay hack in addresses." };
Option optRejectQuotedAtSign 	= { "reject-quoted-at-sign", 	"+", 		"Reject occurrences of quoted @-sign in the local-part of the address." };
Option optRejectUucpRoute 	= { "reject-uucp-route", 	"+", 		"Reject UUCP !-path addresses." };

Stats stat_connect_bl		= { STATS_TABLE_CONNECT, "connect-bl" };
Stats stat_connect_gl		= { STATS_TABLE_CONNECT, "connect-gl" };
Stats stat_connect_wl		= { STATS_TABLE_CONNECT, "connect-wl" };
Stats stat_connect_mail_bl	= { STATS_TABLE_MAIL, "connect-mail-bl" };
Stats stat_connect_mail_wl	= { STATS_TABLE_MAIL, "connect-mail-wl" };
Stats stat_mail_bl		= { STATS_TABLE_MAIL, "mail-bl" };
Stats stat_mail_wl		= { STATS_TABLE_MAIL, "mail-wl" };
Stats stat_connect_rcpt_bl	= { STATS_TABLE_RCPT, "connect-rcpt-bl" };
Stats stat_connect_rcpt_wl	= { STATS_TABLE_RCPT, "connect-rcpt-wl" };
Stats stat_mail_rcpt_bl		= { STATS_TABLE_RCPT, "mail-rcpt-bl" };
Stats stat_mail_rcpt_wl		= { STATS_TABLE_RCPT, "mail-rcpt-wl" };
Stats stat_rcpt_bl		= { STATS_TABLE_RCPT, "rcpt-bl" };
Stats stat_rcpt_wl		= { STATS_TABLE_RCPT, "rcpt-wl" };
Stats stat_tagged		= { STATS_TABLE_MSG, "msg-tagged" };

static char *access_map_path;
static Verbose verb_access	= { { "access", "-", "" } };

/***********************************************************************
 *** Access Database Lookups
 ***********************************************************************/

/**
 * @param sess
 *	A pointer to a Session.
 *
 * @param hay
 *	A C string to search.
 *
 * @param pins
 *	A C string containing an optional list of whitespace separated
 *	pattern/action pairs followed by an optional default action.
 *
 *	( !pattern!action | /regex/action  | [network/cidr]action )* default-action?
 *
 *	The !pattern! uses the simple TextMatch() function with * and ?
 *	wild cards. The /regex/ uses Exteneded Regular Expressions (or
 *	Perl Compatible Regular Expressions if selected at compile time).
 *
 * @param action
 *	A pointer to a C string pointer, which can be NULL. Used to
 *	passback an allocated copy of the action string or NULL. Its
 *	the caller's responsiblity to free() this string.
 *
 * @return
 *	 A SMDB_ACCESS_* code.
 */
int
accessPattern(Session *sess, const char *hay, char *pins, char **actionp)
{
	long cidr, length;
	int access, is_hay_ip, match;
	char *action, *pin, *next_pin;
	unsigned char net[IPV6_BYTE_LENGTH], ipv6[IPV6_BYTE_LENGTH];

	access = SMDB_ACCESS_NOT_FOUND;

	if (actionp != NULL)
		*actionp = NULL;

	if (hay == NULL || pins == NULL || *pins == '\0')
		goto error0;

	action = "";
	is_hay_ip = 0 < parseIPv6(hay, ipv6);

	for (pin = pins; *pin != '\0'; pin = next_pin) {
		/* Pattern/action pairs cannot contain white space, because
		 * the strings they are intended to match: ips, domains, host
		 * names, addresses cannot contain whitespace. I do it this
		 * way because TextSplit() dequotes the string and thats bad
		 * for regex patterns.
		 */
		pin += strspn(pin, " \t");
		next_pin = pin + strcspn(pin, " \t");

		/* !pattern!action */
		if (*pin == '!') {
			/* Find first unescaped exclamation to end pattern.
			 * An exclamation is permitted in the local-part of
			 * an email address and so must be backslash escaped.
			 */
			for (action = pin; (action = strchr(action+1, '!')) != NULL; ) {
			 	if (action[-1] != '\\')
			 		break;
			}
			if (action == NULL) {
				syslog(LOG_ERR, LOG_MSG(100) "pattern delimiter error: \"%.50s...\"", LOG_ARGS(sess), pin);
/*{LOG
Failed to find the end bang (!) delimiter of a <a href="access-map.html#access_simple_pattern">!simple!</a> pattern.
See <a href="access-map.html">access-map</a> about right-hand-side
<a href="access-map.html#access_pattern_lists">pattern lists</a>.
}*/
				continue;
			}

			*action++ = '\0';
			if (verb_access.option.value)
				syslog(LOG_DEBUG, LOG_MSG(101) "pattern=!%s! action=%.6s", LOG_ARGS(sess), pin+1, action);
			match = TextMatch(hay, pin+1, -1, 0);
			action[-1] = '!';

			if (match) {
				if (verb_access.option.value)
					syslog(LOG_DEBUG, LOG_MSG(102) "\"%s\" matched \"%.50s...\"", LOG_ARGS(sess), hay, pin);
				access = smdbAccessCode(action);
				break;
			}
		}

		/* '[' network [ '/' cidr ] ']' action
		 *
		 * Valid forms:
		 *
		 *	[192.0.2.1]OK
		 *	[192.0.2.0/24]REJECT
		 *	[2001:DB8::1]OK
		 *	[2001:DB8::0/32]REJECT
		 *	[::192.0.2.0/104]DISCARD
		 *
		 *	[192.0.2.1]some@example.com
		 *	[192.0.2.1]some@[192.0.2.254]
		 */
		else if (*pin == '[') {
			if (!is_hay_ip)
				continue;

			/* Find first unescaped right-square bracket to end pattern.
			 * A right-square bracket is permitted for an IP-as-domain
			 * literal in an email address and so must be backslash escaped.
			 */
			for (action = pin; (action = strchr(action+1, ']')) != NULL; ) {
			 	if (action[-1] != '\\')
			 		break;
			}
			if (action == NULL) {
				syslog(LOG_ERR, LOG_MSG(103) "network delimiter error: \"%.50s...\"", LOG_ARGS(sess), pin);
/*{LOG
Failed to find the end square-bracket (]) delimiter of a <code>[network/cidr]</code> pattern.
See <a href="access-map.html">access-map</a> about right-hand-side
<a href="access-map.html#access_pattern_lists">pattern lists</a>.
}*/
				continue;
			}

			pin++;
			*action++ = '\0';
			if (verb_access.option.value)
				syslog(LOG_DEBUG, LOG_MSG(104) "network=[%s] action=%.6s", LOG_ARGS(sess), pin, action);
			length = parseIPv6(pin, net);
			action[-1] = ']';

			if (length <= 0) {
				syslog(LOG_ERR, LOG_MSG(105) "network specifier error: \"%.50s...\"", LOG_ARGS(sess), pin-1);
/*{NEXT}*/
				continue;
			}

			/* When the /cidr portion is missing, assume /128. */
			if (pin[length] == '\0') {
				/* This could be IPV4_BIT_LENGTH, but we
				 * treat all our IPv4 as IPv6 addresses.
				 */
				cidr = IPV6_BIT_LENGTH;
			}

			else if (pin[length] == '/') {
				cidr = strtol(pin+length+1, NULL, 10);
				/* If no colons, assume IPv4 address. */
				if (strchr(pin, ':') == NULL)
					cidr = IPV6_BIT_LENGTH - 32 + cidr;
			}

			else {
				syslog(LOG_ERR, LOG_MSG(106) "network specifier error, \"%.50s...\"", LOG_ARGS(sess), pin-1);
/*{LOG
The <code>network</code> portion of a <code>[network/cidr]</code>
pattern does not parse to a valid IPv4 or IPv6 address.
See <a href="access-map.html">access-map</a> about right-hand-side
<a href="access-map.html#access_pattern_lists">pattern lists</a>.
}*/
				continue;
			}

			if (networkContainsIp(net, cidr, ipv6)) {
				if (verb_access.option.value)
					syslog(LOG_DEBUG, LOG_MSG(107) "\"%s\" matched \"%.50s...\"", LOG_ARGS(sess), hay, pin-1);
				access = smdbAccessCode(action);
				break;
			}
		}

#if defined(HAVE_REGEX_H) && ! defined(__MINGW32__)
		/* /regex/action */
		else if (*pin == '/') {
			int code;
			regex_t re;
			char error[256];

			/* Find first unescaped slash delimiter to end pattern.
			 * A slash is permitted in the local-part of an email
			 * address and so must be backslash escaped.
			 */
			for (action = pin; (action = strchr(action+1, '/')) != NULL; ) {
			 	if (action[-1] != '\\')
			 		break;
			}
			if (action == NULL) {
				syslog(LOG_ERR, LOG_MSG(108) "regular expression delimiter error: \"%.50s...\"", LOG_ARGS(sess), pin);
/*{LOG
Failed to find the end slash (/) delimiter of a <a href="access-map.html#access_regex_pattern">/regex/</a> pattern.
See <a href="access-map.html">access-map</a> about right-hand-side
<a href="access-map.html#access_pattern_lists">pattern lists</a>.
}*/
				continue;
			}

			*action++ = '\0';
			if (verb_access.option.value)
				syslog(LOG_DEBUG, LOG_MSG(109) "regex=/%s/ action=%.6s", LOG_ARGS(sess), pin+1, action);
			code = regcomp(&re, pin+1, REG_EXTENDED|REG_NOSUB);
			action[-1] = '/';

			if (code != 0) {
				regerror(code, &re, error, sizeof (error));
				syslog(LOG_ERR, LOG_MSG(110) "regular expression error: %s \"%.50s...\"", LOG_ARGS(sess), error, pin);
/*{NEXT}*/
				continue;
			}

			code = regexec(&re, hay, 0, NULL, 0);

			if (code == 0) {
				if (verb_access.option.value)
					syslog(LOG_DEBUG, LOG_MSG(111) "\"%s\" matched \"%.50s...\"", LOG_ARGS(sess), hay, pin);
				access = smdbAccessCode(action);
				regfree(&re);
				break;
			}

			if (code != REG_NOMATCH) {
				regerror(code, &re, error, sizeof (error));
				syslog(LOG_ERR, LOG_MSG(112) "regular expression error: %s \"%.50s...\"", LOG_ARGS(sess), error, pin);
/*{LOG
There is an error in a <a href="access-map.html#access_regex_pattern">/regex/</a> pattern
that prevents it from being compiled.
}*/
			}
			regfree(&re);
		}
#endif /* HAVE_REGEX_H */
		else {
			if (verb_access.option.value)
				syslog(LOG_DEBUG, LOG_MSG(113) "\"%s\" default action \"%.10s...\"", LOG_ARGS(sess), hay, pin);
			access = smdbAccessCode(pin);
			action = pin;
			break;
		}
	}

	if (strcmp(action, "NEXT") == 0)
		access = SMDB_ACCESS_NOT_FOUND;
	else if (actionp != NULL && access != SMDB_ACCESS_NOT_FOUND) {
		Vector patterns = TextSplit(action, " \t", 0);
		*actionp = VectorReplace(patterns, 0, NULL);
		VectorDestroy(patterns);
	}
error0:
	if (verb_access.option.value) {
		syslog(
			LOG_DEBUG, LOG_MSG(114) "accessPattern(%lx, \"%s\", \"%.50s...\", %lx) rc=%d (%c) action='%s'",
			LOG_ARGS(sess), (long) sess, TextNull(hay), TextNull(pins), (long) actionp, access,
			(unsigned char) access, actionp == NULL || *actionp == NULL ? "" : *actionp
		);
	}

	return access;
}

char *
accessDefault(Session *sess, const char *tag)
{
	return smdbGetValue(sess->access_map, tag);
}

/**
 * Perform the following access.db lookups concerning IP and/or resolved
 * domain name, stopping on the first entry found:
 *
 * For an IPv4 address:
 *
 *	tag:a.b.c.d
 *	tag:a.b.c
 *	tag:a.b
 *	tag:a
 *
 * For an IPv6 address:
 *
 *	tag:a:b:c:d:e:f:g
 *	tag:a:b:c:d:e:f
 *	tag:a:b:c:d:e
 *	tag:a:b:c:d
 *	tag:a:b:c
 *	tag:a:b
 *	tag:a
 *
 * If the above IP address lookups fail to find an entry and the IP address
 * resolved, then the subsequent lookups are:
 *
 *	tag:some.sub.domain.tld
 *	tag:sub.domain.tld
 *	tag:domain.tld
 *	tag:tld
 *	tag:
 *
 * If the above IP address lookups fail to find an entry and the IP address
 * did NOT resolve, then the subsequent lookups are:
 *
 *	tag:[ip]
 *	tag:
 *
 * When an entry is found, then the right-hand-side value is processed
 * as a pattern list and that result returned. Otherwise if no entry is
 * found, then SMDB_ACCESS_NOT_FOUND will be returned.
 *
 * Note this lookup ordering, except the empty tag:, is based on sendmail's
 * lookups. Sendmail syntax limits the netmasks to /32, /24, /16, /8 for IPv4
 * and /128, /112. /96, ... /16 for IPv6, which are the most common cases,
 * but not so flexible as full range netmasks. The accessPattern() pattern
 * list processing provides "[network/cidr]action" for finer granularity.
 *
 * @param sess
 *	A pointer to a Session.
 *
 * @param tag
 *	A C string tag that may be prefixed to access.db look-ups.
 *
 * @param client_name
 *	A C string for the SMTP client host name.
 *
 * @param client_addr
 *	A C string for the SMTP client address.
 *
 * @param lhs
 *	A pointer to C string pointer. May be NULL. If this pointer is
 *	not NULL, then pass back the pointer to an allocated C string
 *	corresponding to the key found. Its the  responsibilty of the
 *	caller to release this memory.
 *
 * @param rhs
 *	A pointer to C string pointer. May be NULL. If this pointer is
 *	not NULL, then pass back the pointer to an allocated C string
 *	corresponding to the value found. Its the  responsibilty of the
 *	caller to release this memory.
 *
 * @param include_default
 *	When set test for default (bare) tag.
 *
 * @return
 *	One of SMDB_ACCESS_OK, SMDB_ACCESS_REJECT, or SMDB_ACCESS_UNKNOWN.
 *
 * @see
 *	accessPattern()
 */
int
accessClient(Session *sess, const char *tag, const char *client_name, const char *client_addr, char **lhs, char **rhs, int include_default)
{
	int access;
	char *value = NULL;

	/*	tag:a.b.c.d
	 *	tag:a.b.c
	 *	tag:a.b
	 *	tag:a
	 */
	if ((access = smdbAccessIp(sess->access_map, tag, client_addr, lhs, &value)) != SMDB_ACCESS_NOT_FOUND)
		access = accessPattern(sess, client_addr, value, rhs);

	/* If the client IP resolved and matched, then the lookup order is:
	 *
	 *	tag:some.sub.domain.tld
	 *	tag:sub.domain.tld
	 *	tag:domain.tld
	 *	tag:tld
	 * 	tag:
	 *
	 * If the client IP did not resolve nor match, then the lookup order is:
	 *
	 *	tag:[ip]
	 * 	tag:
	 */
	if (access == SMDB_ACCESS_NOT_FOUND) {
		access = smdbAccessDomain(sess->access_map, tag, client_name, lhs, &value);

		if (include_default && access == SMDB_ACCESS_NOT_FOUND) {
			value = smdbGetValue(sess->access_map, tag);
			if (value != NULL && lhs != NULL)
				*lhs = strdup(tag);
		}

		access = accessPattern(sess, client_name, value, rhs);
		if (access == SMDB_ACCESS_NOT_FOUND)
			access = accessPattern(sess, client_addr, value, rhs);
	}

	if (access == SMDB_ACCESS_NOT_FOUND && lhs != NULL)
		free(*lhs);

	free(value);

	return access;
}

/**
 * Perform the following access.db lookups for a mail address, stopping on
 * the first entry found:
 *
 *	tag:account@some.sub.domain.tld
 *	tag:some.sub.domain.tld
 *	tag:sub.domain.tld
 *	tag:domain.tld
 *	tag:tld
 *	tag:account@
 * 	tag:
 *
 * When an entry is found, then the right-hand-side value is processed
 * as a pattern list and that result returned. If auth is not NULL, then
 * the string to search will be "auth:mail", else just "mail".
 *
 * Otherwise if no entry is found, then SMDB_ACCESS_NOT_FOUND will be
 * returned.
 *
 * @param work
 *	A pointer to a smfWork workspace.
 *
 * @param tag
 *	A C string tag that may be prefixed to access.db look-ups.
 *
 * @param mail
 *	A C string for the SMTP MAIL FROM: address.
 *
 * @param lhs
 *	A pointer to C string pointer. May be NULL. If this pointer is
 *	not NULL, then pass back the pointer to an allocated C string
 *	corresponding to the key found. Its the  responsibilty of the
 *	caller to release this memory.
 *
 * @param rhs
 *	A pointer to C string pointer. May be NULL. If this pointer is
 *	not NULL, then pass back the pointer to an allocated C string
 *	corresponding to the value found. Its the  responsibilty of the
 *	caller to release this memory.
 *
 * @return
 *	One of SMDB_ACCESS_OK, SMDB_ACCESS_REJECT, SMDB_ACCESS_UNKNOWN,
 *	SMDB_ACCESS_NOT_FOUND, or SMDB_ACCESS_ERROR.
 *
 * @see
 *	accessPattern()
 */
int
accessEmail(Session *sess, const char *tag, const char *mail, char **lhs, char **rhs)
{
	int access;
	char *value;

	access = smdbAccessMail(sess->access_map, tag, mail, lhs, &value);

	if (access == SMDB_ACCESS_NOT_FOUND) {
		value = smdbGetValue(sess->access_map, tag);
		if (value != NULL && lhs != NULL)
			*lhs = strdup(tag);
	}

	/* NEXT is a Snert milter extension that can only be used
	 * with milter specific tags.
	 *
	 * Normally when the access.db lookup matches a milter tag,
	 * then RHS regex pattern list is processed and there are
	 * no further access.db lookups possible.
	 *
	 * The NEXT action allows the access.db lookups to resume
	 * and is effectively the opposite of SKIP.
	 *
	 * Consider the following trival example:
	 *
	 *	milter-NAME-from:com	/@com/REJECT NEXT
	 *	From:com		OK
	 *
	 * would reject mail from places like compaq.com or com.com
	 * if the pattern matches, but resume the the access.db
	 * lookups otherwise.
	 *
	 * Consider this more complex example concerning the format
	 * of aol.com mail addresses. AOL local parts are between 3
	 * and 16 characters long and can contain dots and RFC 2822
	 * atext characters except % and /.
	 *
	 * First is what might be specified if NEXT were not possible:
	 *
	 *	milter-NAME-from:aol.com  /^.{1,2}@aol.com$/REJECT /^[^@]{17,}@aol.com$/REJECT /[%\/]/REJECT
	 *	From:fred@aol.com	OK
	 *	From:john@aol.com	OK
	 *
	 * Now consider this shorter version using NEXT:
	 *
	 *	milter-NAME-from:aol.com  /^[a-zA-Z0-9!#$&'*+=?^_`{|}~.-]{3,16}@aol.com$/NEXT REJECT
	 *	From:fred@aol.com	OK
	 *	From:john@aol.com	OK
	 *
	 * The NEXT used above allowed me to specify one simple regex
	 * instead of (a complex one using alternation or) three in order
	 * to validate the format aol.com address and then proceed to
	 * lookup white listed and/or black listed addresses.
	 */
	access = accessPattern(sess, mail, value, rhs);
	if (access == SMDB_ACCESS_NOT_FOUND && lhs != NULL)
		free(*lhs);

	free(value);

	return access;
}

/***********************************************************************
 *** Filter Handlers
 ***********************************************************************/

int
accessRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_access);
	optionsRegister(&optAccessMap, 1);
	optionsRegister(&optAccessTagWords, 1);
	optionsRegister(&optAccessWordTags, 1);

	(void) statsRegister(&stat_connect_bl);
	(void) statsRegister(&stat_connect_gl);
	(void) statsRegister(&stat_connect_wl);
	(void) statsRegister(&stat_connect_mail_bl);
	(void) statsRegister(&stat_connect_mail_wl);
	(void) statsRegister(&stat_mail_bl);
	(void) statsRegister(&stat_mail_wl);
	(void) statsRegister(&stat_connect_rcpt_bl);
	(void) statsRegister(&stat_connect_rcpt_wl);
	(void) statsRegister(&stat_mail_rcpt_bl);
	(void) statsRegister(&stat_mail_rcpt_wl);
	(void) statsRegister(&stat_rcpt_bl);
	(void) statsRegister(&stat_rcpt_wl);
	(void) statsRegister(&stat_tagged);

	return SMTPF_CONTINUE;
}

int
accessInit(Session *null, va_list ignore)
{
	size_t length;

	smdbSetDebug(verb_db.option.value);

	if (*optAccessMap.string == '\0') {
		syslog(LOG_WARN, LOG_NUM(115) "access-map option disabled");
/*{LOG
The <a href="access-map.html#access_map">access-map</a> option has been
set to an empty string.
}*/
		return SMTPF_CONTINUE;
	}

	if (0 <= TextSensitiveStartsWith(optAccessMap.string, "text!")) {
		syslog(LOG_ERR, LOG_NUM(116) "access-map=%s text method no longer supported ", optAccessMap.string);
		exit(1);
	}

	length = sizeof ("access" KVM_DELIM_S) + strlen(optAccessMap.string);

	if ((access_map_path = malloc(length)) == NULL) {
		syslog(LOG_ERR, LOG_NUM(117) "access-map=%s open error", optAccessMap.string);
/*{LOG
The key-value-map specified by the <a href="access-map.html">access-map</a> option could
not be opened. Check the map type, file path, and file <a href="install.html#unix_permissions">permissions &amp; ownership</a>.
}*/
		exit(1);
	}

	(void) snprintf(access_map_path, length, "access" KVM_DELIM_S "%s", optAccessMap.string);

	return SMTPF_CONTINUE;
}

int
accessFini(Session *null, va_list ignore)
{
	free(access_map_path);
	return SMTPF_CONTINUE;
}

/**
 * Perform the following access.db lookups concerning IP and/or resolved
 * domain name, stopping on the first entry found:
 *
 * For an IPv4 address:
 *
 *	connect:a.b.c.d
 *	connect:a.b.c
 *	connect:a.b
 *	connect:a
 *
 * For an IPv6 address:
 *
 *	connect:a:b:c:d:e:f:g
 *	connect:a:b:c:d:e:f
 *	connect:a:b:c:d:e
 *	connect:a:b:c:d
 *	connect:a:b:c
 *	connect:a:b
 *	connect:a
 *
 * If the above IP address lookups fail to find an entry and the IP address
 * resolved, then the subsequent lookups are:
 *
 *	connect:some.sub.domain.tld
 *	connect:sub.domain.tld
 *	connect:domain.tld
 *	connect:tld
 *	connect:
 *
 * If the above IP address lookups fail to find an entry and the IP address
 * did NOT resolve, then the subsequent lookups are:
 *
 *	connect:[ip]
 *	connect:
 *
 * When an entry is found, then the right-hand-side value is processed
 * as a pattern list and that result returned, else on the result of the
 * the right-hand-side is returned. Otherwise if no entry is found, then
 * SMDB_ACCESS_NOT_FOUND will be returned.
 *
 * Note this lookup ordering, except the empty tag:, is based on sendmail's
 * lookups. Sendmail syntax limits the netmasks to /32, /24, /16, /8 for IPv4
 * and /128, /112. /96, ... /16 for IPv6, which are the most common cases,
 * but not so flexible as full range netmasks. The accessPattern() pattern
 * list processing provides "[network/cidr]action" for finer granularity.
 *
 * @param sess
 *	A pointer to a Session.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	An SMTPF_ return code.
 */
int
accessConnect(Session *sess, va_list args)
{
	char *msg, *value = NULL;
	int access = SMTPF_CONTINUE;

	LOG_TRACE(sess, 118, accessConnect);

	/* Typicallyed already cleared at start of session. Reset these flags
	 * just in case of an idle timer trigger (see also mail-retest-client).
	 */
	CLIENT_CLEAR(sess, CLIENT_IS_BLACK|CLIENT_IS_LOCAL_BLACK|CLIENT_IS_WHITE|CLIENT_IS_TEMPFAIL|CLIENT_IS_GREY|CLIENT_IS_SAVE|CLIENT_IS_TRAP|CLIENT_IS_TAG);

	/* Lookup
	 *
	 *	tag:a.b.c.d
	 *	tag:a.b.c
	 *	tag:a.b
	 *	tag:a
	 *
	 * If the client IP resolved and matched, then lookup:
	 *
	 *	tag:some.sub.domain.tld
	 *	tag:sub.domain.tld
	 *	tag:domain.tld
	 *	tag:tld
	 *	tag:
	 *
	 * If the client IP did not resolve nor match, then lookups:
	 *
	 *	tag:[ip]
	 *	tag:
	 */
	if ((access = accessClient(sess, "connect:", sess->client.name, sess->client.addr, NULL, &value, 1)) != SMDB_ACCESS_NOT_FOUND) {
		if ((msg = strchr(value, ':')) != NULL)
			msg++;

		switch (access = smdbAccessIsOk(access)) {
		case SMDB_ACCESS_OK:
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(119) "host " CLIENT_FORMAT " %s", LOG_ARGS(sess), CLIENT_INFO(sess), msg == NULL ? "white listed" : msg);
/*{LOG
There is a <span class="tag">Connect:</span> tag entry for either the
client name or IP address with a right-hand-side value of OK.
See <a href="access-map.html#access_map">access-map</a>.
}*/
			}
			if (CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY))
				statsCount(&stat_connect_wl);
			CLIENT_SET(sess, CLIENT_IS_WHITE);
			access = SMTPF_ACCEPT;
			break;

		case SMDB_ACCESS_REJECT:
			access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 host " CLIENT_FORMAT " %s" ID_MSG(120) "\r\n", CLIENT_INFO(sess), msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect"><span class="tag">Connect:</span></a> tag entry for either the
client name or IP address with a right-hand-side value of REJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			CLIENT_SET(sess, CLIENT_IS_BLACK|CLIENT_IS_LOCAL_BLACK);
			statsCount(&stat_connect_bl);
			break;

		case SMDB_ACCESS_TEMPFAIL:
			access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_TEMPFAIL, "450 4.7.1 host " CLIENT_FORMAT " %s" ID_MSG(853) "\r\n", CLIENT_INFO(sess), msg == NULL ? "temporary failure" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect"><span class="tag">Connect:</span></a> tag entry for either the
client name or IP address with a right-hand-side value of TEMPFAIL.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			CLIENT_SET(sess, CLIENT_IS_TEMPFAIL);
			break;

		default:
			access = SMTPF_CONTINUE;

			if (strcmp(value, "IREJECT") == 0) {
				access = replyPushFmt(sess, SMTPF_DROP, "550 5.7.1 host " CLIENT_FORMAT " %s" ID_MSG(854) "\r\n", CLIENT_INFO(sess), msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect"><span class="tag">Connect:</span></a> tag entry for either the
client name or IP address with a right-hand-side value of IREJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			CLIENT_SET(sess, CLIENT_IS_BLACK|CLIENT_IS_LOCAL_BLACK);
				statsCount(&stat_connect_bl);
			}

			else if (strcmp(value, "CONTENT") == 0) {
				access = SMTPF_GREY;
				statsCount(&stat_connect_gl);
				CLIENT_SET(sess, CLIENT_IS_GREY);
				sess->client.bw_state = SMTPF_GREY;
			}

			else if (strcmp(value, "SAVE") == 0) {
				access = SMTPF_CONTINUE;
				CLIENT_SET(sess, CLIENT_IS_SAVE);
			}

			else if (strcmp(value, "TRAP") == 0) {
				access = SMTPF_DISCARD;
				CLIENT_SET(sess, CLIENT_IS_TRAP);
				sess->client.bw_state = SMTPF_DISCARD;
			}

			else if (strcmp(value, "TAG") == 0) {
				access = SMTPF_CONTINUE;
				CLIENT_SET(sess, CLIENT_IS_TAG);
			}
		}

		free(value);
	}

	/* Unless by-pass above in the access database, then RFC 2606
	 * reserved special domains will be rejected. Take care with
	 * the .localhost or .localdomain domain if you use it.
	 */
	else if (optRFC2606SpecialDomains.value
	&& CLIENT_NOT_SET(sess, CLIENT_IS_LAN|CLIENT_IS_LOCALHOST) && isRFC2606(sess->client.name)) {
		access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 host " CLIENT_FORMAT " from RFC2606 reserved domain" ID_MSG(121) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2606_special_domains">rfc2606-special-domains</a>.
}*/
	}

	/* Postfix 2.3 uses "unknown" for client_name when there is no rDNS
	 * result instead of an IP-as-domain-literal "[123.45.67.89]" which
	 * Sendmail uses.
	 */
	else if (optRejectUnknownTLD.value
	&& CLIENT_NOT_SET(sess, CLIENT_IS_LAN|CLIENT_IS_LOCALHOST)
	&& *sess->client.name != '\0' && !hasValidTLD(sess->client.name)) {
		access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.7.1 host " CLIENT_FORMAT " from unknown TLD" ID_MSG(122) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_reject_unknown_tld">reject-unknown-tld</a>.
}*/
	}

	sess->client.bw_state = access;

	return access;
}

int
accessIdle(Session *sess, va_list ignore)
{
	int rc;

	/* See mail-retest-client and idle-retest-timer. */
	if ((rc = accessConnect(sess, ignore)) != SMTPF_CONTINUE)
		statsCount(&stat_idle_retest_timer);

	return rc;
}

static int
accessMsgAction(Session *sess, const char *value, int access)
{
	if (strcmp(value, "SAVE") == 0) {
		access = SMTPF_CONTINUE;
		MSG_SET(sess, MSG_SAVE);
	}

	else if (strcmp(value, "TRAP") == 0) {
		access = SMTPF_DISCARD;
		MSG_SET(sess, MSG_TRAP);
	}

	else if (strcmp(value, "TAG") == 0) {
		access = SMTPF_CONTINUE;
		MSG_SET(sess, MSG_TAG);
	}

	return access;
}

/**
 * Perform the following access.db lookups for mail address, stopping on
 * the first entry found:
 *
 *	tag:account@some.sub.domain.tld
 *	tag:some.sub.domain.tld
 *	tag:sub.domain.tld
 *	tag:domain.tld
 *	tag:tld
 *	tag:account@
 * 	tag:
 *
 *	from:account@some.sub.domain.tld
 *	from:some.sub.domain.tld
 *	from:sub.domain.tld
 *	from:domain.tld
 *	from:tld
 *	from:account@
 *
 *	account@some.sub.domain.tld
 *	some.sub.domain.tld
 *	sub.domain.tld
 *	domain.tld
 *	tld
 *	account@
 *
 * When a tag: entry is found, then the right-hand-side value is processed
 * as a pattern list and that result returned, else on the result of the
 * the right-hand-side is returned. Otherwise if no entry is found, then
 * SMDB_ACCESS_NOT_FOUND will be returned.
 *
 * @param sess
 *	A pointer to a Session.
 *
 * @param args
 *	An argument list containing a "ParsePath *" generated from the
 *	MAIL FROM: argument.
 *
 * @return
 *	An SMTPF_ return code.
 */
int
accessMail(Session *sess, va_list args)
{
	int access;
	char *msg, *value = NULL;
	ParsePath *path = va_arg(args, ParsePath *);

	LOG_TRACE(sess, 123, accessMail);

	CLIENT_CLEAR(sess, CLIENT_IS_MX);
	if (CLIENT_ANY_SET(sess, CLIENT_IS_TAG))
		MSG_SET(sess, MSG_TAG);

	/* How to handle the DSN address. */
	if (path->address.length == 0)
		access = SMTPF_CONTINUE;

	if ((access = smdbIpMail(sess->access_map, "connect:", sess->client.addr, SMDB_COMBO_TAG_DELIM "from:", sess->msg.mail->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND
	|| (*sess->client.name != '\0' && (access = smdbDomainMail(sess->access_map, "connect:", sess->client.name, SMDB_COMBO_TAG_DELIM "from:", sess->msg.mail->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND)) {
		if (strcmp(value, "SPF-PASS") == 0 && sess->msg.spf_mail == SPF_PASS)
			access = SMDB_ACCESS_OK;

		if ((msg = strchr(value, ':')) != NULL)
			msg++;

		switch (access = smdbAccessIsOk(access)) {
		case SMDB_ACCESS_OK:
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(124) "host " CLIENT_FORMAT " sender <%s> %s", LOG_ARGS(sess), CLIENT_INFO(sess), sess->msg.mail->address.string, msg == NULL ? "white listed" : msg);
/*{LOG
There is a <a href="access-map.html#tag_connect_from"><span class="tag">Connect:From:</span></a>
 combo tag entry for either the client name and sender pair or client IP address and sender pair with a
right-hand-side value of OK.
See <a href="access-map.html#access_tags">access-map</a>.
}*/			}

			statsCount(&stat_connect_mail_wl);
			MAIL_SET(sess, MAIL_IS_WHITE);
			path->isWhiteListed = 1;
			access = SMTPF_ACCEPT;
			break;

		case SMDB_ACCESS_REJECT:
			access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "550 5.7.1 host " CLIENT_FORMAT " sender <%s> %s" ID_MSG(125) "\r\n", CLIENT_INFO(sess), sess->msg.mail->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect_from"><span class="tag">Connect:From:</span></a> combo tag entry for either the
client name and sender pair or client IP address and sender pair with a
right-hand-side value of REJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			statsCount(&stat_connect_mail_bl);
			MAIL_SET(sess, MAIL_IS_BLACK|MAIL_IS_LOCAL_BLACK);
			path->isWhiteListed = -1;
			break;

		case SMDB_ACCESS_TEMPFAIL:
			access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_TEMPFAIL, "450 4.7.1 host " CLIENT_FORMAT " sender <%s> %s" ID_MSG(814) "\r\n", CLIENT_INFO(sess), sess->msg.mail->address.string, msg == NULL ? "temporary failure" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect_from"><span class="tag">Connect:From:</span></a> combo tag entry for either the
client name and sender pair or client IP address and sender pair with a
right-hand-side value of TEMPFAIL.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			MAIL_SET(sess, MAIL_IS_TEMPFAIL);
			path->isWhiteListed = 0;
			break;

		default:
			if (strcmp(value, "IREJECT") == 0) {
				access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 host " CLIENT_FORMAT " sender <%s> %s" ID_MSG(855) "\r\n", CLIENT_INFO(sess), sess->msg.mail->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect_from"><span class="tag">Connect:From:</span></a> combo tag entry for either the
client name and sender pair or client IP address and sender pair with a
right-hand-side value of IREJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
				statsCount(&stat_connect_mail_bl);
				MAIL_SET(sess, MAIL_IS_BLACK|MAIL_IS_LOCAL_BLACK);
				path->isWhiteListed = -1;
			}

			else {
				access = accessMsgAction(sess, value, sess->client.bw_state);
			}
		}
	}

	/* Lookup
	 *
	 *	tag:account@some.sub.domain.tld
	 *	tag:some.sub.domain.tld
	 *	tag:sub.domain.tld
	 *	tag:domain.tld
	 *	tag:tld
	 *	tag:account@
	 *	tag:
	 */
	else if ((access = accessEmail(sess, "from:", path->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND) {
		if (strcmp(value, "SPF-PASS") == 0 && sess->msg.spf_mail == SPF_PASS)
			access = SMDB_ACCESS_OK;

		if ((msg = strchr(value, ':')) != NULL)
			msg++;

		switch (access = smdbAccessIsOk(access)) {
		case SMDB_ACCESS_OK:
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(126) "sender <%s> %s", LOG_ARGS(sess), path->address.string, msg == NULL ? "white listed" : msg);
/*{LOG
There is a <a href="access-map.html#tag_from"><span class="tag">From:</span></a> tag entry for
the sender address or their domain with a right-hand-side value of OK.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			}
			statsCount(&stat_mail_wl);
			MAIL_SET(sess, MAIL_IS_WHITE);
			path->isWhiteListed = 1;
			access = SMTPF_ACCEPT;
			break;

		case SMDB_ACCESS_REJECT:
			access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "550 5.7.1 sender <%s> %s" ID_MSG(127) "\r\n", path->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_from"><span class="tag">From:</span></a> tag entry for
the sender address or their domain with a right-hand-side value of REJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			statsCount(&stat_mail_bl);
			MAIL_SET(sess, MAIL_IS_BLACK|MAIL_IS_LOCAL_BLACK);
			path->isWhiteListed = -1;
			break;

		case SMDB_ACCESS_TEMPFAIL:
			access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_TEMPFAIL, "450 4.7.1 sender <%s> %s" ID_MSG(815) "\r\n", path->address.string, msg == NULL ? "temporary failure" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_from"><span class="tag">From:</span></a> tag entry for
the sender address or their domain with a right-hand-side value of TEMPFAIL.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			MAIL_SET(sess, MAIL_IS_TEMPFAIL);
			path->isWhiteListed = 0;
			break;

		default:
			if (strcmp(value, "IREJECT") == 0) {
				access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 sender <%s> %s" ID_MSG(856) "\r\n", path->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_from"><span class="tag">From:</span></a> tag entry for
the sender address or their domain with a right-hand-side value of IREJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
				statsCount(&stat_mail_bl);
				MAIL_SET(sess, MAIL_IS_BLACK|MAIL_IS_LOCAL_BLACK);
				path->isWhiteListed = -1;
			}

			else {
				access = accessMsgAction(sess, value, sess->client.bw_state);
			}
		}
	}

	/* Unless by-pass above in the access database, then RFC 2606
	 * reserved special domains will be rejected. Take care with
	 * the .localhost domain if you use it.
	 */
	else if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)
	&& optRFC2606SpecialDomains.value && isRFC2606(path->domain.string)) {
		access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "550 5.7.1 sender <%s> from RFC2606 reserved domain" ID_MSG(128) "\r\n", path->address.string, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2606_special_domains">rfc2606-special-domains</a>.
}*/
	}

	else if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)
	&& optRejectUnknownTLD.value && 0 < path->domain.length && *path->domain.string != '[' && !hasValidTLD(path->domain.string)) {
		access = replyPushFmt(sess, SMTPF_DELAY|SMTPF_REJECT, "550 5.7.1 sender <%s> from unknown TLD" ID_MSG(129) "\r\n", path->address.string, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_reject_unknown_tld">reject-unknown-tld</a>.
}*/
	}

	else {
		/* Set the B/W transaction state based on the B/W session state. */
		access = sess->client.bw_state;
	}

	sess->msg.bw_state = access;
	free(value);

	return access;
}

/**
 * Perform the following access.db lookups for mail address, stopping on
 * the first entry found:
 *
 *	from:account@some.sub.domain.tld
 *	from:some.sub.domain.tld
 *	from:sub.domain.tld
 *	from:domain.tld
 *	from:tld
 *	from:account@
 *	from:
 *
 * When a tag: entry is found, then the right-hand-side value is processed
 * as a pattern list and that result returned, else on the result of the
 * the right-hand-side is returned. Otherwise if no entry is found, then
 * SMDB_ACCESS_NOT_FOUND will be returned.
 *
 * @param sess
 *	A pointer to a Session.
 *
 * @param args
 *	An argument list containing a "ParsePath *" generated from the
 *	MAIL FROM: argument.
 *
 * @return
 *	An SMTPF_ return code.
 */
int
accessRcpt(Session *sess, va_list args)
{
	int access;
	char *msg, *value = NULL;
	ParsePath *path = va_arg(args, ParsePath *);

	LOG_TRACE(sess, 130, accessRcpt);

	/* Block this form of routed address:
	 *
	 *	user%other.domain.com@our.domain.com
	 *
	 * Normally Sendmail prevents the %-hack relaying form, but some
	 * local rule sets might overlook this and inadvertantly circumvent
	 * Sendmail, eg. mailertable relay rule set in cookbook.mc. This
	 * test catches these slips.
	 */
	if (optRejectPercentRelay.value && strchr(path->address.string, '%') != NULL) {
		access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 routed address relaying denied" ID_MSG(131) "\r\n", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_reject_percent_relay">reject-percent-relay</a>.
}*/
	}

	else if (optRejectUucpRoute.value && strchr(path->address.string, '!') != NULL) {
		access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 UUCP addressing denied" ID_MSG(132) "\r\n", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_reject_uucp_route">reject-uucp-route</a>.
@PACKAGE_NAME@ currently does nothing special with UUCP paths, so disabling
this option will have undefined results.
}*/
	}

	else if (optRejectQuotedAtSign.value && strchr(path->localLeft.string, '@') != NULL) {
		access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 special case of at-sign in local-part denied" ID_MSG(133) "\r\n", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_reject_quoted_at_sign">reject-quoted-at-sign</a>.
}*/
	}

	else if ((access = smdbIpMail(sess->access_map, "connect:", sess->client.addr, SMDB_COMBO_TAG_DELIM "to:", path->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND
	     || (*sess->client.name != '\0' && (access = smdbDomainMail(sess->access_map, "connect:", sess->client.name, SMDB_COMBO_TAG_DELIM "to:", path->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND)) {
		if ((msg = strchr(value, ':')) != NULL)
			msg++;

		switch (access = smdbAccessIsOk(access)) {
		case SMDB_ACCESS_OK:
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(134) "host " CLIENT_FORMAT " recipient <%s> %s", LOG_ARGS(sess), CLIENT_INFO(sess), path->address.string, msg == NULL ? "white listed" : msg);
/*{LOG
There is a <a href="access-map.html#tag_connect_to"><span class="tag">Connect:To:</span></a> combo tag entry for either the
client name and recipient pair or client IP address and recipient pair with a
right-hand-side value of OK.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			}
			statsCount(&stat_connect_rcpt_wl);
			RCPT_SET(sess, RCPT_IS_WHITE);
			path->isWhiteListed = 1;
			access = SMTPF_ACCEPT;
			break;

		case SMDB_ACCESS_REJECT:
			access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 host " CLIENT_FORMAT " recipient <%s> %s" ID_MSG(135) "\r\n", CLIENT_INFO(sess), path->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect_to"><span class="tag">Connect:To:</span></a> combo tag entry for either the
client name and recipient pair or client IP address and recipient pair with a
right-hand-side value of REJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			statsCount(&stat_connect_rcpt_bl);
			RCPT_SET(sess, RCPT_IS_BLACK|RCPT_IS_LOCAL_BLACK);
			path->isWhiteListed = -1;
			break;

		case SMDB_ACCESS_TEMPFAIL:
			access = replyPushFmt(sess, SMTPF_TEMPFAIL, "450 4.7.1 host " CLIENT_FORMAT " recipient <%s> %s" ID_MSG(816) "\r\n", CLIENT_INFO(sess), path->address.string, msg == NULL ? "temporary failure" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_connect_to"><span class="tag">Connect:To:</span></a> combo tag entry for either the
client name and recipient pair or client IP address and recipient pair with a
right-hand-side value of TEMPFAIL.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			RCPT_SET(sess, RCPT_IS_TEMPFAIL);
			path->isWhiteListed = 0;
			break;

		default:
			access = accessMsgAction(sess, value, sess->msg.bw_state);
		}
	}

	else if ((access = smdbMailMail(sess->access_map, "from:", sess->msg.mail->address.string, SMDB_COMBO_TAG_DELIM "to:", path->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND) {
		if ((msg = strchr(value, ':')) != NULL)
			msg++;

		switch (access = smdbAccessIsOk(access)) {
		case SMDB_ACCESS_OK:
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(136) "sender <%s> recipient <%s> %s", LOG_ARGS(sess), sess->msg.mail->address.string, path->address.string, msg == NULL ? "white listed" : msg);
/*{LOG
There is a <a href="access-map.html#tag_from_to"><span class="tag">From:To:</span></a> combo tag entry for a sender
and recipient pair with a right-hand-side value of OK.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			}
			statsCount(&stat_mail_rcpt_wl);
			RCPT_SET(sess, RCPT_IS_WHITE);
			path->isWhiteListed = 1;
			access = SMTPF_ACCEPT;
			break;

		case SMDB_ACCESS_REJECT:
			access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 sender <%s> recipient <%s> %s" ID_MSG(137) "\r\n", sess->msg.mail->address.string, path->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_from_to"><span class="tag">From:To:</span></a> combo tag entry for a sender
and recipient pair with a right-hand-side value of REJECT.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			statsCount(&stat_mail_rcpt_bl);
			RCPT_SET(sess, RCPT_IS_BLACK|RCPT_IS_LOCAL_BLACK);
			path->isWhiteListed = -1;
			break;

		case SMDB_ACCESS_TEMPFAIL:
			access = replyPushFmt(sess, SMTPF_TEMPFAIL, "450 4.7.1 sender <%s> recipient <%s> %s" ID_MSG(817) "\r\n", sess->msg.mail->address.string, path->address.string, msg == NULL ? "temporary failure" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_from_to"><span class="tag">From:To:</span></a> combo tag entry for a sender
and recipient pair with a right-hand-side value of TEMPFAIL.
See <a href="access-map.html#access_tags">access-map</a>.
}*/
			RCPT_SET(sess, RCPT_IS_TEMPFAIL);
			path->isWhiteListed = 0;
			break;

		default:
			access = accessMsgAction(sess, value, sess->msg.bw_state);
		}
	}

	/* Lookup
	 *
	 *	tag:account@some.sub.domain.tld
	 *	tag:some.sub.domain.tld
	 *	tag:sub.domain.tld
	 *	tag:domain.tld
	 *	tag:tld
	 *	tag:account@
	 *	tag:
	 */
	else if ((access = accessEmail(sess, "to:", path->address.string, NULL, &value)) != SMDB_ACCESS_NOT_FOUND) {
		if ((msg = strchr(value, ':')) != NULL)
			msg++;

		switch (access = smdbAccessIsOk(access)) {
		case SMDB_ACCESS_OK:
			if (verb_info.option.value) {
				syslog(LOG_INFO, LOG_MSG(138) "recipient <%s> %s", LOG_ARGS(sess), path->address.string, msg == NULL ? "white listed" : msg);
/*{LOG
There is a <a href="access-map.html#tag_to"><span class="tag">To:</span></a> tag entry for sender's
address with a right-hand-side value of OK.
See <a href="access-map.html#access_map">access-map</a>.
}*/
			}
			statsCount(&stat_rcpt_wl);
			RCPT_SET(sess, RCPT_IS_WHITE);
			path->isWhiteListed = 1;
			access = SMTPF_ACCEPT;
			break;

		case SMDB_ACCESS_REJECT:
			access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> %s" ID_MSG(139) "\r\n", path->address.string, msg == NULL ? "black listed" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_to"><span class="tag">To:</span></a> tag entry for sender's
address with a right-hand-side value of REJECT.
See <a href="access-map.html#access_map">access-map</a>.
}*/
			statsCount(&stat_rcpt_bl);
			RCPT_SET(sess, RCPT_IS_BLACK|RCPT_IS_LOCAL_BLACK);
			path->isWhiteListed = -1;
			break;

		case SMDB_ACCESS_TEMPFAIL:
			access = replyPushFmt(sess, SMTPF_TEMPFAIL, "450 4.7.1 recipient <%s> %s" ID_MSG(818) "\r\n", path->address.string, msg == NULL ? "temporary failure" : msg, ID_ARG(sess));
/*{REPLY
There is a <a href="access-map.html#tag_to"><span class="tag">To:</span></a> tag entry for sender's
address with a right-hand-side value of TEMPFAIL.
See <a href="access-map.html#access_map">access-map</a>.
}*/
			RCPT_SET(sess, RCPT_IS_TEMPFAIL);
			path->isWhiteListed = 0;
			break;

		default:
			access = accessMsgAction(sess, value, sess->msg.bw_state);
		}
	}

	/* Unless by-pass above in the access database, then RFC 2606
	 * reserved special domains will be rejected. Take care with
	 * the .localhost domain if you use it.
	 */
	else if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)
	&& optRFC2606SpecialDomains.value && isRFC2606(path->domain.string)) {
		access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> from RFC2606 reserved domain" ID_MSG(140) "\r\n", path->address.string, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2606_special_domains">rfc2606-special-domains</a>.
}*/
	}

	else if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)
	&& optRejectUnknownTLD.value
	&& 0 < path->domain.length && *path->domain.string != '['
	&& TextInsensitiveCompare(path->localLeft.string, "postmaster") != 0
	&& !hasValidTLD(path->domain.string)) {
		access = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> from unknown TLD" ID_MSG(141) "\r\n", path->address.string, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_reject_unknown_tld">reject-unknown-tld</a>.
}*/
	} else {
		access = sess->msg.bw_state;
	}

	free(value);

	return access;
}

int
accessHelo(Session *sess, va_list ignore)
{
	LOG_TRACE(sess, 142, accessHelo);

	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY))
		return SMTPF_SKIP_REMAINDER;

	return SMTPF_CONTINUE;
}

static int
access_rcpt_bw(Session *sess)
{
	Rcpt *rcpt;
	Connection *fwd;

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
		for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
			if (rcpt->rcpt->isWhiteListed)
				return SMTPF_ACCEPT;
		}
	}

	return SMTPF_CONTINUE;
}

int
accessData(Session *sess, va_list ignore)
{
	LOG_TRACE(sess, 143, accessData);

	/* Save message handlers must come before anything that
	 * might reject or discard the message. Access handlers
	 * must come before expensive content handlers, such as
	 * spamd.
	 */
	if (/* MSG_NOT_SET(sess, MSG_SAVE) && */ MSG_ANY_SET(sess, MSG_DISCARD)) {
		LOG_TRACE(sess, 857, discard flag set);
		return SMTPF_DISCARD;
	}

	if (optSmtpAuthWhite.value && CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH)) {
		/* White listed authenticated session. */
		LOG_TRACE(sess, 144, white authenticated);
		return SMTPF_ACCEPT;
	}

	switch (access_rcpt_bw(sess)) {
	case SMTPF_ACCEPT:
		/* White listed recipient. */
		LOG_TRACE(sess, 145, white recipient);
		return SMTPF_ACCEPT;

	case SMTPF_TEMPFAIL:
		LOG_TRACE(sess, 145, temp. fail recipient);
		return SMTPF_TEMPFAIL;
	}

	switch (sess->msg.bw_state) {
	case SMTPF_ACCEPT:
		/* White listed client or sender. */
		LOG_TRACE(sess, 146, white client or sender or tagged message);
		return SMTPF_ACCEPT;

	case SMTPF_TEMPFAIL:
		LOG_TRACE(sess, 146, temp. fail client or sender);
		return SMTPF_ACCEPT;

	case SMTPF_DISCARD:
		/* Discard because of client or sender. */
		LOG_TRACE(sess, 147, discard due to client or sender);
		return SMTPF_DISCARD;
	}

	return SMTPF_CONTINUE;
}

int
accessHeaders(Session *sess, va_list args)
{
	return accessData(sess, NULL);
}

int
accessContent(Session *sess, va_list args)
{
	return accessData(sess, NULL);
}

int
accessDot(Session *sess, va_list ignore)
{
	return accessData(sess, NULL);
}

int
accessMapOpen(Session *sess)
{
	sess->access_map = smdbOpen(access_map_path, 1);
	return -(sess->access_map == NULL);
}

void
accessMapClose(Session *sess)
{
	smdbClose(sess->access_map);
}

AccessMapping accessTagWordsMap[] =
{
	{	 ACCESS_CONN_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_DISCARD_WORD
		"|" ACCESS_REJECT_WORD
		"|" ACCESS_IREJECT_WORD
		"|" ACCESS_TEMPFAIL_WORD
		"|" ACCESS_SAVE_WORD
		"|" ACCESS_TRAP_WORD
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
		"|" ACCESS_TAG_WORD
		"|" ACCESS_CONTENT_WORD
	},
	{	ACCESS_MAIL_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_DISCARD_WORD
		"|" ACCESS_REJECT_WORD
		"|" ACCESS_IREJECT_WORD
		"|" ACCESS_TEMPFAIL_WORD
		"|" ACCESS_SAVE_WORD
		"|" ACCESS_TRAP_WORD
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
		"|" ACCESS_TAG_WORD
		"|" ACCESS_SPF_PASS_WORD
	},
	{	ACCESS_CONN_MAIL_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_DISCARD_WORD
		"|" ACCESS_REJECT_WORD
		"|" ACCESS_IREJECT_WORD
		"|" ACCESS_TEMPFAIL_WORD
		"|" ACCESS_SAVE_WORD
		"|" ACCESS_TRAP_WORD
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
		"|" ACCESS_TAG_WORD
		"|" ACCESS_SPF_PASS_WORD
	},
	{	ACCESS_RCPT_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_DISCARD_WORD
		"|" ACCESS_REJECT_WORD
		"|" ACCESS_TEMPFAIL_WORD
		"|" ACCESS_SAVE_WORD
		"|" ACCESS_TRAP_WORD
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
		"|" ACCESS_TAG_WORD
	},
	{	ACCESS_CONN_RCPT_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_DISCARD_WORD
		"|" ACCESS_REJECT_WORD
		"|" ACCESS_TEMPFAIL_WORD
		"|" ACCESS_SAVE_WORD
		"|" ACCESS_TRAP_WORD
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
		"|" ACCESS_TAG_WORD
	},
	{	ACCESS_MAIL_RCPT_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_DISCARD_WORD
		"|" ACCESS_REJECT_WORD
		"|" ACCESS_TEMPFAIL_WORD
		"|" ACCESS_SAVE_WORD
		"|" ACCESS_TRAP_WORD
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
		"|" ACCESS_TAG_WORD
	},
	{ 	ACCESS_BODY_TAG,
		    ACCESS_OK_WORD
		"|" ACCESS_REJECT_WORD
	},
	{ 	ACCESS_RATE_TAG,
		    "^[0-9]+$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_CONCURRENT_TAG,
		    "^[0-9]+$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_GREY_CONN_TAG,
		    "^[0-9]+$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_GREY_RCPT_TAG,
		    "^[0-9]+$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_NULL_TAG,
		    "^[0-9]+$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_SIZE_CONN_TAG,
		    "^-?[0-9]+[KMGkmg]?$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_SIZE_MAIL_TAG,
		    "^-?[0-9]+[KMGkmg]?$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_SIZE_RCPT_TAG,
		    "^-?[0-9]+[KMGkmg]?$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_MSGS_CONN_TAG,
		    "^[0-9]+\\/([0-9]*[WDHMSwdhms]|[0-9]+[WDHMSwdhms]?)$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_MSGS_MAIL_TAG,
		    "^[0-9]+\\/([0-9]*[WDHMSwdhms]|[0-9]+[WDHMSwdhms]?)$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_MSGS_RCPT_TAG,
		    "^[0-9]+\\/([0-9]*[WDHMSwdhms]|[0-9]+[WDHMSwdhms]?)$"
		"|" ACCESS_NEXT_WORD
		"|" ACCESS_SKIP_WORD
	},
	{ 	ACCESS_EMEW_TAG,
		    ".+"
	},
	{ 	ACCESS_SPAM_TAG,
		    ".+"
	},
	{	NULL, NULL }
};

AccessMapping accessWordTagsMap[] =
{
	{
		ACCESS_OK_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
		"|" ACCESS_BODY_TAG
	},
	{
		ACCESS_CONTENT_WORD,
		    ACCESS_CONN_TAG
	},
	{
		ACCESS_DISCARD_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
	},
	{
		ACCESS_IREJECT_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_CONN_MAIL_TAG
	},
	{
		ACCESS_NEXT_WORD,
		    ".+"
	},
	{
		ACCESS_REJECT_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
		"|" ACCESS_BODY_TAG
	},
	{
		ACCESS_SAVE_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
	},
	{
		ACCESS_SKIP_WORD,
		   ".+"
	},
	{
		ACCESS_SPF_PASS_WORD,
		    ACCESS_MAIL_TAG
		"|" ACCESS_CONN_MAIL_TAG
	},
	{
		ACCESS_TAG_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
	},
	{
		ACCESS_TEMPFAIL_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
	},
	{
		ACCESS_TRAP_WORD,
		    ACCESS_CONN_TAG
		"|" ACCESS_MAIL_TAG
		"|" ACCESS_RCPT_TAG
		"|" ACCESS_CONN_MAIL_TAG
		"|" ACCESS_CONN_RCPT_TAG
		"|" ACCESS_MAIL_RCPT_TAG
	},
	{
		"^[0-9]+$",
		    ACCESS_CONCURRENT_TAG
		"|" ACCESS_RATE_TAG
		"|" ACCESS_GREY_CONN_TAG
		"|" ACCESS_GREY_RCPT_TAG
		"|" ACCESS_NULL_TAG
	},
	{	"^-?[0-9]+[KMGkmg]?$",
		    ACCESS_SIZE_CONN_TAG
		"|" ACCESS_SIZE_MAIL_TAG
		"|" ACCESS_SIZE_RCPT_TAG
	},
	{
		"^[0-9]+\\/([0-9]*[WDHMSwdhms]|[0-9]+[WDHMSwdhms]?)$",
		    ACCESS_MSGS_CONN_TAG
		"|" ACCESS_MSGS_MAIL_TAG
		"|" ACCESS_MSGS_RCPT_TAG
	},
	{
		".+",
		    ACCESS_EMEW_TAG
		"|" ACCESS_SPAM_TAG
	},
	{ 	NULL, NULL }
};

#ifdef NOPE
	{
		ACCESS_OK_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE "|"
		ACCESS_BODY_RE
	},
	{
		ACCESS_CONTENT_RE,
		ACCESS_CONN_RE
	},
	{
		ACCESS_DISCARD_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE
	},
	{
		ACCESS_IREJECT_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_CONN_MAIL_RE
	},
	{
		ACCESS_NEXT_RE,
		".+"
	},
	{
		ACCESS_REJECT_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE "|"
		ACCESS_BODY_RE
	},
	{
		ACCESS_SAVE_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE
	},
	{
		ACCESS_SKIP_RE,
		".+"
	},
	{
		ACCESS_SPF_PASS_RE,
		ACCESS_MAIL_RE "|" ACCESS_CONN_MAIL_RE
	},
	{
		ACCESS_TAG_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE
	},
	{
		ACCESS_TEMPFAIL_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE
	},
	{
		ACCESS_TRAP_RE,
		ACCESS_CONN_RE "|" ACCESS_MAIL_RE "|" ACCESS_RCPT_RE "|"
		ACCESS_CONN_MAIL_RE "|" ACCESS_CONN_RCPT_RE "|" ACCESS_MAIL_RCPT_RE
	},
	{
		"^[0-9]+$",
		ACCESS_CONCURRENT_RE "|" ACCESS_RATE_RE "|"
		ACCESS_GREY_CONN_RE "|" ACCESS_GREY_RCPT_RE "|"
		ACCESS_NULL_RE
	},
	{	"^-?[0-9]+[KMGkmg]?$",
		ACCESS_SIZE_CONN_RE "|" ACCESS_SIZE_MAIL_RE "|" ACCESS_SIZE_RCPT_RE
	},
	{
		"^[0-9]+\\/([0-9]*[WDHMSwdhms]|[0-9]+[WDHMSwdhms]?)$",
		ACCESS_MSGS_CONN_RE "|" ACCESS_MSGS_MAIL_RE "|" ACCESS_MSGS_RCPT_RE
	},
	{
		".+",
		ACCESS_EMEW_RE "|" ACCESS_SPAM_RE
	},
	{ NULL, NULL }
};
#endif

void
accessPrintMapping(AccessMapping *table)
{
	for ( ; table->token != NULL; table++) {
		printf("/%s/ /%s/\n", table->token, table->valid);
	}
}

