/*
 * timelimit.c
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_SIZE

#include "smtpf.h"

#include <ctype.h>
#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_time_limit_delimiters[] =
  "time-limit-delimiters=\n"
"#\n"
"# A string of characters that can be used to indicate a time limit\n"
"# field in the local part of a recipient address. Specify the empty\n"
"# string to disable. Characters that can be used are defined in RFC\n"
"# 5322 \"atext\". They are:\n"
"#\n"
"#    ! # $ % & ' * + - / = ? ^ _ ` { | } ~ .\n"
"#\n"
"# Note that dot (.) is fairly common and should not be used. Also\n"
"# sendmail and postfix treat plus (+) and hyphen (-) specially and\n"
"# are not recommended. Percent (%) was used for an old routing synatx,\n"
"# which may be rejected by sites and not recommeded.\n"
"#\n"
"# The delimiter indicates the start of a time limit field, which is\n"
"# an optional non-numeric informational token followed by a series of\n"
"# 4 to 12 decimal digits. The digits represents \"YYYY[MM[DD[hh[mm]]]]\"\n"
"# of the expire time when this recipient address is no longer valid\n"
"# and will be rejected. The delimiter and time limit field can appear\n"
"# any where in the user portion of the address and are removed before\n"
"# forwarding the receipient.\n"
"#\n"
"# Examples using the address <john.smith@domain.example> and delimiter\n"
"# dollar-sign ($):\n"
"#\n"
"#\t<john.smith$20080401@domain.example>\n"
"#\t<$token_word20080401john.smith@domain.example>\n"
"#\t<john$mail.list.name20080401.smith@domain.example>\n"
"#"
;
Option optTimeLimitDelimiters = { "time-limit-delimiters", "", usage_time_limit_delimiters };

Verbose verb_timelimit = { { "timelimitrcpt", "-", "" } };

Stats stat_time_limit_rcpt = { STATS_TABLE_RCPT, "time-limited-rcpt" };

/***********************************************************************
 ***
 ***********************************************************************/

int
timeLimitRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_timelimit);
	optionsRegister(&optTimeLimitDelimiters, 0);
	(void) statsRegister(&stat_time_limit_rcpt);

	return SMTPF_CONTINUE;
}

int
timeLimitRcpt(Session *sess, va_list args)
{
	time_t expire;
	ParsePath *rcpt;
	struct tm local_time;
	int span, delim, length, ch;
	char *digits, *mark, *at_sign;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(623) "timeLimitRcpt()", LOG_ARGS(sess));

	if (*optTimeLimitDelimiters.string == '\0')
		return SMTPF_CONTINUE;

	rcpt = va_arg(args, ParsePath *);
	if (verb_timelimit.option.value)
		syslog(
			LOG_DEBUG, LOG_MSG(882) "RCPT=<%s> left=\"%s\" right=\"%s\" delimiters=\"%s\"",
			LOG_ARGS(sess), rcpt->address.string,
			rcpt->localLeft.string, rcpt->localRight.string,
			optTimeLimitDelimiters.string
		);

	if ((at_sign = strchr(rcpt->address.string, '@')) == NULL)
		return SMTPF_CONTINUE;
	*at_sign = '\0';
	span = delim = strcspn(rcpt->address.string, optTimeLimitDelimiters.string);

	/* Is a time-limit delimiter followed by a digit present? */
	if (rcpt->address.string[span] == '\0') {
		if (verb_timelimit.option.value)
			syslog(LOG_DEBUG, LOG_MSG(883) "no time-limit-delimiters", LOG_ARGS(sess));
		*at_sign = '@';
		return SMTPF_CONTINUE;
	}

	/* The time limit specifier starts with marker delimiter
	 * followed by optional non-numeric informational token
	 * followed by 4 to 12 decimal digit time specifier.
	 *
	 * 	/(.)([^0-9]*)([0-9]{4,12})/
	 *
	 *	$1	delimiter from set of allowed time-limit-delimiters
	 *	$2	optional non-numeric informational token
	 *	$3	time specifier: YYYY[MM[DD[hh[mm]]]]
	 *
	 * Example:
	 *	achowe$zorch20091231@snert.com
	 *	$listname2010achowe@snert.com
	 *	first_name$200812061430.last_name@some.domain
	 *
	 * Since the time limit specifier has a well defined structure,
	 * it can appear any where in the local-part of a mail address
	 * and is removed before forwarding the recipient to the forward
	 * host.
	 */
	digits = rcpt->address.string + span + 1;
	length = strcspn(digits, "0123456789");
	digits += length;
	span = strspn(digits, "0123456789");
	length += span;

	/* Is the time field between 4..12 long and an even length? */
	if (span < 4 || 12 < span || (span & 1)) {
		if (verb_timelimit.option.value)
			syslog(LOG_DEBUG, LOG_MSG(884) "RCPT=<%s> span=%d too short, long, or odd", LOG_ARGS(sess), rcpt->address.string, span);
		*at_sign = '@';
		return SMTPF_CONTINUE;
	}

	/* Parse the time field into a time stamp. */
	memset(&local_time, 0, sizeof (local_time));
	local_time.tm_isdst = -1;
	local_time.tm_mday = 1;

	ch = digits[4];
	digits[4] = '\0';
	local_time.tm_year = strtol(digits, NULL, 10) - 1900;
	digits[4] = ch;
	digits += 4;
	span -= 4;

	if (0 < span) {
		ch = digits[2];
		digits[2] = '\0';
		local_time.tm_mon = strtol(digits, NULL, 10) - 1;
		digits[2] = ch;
		digits += 2;
		span -= 2;

		if (0 < span) {
			ch = digits[2];
			digits[2] = '\0';
			local_time.tm_mday = strtol(digits, NULL, 10);
			digits[2] = ch;
			digits += 2;
			span -= 2;

			if (0 < span) {
				ch = digits[2];
				digits[2] = '\0';
				local_time.tm_hour = strtol(digits, NULL, 10);
				digits[2] = ch;
				digits += 2;
				span -= 2;

				if (0 < span) {
					ch = digits[2];
					digits[2] = '\0';
					local_time.tm_min = strtol(digits, NULL, 10);
					digits[2] = ch;
					digits += 2;
					span -= 2;
				}
			}
		}
	}

	*at_sign = '@';
	expire = mktime(&local_time);

	if (verb_timelimit.option.value)
		syslog(
			LOG_DEBUG, LOG_MSG(885) "time parse=%.4d-%.2d-%.2d %.2d:%.2d dst=%d expire=%lu",
			LOG_ARGS(sess), local_time.tm_year+1900, local_time.tm_mon+1, local_time.tm_mday,
			local_time.tm_hour, local_time.tm_min, local_time.tm_isdst, (unsigned long) expire
		);

	if (expire <= time(NULL)) {
		statsCount(&stat_time_limit_rcpt);
		CLIENT_SET(sess, CLIENT_IS_BLACK);
		return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> black listed" ID_MSG(886) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
A time-limited recipient has expired and was rejected.
See <a href="smtpf.html#opt_time_limit_delimiters">time-limit-delimiters</a>.
}*/
	}

	/* Strip the time limit field from the recipient
	 * address and reparse it.
	 */
	mark = strstr(rcpt->localLeft.string, rcpt->address.string+delim);
	if (mark != NULL) {
		memmove(
			mark, mark+length+1,
			rcpt->localLeft.length - ((mark+length+1) - rcpt->localLeft.string) +1
		);
		rcpt->localLeft.length -= length+1;
	}

	mark = strstr(rcpt->localRight.string, rcpt->address.string+delim);
	if (mark != NULL) {
		memmove(
			mark, mark+length+1,
			rcpt->localRight.length - ((mark+length+1) - rcpt->localRight.string) +1
		);
		rcpt->localRight.length -= length+1;
	}

	memmove(
		rcpt->address.string+delim, digits,
		rcpt->address.length - (digits - &rcpt->address.string[delim]) +1
	);
	rcpt->address.length -= length+1;

	if (verb_timelimit.option.value)
		syslog(
			LOG_DEBUG, LOG_MSG(887) "modified RCPT=<%s> left=\"%s\" right=\"%s\"",
			LOG_ARGS(sess), rcpt->address.string,
			rcpt->localLeft.string,
			rcpt->localRight.string
		);

	return SMTPF_CONTINUE;
}

#endif /* FILTER_SIZE */
