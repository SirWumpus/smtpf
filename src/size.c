/*
 * size.c
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

#ifdef FILTER_SIZE

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define USAGE_LENGTH_TAGS						\
  "Message Length Controls\n"						\
"#\n"									\
"# The tags Length-Connect:, Length-From:, and Length-To: can be used\n"\
"# in the access-map.\n"						\
"#\n"									\
"# If a key is found, then the value is processed as a pattern list\n"	\
"# and the result returned. A size limit is specified in place of an\n"	\
"# action, and is the maximum number of octets permitted per message.\n"\
"# It is expressed as a number with an optional scale suffix K (kilo),\n"	\
"# M (mega), or G (giga). If no size limit is given or is -1, then\n"	\
"# the message can be any length (ULONG_MAX).\n"			\
"#\n"									\
"# When there are multiple message size limits possible, then the\n"	\
"# limit applied, in order of precedence is: maximum value of all\n"	\
"# relevant Length-To:, Length-From:, or Length-Connect:.\n"		\
"#\n"									\


Option optLengthTags			= { "",				NULL,		USAGE_LENGTH_TAGS };

Stats stat_message_size			= { STATS_TABLE_MSG, "message-size" };

static Verbose verb_size 		= { { "size", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

static unsigned long
size_in_bytes(char *value)
{
	char *stop;
	unsigned long size;

	size = ULONG_MAX;

	if (value != NULL) {
		size = strtoul(value, &stop, 10);

		switch (*stop) {
		case 'G': case 'g': size *= 1024;
		case 'M': case 'm': size *= 1024;
		case 'K': case 'k': size *= 1024;
		}
	}

	return size;
}

int
sizeRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_size);
	optionsRegister(&optLengthTags, 0);
	(void) statsRegister(&stat_message_size);

	return SMTPF_CONTINUE;
}

int
sizeConnect(Session *sess, va_list ignore)
{
	char *value;

	LOG_TRACE(sess, 620, sizeConnect);

	sess->client.max_size = ULONG_MAX;

	if (accessClient(sess, "length-connect:", sess->client.name, sess->client.addr, NULL, &value, 1) != ACCESS_NOT_FOUND) {
		sess->client.max_size = size_in_bytes(value);
		free(value);
	}

	return SMTPF_CONTINUE;
}

int
sizeRset(Session *sess, va_list ignore)
{
	LOG_TRACE(sess, 621, sizeRset);

	sess->msg.length = 0;
	sess->msg.mail_size = 0;
	sess->msg.max_size_rcpt = 0;
	sess->msg.max_size = sess->client.max_size;

	return SMTPF_CONTINUE;
}

int
sizeMail(Session *sess, va_list args)
{
	char *value;
	Vector params;
	ParsePath *mail;
	const char **param;

	LOG_TRACE(sess, 622, sizeMail);

	mail = va_arg(args, ParsePath *);

	if (accessEmail(sess, "length-from:", mail->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
		sess->msg.max_size = size_in_bytes(value);
		free(value);
	}

	params = va_arg(args, Vector);

	if (params != NULL) {
		for (param = (const char **) VectorBase(params); *param != NULL; param++) {
			if (0 < TextInsensitiveStartsWith(*param, "SIZE=")) {
				if (20 + sizeof ("SIZE=")-1 < strlen(*param))
					return replySetFmt(sess, SMTPF_REJECT, "501 5.5.4 <%s> SIZE exceeds RFC 1870 max. length" ID_MSG(903) CRLF, mail->address.string, ID_ARG(sess));
				sess->msg.mail_size = strtoul(*param + sizeof ("SIZE=")-1, NULL, 10);
				break;
			}
		}
	}

	return SMTPF_CONTINUE;
}

int
sizeRcpt(Session *sess, va_list args)
{
	char *value;
	ParsePath *rcpt;
	unsigned long size_limit, max_bytes;

	LOG_TRACE(sess, 623, sizeRcpt);

	rcpt = va_arg(args, ParsePath *);

	if (accessEmail(sess, "length-to:", rcpt->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
		size_limit = size_in_bytes(value);
		if (sess->msg.max_size_rcpt < size_limit)
			sess->msg.max_size_rcpt = size_limit;
		free(value);

		if (verb_size.option.value)
			syslog(LOG_DEBUG, LOG_MSG(902) "length-connect=%lu length-from=%lu length-to=%lu mail-size=%lu", LOG_ARGS(sess), sess->client.max_size, sess->msg.max_size, size_limit, sess->msg.mail_size);
	}

	max_bytes = 0 < sess->msg.max_size_rcpt ? sess->msg.max_size_rcpt : sess->msg.max_size;

	if (max_bytes != ULONG_MAX && max_bytes < sess->msg.mail_size) {
		statsCount(&stat_message_size);
		return replyPushFmt(sess, SMTPF_REJECT, "552 5.3.4 <%s> (%lu bytes) exceeded max. message size of %lu bytes" ID_MSG(901) "\r\n", rcpt->address.string, sess->msg.mail_size, max_bytes, ID_ARG(sess));
/*{NEXT}*/
	}

	return SMTPF_CONTINUE;
}

int
sizeDot(Session *sess, va_list ignore)
{
	unsigned long max_bytes;

	LOG_TRACE(sess, 624, sizeDot);

	max_bytes = 0 < sess->msg.max_size_rcpt ? sess->msg.max_size_rcpt : sess->msg.max_size;

	if (max_bytes != ULONG_MAX && max_bytes < sess->msg.length) {
		statsCount(&stat_message_size);
		return replyPushFmt(sess, SMTPF_REJECT, "550 5.3.4 " CLIENT_FORMAT " (%lu bytes) exceeded max. message size of %lu bytes" ID_MSG(625) "\r\n", CLIENT_INFO(sess), sess->msg.length, max_bytes, ID_ARG(sess));
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_length"><span class="tag">Length-Connect:</span></a>,
<a href="access-map.html#tag_length"><span class="tag">Length-From:</span></a>,
<a href="access-map.html#tag_length"><span class="tag">Length-To:</span></a> tags.
}*/
	}

	return SMTPF_CONTINUE;
}

#endif /* FILTER_SIZE */
