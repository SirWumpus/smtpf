/*
 * spamd.c
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

#if defined(FILTER_SPAMD) && !defined(FILTER_SPAMD2)

#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifndef SPAMD_PORT
#define SPAMD_PORT			783
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define USAGE_SPAMD_COMMAND						\
  "Specify one of the SPAMD protocol commands: CHECK, SYMBOLS, REPORT,\n"\
"# REPORT_IFSPAM to check the message. When used in conjunction with\n"	\
"# verbose=spamd, more detailed results from spamd will be logged.\n"	\
"#"

#define USAGE_SPAMD_POLICY						\
  "Policy to apply if message is spam. Specify either none, reject,\n"	\
"# or discard.\n"						\
"#"

#define USAGE_SPAMD_SOCKET						\
  "The unix domain socket or Internet host[:port] of the spamd\n"	\
"# server. Specify the empty string to disable spamd scan. The\n"	\
"# default spamd port is 783.\n"					\
"#"

Option optSpamdCommand	= { "spamd-command",	"CHECK",	USAGE_SPAMD_COMMAND };
Option optSpamdMaxSize	= { "spamd-max-size",	"0",		"Max. number of kilobytes to pass to spamd, 0 for unlimited." };
Option optSpamdSocket	= { "spamd-socket",	"",		USAGE_SPAMD_SOCKET };
Option optSpamdTimeout	= { "spamd-timeout",	"120",		"The spamd I/O timeout in seconds." };
Option optSpamdPolicy	= { "spamd-policy",	"reject",	USAGE_SPAMD_POLICY };

Verbose verb_spamd = { { "spamd", "-", "" } };

Stats stat_junk_mail = { STATS_TABLE_MSG, "junk-mail" };

typedef struct {
	Socket2 *socket;
	float threshold;
	float score;
} Spamd;

static FilterContext spamd_context;

/***********************************************************************
 ***
 ***********************************************************************/

static int
spamd_open(Session *sess, Spamd *spamd)
{
	int length;

	if (*optSpamdSocket.string == '\0')
		return SMTPF_CONTINUE;

	if (socketOpenClient(optSpamdSocket.string, SPAMD_PORT, optSpamdTimeout.value, NULL, &spamd->socket)) {
		syslog(LOG_ERR, LOG_MSG(646) "spamd connect error \"%s\": %s (%d)", LOG_ARGS(sess), optSpamdSocket.string, strerror(errno), errno);
		if (errno == EMFILE || errno == ENFILE)
			replyResourcesError(sess, FILE_LINENO);
		goto error0;
	}

	socketSetTimeout(spamd->socket, optSpamdTimeout.value);

	length = snprintf(sess->input, sizeof (sess->input), "%s SPAMC/1.2\r\n", optSpamdCommand.string);
	if (verb_spamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(647) "spamd >> %s", LOG_ARGS(sess), sess->input);
	if (socketWrite(spamd->socket, (unsigned char *) sess->input, length) != length)
		goto error1;

#ifdef SPAMD_CONTENT_LENGTH
/* The SPAMD protocol documentation sucks. Only by reading the
 * source do you find out that the Content-Length: header is
 * optional. Open source peons write crap documentation.
 */
	if (0 < optSpamdMaxSize.value) {
		length = snprintf(sess->input, sizeof (sess->input), "Content-Length: %ld\r\n", optSpamdMaxSize.value);
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(648) "spamd >> %s", LOG_ARGS(sess), sess->input);
		if (socketWrite(spamd->socket, (unsigned char *) sess->input, length) != length)
			goto error1;
	}
#endif
	if (socketWrite(spamd->socket, (unsigned char *) "\r\n", sizeof ("\r\n")-1) != sizeof ("\r\n")-1)
		goto error1;

	length = snprintf(sess->input, sizeof (sess->input), "Return-Path: <%s>\r\n", sess->msg.mail->address.string);
	if (socketWrite(spamd->socket, (unsigned char *) sess->input, length) != length)
		goto error1;

	length = getReceivedHeader(sess, sess->input, sizeof (sess->input));
	if (socketWrite(spamd->socket, (unsigned char *) sess->input, length) != length)
		goto error1;

	return SMTPF_CONTINUE;
error1:
	syslog(LOG_ERR, LOG_MSG(649) "spamd write error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
	socketClose(spamd->socket);
	spamd->socket = NULL;
error0:
	return SMTPF_CONTINUE;
}

int
spamdOptn(Session *null, va_list ignore)
{
	optSpamdTimeout.value = strtol(optSpamdTimeout.string, NULL, 10) * 1000;
	optSpamdMaxSize.value = strtol(optSpamdMaxSize.string, NULL, 10) * 1024;

	if (optSpamdMaxSize.value <= 0)
		 optSpamdMaxSize.value = LONG_MAX;
	if (optSpamdCommand.initial != optSpamdCommand.string)
		TextUpper(optSpamdCommand.string, -1);

	return SMTPF_CONTINUE;
}

int
spamdRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_spamd);

	optionsRegister(&optSpamdCommand, 		0);
	optionsRegister(&optSpamdMaxSize, 		0);
	optionsRegister(&optSpamdPolicy, 		0);
	optionsRegister(&optSpamdSocket, 		0);
	optionsRegister(&optSpamdTimeout, 		0);

	(void) statsRegister(&stat_junk_mail);

	spamd_context = filterRegisterContext(sizeof (Spamd));

	return SMTPF_CONTINUE;
}

int
spamdInit(Session *null, va_list ignore)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_NUM(650) "spamdInit");

	(void) spamdOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
spamdConnect(Session *sess, va_list ignore)
{
	Spamd *spamd = filterGetContext(sess, spamd_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(651) "spamdConnect", LOG_ARGS(sess));

	spamd->socket = NULL;

	return SMTPF_CONTINUE;
}

int
spamdRset(Session *sess, va_list ignore)
{
	Spamd *spamd = filterGetContext(sess, spamd_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(652) "spamdRset", LOG_ARGS(sess));

	/* Assert that these are closed between messages. */
	socketClose(spamd->socket);
	spamd->socket = NULL;

	return SMTPF_CONTINUE;
}

int
spamdContent(Session *sess, va_list args)
{
	char *hdr;
	long i, size;
	Spamd *spamd;
	size_t length;
	unsigned char *chunk;

	spamd = filterGetContext(sess, spamd_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(653) "spamdContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	/* Open the spamd connection on the first chunk. */
	if (chunk == sess->msg.chunk0+sess->msg.eoh) {
		(void) spamd_open(sess, spamd);
		if (spamd->socket == NULL)
			return SMTPF_CONTINUE;

		for (i = 0; i < VectorLength(sess->msg.headers); i++) {
			if ((hdr = VectorGet(sess->msg.headers, i)) == NULL)
				continue;

			length = strlen(hdr);
			if (socketWrite(spamd->socket, (unsigned char *) hdr, length) != length)
				goto write_error;
		}
	}

	if (spamd->socket == NULL)
		return SMTPF_CONTINUE;

	if (optSpamdMaxSize.value <= sess->msg.length)
		return SMTPF_CONTINUE;

	if (socketWrite(spamd->socket, chunk, size) != size) {
		goto write_error;
	}

	if (verb_spamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(654) "spamd >> (wrote %ld bytes)", LOG_ARGS(sess), size);

	if (optSpamdMaxSize.value <= sess->msg.length + size) {
		/* Signal EOF to spamd so that it can begin processing now.
		 * This should improve performance so that the result is
		 * ready by the time filterDot() needs it.
		 */
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(655) "spamd >> (EOF)", LOG_ARGS(sess));
		socketShutdown(spamd->socket, SHUT_WR);
		syslog(LOG_WARN, LOG_MSG(656) "spamd-max-size=%ld reached", LOG_ARGS(sess), optSpamdMaxSize.value);
	}

	return SMTPF_CONTINUE;

write_error:
	syslog(LOG_ERR, LOG_MSG(657) "spamd write error after %lu bytes", LOG_ARGS(sess), sess->msg.length);

	socketClose(spamd->socket);
	spamd->socket = NULL;

	return SMTPF_CONTINUE;
}

int
spamdDot(Session *sess, va_list ignore)
{
	int rc;
	long length;
	Spamd *spamd;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(658) "spamdDot", LOG_ARGS(sess));

	spamd = filterGetContext(sess, spamd_context);

	rc = SMTPF_CONTINUE;

	if (spamd->socket == NULL)
		goto error0;

	socketShutdown(spamd->socket, SHUT_WR);

	if (socketReadLine(spamd->socket, sess->input, sizeof (sess->input)) <= 0) {
		syslog(LOG_ERR, LOG_MSG(659) "spamd read error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
		goto error1;
	}

	if (verb_spamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(660) "spamd << %s", LOG_ARGS(sess), sess->input);

	if (TextInsensitiveStartsWith(sess->input, "SPAMD/1.1 0 EX_OK") < 0) {
		syslog(LOG_ERR, LOG_MSG(661) "spamd error: %s", LOG_ARGS(sess), sess->input);
		goto error1;
	}

	while (0 < (length = socketReadLine(spamd->socket, sess->input, sizeof (sess->input)))) {
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(662) "spamd << %s", LOG_ARGS(sess), sess->input);

		if (0 < TextInsensitiveStartsWith(sess->input, "spam:")) {
			if (sscanf(sess->input, "%*[^;]; %f / %f", &spamd->score, &spamd->threshold) != 2) {
				syslog(LOG_ERR, LOG_MSG(663) "spamd parse error: %s", LOG_ARGS(sess), sess->input);
				goto error1;
			}
		}
	}

	if (length < 0) {
		syslog(LOG_ERR, LOG_MSG(664) "spamd read error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
		goto error1;
	}

	/* Collect and log report lines. */
	while (0 <= (length = socketReadLine(spamd->socket, sess->input, sizeof (sess->input)))) {
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(665) "spamd << %s", LOG_ARGS(sess), sess->input);
	}

	(void) snprintf(sess->input, sizeof (sess->input), "message %s junk mail score %.2f/%.2f", sess->msg.id, spamd->score, spamd->threshold);

	if (spamd->threshold <= spamd->score) {
		statsCount(&stat_junk_mail);
		switch (*optSpamdPolicy.string) {
		case 'r':
			rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(666) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_spamd_score_reject">spamd-score-reject</a> option.
}*/
			break;
		case 'd':
			rc = SMTPF_DISCARD;
			/*@fallthrough@*/
		default:
			syslog(LOG_ERR, LOG_MSG(667) "%s", LOG_ARGS(sess), sess->input);
			break;
		}
	} else {
		syslog(LOG_INFO, LOG_MSG(668) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
Assorted spamd errors from the 1.0 version of the spamd module.
}*/
	}
error1:
	socketClose(spamd->socket);
	spamd->socket = NULL;
error0:
	return rc;
}

int
spamdClose(Session *sess, va_list ignore)
{
	Spamd *spamd = filterGetContext(sess, spamd_context);

	/* Assert that these are closed at end of connection in case
	 * spamdDot() is not called ,because of a rejection or dropped
	 * connection betweem DATA and DOT.
	 */
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(669) "spamdClose", LOG_ARGS(sess));

	socketClose(spamd->socket);

	return SMTPF_CONTINUE;
}

#endif /* defined(FILTER_SPAMD) && !defined(FILTER_SPAMD2) */
