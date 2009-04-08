/*
 * clamd.c
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

#ifdef FILTER_CLAMD
#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <com/snert/lib/net/network.h>

#ifndef CLAMD_PORT
#define CLAMD_PORT			3310
#endif

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct {
	Socket2 *socket;
	Socket2 *session;
	int io_error;
} Clamd;

static const char usage_clamd_policy[] = 						\
  "Policy to apply if message is infected. Specify either none,\n"	\
"# reject, or discard.\n"						\
"#"
;

static const char usage_clamd_socket[] =
  "The unix domain socket or Internet host[:port] of the clamd\n"
"# server. Specify the empty string to disable clamd scan. The\n"
"# default clamd port is 3310. If clamd is running on the same\n"
"# host as " _NAME ", then the special token SCAN can be specified\n"
"# to use scanning by file path instead of by socket stream for\n"
"# an I/O efficiency gain.\n"
"#"
;

static const char usage_clamd_scan[] =
  "When set, scan all messages for viruses. ClamAV can also scan for\n"
"# phishing scams. Otherwise, as an optimisation, only scan messages\n"
"# with attachments for viruses.\n"
"#"
;

Option optClamdMaxSize	= { "clamd-max-size",	"10000",	"Max. number of kilobytes to pass to clamd, 0 for unlimited." };
Option optClamdSocket	= { "clamd-socket",	"",		usage_clamd_socket };
Option optClamdTimeout	= { "clamd-timeout",	"120",		"The clamd I/O timeout in seconds." };
Option optClamdPolicy	= { "clamd-policy",	"reject",	usage_clamd_policy };
Option optClamdScanAll	= { "clamd-scan-all",	"+",		usage_clamd_scan };

static int clamd_is_local;
static FilterContext clamd_context;
static Verbose verb_clamd = { { "clamd", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

static void
clamdError(Session *sess, Clamd *clamd, const char *fmt, ...)
{
	va_list args;

	if (!clamd->io_error) {
		va_start(args, fmt);
		(void) vsnprintf(sess->msg.reject, sizeof (sess->msg.reject), fmt, args);
		va_end(args);

		socketClose(clamd->session);
		clamd->session = NULL;

		socketClose(clamd->socket);
		clamd->socket = NULL;

		clamd->io_error = 1;
	}
}

static int
clamd_open(Session *sess, Clamd *clamd)
{
	int rc;
	SocketAddress *caddr;

	rc = SMTPF_TEMPFAIL;

	if ((caddr = socketAddressCreate(clamd_is_local ? "127.0.0.1" : optClamdSocket.string, CLAMD_PORT)) == NULL) {
		clamdError(sess, clamd, "451 4.4.0 clamd address error: %s (%d)" ID_MSG(178), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error0;
	}

	if ((clamd->socket = socketOpen(caddr, 1)) == NULL) {
		clamdError(sess, clamd, "451 4.4.0 clamd open error: %s (%d)" ID_MSG(179), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		if (errno == EMFILE || errno == ENFILE)
			replyResourcesError(sess, FILE_LINENO);
		goto error1;
	}

	cliFdCloseOnExec(socketGetFd(clamd->socket), 1);

	if (socketClient(clamd->socket, optClamdTimeout.value)) {
		clamdError(sess, clamd, "451 4.4.0 clamd connect error: %s (%d)" ID_MSG(180), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		socketClose(clamd->socket);
		clamd->socket = NULL;
		goto error1;
	}

	socketSetTimeout(clamd->socket, optClamdTimeout.value);
	rc = SMTPF_CONTINUE;
error1:
	free(caddr);
error0:
	return rc;
}

static int
clamd_open_scan(Session *sess, Clamd *clamd)
{
	int rc, length;
	char buffer[SMTP_REPLY_LINE_LENGTH];

	if (*optClamdSocket.string == '\0' || !clamd_is_local)
		return SMTPF_CONTINUE;

	length = snprintf(buffer, sizeof (buffer), "SCAN %s\n", saveGetName(sess));
	if (sizeof (buffer) <= length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 clamd buffer overflow" ID_MSG(181) "\r\n");
/*{NEXT}*/
		return SMTPF_TEMPFAIL;
	}

	rc = clamd_open(sess, clamd);
	if (clamd->socket == NULL)
		return rc;

	if (verb_clamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(182) "clamd >> %s", LOG_ARGS(sess), buffer);
	if (socketWrite(clamd->socket, buffer, (long) length) != length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 clamd write error: %s (%d)" ID_MSG(183) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		socketClose(clamd->socket);
		clamd->socket = NULL;
		return SMTPF_TEMPFAIL;
	}

	return SMTPF_CONTINUE;
}

static int
clamd_open_stream(Session *sess, Clamd *clamd)
{
	long length;
	int rc, assigned;
	unsigned sessionPort;
	SocketAddress *saddr;
	static char buffer[64];

	if (*optClamdSocket.string == '\0' || clamd_is_local)
		return SMTPF_CONTINUE;

	rc = clamd_open(sess, clamd);
	if (clamd->socket == NULL)
		return rc;

	rc = SMTPF_TEMPFAIL;

	if (verb_clamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(184) "clamd >> STREAM", LOG_ARGS(sess));

	if (socketWrite(clamd->socket, (unsigned char *) "STREAM\n", sizeof ("STREAM\n")-1) != sizeof ("STREAM\n")-1) {
		clamdError(sess, clamd, "451 4.4.0 clamd write error: %s (%d)" ID_MSG(185), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error1;
	}

	if ((length = socketReadLine(clamd->socket, buffer, sizeof (buffer))) < 0) {
		clamdError(sess, clamd, "451 4.4.0 clamd read error len=%ld: %s (%d)" ID_MSG(186), length, strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error1;
	}

	if (verb_clamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(187) "clamd << %s", LOG_ARGS(sess), buffer);

	if ((assigned = sscanf(buffer, "PORT %u", &sessionPort)) != 1) {
		clamdError(sess, clamd, "451 4.4.0 clamd session port parse error (%d) buffer=%ld:\"%s\"" ID_MSG(188), assigned, length, buffer, ID_ARG(sess));
/*{NEXT}*/
		goto error1;
	}

	if ((saddr = socketAddressCreate(*optClamdSocket.string == '/' ? "0.0.0.0" : optClamdSocket.string, sessionPort)) == NULL) {
		clamdError(sess, clamd, "451 4.4.0 clamd address error: %s (%d)" ID_MSG(189), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error1;
	}

	if (*optClamdSocket.string != '/')
		(void) socketAddressSetPort(saddr, sessionPort);

	if ((clamd->session = socketOpen(saddr, 1)) == NULL) {
		clamdError(sess, clamd, "451 4.4.0 clamd session open error: %s (%d)" ID_MSG(190), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	cliFdCloseOnExec(socketGetFd(clamd->session), 1);

	if (socketClient(clamd->session, optClamdTimeout.value)) {
		clamdError(sess, clamd, "451 4.4.0 clamd session connection error: %s (%d)" ID_MSG(191), strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	socketSetTimeout(clamd->session, optClamdTimeout.value);

	rc = SMTPF_CONTINUE;
error2:
	free(saddr);
error1:
	return rc;
}

int
clamdOptn(Session *null, va_list ignore)
{
	optClamdTimeout.value = strtol(optClamdTimeout.string, NULL, 10) * 1000;
	optClamdMaxSize.value = strtol(optClamdMaxSize.string, NULL, 10) * 1024;

	if (optClamdMaxSize.value <= 0)
		 optClamdMaxSize.value = LONG_MAX;

	clamd_is_local = TextInsensitiveCompare(optClamdSocket.string, "SCAN") == 0;

	if (*optClamdSocket.string != '\0' && clamd_is_local) {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, "/tmp");
	}

	return SMTPF_CONTINUE;
}

int
clamdRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_clamd);

	optionsRegister(&optClamdMaxSize, 		0);
	optionsRegister(&optClamdPolicy, 		0);
	optionsRegister(&optClamdSocket, 		0);
	optionsRegister(&optClamdTimeout, 		0);
	optionsRegister(&optClamdScanAll, 		0);

	clamd_context = filterRegisterContext(sizeof (Clamd));

	return SMTPF_CONTINUE;
}

int
clamdInit(Session *null, va_list ignore)
{
	(void) clamdOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
clamdConnect(Session *sess, va_list ignore)
{
	LOG_TRACE(sess, 192, clamdConnect);

	filterClearContext(sess, clamd_context);

	return SMTPF_CONTINUE;
}

int
clamdRset(Session *sess, va_list ignore)
{
	Clamd *clamd;

	LOG_TRACE(sess, 193, clamdRset);

	clamd = filterGetContext(sess, clamd_context);

	/* Assert that these are closed between messages. */
	socketClose(clamd->session);
	clamd->session = NULL;

	socketClose(clamd->socket);
	clamd->socket = NULL;

	return SMTPF_CONTINUE;
}

#ifdef MOVED
int
clamdData(Session *sess, va_list ignore)
{
	Clamd *clamd;
	clamd = filterGetContext(sess, clamd_context);

	LOG_TRACE(sess, 194, clamdData);

	*sess->msg.reject = '\0';
	clamd->io_error = 0;

	if (clamd_open_stream(sess, clamd) != SMTPF_CONTINUE) {
		return replyPushFmt(sess, SMTPF_TEMPFAIL, "%s\r\n", sess->msg.reject);
	}

	return SMTPF_CONTINUE;
}
#endif

int
clamdHeaders(Session *sess, va_list args)
{
	long i;
	char *hdr;
	Clamd *clamd;
	size_t length;
	Vector headers;

	LOG_TRACE(sess, 195, clamdHeaders);

	clamd = filterGetContext(sess, clamd_context);
	headers = va_arg(args, Vector);
	*sess->msg.reject = '\0';
	clamd->io_error = 0;

	if (!optClamdScanAll.value) {
		if (headerFind(sess->msg.headers, "Content-Type", &hdr) == -1)
			return SMTPF_CONTINUE;

		if (!TextMatch(hdr, "*multipart/mixed*", -1, 1))
			return SMTPF_CONTINUE;
	}

	if (clamd_open_stream(sess, clamd) != SMTPF_CONTINUE)
		return replyPushFmt(sess, SMTPF_TEMPFAIL, "%s\r\n", sess->msg.reject);

	if (clamd->session == NULL)
		return SMTPF_CONTINUE;

	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		length = strlen(hdr);
		if (socketWrite(clamd->session, (unsigned char *) hdr, length) != length) {
			clamdError(sess, clamd, "451 4.4.0 clamd session write error after %lu bytes" ID_MSG(196), sess->msg.length, ID_ARG(sess));
/*{NEXT}*/
			return SMTPF_CONTINUE;
		}

	}

	if (optClamdMaxSize.value <= sess->msg.length + sess->msg.eoh) {
		/* Signal EOF to clamd so that it can begin processing now.
		 * This should improve performance so that the result is
		 * ready by the time filterDot() needs it.
		 */
		if (verb_clamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(197) "clamd >> (EOF)", LOG_ARGS(sess));
		socketClose(clamd->session);
		clamd->session = NULL;
	}

	return SMTPF_CONTINUE;
}

int
clamdContent(Session *sess, va_list args)
{
	long size;
	Clamd *clamd;
	unsigned char *chunk;

	clamd = filterGetContext(sess, clamd_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(198) "clamdContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	if (clamd->session == NULL)
		return SMTPF_CONTINUE;

	if (optClamdMaxSize.value <= sess->msg.length)
		return SMTPF_CONTINUE;

	if (socketWrite(clamd->session, chunk, size) != size) {
		clamdError(sess, clamd, "451 4.4.0 clamd session write error after %lu bytes" ID_MSG(199), sess->msg.length, ID_ARG(sess));
/*{NEXT}*/
		return SMTPF_CONTINUE;
	}

	if (verb_clamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(200) "clamd >> (wrote %ld bytes)", LOG_ARGS(sess), size);

	if (optClamdMaxSize.value <= sess->msg.length + size) {
		/* Signal EOF to clamd so that it can begin processing now.
		 * This should improve performance so that the result is
		 * ready by the time filterDot() needs it.
		 */
		if (verb_clamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(201) "clamd >> (EOF)", LOG_ARGS(sess));
		socketClose(clamd->session);
		clamd->session = NULL;
		if (verb_warn.option.value) {
			syslog(LOG_WARN, LOG_MSG(202) "clamd-max-size=%ld reached", LOG_ARGS(sess), optClamdMaxSize.value);
/*{LOG
The size of the message passed to clamd has been reached.
No additional data will be passed to clamd.
See <a href="smtpf-cf.html#smtpf_clamd">clamd-max-size</a>.
}*/
		}
	}

	return SMTPF_CONTINUE;
}

int
clamdDot(Session *sess, va_list ignore)
{
	int rc;
	Clamd *clamd;
	char *result, *found;

	LOG_TRACE(sess, 203, clamdDot);

	clamd = filterGetContext(sess, clamd_context);

	rc = SMTPF_CONTINUE;

	socketClose(clamd->session);
	clamd->session = NULL;

	if (clamd->io_error) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "%s\r\n", sess->msg.reject);
		goto error1;
	}

	(void) clamd_open_scan(sess, clamd);

	if (clamd->socket == NULL)
		goto error0;

	if (socketReadLine(clamd->socket, sess->reply, sizeof (sess->reply)) <= 0) {
		clamdError(sess, clamd, "451 4.4.0 clamd session read error: %s (%d)" ID_MSG(204), strerror(errno), errno, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_clamd_socket">clamd-socket</a> and <a href="summary.html#opt_clamd_timeout">clamd-timeout</a>.
}*/
		rc = replyPushFmt(sess, SMTPF_REJECT, "%s\r\n", sess->msg.reject);
		goto error1;
	}

	if (verb_clamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(205) "clamd << %s", LOG_ARGS(sess), sess->reply);

	if ((result = strstr(sess->reply, ": ")) == NULL) {
		clamdError(sess, clamd, "451 4.4.0 unexpected clamd result: %s" ID_MSG(206), sess->reply, ID_ARG(sess));
/*{REPLY
The clamd daemon returned an unexpected result. This may be due to
unexpected changes in the clamd protocol between program updates or data
corruption over the network (assuming clamd runs on a different machine).
}*/
		rc = replyPushFmt(sess, SMTPF_REJECT, "%s\r\n", sess->msg.reject);
		goto error1;
	}

	result += sizeof (": ")-1;
	found = strstr(result, "FOUND");

	if (found != NULL) {
		*found = '\0';

		MSG_SET(sess, MSG_POLICY);
		(void) snprintf(sess->input, sizeof (sess->input), "message %s is INFECTED with %s", sess->msg.id, result);

		switch (*optClamdPolicy.string) {
		case 'd':
			statsCount(&stat_virus_infected);
			rc = SMTPF_DISCARD;
			/*@fallthrough@*/
		default:
			syslog(LOG_ERR, LOG_MSG(207) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
The clamd daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_clamd_policy">clamd-policy</a>.
}*/
			break;
		case 'r':
			statsCount(&stat_virus_infected);
			rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(208) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The clamd daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_clamd_policy">clamd-policy</a>.
}*/
		}
	}
error1:
	socketClose(clamd->socket);
	clamd->socket = NULL;
error0:
	return rc;
}

int
clamdClose(Session *sess, va_list ignore)
{
	Clamd *clamd;

	LOG_TRACE(sess, 209, clamdClose);

	clamd = filterGetContext(sess, clamd_context);

	/* Assert that these are closed at end of connection in case
	 * clamdDot() is not called ,because of a rejection or dropped
	 * connection betweem DATA and DOT.
	 */
	socketClose(clamd->session);
	socketClose(clamd->socket);

	return SMTPF_CONTINUE;
}

#endif /* FILTER_CLAMD */
