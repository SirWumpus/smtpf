/*
 * avastd.c
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

#ifdef FILTER_AVASTD
#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifndef AVASTD_PORT
#define AVASTD_PORT			5037
#endif

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_avastd_socket[] =
  "The unix domain socket or Internet host[:port] of the avastd\n"
"# server. Specify the empty string to disable avastd scan. The\n"
"# default avastd port is " QUOTE(AVASTD_PORT) ".\n"
"#"
;
Option optAvastdSocket	= { "avastd-socket",	"",		usage_avastd_socket };

Option optAvastdTimeout	= { "avastd-timeout",	"120",		"The avastd I/O timeout in seconds." };

static const char usage_avastd_policy[] =
  "Policy to apply if message is infected. Specify either none,\n"
"# reject, or discard.\n"
"#"
;
Option optAvastdPolicy	= { "avastd-policy",	"reject",	usage_avastd_policy };

static Verbose verb_avastd = { { "avastd", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

int
avastdOptn(Session *null, va_list ignore)
{
	optAvastdTimeout.value = strtol(optAvastdTimeout.string, NULL, 10) * 1000;

	if (*optAvastdSocket.string != '\0') {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, "/tmp");
	}

	return SMTPF_CONTINUE;
}

int
avastdRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_avastd);

	optionsRegister(&optAvastdPolicy, 		0);
	optionsRegister(&optAvastdSocket, 		0);
	optionsRegister(&optAvastdTimeout, 		0);

	return SMTPF_CONTINUE;
}

int
avastdInit(Session *null, va_list ignore)
{
	(void) avastdOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
avastdDot(Session *sess, va_list ignore)
{
	int rc, length;
	char *tab, *hdr;
	Socket2 *socket;
	SocketAddress *caddr;
	char buffer[SMTP_REPLY_LINE_LENGTH];

	LOG_TRACE(sess, 148, avastdDot);

	if (*optAvastdSocket.string == '\0')
		return SMTPF_CONTINUE;

	/* Only scan messages with attachments. */
	if (headerFind(sess->msg.headers, "Content-Type", &hdr) == -1)
		return SMTPF_CONTINUE;
	if (!TextMatch(hdr, "*multipart/mixed*", -1, 1))
		return SMTPF_CONTINUE;

	rc = SMTPF_TEMPFAIL;

	/* Open the avastd connection... */
	if ((caddr = socketAddressCreate(optAvastdSocket.string, AVASTD_PORT)) == NULL) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd address error: %s (%d)" ID_MSG(149) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error0;
	}

	if ((socket = socketOpen(caddr, 1)) == NULL) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd open error: %s (%d)" ID_MSG(150) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		if (errno == EMFILE || errno == ENFILE)
			replyResourcesError(sess, FILE_LINENO);
		goto error1;
	}

	cliFdCloseOnExec(socketGetFd(socket), 1);

	if (socketClient(socket, optAvastdTimeout.value)) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd connect error: %s (%d)" ID_MSG(151) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	socketSetTimeout(socket, optAvastdTimeout.value);

	/* Get welcome banner. */
	length = socketReadLine(socket, buffer, sizeof (buffer));
	if (verb_avastd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(152) "avastd << %s", LOG_ARGS(sess), buffer);
	if (length <= 0 || strtol(buffer, NULL, 10) != 220) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd read error: %s (%d)" ID_MSG(153) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	/* Start scan of file. */
	length = snprintf(buffer, sizeof (buffer), "SCAN %s\r\n", saveGetName(sess));
	if (sizeof (buffer) <= length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd buffer overflow" ID_MSG(154) "\r\n");
		goto error2;
	}
	if (verb_avastd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(155) "avastd >> %s", LOG_ARGS(sess), buffer);
	if (socketWrite(socket, (unsigned char *) buffer, (long) length) != length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd write error: %s (%d)" ID_MSG(156) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	/* Get result of command. */
	length = socketReadLine(socket, buffer, sizeof (buffer));
	if (verb_avastd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(157) "avastd << %s", LOG_ARGS(sess), buffer);
	if (length <= 0 || strtol(buffer, NULL, 10) != 200) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd read error: %s (%d)" ID_MSG(158) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	/* Get list of clean/infected file and attachments. */
	rc = SMTPF_CONTINUE;
	do {
		length = socketReadLine(socket, buffer, sizeof (buffer));
		if (verb_avastd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(159) "avastd << %s", LOG_ARGS(sess), buffer);
		if (length == SOCKET_ERROR) {
			rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 avastd read error: %s (%d)" ID_MSG(160) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_avastd_socket">avastd-socket</a> and <a href="summary.html#opt_avastd_timeout">avastd-timeout</a>.
}*/
			goto error2;
		}

		if ((tab = strchr(buffer, '\t')) == NULL)
			continue;

		/* Check for infected result, string "[L]". */
		if (tab[2] == 'L' && rc == SMTPF_CONTINUE) {
			statsCount(&stat_virus_infected);
			MSG_SET(sess, MSG_POLICY|MSG_INFECTED);
			(void) snprintf(sess->input, sizeof (sess->input), "message %s is INFECTED with %s%s", sess->msg.id, tab+5, MSG_ANY_SET(sess, MSG_OK_AV) ? ", but ignored because OK+AV" : "");

			if (MSG_NOT_SET(sess, MSG_OK_AV)) {
				switch (*optAvastdPolicy.string) {
				case 'd':
					MSG_SET(sess, MSG_DISCARD);
					rc = SMTPF_DISCARD;
					/*@fallthrough@*/
				default:
					syslog(LOG_ERR, LOG_MSG(161) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
The avastd daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_avastd_policy">avastd-policy</a>.
}*/
					break;
				case 'r':
					rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(162) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The avastd daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_avastd_policy">avastd-policy</a>.
}*/
				}
			}
		}

		/* Check for error result, string "[E]". */
		else if (tab[2] == 'E') {
			syslog(LOG_ERR, LOG_MSG(163) "avastd error: %s", LOG_ARGS(sess), buffer);
		}

		/* A clean result is string "[+]". */
	} while (0 < length);

	/* End avastd session. */
	if (verb_avastd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(164) "avastd >> QUIT", LOG_ARGS(sess));
	(void) socketWrite(socket, (unsigned char *) "QUIT\r\n", sizeof ("QUIT\r\n")-1);
error2:
	socketClose(socket);
error1:
	free(caddr);
error0:
	return rc;
}

#endif /* FILTER_AVASTD */
