/*
 * fpscand.c
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

#ifdef FILTER_FPSCAND
#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifndef FPSCAND_PORT
#define FPSCAND_PORT			10200
#endif

#ifndef FPSCAND_MAX_SIZE
#define FPSCAND_MAX_SIZE		(9999 * 1024)
#endif

#define FPSCAND_RESULT_VIRUS		0x0001
#define FPSCAND_RESULT_SUSPICIOUS	0x0002
#define FPSCAND_RESULT_INFECTED		(FPSCAND_RESULT_VIRUS|FPSCAND_RESULT_SUSPICIOUS)

#define FPSCAND_RESULT_INTERRUPT	0x0004
#define FPSCAND_RESULT_SKIPPED_FILES	0x0008
#define FPSCAND_RESULT_RESOURCE_ERROR	0x0010
#define FPSCAND_RESULT_INTERNAL_ERROR	0x0020
#define FPSCAND_RESULT_INIT_ERROR	(FPSCAND_RESULT_INTERRUPT|FPSCAND_RESULT_RESOURCE_ERROR)
#define FPSCAND_RESULT_CRASHED_ERROR	(FPSCAND_RESULT_RESOURCE_ERROR|FPSCAND_RESULT_INTERNAL_ERROR)

#define FPSCAND_RESULT_CLEAN		0x0040
#define FPSCAND_RESULT_DISINFECTED	0x0080

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_fpscand_policy[] =
  "Policy to apply if message is infected. Specify either none,\n"
"# reject, or discard.\n"
"#"
;
static const char usage_fpscand_socket[] =
  "The Internet host[:port] of the fpscand server. Specify the empty\n"
"# string to disable fpscand scan. The default fpscand port is 10200.\n"
"#"
;

Option optFpscandSocket		= { "fpscand-socket",	"",		usage_fpscand_socket };
Option optFpscandTimeout	= { "fpscand-timeout",	"120",		"The fpscand I/O timeout in seconds." };
Option optFpscandPolicy		= { "fpscand-policy",	"reject",	usage_fpscand_policy };

static Verbose verb_fpscand = { { "fpscand", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

int
fpscandOptn(Session *null, va_list ignore)
{
	optFpscandTimeout.value = strtol(optFpscandTimeout.string, NULL, 10) * 1000;

	if (*optFpscandSocket.string != '\0') {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, TMP_DIR);
	}

	return SMTPF_CONTINUE;
}

int
fpscandRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_fpscand);

	optionsRegister(&optFpscandPolicy, 		0);
	optionsRegister(&optFpscandSocket, 		0);
	optionsRegister(&optFpscandTimeout, 		0);

	return SMTPF_CONTINUE;
}

int
fpscandInit(Session *null, va_list ignore)
{
	(void) fpscandOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
fpscandDot(Session *sess, va_list ignore)
{
	int rc, length;
	Socket2 *socket;
	unsigned long code;
	SocketAddress *caddr;
	char *result, *path, *hdr;
	char buffer[SMTP_REPLY_LINE_LENGTH];

	LOG_TRACE(sess, 366, fpscandDot);

	if (*optFpscandSocket.string == '\0')
		return SMTPF_CONTINUE;

	/* Only scan messages with attachments. */
	if (headerFind(sess->msg.headers, "Content-Type", &hdr) == -1)
		return SMTPF_CONTINUE;
	if (!TextMatch(hdr, "*multipart/mixed*", -1, 1))
		return SMTPF_CONTINUE;

	/* Open the fpscand connection... */
	if ((caddr = socketAddressCreate(optFpscandSocket.string, FPSCAND_PORT)) == NULL) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 fpscand address error: %s (%d)" ID_MSG(367) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error0;
	}

	if ((socket = socketOpen(caddr, 1)) == NULL) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 fpscand open error: %s (%d)" ID_MSG(368) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		if (errno == EMFILE || errno == ENFILE)
			replyResourcesError(sess, FILE_LINENO);
		goto error1;
	}

	cliFdCloseOnExec(socketGetFd(socket), 1);

	if (socketClient(socket, optFpscandTimeout.value)) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 fpscand connect error: %s (%d)" ID_MSG(369) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	socketSetTimeout(socket, optFpscandTimeout.value);

	/* Send the command. fpscand supports a SCAN STREAM option in
	 * their protocol, which is just BROKEN, because it requires
	 * knowing the exact size of the stream in advance. This of
	 * course doesn't work at all well for a proxy.
	 */
	length = snprintf(buffer, sizeof (buffer), "SCAN FILE %s\n", saveGetName(sess));
	if (sizeof (buffer) <= length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 fpscand buffer overflow" ID_MSG(370) "\r\n");
/*{NEXT}*/
		goto error2;
	}

	if (verb_fpscand.option.value)
		syslog(LOG_DEBUG, LOG_MSG(371) "fpscand >> %s", LOG_ARGS(sess), buffer);

	if (socketWrite(socket, (unsigned char *) buffer, (long) length) != length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 fpscand write error: %s (%d)" ID_MSG(372) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	if (socketReadLine(socket, buffer, sizeof (buffer)) <= 0) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 fpscand read error: %s (%d)" ID_MSG(373) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_fpscand_socket">fpscand-socket</a> and <a href="summary.html#opt_fpscand_timeout">fpscand-timeout</a>.
}*/
		goto error2;
	}

	if (verb_fpscand.option.value)
		syslog(LOG_DEBUG, LOG_MSG(374) "fpscand << %s", LOG_ARGS(sess), buffer);

	code = (unsigned long) strtol(buffer, &result, 10);
	if ((path = strrchr(buffer, ' ')) != NULL)
		*path = '\0';

	rc = SMTPF_CONTINUE;
	if (code & FPSCAND_RESULT_INFECTED) {
		statsCount(&stat_virus_infected);
		MSG_SET(sess, MSG_POLICY|MSG_INFECTED);
		(void) snprintf(sess->input, sizeof (sess->input), "message %s is %s%s", sess->msg.id, result+1, MSG_ANY_SET(sess, MSG_OK_AV) ? ", but ignored because OK+AV" : "");

		if (MSG_NOT_SET(sess, MSG_OK_AV)) {
			switch (*optFpscandPolicy.string) {
			case 'd':
				MSG_SET(sess, MSG_DISCARD);
				rc = SMTPF_DISCARD;
				/*@fallthrough@*/
			default:
				syslog(LOG_ERR, LOG_MSG(375) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
The fpscand daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_fpscand_policy">fpscand-policy</a>.
}*/
				break;
			case 'r':
				rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(376) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The fpscand daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_fpscand_policy">fpscand-policy</a>.
}*/
			}
		}
	}
error2:
	socketClose(socket);
error1:
	free(caddr);
error0:
	return rc;
}

#endif /* FILTER_FPSCAND */
