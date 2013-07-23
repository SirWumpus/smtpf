/*
 * savdid.c
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

#ifdef FILTER_SAVDID
#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifndef SAVDID_PORT
#define SAVDID_PORT			4010
#endif

#ifndef SAVDID_MAX_SIZE
#define SAVDID_MAX_SIZE			(9999 * 1024)
#endif

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_savdid_policy[] =
  "Policy to apply if message is infected. Specify either none,\n"
"# reject, or discard.\n"
"#"
;
static const char usage_savdid_socket[] =
  "The Internet host[:port] of the savdid server. Specify the empty\n"
"# string to disable savdid scan. The default savdid port is 4010.\n"
"#"
;

Option optSavdiddSocket		= { "savdid-socket",	"",		usage_savdid_socket };
Option optSavdiddTimeout	= { "savdid-timeout",	"60",		"The savdid I/O timeout in seconds." };
Option optSavdiddPolicy		= { "savdid-policy",	"reject",	usage_savdid_policy };

static Verbose verb_savdid = { { "savdid", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

int
savdidOptn(Session *null, va_list ignore)
{
	optSavdiddTimeout.value = strtol(optSavdiddTimeout.string, NULL, 10) * 1000;

	if (*optSavdiddSocket.string != '\0') {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, TMP_DIR);
	}

	return SMTPF_CONTINUE;
}

int
savdidRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_savdid);

	optionsRegister(&optSavdiddPolicy, 		0);
	optionsRegister(&optSavdiddSocket, 		0);
	optionsRegister(&optSavdiddTimeout, 		0);

	return SMTPF_CONTINUE;
}

int
savdidInit(Session *null, va_list ignore)
{
	(void) savdidOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
savdidDot(Session *sess, va_list ignore)
{
	char *hdr;
	int rc, length;
	Socket2 *socket;
	SocketAddress *caddr;
	char buffer[SMTP_REPLY_LINE_LENGTH];

	LOG_TRACE(sess, 831, savdidDot);

	if (*optSavdiddSocket.string == '\0')
		return SMTPF_CONTINUE;

	/* Only scan messages with attachments. */
	if (headerFind(sess->msg.headers, "Content-Type", &hdr) == -1)
		return SMTPF_CONTINUE;
	if (!TextMatch(hdr, "*multipart/mixed*", -1, 1))
		return SMTPF_CONTINUE;

	/* Open the savdid connection... */
	if ((caddr = socketAddressCreate(optSavdiddSocket.string, SAVDID_PORT)) == NULL) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid address error: %s (%d)" ID_MSG(832) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error0;
	}

	if ((socket = socketOpen(caddr, 1)) == NULL) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid open error: %s (%d)" ID_MSG(833) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		if (errno == EMFILE || errno == ENFILE)
			replyResourcesError(sess, FILE_LINENO);
		goto error1;
	}

	cliFdCloseOnExec(socketGetFd(socket), 1);

	if (socketClient(socket, optSavdiddTimeout.value)) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid connect error: %s (%d)" ID_MSG(834) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	socketSetTimeout(socket, optSavdiddTimeout.value);

	/* Get welcome banner. */
	length = socketReadLine(socket, buffer, sizeof (buffer));
	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(835) "savdid << %s", LOG_ARGS(sess), buffer);
	if (length <= 0) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid read error: %s (%d)" ID_MSG(836) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	/* Send version. */
	length = snprintf(buffer, sizeof (buffer), "SSSP/1.0\n");
	if (socketWrite(socket, (unsigned char *) buffer, (long) length) != length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid write error: %s (%d)" ID_MSG(837) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}
	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(838) "savdid >> %s", LOG_ARGS(sess), buffer);

	if (socketReadLine(socket, buffer, sizeof (buffer)) <= 0) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid read error: %s (%d)" ID_MSG(839) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_savdid_socket">savdid-socket</a> and <a href="summary.html#opt_savdid_timeout">savdid-timeout</a>.
}*/
		goto error2;
	}
	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(840) "savdid << %s", LOG_ARGS(sess), buffer);

	if (strncmp(buffer, "ACC ", sizeof ("ACC ")-1) != 0) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid read error: %s (%d)" ID_MSG(841) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_savdid_socket">savdid-socket</a> and <a href="summary.html#opt_savdid_timeout">savdid-timeout</a>.
}*/
		goto error2;
	}

	/* Send the command. savdid supports a SCANDATA command in
	 * their protocol, which is just BROKEN, because it requires
	 * knowing the exact size of the stream in advance. This of
	 * course doesn't work at all well for a proxy.
	 */
	length = snprintf(buffer, sizeof (buffer), "SCANFILE %s\n", saveGetName(sess));
	if (sizeof (buffer) <= length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid buffer overflow" ID_MSG(842) "\r\n");
/*{NEXT}*/
		goto error2;
	}

	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(843) "savdid >> %s", LOG_ARGS(sess), buffer);

	if (socketWrite(socket, (unsigned char *) buffer, (long) length) != length) {
		rc = replyPushFmt(sess, SMTPF_REJECT, "451 4.4.0 savdid write error: %s (%d)" ID_MSG(844) "\r\n", strerror(errno), errno, ID_ARG(sess));
/*{NEXT}*/
		goto error2;
	}

	/* Read multiline response looking for a VIRUS result.
	 * Ignore the other lines.
	 */
	rc = SMTPF_CONTINUE;
	while (0 < (length = socketReadLine(socket, buffer, sizeof (buffer)))) {
		if (verb_savdid.option.value)
			syslog(LOG_DEBUG, LOG_MSG(845) "savdid << %s", LOG_ARGS(sess), buffer);

		if (strncmp(buffer, "VIRUS ", sizeof ("VIRUS ")-1) == 0) {
			char *end_of_name;

			if ((end_of_name = strchr(buffer+sizeof ("VIRUS ")-1, ' ')) == NULL)
				end_of_name = buffer + length;
			*end_of_name = '\0';

			statsCount(&stat_virus_infected);
			MSG_SET(sess, MSG_POLICY|MSG_INFECTED);
			(void) snprintf(sess->input, sizeof (sess->input), "message %s is INFECTED with %s%s", sess->msg.id, buffer+sizeof ("VIRUS ")-1, MSG_ANY_SET(sess, MSG_OK_AV) ? ", but ignored because OK+AV" : "");

			if (MSG_NOT_SET(sess, MSG_OK_AV)) {
				switch (*optSavdiddPolicy.string) {
				case 'd':
					MSG_SET(sess, MSG_DISCARD);
					rc = SMTPF_DISCARD;
					/*@fallthrough@*/
				default:
					syslog(LOG_ERR, LOG_MSG(846) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
The savdid daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_savdid_policy">savdid-policy</a>.
}*/
					break;
				case 'r':
					rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(847) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The savdid daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_savdid_policy">savdid-policy</a>.
}*/
				}
			}
		}
	}
	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(848) "savdid << %s", LOG_ARGS(sess), buffer);

	length = snprintf(buffer, sizeof (buffer), "BYE\n");
	(void) socketWrite(socket, (unsigned char *) buffer, (long) length);
	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(849) "savdid >> %s", LOG_ARGS(sess), buffer);

	(void) socketReadLine(socket, buffer, sizeof (buffer));
	if (verb_savdid.option.value)
		syslog(LOG_DEBUG, LOG_MSG(850) "savdid << %s", LOG_ARGS(sess), buffer);
error2:
	socketClose(socket);
error1:
	free(caddr);
error0:
	return rc;
}

#endif /* FILTER_SAVDID */
