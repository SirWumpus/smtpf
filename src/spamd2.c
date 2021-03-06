/*
 * spamd2.c
 *
 * Copyright 2006, 2010 by Anthony Howe. All rights reserved.
 */

#define SPAMD_CONTENT_LENGTH

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)

#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifndef SPAMD_PORT
#define SPAMD_PORT			783
#endif

#define X_SPAM_REPORT_NL		"\r\n  | "

#define ACCESS_TAG			"spamd:"

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_spamd_command[] =
  "Specify one of the SPAMD protocol commands: CHECK, SYMBOLS, REPORT,\n"
"# REPORT_IFSPAM to check the message. When used in conjunction with\n"
"# verbose=spamd, more detailed results from spamd will be logged.\n"
"#"
;

static const char usage_spamd_socket[] =
  "The unix domain socket or Internet host[:port] of the spamd\n"
"# server. Specify the empty string to disable spamd scan. The\n"
"# default spamd port is 783.\n"
"#"
;

static const char usage_spamd_score_reject[] =
  "When spamd returns a score greater than or equal to this value\n"
"# then the message will be rejected. Specify -1 to never reject.\n"
"#"
;


Option optSpamdCommand		= { "spamd-command",		"CHECK",	usage_spamd_command };
Option optSpamdMaxSize		= { "spamd-max-size",		"0",		"Max. number of kilobytes to pass to spamd, 0 for unlimited." };
Option optSpamdSocket		= { "spamd-socket",		"",		usage_spamd_socket };
Option optSpamdTimeout		= { "spamd-timeout",		"120",		"The spamd I/O timeout in seconds." };
Option optSpamdScoreReject	= { "spamd-score-reject",	"10",		usage_spamd_score_reject };

static const char usage_spamd_skip_tagged[] =
  "If the message has already been subject tagged by a previous test, then\n"
"# skip the spamd scan, which may reject the message or add an aditional tag.\n"
"#"
;
Option optSpamdSkipTagged	= { "spamd-skip-tagged",	"-",		usage_spamd_skip_tagged };

static const char usage_spamd_subject_tag[] =
  "When the score is greater than or equal to SpamAssassin's required_hits\n"
"# and less than spamd-score-reject (when not disabled), then the Subject\n"
"# header is prepended with this tag to identify suspect messages. Specify\n"
"# the empty string to disable the subject tag.\n"
"#"
;
Option optSpamdSubjectTag	= { "spamd-subject-tag",	"[SPAM]",	usage_spamd_subject_tag };

static const char usage_spamd_reject_sender_marked_spam[] =
  "When an X-Spam-Status header is supplied by the sender, then check their\n"
"# claimed score against spamd-score-reject and reject if they exceed it.\n"
"# Else if a \"X-Spam-Flag: YES\" header is supplied by the sender, then\n"
"# reject the message. If the sender thought it was spam, why would we want\n"
"# it? Otherwise the message will be scanned and scored as per usual.\n"
"#"
;
Option optSpamdRejectSenderMarkedSpam	= { "spamd-reject-sender-marked-spam",	"+",	usage_spamd_reject_sender_marked_spam };

Option optSpamdFlagHeader	= { "spamd-flag-header", "X-Spam-Flag",  "The name of the flag header. Empty string to disable."};
Option optSpamdLevelHeader	= { "spamd-level-header", "X-Spam-Level", "The name of the level header. Empty string to disable." };
Option optSpamdStatusHeader	= { "spamd-status-header", "X-Spam-Status", "The name of the status header. Empty string to disable." };
Option optSpamdReportHeader	= { "spamd-report-header", "X-Spam-Report", "The name of the report header. Empty string to disable." };

static const char usage_spamd_level_character[] =
  "The character used for the X-Spam-Level: header. By default it is\n"
"# a regular expression neutral character, 'x', though the historical\n"
"# default is '*'."
"#"
;
Option optSpamdLevelCharacter	= { "spamd-level-character",	"x", usage_spamd_level_character };

Verbose verb_spamd = { { "spamd", "-", "" } };

Stats stat_spamd_connect	= { STATS_TABLE_MSG, "spamd-connect" };
Stats stat_spamd_connect_error	= { STATS_TABLE_MSG, "spamd-connect-error" };
Stats stat_spamd_tag 		= { STATS_TABLE_MSG, "spamd-tag" };
Stats stat_spamd_reject		= { STATS_TABLE_MSG, "spamd-reject" };
Stats stat_sender_marked_spam	= { STATS_TABLE_MSG, "spamd-sender-marked-spam" };

typedef struct {
	Socket2 *socket;
	float threshold;
	float score;
} Spamd;

static FilterContext spamd_context;

/***********************************************************************
 ***
 ***********************************************************************/

char *
spamd_user(Session *sess)
{
	Rcpt *rcpt;
	Connection *fwd;
	char *user = NULL;
	ParsePath *first_rcpt;

	/* Do we have any open routes? */
	if (sess->msg.fwds == NULL || sess->msg.rcpt_count == 0)
		return NULL;

	if ((first_rcpt = rcptFindFirstValid(sess)) == NULL)
		return NULL;

	/* A single recipient? */
	if (sess->msg.rcpt_count == 1) {
		(void) accessEmail(sess, ACCESS_TAG, first_rcpt->address.string, NULL, &user);
		return user;
	}

	/* Otherwise check that all the recipients are within the
	 * same domain before looking up by domain name.
	 */
	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
		for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
			if (TextInsensitiveCompare(rcpt->rcpt->domain.string, first_rcpt->domain.string) != 0) {
				/* Mismatched domains, used global default. */
				char *value = accessDefault(sess, ACCESS_TAG);
				(void) accessPattern(sess, first_rcpt->domain.string, value, &user);
				free(value);
				return user;
			}
		}
	}

	if (fwd == NULL) {
		/* Recipients all in same domain, get domain value. */
		(void) accessClient(sess, ACCESS_TAG, first_rcpt->domain.string, NULL, NULL, &user, 1);
	}

	return user;
}

static int
spamd_printf(Session *sess, Spamd *spamd, char *buffer, size_t size, const char *fmt, ...)
{
	int length;
	va_list args;

	va_start(args, fmt);
	length = vsnprintf(buffer, size, fmt, args);
	if (verb_spamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(672) "spamd >> %d:%s", LOG_ARGS(sess), length, buffer);
	if (socketWrite(spamd->socket, (unsigned char *) buffer, length) != length)
		length = -1;
	va_end(args);

	return length;
}

static int
spamd_open(Session *sess, Spamd *spamd)
{
	char *user;

	if ((user = spamd_user(sess)) != NULL && strcmp(user, "OK") == 0) {
		if (verb_info.option.value)
			syslog(LOG_INFO, LOG_MSG(670) "spamd disabled this message", LOG_ARGS(sess));
		goto error1;
	}

	if (socketOpenClient(optSpamdSocket.string, SPAMD_PORT, optSpamdTimeout.value, NULL, &spamd->socket)) {
		syslog(LOG_ERR, LOG_MSG(671) "spamd connect error \"%s\": %s (%d)", LOG_ARGS(sess), optSpamdSocket.string, strerror(errno), errno);
/*{NEXT}*/
		statsCount(&stat_spamd_connect_error);
		if (errno == EMFILE || errno == ENFILE)
			replyResourcesError(sess, FILE_LINENO);
		goto error1;
	}

	statsCount(&stat_spamd_connect);

	socketSetTimeout(spamd->socket, optSpamdTimeout.value);
	if (spamd_printf(sess, spamd, sess->input, sizeof (sess->input), "%s SPAMC/1.2" CRLF, optSpamdCommand.string) < 0)
		goto error2;

	if (user != NULL && spamd_printf(sess, spamd, sess->input, sizeof (sess->input), "User: %s" CRLF, user) < 0)
		goto error2;

#ifdef SPAMD_CONTENT_LENGTH
{
/* The SPAMD protocol documentation sucks. Only by reading the
 * source do you find out that the Content-Length: header is
 * optional. Open source peons write crap documentation.
 */
 	char **hdr;
	size_t msg_length = sess->msg.length - sess->msg.eoh + CRLF_LENGTH;
	for (hdr = (char **) VectorBase(sess->msg.headers); *hdr != NULL; hdr++) {
		msg_length += strlen(*hdr);
 	}

 	/* Add length of simulated Return-Path: header. */
	msg_length += snprintf(sess->input, sizeof (sess->input), "Return-Path: <%s>" CRLF, sess->msg.mail->address.string);

	if (spamd_printf(sess, spamd, sess->input, sizeof (sess->input), "Content-Length: %lu" CRLF, (unsigned long) msg_length) < 0)
		goto error2;
}
#endif
	/* End spamd header section. */
	if (spamd_printf(sess, spamd, sess->input, sizeof (sess->input), CRLF, CRLF_LENGTH) < 0)
		goto error2;

	/* Start message headers with simulated Return-Path: header. */
	if (spamd_printf(sess, spamd, sess->input, sizeof (sess->input), "Return-Path: <%s>" CRLF, sess->msg.mail->address.string) < 0)
		goto error2;

	free(user);

	return SMTPF_CONTINUE;
error2:
	syslog(LOG_ERR, LOG_MSG(675) "spamd write error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{LOG
An I/O error trying to connect or send to spamd.
See <a href="summary.html#opt_spamd_socket">spamd-socket</a> option.
}*/
	socketClose(spamd->socket);
	spamd->socket = NULL;
error1:
	free(user);

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

	if (*optSpamdSocket.string != '\0') {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, TMP_DIR);
	}

	return SMTPF_CONTINUE;
}

int
spamdRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_spamd);

	optionsRegister(&optSpamdCommand, 0);
	optionsRegister(&optSpamdMaxSize, 0);
	optionsRegister(&optSpamdSocket, 0);
	optionsRegister(&optSpamdTimeout, 0);
	optionsRegister(&optSpamdRejectSenderMarkedSpam, 0);
	optionsRegister(&optSpamdScoreReject, 0);
	optionsRegister(&optSpamdSkipTagged, 0);
	optionsRegister(&optSpamdSubjectTag, 0);

	optionsRegister(&optSpamdFlagHeader, 0);
	optionsRegister(&optSpamdLevelHeader, 0);
	optionsRegister(&optSpamdStatusHeader, 0);
	optionsRegister(&optSpamdReportHeader, 0);
	optionsRegister(&optSpamdLevelCharacter, 0);

	(void) statsRegister(&stat_spamd_connect);
	(void) statsRegister(&stat_spamd_connect_error);
	(void) statsRegister(&stat_spamd_reject);
	(void) statsRegister(&stat_sender_marked_spam);
	(void) statsRegister(&stat_spamd_tag);

	spamd_context = filterRegisterContext(sizeof (Spamd));

	return SMTPF_CONTINUE;
}

int
spamdInit(Session *null, va_list ignore)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_NUM(676) "spamdInit");

	(void) spamdOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
spamdHeaders(Session *sess, va_list args)
{
	float score;
	long i, offset;
	Vector headers;
	char *hdr, *x_spam_flag = NULL, *x_spam_status = NULL;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(677) "spamdHeaders", LOG_ARGS(sess));

	headers = va_arg(args, Vector);
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (TextMatch(hdr, "X-Spam-Status:*", -1, 1))
			x_spam_status = hdr;
		else if (TextMatch(hdr, "X-Spam-Flag:*YES*", -1, 1))
			x_spam_flag = hdr;
	}

	if (optSpamdRejectSenderMarkedSpam.value) {
		/* When an X-Spam-Status header is supplied by the sender, then
		 * check their claimed score against our reject threshold and
		 * reject if they exceed it.
		 */
		if (x_spam_status != NULL && 0 <= optSpamdScoreReject.value) {
			score = -1;
			if (0 < (offset = TextFind(x_spam_status, "*hits=*", -1, 1)))
				offset += sizeof ("hits=")-1;
			else if (0 < (offset = TextFind(x_spam_status, "*score=*", -1, 1)))
				offset += sizeof ("score=")-1;

			if (0 < offset && sscanf(x_spam_status+offset, "%f", &score) == 1
			&& optSpamdScoreReject.value <= score) {
				statsCount(&stat_sender_marked_spam);
				return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 message was already marked as spam by sender" ID_MSG(678) "" CRLF, ID_ARG(sess));
/*{REPLY
See
<a href="summary.html#opt_spamd_reject_sender_marked_spam">spamd-reject-sender-marked-spam</a> and
<a href="summary.html#opt_spamd_score_reject">spamd-score-reject</a> options.
}*/
			}
		}

		/* Otherwise if an "X-Spam-Flag: YES" header is supplied by the
		 * sender, then reject the message. If the sender thought it was
		 * spam, why would we want it?
		 */
		else if (x_spam_flag != NULL) {
			statsCount(&stat_sender_marked_spam);
			return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 message was already marked as spam by sender" ID_MSG(679) "" CRLF, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_spamd_sender_marked_spam">spamd-sender-marked-spam</a> option.
}*/
		}
	}

	/* Remove X-Spam- headers from outside our network. */
	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (TextMatch(hdr, "X-Spam-*", -1, 1)) {
			if (verb_spamd.option.value)
				syslog(LOG_DEBUG, LOG_MSG(680) "removed header \"%s\"", LOG_ARGS(sess), hdr);
			VectorRemove(headers, i--);
		}
	}

	return SMTPF_CONTINUE;
}

int
spamdDot(Session *sess, va_list ignore)
{
	int rc;
	FILE *fp;
	char *hdr;
	Spamd *spamd;
	char wanker_option;
	long i, length, size, score;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(681) "spamdDot", LOG_ARGS(sess));

	rc = SMTPF_CONTINUE;

	if (*optSpamdSocket.string == '\0'
	|| (optSpamdSkipTagged.value && MSG_ANY_SET(sess, MSG_TAGGED)))
		goto error0;

	spamd = filterGetContext(sess, spamd_context);

	/* Reopen the saved message file. */
	(void) snprintf(sess->input, sizeof (sess->input), "%s", saveGetName(sess));
	if ((fp = fopen(sess->input, "rb")) == NULL) {
		syslog(LOG_ERR, LOG_MSG(682) "spamd open error \"%s\": %s (%d)", LOG_ARGS(sess), sess->input, strerror(errno), errno);
/*{LOG
An error trying to open a temporary message file to forward to spamd.
See <a href="summary.html#opt_save_dir">save-dir</a> option.
}*/
		rc = replyPushFmt(sess, SMTPF_TEMPFAIL, msg_451_internal, ID_ARG(sess));
		goto error0;
	}

	cliFdCloseOnExec(fileno(fp), 1);

	/* Open the spamd connection. */
	(void) spamd_open(sess, spamd);
	if (spamd->socket == NULL)
		goto error1;

	/* Send spamd the updated message headers. */
	for (i = 0; i < VectorLength(sess->msg.headers); i++) {
		if ((hdr = VectorGet(sess->msg.headers, i)) == NULL)
			continue;

		length = (long) strlen(hdr);
		if (socketWrite(spamd->socket, (unsigned char *) hdr, length) != length)
			goto error2;
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(673) "spamd >> (wrote %ld bytes)", LOG_ARGS(sess), length);
	}

	/* Send spamd the message body including the EOH CRLF. */
	if (fseek(fp, saveGetEOH(sess) - CRLF_LENGTH, SEEK_SET))
		goto error2;

	for (size = 0; !feof(fp) && size < optSpamdMaxSize.value; size += length) {
		length = (long) fread(sess->msg.chunk1, 1, sizeof (sess->msg.chunk1), fp);
		if (ferror(fp))
			goto error2;
		if (socketWrite(spamd->socket, (unsigned char *) sess->msg.chunk1, length) != length)
			goto error2;
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(683) "spamd >> (wrote %ld bytes)", LOG_ARGS(sess), length);
	}

	if (optSpamdMaxSize.value <= size) {
		syslog(LOG_WARN, LOG_MSG(684) "spamd-max-size=%ld reached", LOG_ARGS(sess), optSpamdMaxSize.value);
/*{LOG
The size of the message passed to spamd have been reached.
No additional data will be passed to spamd.
See <a href="smtpf-cf.html#smtpf_spamd">spamd-max-size</a>.
}*/
	}

	/* Signal EOF to spamd to start processing. */
	socketShutdown(spamd->socket, SHUT_WR);

	/* Read the spamd response. */
	if (socketReadLine(spamd->socket, sess->input, sizeof (sess->input)) <= 0) {
		syslog(LOG_ERR, LOG_MSG(685) "spamd read error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{LOG
An I/O error while reading from spamd.
See <a href="summary.html#opt_spamd_socket">spamd-socket</a> option.
}*/
		goto error2;
	}

	if (verb_spamd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(686) "spamd << %s", LOG_ARGS(sess), sess->input);

	if (TextInsensitiveStartsWith(sess->input, "SPAMD/1.1 0 EX_OK") < 0) {
		syslog(LOG_ERR, LOG_MSG(687) "spamd parse error: %s", LOG_ARGS(sess), sess->input);
/*{NEXT}*/
		goto error2;
	}

	while (0 < (length = socketReadLine(spamd->socket, sess->input, sizeof (sess->input)))) {
		if (verb_spamd.option.value)
			syslog(LOG_DEBUG, LOG_MSG(688) "spamd << %s", LOG_ARGS(sess), sess->input);

		if (0 < TextInsensitiveStartsWith(sess->input, "spam:")) {
			if (sscanf(sess->input, "%*[^;]; %f / %f", &spamd->score, &spamd->threshold) != 2) {
				syslog(LOG_ERR, LOG_MSG(689) "spamd parse error: %s", LOG_ARGS(sess), sess->input);
/*{LOG
The response from spamd does not match the current supported protocol.
}*/
				goto error2;
			}
		}
	}

	if (length < 0) {
		syslog(LOG_ERR, LOG_MSG(690) "spamd read error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{LOG
An I/O error while reading from spamd.
See <a href="summary.html#opt_spamd_socket">spamd-socket</a> option.
}*/
		goto error2;
	}

	/* Create X-Spam-Flag: header */
	if (*optSpamdFlagHeader.string != '\0') {
		(void) snprintf(sess->input, sizeof (sess->input), "%s: %s" CRLF, optSpamdFlagHeader.string, spamd->score < spamd->threshold ? "NO" : "YES");
		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	/* Create X-Spam-Status: header */
	if (*optSpamdStatusHeader.string != '\0') {
		(void) snprintf(sess->input, sizeof (sess->input), "%s: %s, score=%.2f required=%.2f" CRLF, optSpamdStatusHeader.string, spamd->score < spamd->threshold ? "NO" : "YES", spamd->score, spamd->threshold);
		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	/* Create X-Spam-Level: header */
	wanker_option = (!isspace(*optSpamdLevelCharacter.string) && *optSpamdLevelCharacter.string != '\0')
		? *optSpamdLevelCharacter.string
		: 'x';
	if (*optSpamdLevelHeader.string != '\0') {
		length = snprintf(sess->input, sizeof (sess->input)-3, "%s: ", optSpamdLevelHeader.string);
		score = (int) spamd->score;
		for (i = 0; i < score; i++)
			sess->input[length++] = wanker_option;
		sess->input[length++] = '\r';
		sess->input[length++] = '\n';
		sess->input[length  ] = '\0';

		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	/* Create X-Spam-Report: header and log. */
	if (*optSpamdCommand.string != 'C' && *optSpamdReportHeader.string != '\0') {
		size = snprintf((char *) sess->msg.chunk1, sizeof (sess->msg.chunk1), "%s: score=%.2f required=%.2f" X_SPAM_REPORT_NL, optSpamdReportHeader.string, spamd->score, spamd->threshold);
		for ( ; 0 <= (length = socketReadLine(spamd->socket, (char *) (sess->msg.chunk1+size), sizeof (sess->msg.chunk1)-size)); size += length) {
			if (verb_spamd.option.value)
				syslog(LOG_DEBUG, LOG_MSG(691) "spamd << %s", LOG_ARGS(sess), sess->msg.chunk1+size);
			length += TextCopy((char *) (sess->msg.chunk1+size+length), sizeof (sess->msg.chunk1)-size-length, X_SPAM_REPORT_NL);
		}

		/* Terminate the X-Spam-Report: header removing our trailing
 		 * spaces used for long line continuation, ie, "  | ".
		 */
		sess->msg.chunk1[size - 4] = '\0';

		if ((hdr = strdup((char *) sess->msg.chunk1)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	/* Log the final result. */
	(void) snprintf(sess->input, sizeof (sess->input), "message %s junk mail score %.2f/%.2f", sess->msg.id, spamd->score, spamd->threshold);
	syslog(LOG_INFO, LOG_MSG(692) "spamd " CLIENT_FORMAT " %s", LOG_ARGS(sess), CLIENT_INFO(sess), sess->input);
/*{LOG
A summary of the spamd score for a message.
}*/

	if (0 <= optSpamdScoreReject.value && optSpamdScoreReject.value <= spamd->score) {
		statsCount(&stat_spamd_reject);
		rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(693) "" CRLF, sess->input, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_spamd_score_reject">spamd-score-reject</a> option.
}*/
	} else if (spamd->threshold <= spamd->score) {
		MSG_SET(sess, MSG_TAGGED);
		statsCount(&stat_spamd_tag);
		headerAddPrefix(sess, "Subject", optSpamdSubjectTag.string);
		headerReplace(sess->msg.headers, "Precedence", strdup("Precedence: bulk" CRLF));
	}
error2:
	socketClose(spamd->socket);
	spamd->socket = NULL;
error1:
	(void) fclose(fp);
error0:
	return rc;
}

int
spamdRset(Session *sess, va_list ignore)
{
	Spamd *ctx;

	LOG_TRACE(sess, 694, spamdRset);
	ctx = filterGetContext(sess, spamd_context);
	socketClose(ctx->socket);
	ctx->socket = NULL;

	return SMTPF_CONTINUE;
}

#endif /* !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2) */
