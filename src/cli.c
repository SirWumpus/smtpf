/*
 * cli.c
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

#include "smtpf.h"

#ifdef FILTER_CLI
#include <ctype.h>

#if defined(HAVE_FCNTL_H)
# include <fcntl.h>
#endif
#if defined(HAVE_SYSEXITS_H) && ! defined(__MINGW32__)
# include <sysexits.h>
#endif

#include <com/snert/lib/util/Token.h>
#include <com/snert/lib/util/ProcTitle.h>

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef __WIN32__
#define NOT_IMPLEMENTED							\
  "*********************************************************************\n"\
"# ***               Not yet implemented for Windows.                ***\n"\
"# *********************************************************************\n"\
"# "
#else
#define NOT_IMPLEMENTED
#endif

/***
 *** NOTE that the return codes correspond to the SMTPF_ codes.
 ***/

#define USAGE_CLI_CONTENT						\
  "The absolute file path of a CLI script or program used to filter\n"	\
"# message content. This command is initiated after the cli-envelope\n"	\
"# option and just before returning a 354 response to the DATA command.\n"\
"# The mesasge content is later passed as to the CLI as it is received.\n"\
"#\n"									\
"# The command first reads from standard input, until EOF, a simulated\n"\
"# Return-Path header with the sender's address, our Received header\n" \
"# containing client connection details and message queue ID, followed\n"\
"# by the original message headers, and content. The command may write\n"\
"# to standard output a report. Standard error is merged with standard\n"\
"# output.\n"								\
"#\n"									\
"# The command must exit with one of the following values:\n"		\
"#\n"									\
"#   0\tContinue; standard output is logged.\n"				\
"#\n"									\
"#   1\tReserved.\n"							\
"#\n"									\
"#   2\tReserved.\n"							\
"#\n"									\
"#   3\tReserved.\n"							\
"#\n"									\
"#   4\tReserved.\n"							\
"#\n"									\
"#   5\tPermanent reject the message with 550 5.7.0; lines from\n"	\
"#\tstandard output will be used for the SMTP response.\n"		\
"#\n"									\
"#   6\tDiscard the message; standard output is logged.\n"		\
"#\n"									\
"#   7\tDrop the client connection; standard output is logged.\n"	\
"#\n"									\
"# Any other values are reserved for future use.\n"			\
"#"

/***
 *** NOTE that the return codes correspond to the SMTPF_ codes.
 ***/

#define USAGE_CLI_ENVELOPE						\
  "The absolute file path of a CLI script or program used to filter\n"	\
"# envelope details. This command is executed when the DATA command\n"	\
"# is sent by the client. The response from the CLI can reject the\n"	\
"# DATA command.\n"							\
"#\n"									\
"# The command reads the following lines from standard input: the\n"	\
"# client IP, the client PORT, the client name, the HELO/EHLO\n"	\
"# argument, the MAIL FROM: argument, the message queue ID, and one\n"	\
"# or more RCPT TO: arguments until EOF. The command may write to\n"	\
"# standard output a report. Standard error is merged with standard\n"	\
"# output.\n"								\
"#\n"									\
"# The command must exit with one of the following values:\n"		\
"#\n"									\
"#   0\tContinue; standard output is logged.\n"				\
"#\n"									\
"#   1\tReserved.\n"							\
"#\n"									\
"#   2\tReserved.\n"							\
"#\n"									\
"#   3\tReserved.\n"							\
"#\n"									\
"#   4\tTemporary reject the message with 451 4.7.0; lines from\n"	\
"#\tstandard output will be used for the SMTP response.\n"		\
"#\n"									\
"#   5\tPermanent reject the message with 550 5.7.0; lines from\n"	\
"#\tstandard output will be used for the SMTP response.\n"		\
"#\n"									\
"#   6\tDiscard the message; standard output is logged.\n"		\
"#\n"									\
"#   7\tDrop the client connection; standard output is logged.\n"	\
"#\n"									\
"# Any other values are reserved for future use.\n"			\
"#"									\

Option optCliContent	= { "cli-content",	"",	NOT_IMPLEMENTED USAGE_CLI_CONTENT  };
Option optCliEnvelope	= { "cli-envelope",	"",	NOT_IMPLEMENTED USAGE_CLI_ENVELOPE  };
Option optCliTimeout	= { "cli-timeout",	"60",	NOT_IMPLEMENTED "The CLI I/O timeout in seconds." };

Stats stat_cli_envelope	= { STATS_TABLE_DATA, "cli-envelope" };
Stats stat_cli_content	= { STATS_TABLE_MSG, "cli-content" };

typedef struct {
	char *commandLine;
	char *basename;
	char **argv;
	int argc;
} CLI_Command;

typedef struct {
	pid_t child;
	int exit_code;
	int childIn[2];
	int childOut[2];
	Vector report;
} CLI;

static CLI_Command cmdContent;
static CLI_Command cmdEnvelope;
static char *command_env[] = { "PATH=" SAFE_PATH, NULL };

static Verbose verb_cli	= { { "cli", "-", "" } };
static FilterContext cli_context;

#define NO_CHILD			((pid_t) 0)
#define CHILD_INPUT(cli)		(cli)->childIn[1]
#define CHILD_OUTPUT(cli)		(cli)->childOut[0]

/***********************************************************************
 ***
 ***********************************************************************/

static int
reaper(pid_t child)
{
	int status;

	while (waitpid(child, &status, WUNTRACED) < 0 && errno == EINTR)
		;

	return status;
}

int
setNonBlocking(int fd, int flag)
{
	long flags;

	flags = (long) fcntl(fd, F_GETFL);

	if (flag)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	return fcntl(fd, F_SETFL, flags);
}

static void
cmdInit(Option *option, CLI_Command *cmd)
{
	if (*option->string == '\0')
		return;

	cmd->commandLine = option->string;

	free(cmd->argv);
	if (TokenSplit(cmd->commandLine, NULL, &cmd->argv, &cmd->argc, 0)) {
		syslog(LOG_ERR, LOG_NUM(210) "error parsing %s='%s': %s (%d)", option->name, option->string, strerror(errno), errno);
/*{LOG
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
		exit(1);
	}

	if ((cmd->basename = strrchr(cmd->argv[0], '/')) == NULL)
		cmd->basename = cmd->argv[0];
	else
		cmd->basename++;
}

int
cliOptn(Session *null, va_list ignore)
{
	optCliTimeout.value = strtol(optCliTimeout.string, NULL, 10) * 1000;

	return SMTPF_CONTINUE;
}

int
cliRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_cli);

	optionsRegister(&optCliContent, 		0);
	optionsRegister(&optCliEnvelope, 		0);
	optionsRegister(&optCliTimeout, 		0);

	(void) statsRegister(&stat_cli_envelope);
	(void) statsRegister(&stat_cli_content);

	return SMTPF_CONTINUE;
}

int
cliInit(Session *null, va_list ignore)
{
	(void) cliOptn(null, ignore);
	cmdInit(&optCliContent, &cmdContent);
	cmdInit(&optCliEnvelope, &cmdEnvelope);

	cli_context = filterRegisterContext(sizeof (CLI));

	return SMTPF_CONTINUE;
}

static int
cmdStart(Session *sess, CLI *cli, CLI_Command *cmd)
{
	/* No commands */
	if (cmd->commandLine == NULL || *cmd->commandLine == '\0')
		return -1;

	if ((cli->report = VectorCreate(10)) == NULL)
		goto error0;

	VectorSetDestroyEntry(cli->report, free);

	if (pipe(cli->childIn))
		goto error1;

	/* Should we fork()/exec() in another thread, then make
	 * sure these file descriptors are closed on exec.
	 */
	(void) fcntl(cli->childIn[0], F_SETFD, FD_CLOEXEC);
	(void) fcntl(cli->childIn[1], F_SETFD, FD_CLOEXEC);

	if (pipe(cli->childOut))
		goto error2;

	(void) fcntl(cli->childOut[0], F_SETFD, FD_CLOEXEC);
	(void) fcntl(cli->childOut[1], F_SETFD, FD_CLOEXEC);

	if ((cli->child = fork()) == -1)
		goto error3;

	if (cli->child == 0) {
		/* The Child */
#if defined(__linux__) && HACK_TZSET_LOCK
/*** HACK - Force tzset_lock in libc's tzset.c into a known state.
 *** tzset_lock is static and follows after timezone variable.
 ***/
{
		pthread_mutex_t *mutexp = (pthread_mutex_t *) ((long *) &timezone)[1];

		(void) pthread_mutex_trylock(mutexp);
		(void) pthread_mutex_unlock(mutexp);
		(void) pthread_mutex_destroy(mutexp);

		syslog(LOG_DEBUG, LOG_MSG(211) "tzset_lock unlocked", LOG_ARGS(sess));
}
#endif
		/* Linux: syslog() calls strftime() calls tzset() which
		 * tries to lock tzset_lock, which might already be in a
		 * locked state by some other thread in the parent process.
		 *
		 * The simple solution is to close syslog() to prevent any
		 * chance of hanging on the tzset_lock mutex between fork()
		 * and execve(). Once we reach execve(), the process will
		 * return to a know safe state. Between fork() and execve()
		 * we can only use async-signal-safe library routines (see
		 * SUS rationale for pthread_atfork for commentary).
		 */
		closelog();

		/* Redirect standard I/O for the child. */
		if (dup2(cli->childIn[0], 0) < 0) {
			_exit(10);
		}

		if (dup2(cli->childOut[1], 1) < 0) {
			_exit(11);
		}

		if (dup2(cli->childOut[1], 2) < 0) {
			_exit(12);
		}

		ProcTitleSet(NULL);
		_atExitCleanUp();
		signalFini(NULL);

		/* Close these pipe handles now that the standard
		 * ones have been redirected. FD_CLOEXEC should
		 * have already been applied else where for all
		 * SMTP client sockets.
		 */
		(void) close(cli->childIn[0]);
		(void) close(cli->childIn[1]);
		(void) close(cli->childOut[0]);
		(void) close(cli->childOut[1]);

		/* Do not allow the child to use seteuid() back to root. */
		(void) setuid(geteuid());

		/* Time for a change of scenery. */
		(void) execve(cmd->argv[0], cmd->argv, command_env);

		/* Exit without running atexit() routines. */
		_exit(EX_OSERR);
	}

	/* The Parent */

	/* Close our copies of the child's standard I/O handles. */
	close(cli->childIn[0]);
	close(cli->childOut[1]);

	if (verb_info.option.value) {
		syslog(LOG_INFO, LOG_MSG(212) "started %s[%d] %s", LOG_ARGS(sess), cmd->basename, cli->child, cmd->commandLine);
/*{LOG
See <a href="smtpf-cf.html#smtpf_cli">CLI</a> section, and the options
<a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
	}

	return 0;
error3:
	(void) close(cli->childOut[0]);
	(void) close(cli->childOut[1]);
error2:
	(void) close(cli->childIn[0]);
	(void) close(cli->childIn[1]);
error1:
	VectorDestroy(cli->report);
	cli->report = NULL;
error0:
	syslog(LOG_ERR, LOG_MSG(213) "cmdStart(%s) failed: %s (%d)", LOG_ARGS(sess), cmd->commandLine, strerror(errno), errno);
/*{LOG
There was a problem invoking the specified command-line.
Things to check are if the command is on default PATH or specify an absolute path and/or check that options are correct.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
	cli->child = NO_CHILD;

	return -1;
}

static int
cmdStop(Session *sess, CLI *cli, CLI_Command *cmd)
{
	int rc;
	char *p;

	rc = -1;

	if (cli->child == NO_CHILD)
		goto error0;

	if (verb_cli.option.value)
		syslog(LOG_DEBUG, LOG_MSG(214) "enter cmdStop(%lx, %lx) %s[%d]", LOG_ARGS(sess), (long) sess, (long) cmd, cmd->basename, cli->child);

	if (close(CHILD_INPUT(cli))) {
		syslog(LOG_ERR, LOG_MSG(215) "write error to child=%d: %s (%d)", LOG_ARGS(sess), cli->child, strerror(errno), errno);
/*{LOG
There was a problem closing the input stream to the CLI child process.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
		(void) kill(-cli->child, SIGKILL);
		(void) kill(cli->child, SIGKILL);
		goto error1;
	}

	setNonBlocking(CHILD_OUTPUT(cli), 1);

	if (verb_cli.option.value)
		syslog(LOG_DEBUG, LOG_MSG(216) "read from child=%d", LOG_ARGS(sess), cli->child);

	/*** WARNING WARNING WARNING
	 *** For Windows socketTimeoutIO() wants a SOCKET handle which
	 *** is different from a file handle, so some other code will
	 *** be required for Windows.
	 ***/
	while (socketTimeoutIO(CHILD_OUTPUT(cli), optCliTimeout.value, 1)) {
		if (TextReadLine(CHILD_OUTPUT(cli), sess->input, SMTP_REPLY_LINE_LENGTH+1) < 0) {
			if (verb_cli.option.value)
				syslog(LOG_DEBUG, LOG_MSG(217) "child=%d EOF", LOG_ARGS(sess), cli->child);
			break;
		}

		for (p = sess->input; *p != '\0'; p++)
			if (*p == '\r' || *p == '\n')
				*p = '\0';

		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(218) "cli << %s", LOG_ARGS(sess),sess->input);
		VectorAdd(cli->report, strdup(sess->input));
	}
error1:
	close(CHILD_OUTPUT(cli));
	if (verb_cli.option.value)
		syslog(LOG_DEBUG, LOG_MSG(219) "waiting on child=%d", LOG_ARGS(sess), cli->child);
	cli->exit_code = reaper(cli->child);

	if (WIFSIGNALED(cli->exit_code)) {
		syslog(
			LOG_ERR, LOG_MSG(220) "%s[%d] terminated on signal=%d%s",
			LOG_ARGS(sess), cmd->basename, cli->child,
			WTERMSIG(cli->exit_code),
			WCOREDUMP(cli->exit_code) ? ", core dumped" : ""
		);
/*{LOG
The CLI child process terminated on signal, possibly due to a program fault.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
		cli->exit_code = SMTPF_CONTINUE;
	} else if (WIFEXITED(cli->exit_code)) {
		cli->exit_code = WEXITSTATUS(cli->exit_code);
		if (VectorLength(cli->report) <= 0 && 0 < cli->exit_code)
			VectorAdd(cli->report, strdup("message rejected"));
		if (cli->exit_code < SMTPF_CONTINUE || SMTPF_DROP < cli->exit_code) {
			syslog(LOG_ERR, LOG_MSG(221) "exit status=%d out of range", LOG_ARGS(sess), cli->exit_code);
/*{LOG
The CLI child process returned an unsupported exit code.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
			cli->exit_code = SMTPF_CONTINUE;
		}
		if (verb_info.option.value) {
			syslog(LOG_INFO, LOG_MSG(222) "%s[%d] exit status=%d", LOG_ARGS(sess), cmd->basename, cli->child, cli->exit_code);
/*{LOG
The CLI child process returned a supported exit code.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
		}
	} else {
		cli->exit_code = SMTPF_CONTINUE;
	}

	rc = 0;

	if (verb_cli.option.value)
		syslog(LOG_DEBUG, LOG_MSG(223) "exit  cmdStop(%lx, %lx) %s[%d] rc=%d", LOG_ARGS(sess), (long) sess, (long) cmd, cmd->basename, cli->child, rc);
	cli->child = NO_CHILD;
error0:
	return rc;
}

static int
cmdReport(Session *sess, CLI *cli)
{
	char *line;
	int i, smtp_code;
	Reply *reply = NULL;

	if (cli->exit_code == SMTPF_TEMPFAIL || cli->exit_code == SMTPF_REJECT) {
		smtp_code = cli->exit_code == SMTPF_TEMPFAIL ? 451 : 550;

		for (i = 0; i < VectorLength(cli->report)-1; i++) {
			if ((line = VectorGet(cli->report, i)) == NULL)
				continue;

			reply = replyAppendFmt(reply, "%d-%d.7.0 %s\r\n", smtp_code, cli->exit_code, line);
		}

		line = VectorGet(cli->report, i);
		reply = replyAppendFmt(reply, "%d %d.7.0 %s" ID_MSG(224) "\r\n", smtp_code, cli->exit_code, TextEmpty(line), ID_ARG(sess));
/*{REPLY
The CLI child process standard output and standard error are used for specifying a multiline response.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
		if (reply == NULL)
			replyInternalError(sess, FILE_LINENO);
		replySetCode(reply, cli->exit_code);

		return replyPush(sess, reply);
	}

	for (i = 0; i < VectorLength(cli->report); i++) {
		if ((line = VectorGet(cli->report, i)) == NULL)
			continue;
		if (verb_info.option.value) {
			syslog(LOG_INFO, LOG_MSG(225) "%s", LOG_ARGS(sess), line);
/*{LOG
The CLI child process standard output and standard error are logged.
See <a href="summary.html#opt_cli_content">cli-content</a> and <a href="summary.html#opt_cli_envelope">cli-envelope</a>.
}*/
		}
	}

	return SMTPF_CONTINUE;
}

static long
cliWritePipe(CLI *cli, unsigned char *chunk, long size)
{
	long offset, sent;

	for (offset = 0; offset < size; offset += sent) {
		if ((sent = write(CHILD_INPUT(cli), chunk+offset, size-offset)) < 0) {
			UPDATE_ERRNO;
			if (!ERRNO_EQ_EAGAIN) {
				if (offset == 0) {
					(void) close(CHILD_INPUT(cli));
					return -1;
				}
				break;
			}
			sent = 0;
		}
	}

	return offset;
}

int
cliConnect(Session *sess, va_list ignore)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(226) "cliConnect()", LOG_ARGS(sess));

	filterClearContext(sess, cli_context);

	return SMTPF_CONTINUE;
}

int
cliRset(Session *sess, va_list ignore)
{
	CLI *cli = filterGetContext(sess, cli_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(227) "cliRset()", LOG_ARGS(sess));

	/* Assert that these are closed at end of connection in case
	 * clamdDot() is not called ,because of a rejection or dropped
	 * connection betweem DATA and DOT.
	 */
	if (cli->child != NO_CHILD) {
		(void) close(CHILD_INPUT(cli));
		(void) close(CHILD_OUTPUT(cli));
		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(228) "killing child=%d", LOG_ARGS(sess), cli->child);
		(void) kill(-cli->child, SIGKILL);
		(void) kill(cli->child, SIGKILL);
		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(229) "reaping child=%d", LOG_ARGS(sess), cli->child);
		(void) reaper(cli->child);
		cli->child = NO_CHILD;

		VectorDestroy(cli->report);
	}

	return SMTPF_CONTINUE;
}

int
cliData(Session *sess, va_list ignore)
{
	Rcpt *rcpt;
	long length;
	char port[20];
	Connection *fwd;
	CLI *cli = filterGetContext(sess, cli_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(230) "cliData()", LOG_ARGS(sess));

	if (!cmdStart(sess, cli, &cmdEnvelope)) {
		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(231) "cli >> %s", LOG_ARGS(sess), sess->client.addr);
		(void) cliWritePipe(cli, sess->client.addr, strlen(sess->client.addr));
		(void) cliWritePipe(cli, "\n", 1);

		length = snprintf(port, sizeof (port), "%d", socketAddressGetPort(&sess->client.socket->address));
		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(232) "cli >> %s", LOG_ARGS(sess), port);
		(void) cliWritePipe(cli, port, length);
		(void) cliWritePipe(cli, "\n", 1);

		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(233) "cli >> %s", LOG_ARGS(sess), sess->client.name);
		(void) cliWritePipe(cli, sess->client.name, strlen(sess->client.name));
		(void) cliWritePipe(cli, "\n", 1);

		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(234) "cli >> %s", LOG_ARGS(sess), sess->client.helo);
		(void) cliWritePipe(cli, sess->client.helo, strlen(sess->client.helo));
		(void) cliWritePipe(cli, "\n", 1);

		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(235) "cli >> %s", LOG_ARGS(sess), sess->msg.mail->address.string);
		(void) cliWritePipe(cli, sess->msg.mail->address.string, sess->msg.mail->address.length);
		(void) cliWritePipe(cli, "\n", 1);

		if (verb_cli.option.value)
			syslog(LOG_DEBUG, LOG_MSG(236) "cli >> %s", LOG_ARGS(sess), sess->msg.id);
		(void) cliWritePipe(cli, sess->msg.id, strlen(sess->msg.id));
		(void) cliWritePipe(cli, "\n", 1);

		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next) {
				if (verb_cli.option.value)
					syslog(LOG_DEBUG, LOG_MSG(237) "cli >> %s", LOG_ARGS(sess), rcpt->rcpt->address.string);
				(void) cliWritePipe(cli, rcpt->rcpt->address.string, rcpt->rcpt->address.length);
				(void) cliWritePipe(cli, "\n", 1);
			}
		}

		if (cmdStop(sess, cli, &cmdEnvelope))
			return SMTPF_CONTINUE;

		if (cmdReport(sess, cli) == SMTPF_DROP)
			return SMTPF_DROP;

		if (cli->exit_code != SMTPF_CONTINUE) {
			statsCount(&stat_cli_envelope);
			return cli->exit_code;
		}
	}

	if (!cmdStart(sess, cli, &cmdContent)) {
		length = snprintf(sess->input, sizeof (sess->input), "Return-Path: <%s>\r\n", sess->msg.mail->address.string);
		(void) cliWritePipe(cli, sess->input, length);

		length = getReceivedHeader(sess, sess->input, sizeof (sess->input));
		(void) cliWritePipe(cli, sess->input, length);
	}

	return SMTPF_CONTINUE;
}

int
cliHeaders(Session *sess, va_list args)
{
	long i;
	char *hdr;
	Vector headers = va_arg(args, Vector);
	CLI *cli = filterGetContext(sess, cli_context);

	if (cli->child != NO_CHILD) {
		for (i = 0; i < VectorLength(headers); i++) {
			if ((hdr = VectorGet(headers, i)) == NULL)
				continue;
			(void) cliWritePipe(cli, hdr, strlen(hdr));
		}
	}

	return SMTPF_CONTINUE;
}

int
cliContent(Session *sess, va_list args)
{
	long size;
	unsigned char *chunk;
	CLI *cli = filterGetContext(sess, cli_context);

	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(238) "cliContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	if (cli->child != NO_CHILD) {
		(void) cliWritePipe(cli, chunk, size);
	}

	return SMTPF_CONTINUE;
}

int
cliDot(Session *sess, va_list ignore)
{
	CLI *cli = filterGetContext(sess, cli_context);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(239) "cliDot()", LOG_ARGS(sess));
	if (cmdStop(sess, cli, &cmdContent))
		return SMTPF_CONTINUE;

	if (cmdReport(sess, cli) == SMTPF_DROP)
		return SMTPF_DROP;

	if (cli->exit_code != SMTPF_CONTINUE)
		statsCount(&stat_cli_content);

	return cli->exit_code;
}

int
cliClose(Session *sess, va_list ignore)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(240) "cliClose()", LOG_ARGS(sess));

	return cliRset(sess, ignore);
}

#endif /* FILTER_CLI */

