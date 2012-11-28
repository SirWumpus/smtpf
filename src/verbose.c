/*
 * verbose.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#include <com/snert/lib/net/dnsList.h>

/***********************************************************************
 ***
 ***********************************************************************/

static Verbose *verb_list;
static const char empty[] = "";

/* Verbose levels */
Verbose verb_info	= { { "info",		"+", empty } };
Verbose verb_trace	= { { "trace",		"-", empty } };
Verbose verb_debug	= { { "debug",		"-", empty } };

/* Verbose API */
Verbose verb_db		= { { "db",		"-", empty } };
Verbose verb_dns	= { { "dns",		"-", empty } };
Verbose verb_kvm	= { { "kvm",		"-", empty } };
Verbose verb_socket	= { { "socket",		"-", empty } };
Verbose verb_subject	= { { "subject",	"-", empty } };
#ifdef __linux__
Verbose verb_valgrind	= { { "valgrind",	"-", empty } };
#endif

/* Verbose SMTP command */
Verbose verb_connect	= { { "connect",	"-", empty } };
Verbose verb_helo	= { { "helo",		"-", empty } };
Verbose verb_auth	= { { "auth",		"-", empty } };
Verbose verb_mail	= { { "mail",		"-", empty } };
Verbose verb_rcpt	= { { "rcpt",		"-", empty } };
Verbose verb_data	= { { "data",		"-", empty } };
Verbose verb_noop	= { { "noop",		"-", empty } };
Verbose verb_rset	= { { "rset",		"-", empty } };

/* Verbose SMTP client. */
Verbose verb_smtp	= { { "smtp",		"-", empty } };

static const char verbose_usage[] =
  "Verbose logging to mail log. Specify one or more comma separated words:"
;

#ifndef USAGE_LINE_LENGTH
#define USAGE_LINE_LENGTH	(sizeof (verbose_usage))
#endif

static char usage_verbose[1024];

Option optVerbose = { "verbose", "warn,info,smtp-dot,tls", (const char *) usage_verbose };

/***********************************************************************
 ***
 ***********************************************************************/

int
verboseRegister(Verbose *v)
{
	Verbose **p, *q;

	if (v != NULL) {
		/* Insert words in sorted order. */
		for (p = &verb_list, q = verb_list; q != NULL; p = &q->next, q = q->next) {
			if (TextInsensitiveCompare(v->option.name, q->option.name) < 0) {
				v->next = q;
				*p = v;
				return 0;
			}
		}

		v->next = NULL;
		*p = v;

		return 0;
	}

	return -1;
}

int
verboseSet(char *s)
{
	Verbose *v;
	char *name, *value;

	if (!optionParse(s, 1, &name, &value))
		return -1;

	for (v = verb_list; v != NULL; v = v->next) {
		if (TextInsensitiveCompare(name, v->option.name) == 0) {
			if (!optionSet(&v->option, value))
				free(value);
			free(name);
			return 0;
		}
	}

	free(value);
	free(name);

	return -1;
}

extern void socket3_set_debug(int);

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
static void
verboseClear(void)
{
	kvmDebug(0);
	pdqSetDebug(0);
	dnsListSetDebug(0);
	smdbSetDebug(0);
	mccSetDebug(0);
	socketSetDebug(0);
	socket3_set_debug(0);
}
#endif

static void
verboseReset(void)
{
	kvmDebug(verb_kvm.option.value);
	pdqSetDebug(verb_dns.option.value);
	dnsListSetDebug(verb_dns.option.value);

	smdbSetDebug(verb_db.option.value);
	mccSetDebug(verb_cache.option.value);
	socketSetDebug(verb_socket.option.value);
#ifdef FILTER_SPF
	spfSetDebug(verb_spf.option.value);
#endif
#ifdef FILTER_URIBL
	uriSetDebug(verb_uri.option.value);
#endif
	server.option.min_threads = optServerMinThreads.value;
	server.option.max_threads = optServerMaxThreads.value;
	server.option.spare_threads = optServerNewThreads.value;
	server.option.accept_to   = optServerAcceptTimeout.value;
	server.option.read_to     = optSmtpCommandTimeout.value;
	server.debug.level 	  = verb_connect.option.value;
#ifdef VERB_VALGRIND
	server.debug.valgrind	  = verb_valgrind.option.value;
#endif
}

void
verboseParse(const char *string)
{
	long i;
	Vector args;

	if ((args = TextSplit(string, OPTION_LIST_DELIMS, 0)) != NULL) {
		for (i = 0; i < VectorLength(args); i++)
			(void) verboseSet(VectorGet(args, i));
		verboseReset();
		VectorDestroy(args);
	}
}

int
verboseRegister0(Session *null, va_list ignore)
{
	verb_list = NULL;
	(void) TextCopy(usage_verbose, sizeof (usage_verbose), verbose_usage);

	verboseRegister(&verb_info);
	verboseRegister(&verb_trace);
	verboseRegister(&verb_debug);

	verboseRegister(&verb_db);
	verboseRegister(&verb_dns);
	verboseRegister(&verb_kvm);
	verboseRegister(&verb_socket);
	verboseRegister(&verb_subject);
#ifdef __linux__
	verboseRegister(&verb_valgrind);
#endif
	verboseRegister(&verb_connect);
	verboseRegister(&verb_helo);
	verboseRegister(&verb_auth);
	verboseRegister(&verb_mail);
	verboseRegister(&verb_rcpt);
	verboseRegister(&verb_data);
	verboseRegister(&verb_noop);
	verboseRegister(&verb_rset);

	verboseRegister(&verb_smtp);

	optionsRegister(&optVerbose, 0);

	return SMTPF_CONTINUE;
}

void
verboseInit(const char *s)
{
	Verbose *v;
	size_t length, vlen;

	length = strlen(usage_verbose);
	for (v = verb_list; v != NULL; v = v->next) {
		vlen = strlen(v->option.name);

		if (sizeof (usage_verbose) <= length + vlen + sizeof ("\n# ")) {
			syslog(LOG_ERR, LOG_NUM(795) "verbose word list too long");
			exit(1);
		}

		if (USAGE_LINE_LENGTH <= length % USAGE_LINE_LENGTH + 1 + vlen)
			length += TextCopy(usage_verbose+length, sizeof (usage_verbose)-length, "\n#");
		length += TextCopy(usage_verbose+length, sizeof (usage_verbose)-length, " ");
		length += TextCopy(usage_verbose+length, sizeof (usage_verbose)-length, v->option.name);
	}
	length += TextCopy(usage_verbose+length, sizeof (usage_verbose)-length, "\n#");

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(NULL, NULL, verboseClear)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif

	verboseParse(s);
}

#ifdef NOT_USED
void
verbose(int ignore, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (logFile == NULL)
		vsyslog(LOG_INFO, fmt, args);
	else
		LogV(LOG_INFO, fmt, args);
	va_end(args);
}
#endif

int
verboseCommand(Session *sess)
{
	Verbose *v;
	Reply *reply;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
		return cmdOutOfSequence(sess);

	statsCount(&stat_admin_commands);

	if (sizeof ("VERB\r\n")-1 < sess->input_length)
		verboseParse(sess->input + sizeof ("VERB ")-1);

	reply = REPLY_CONST(SMTPF_CONTINUE, "214-2.0.0");

	for (v = verb_list; v != NULL; v = v->next) {
		if (LINE_WRAP <= reply->length % LINE_WRAP + strlen(v->option.name) + 2)
			reply = REPLY_APPEND_CONST(reply, "\r\n214-2.0.0");

		reply = replyAppendFmt(reply, " %c%s", v->option.value != 0 ? '+' : '-', v->option.name);
	}

	reply = REPLY_APPEND_CONST(reply, "\r\n214 2.0.0 End.\r\n");

	return replyPush(sess, reply);
}

