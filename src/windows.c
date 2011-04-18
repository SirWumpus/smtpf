/*
 * windows.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef MAX_ARGV_LENGTH
#define MAX_ARGV_LENGTH		50
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "smtpf.h"

#include <stdio.h>

#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/sys/pthread.h>
#include <com/snert/lib/sys/sysexits.h>
#include <com/snert/lib/sys/winService.h>
#include <com/snert/lib/util/Token.h>

#include <windows.h>
#include <sddl.h>

/***********************************************************************
 *** Logging
 ***********************************************************************/

static HANDLE eventLog;

void
ReportInit(void)
{
	eventLog = RegisterEventSource(NULL, _NAME);
}

void
ReportLogV(int type, char *fmt, va_list args)
{
	LPCTSTR strings[1];
	char message[1024];

	strings[0] = message;
	(void) vsnprintf(message, sizeof (message), fmt, args);

	ReportEvent(
		eventLog,	// handle of event source
		type,		// event type
		0,		// event category
		0,		// event ID
		NULL,		// current user's SID
		1,		// strings in lpszStrings
		0,		// no bytes of raw data
		strings,	// array of error strings
		NULL		// no raw data
	);
}

void
ReportLog(int type, char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ReportLogV(type, fmt, args);
	va_end(args);
}

static DWORD strerror_tls = TLS_OUT_OF_INDEXES;
static const char unknown_error[] = "(unknown error)";

char *
strerror(int error_code)
{
	char *error_string;

	if (strerror_tls == TLS_OUT_OF_INDEXES) {
		strerror_tls = TlsAlloc();
		if (strerror_tls == TLS_OUT_OF_INDEXES)
			return (char *) unknown_error;
	}

	error_string = (char *) TlsGetValue(strerror_tls);
	LocalFree(error_string);

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, error_code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &error_string, 0, NULL
	);

	if (!TlsSetValue(strerror_tls, error_string)) {
		LocalFree(error_string);
		return (char *) unknown_error;
	}

	return error_string;
}

void
freeThreadData(void)
{
	if (strerror_tls != TLS_OUT_OF_INDEXES) {
		char *error_string = (char *) TlsGetValue(strerror_tls);
		LocalFree(error_string);
	}
}

/***********************************************************************
 *** Signals
 ***********************************************************************/

#define QUIT_EVENT_NAME 	"Global\\" _NAME "-QUIT"
#define TERM_EVENT_NAME 	"Global\\" _NAME "-TERM"

/***********************************************************************
 *** Windows Service Framework
 ***********************************************************************/

static char *server_root = NULL;

int
dropPrivilages(void)
{
	/* Do nothing (yet). */
	return 0;
}

void
atExitCleanUp(void)
{
	syslog(LOG_INFO, LOG_NUM(802) "terminated");
	_atExitCleanUp();
}

static void
atExitCleanUpOptions(void)
{
	optionFree(optTable, lickeyOptTable, NULL);
}

void
serverOptions(int argc, char **argv)
{
	int argi;

	filterRegister();
	(void) atexit(atExitCleanUpOptions);

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, NULL);
	argi = optionArrayL(argc, argv, optTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (optFile.string != NULL && *optFile.string != '\0') {
		/* Do NOT reset this option. */
		optFile.initial = optFile.string;
		optFile.string = NULL;

		optionInit(optTable, NULL);
		(void) optionFile(optFile.string, optTable, NULL);
		(void) optionArrayL(argc, argv, optTable, NULL);
	}

	if (optVersion.string != NULL) {
		serverPrintVersion();
		exit(2);
	}

	if (optInfo.string != NULL) {
		serverPrintInfo();
		exit(2);
	}

	if (optAccessTagWords.string != NULL) {
		accessPrintMapping(accessTagWordsMap);
		exit(2);
	}

	if (optAccessWordTags.string != NULL) {
		accessPrintMapping(accessWordTagsMap);
		exit(2);
	}

	/* Initialise the verbose options and define the usage string. */
	verboseInit(optVerbose.string);

	/* Show them the funny farm. */
	if (optHelp.string != NULL) {
#ifdef ENABLE_CONSOLE
		int show_options = (optHelp.string[0] == '-' || optHelp.string[0] == '+') && optHelp.string[1] == '\0';

		if (show_options) {
			/* AllocConsole() only works for Windows GUI applications. */
			if (AllocConsole()) {
				(void) freopen("CONIN$", "rb", stdin);
				(void) freopen("CONOUT$", "w", stdout);
			} else {
				(void) freopen(_NAME ".help", "w", stdout);
			}
		} else {
			(void) freopen(optHelp.string, "w", stdout);
		}

		optionUsageL(optTable, NULL);

		if (show_options) {
			printf("\nPress ENTER to continue...");
			fflush(stdout);

			while (fgetc(stdin) != '\n')
				;
		}
#else
		if (optHelp.string[0] != '-' && optHelp.string[0] != '+')
			(void) freopen(optHelp.string, "w", stdout);
		optionUsageL(optTable, NULL);
#endif
		exit(2);
	}

	if (optTestLickey.value)
		optDaemon.value = 0;
}

#ifdef ENABLE_CONSOLE
int WINAPI
WinMain(HINSTANCE me, HINSTANCE other, LPSTR cmdline, int wstate)
#else
int
main(int argc, char **argv)
#endif
{
#ifdef ENABLE_CONSOLE
	int argc;
	static char *argv[MAX_ARGV_LENGTH+1];
#endif
	long length;
	HANDLE event;
	static char default_root[256];
	char *cwd, *backslash, *install_path;

	/* Get this now so we can use the event log. */
	ReportInit();

	/* Open the log file for use now by the service start or
	 * for the application -daemon. We have to open it again
	 * in ServiceMain for +daemon. All other initialisation
	 * should happen in serverMain.
	 */
	openlog(_NAME, LOG_PID, LOG_MAIL);

#ifdef ENABLE_CONSOLE
	if ((argc = TokenSplitA(cmdline, NULL, argv+1, MAX_ARGV_LENGTH)) == -1) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(805) "command-line split failed");
		return 1;
	}

	argv[0] = _NAME;
	argc++;
#endif

	/* Get the absolute path of this executable and set the working
	 * directory to correspond to it so that we can find the options
	 * configuration file along side the executable, when running as
	 * a service. (I hate using the registry.)
	 */
	if ((length = GetModuleFileName(NULL, default_root, sizeof default_root)) == 0 || length == sizeof default_root) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(806) "failed to find default server root");
		return EXIT_FAILURE;
	}

	/* Remember the full path of the executable. */
	install_path = strdup(default_root);

	/* Strip off the executable filename, leaving its parent directory. */
	for (backslash = default_root+length; default_root < backslash && *backslash != '\\'; backslash--)
		;

	server_root = default_root;
	*backslash = '\0';

	/* Remember where we are in case we are running in application mode. */
	cwd = getcwd(NULL, 0);

	/* Change to the executable's directory for default configuration file. */
	if (chdir(server_root)) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(808) "failed to change directory to '%s': %s (%d)\n", server_root, strerror(errno), errno);
		return EXIT_FAILURE;
	}

	/* Parse any command options. */
	serverOptions(argc, argv);

	if (optQuit.string != NULL || optSlowQuit.string != NULL) {
		event = OpenEvent(EVENT_MODIFY_STATE , 0, optSlowQuit.string == NULL ? TERM_EVENT_NAME : QUIT_EVENT_NAME);
		if (event == NULL) {
			syslog(LOG_ERR, LOG_NUM(807) "%s quit error %d", _NAME, GetLastError());
			exit(1);
		}

		SetEvent(event);
		CloseHandle(event);
		return EXIT_SUCCESS;
	}

	if (optService.string != NULL) {
		if (winServiceInstall(*optService.string == '+', _NAME, NULL) < 0) {
			ReportLog(EVENTLOG_ERROR_TYPE, "service %s %s error: %s (%d)", _NAME, *optService.string == '+'  ? "add" : "remove", strerror(errno), errno);
			return EX_OSERR;
		}
		return EXIT_SUCCESS;
	}

	if (optDaemon.value) {
		winServiceSetSignals(&signals);
		if (winServiceStart(_NAME, argc, argv) < 0) {
			ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(811) "service %s start error", _NAME);
			return EX_OSERR;
		}
		return EXIT_SUCCESS;
	}

	if (cwd != NULL) {
		(void) chdir(cwd);
		free(cwd);
	}

#ifdef ENABLE_CONSOLE
	/* AllocConsole() only works for Windows GUI applications. */
	if (AllocConsole())
		LogOpen("CONOUT$");
	else
		LogOpen("(standard error)");
#endif
	return serverMain();
}
