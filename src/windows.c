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

#include <com/snert/lib/io/Dns.h>
#include <com/snert/lib/sys/pthread.h>
#include <com/snert/lib/sys/pid.h>
#include <com/snert/lib/sys/Time.h>
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

#define QUIT_EVENT_NAME 	"Global\\BarricadeMX-quit"

static HANDLE signalThreadEvent;

#ifdef ENABLE_OPTION_QUIT
/* Cygwin/Mingw do not define ConvertStringSecurityDescriptorToSecurityDescriptor().
 * This would allow for ./smtpf -quit by an admin. user. The current alternative is
 * to use the Windows service console or "net start smtp" and "net stop smtpf".
 */

static int
createMyDACL(SECURITY_ATTRIBUTES *sa)
{
	TCHAR * szSD =
	TEXT("D:")			/* Discretionary ACL */
	TEXT("(OD;OICI;GA;;;BG)")     	/* Deny access to built-in guests */
	TEXT("(OD;OICI;GA;;;AN)")     	/* Deny access to anonymous logon */
#ifdef ALLOW_AUTH_USER
	TEXT("(OA;OICI;GRGWGX;;;AU)") 	/* Allow read/write/execute auth. users */
#endif
	TEXT("(OA;OICI;GA;;;BA)");    	/* Allow full control to administrators. */

	if (sa == NULL)
		return 0;

	return ConvertStringSecurityDescriptorToSecurityDescriptor(
		szSD, SDDL_REVISION_1, &sa->lpSecurityDescriptor, NULL
	);
}
#endif

void
signalInit(Server *ignore)
{
#ifdef ENABLE_OPTION_QUIT
	SECURITY_ATTRIBUTES sa;

	sa.bInheritHandle = 0;
	sa.nLength = sizeof (sa);

	if (!createMyDACL(&sa)) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(796) "cannot create secuirty descriptor");
		exit(1);
	}
	signalThreadEvent = CreateEvent(&sa, 0, 0, QUIT_EVENT_NAME);
	LocalFree(sa.lpSecurityDescriptor);
#else
	signalThreadEvent = CreateEvent(NULL, 0, 0, QUIT_EVENT_NAME);
#endif
	if (signalThreadEvent == NULL) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(797) "cannot create Event object");
		exit(1);
	}
}

void
signalFini(Server *ignore)
{
	CloseHandle(signalThreadEvent);
}

void
signalKillAll(int signal)
{
	Session *conn;

	(void) mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	for (conn = server.head; conn != NULL; conn = conn->next) {
		/* Originally I had planned to just do an on_error longjmp,
		 * but realised that can only be done within the thread's
		 * context.
		 *
		 * So instead we set a kill_event, which each thread polls
		 * before reading the next client command.
		 */
		SetEvent(conn->kill_event);
	}

	(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);
}

/*
 * serverMain arrives here and we wait for a termination signal (event)
 * from either HandlerRoutine or ServiceStop.
 */
void *
signalThread(void *data)
{
	Server *srv = (Server *) data;

	while (WaitForSingleObject(signalThreadEvent, INFINITE) != WAIT_OBJECT_0)
		;

	syslog(LOG_INFO, LOG_NUM(798) "signal %d, stopping sessions, cn=%lu", SIGTERM, srv->connections);

	/* Flag server shutdown. */
	srv->running = 0;
	signalKillAll(SIGUSR1);

	syslog(LOG_INFO, LOG_NUM(799) "signal %d, terminating process", SIGTERM);

	return NULL;
}

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

/*
 * Called from a different thread.
 *
 * @return
 *	If the function handles the control signal, it should return TRUE.
 *	If it returns FALSE, the next handler function in the list of handlers
 *	for this process is used.
 */
BOOL WINAPI
HandlerRoutine(DWORD ctrl)
{
	switch (ctrl) {
	case CTRL_SHUTDOWN_EVENT:
		SetEvent(signalThreadEvent);
		return FALSE;

	case CTRL_LOGOFF_EVENT:
		return TRUE;

	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
		if (!optDaemon.value) {
			SetEvent(signalThreadEvent);
			return TRUE;
		}
	}

	return FALSE;
}

static SERVICE_STATUS_HANDLE ServiceStatus;

#ifdef OLD
/*
 * Called from a different thread.
 */
DWORD WINAPI
ServiceStop(LPVOID ignore)
{
	SERVICE_STATUS status;

	ReportLog(EVENTLOG_INFORMATION_TYPE, LOG_NUM(800) "stopping service " _NAME);

	/* Don't know where application is spinning, but if its
	 * important they should have registered one or more
	 * shutdown hooks. Begin normal exit sequence. We will
	 * end up in our ExitHandler() when the application has
	 * finished.
	 */
	SetEvent(signalThreadEvent);

	status.dwCheckPoint = 0;
	status.dwWaitHint = 2000;
	status.dwWin32ExitCode = NO_ERROR;
	status.dwServiceSpecificExitCode = 0;
	status.dwCurrentState = SERVICE_STOPPED;
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
	SetServiceStatus(ServiceStatus, &status);

	return 0;
}
#endif

/*
 * Called from within Service Control Manager distpatch thread.
 */
DWORD WINAPI
ServiceControl(DWORD code, DWORD eventType, LPVOID eventData, LPVOID userData)
{
#ifdef OLD
	HANDLE stopThread;
#else
	SERVICE_STATUS status;
#endif
	switch (code) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
#ifdef OLD
		/* Stop the service in another thread allows us to
		 * successful return to the Windows service manager
		 * and stop the service. Otherwise Windows ends up
		 * waiting for us to return from here, which would
		 * not happen since stopping the service terminates
		 * the program.
		 */
		stopThread = CreateThread(NULL, 4096, ServiceStop, NULL, 0, NULL);
		if (stopThread == NULL) {
			ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(801) "failed to stop %s service", _NAME);
			return GetLastError();
		}
#else
		/* Don't know where application is spinning, but if its
		 * important they should have registered one or more
		 * shutdown hooks. Begin normal exit sequence. We will
		 * end up in our ExitHandler() when the application has
		 * finished.
		 */
		SetEvent(signalThreadEvent);

		status.dwCheckPoint = 0;
		status.dwWaitHint = 2000;
		status.dwWin32ExitCode = NO_ERROR;
		status.dwServiceSpecificExitCode = 0;
		status.dwCurrentState = SERVICE_STOPPED;
		status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
		SetServiceStatus(ServiceStatus, &status);
#endif
		break;
	default:
		return ERROR_CALL_NOT_IMPLEMENTED;
	}

	return NO_ERROR;
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

VOID WINAPI
ServiceMain(DWORD argc, char **argv)
{
	SERVICE_STATUS status;

	/* Parse options passed from the Windows Service properties dialog. */
	options(argc, argv);

	ServiceStatus = RegisterServiceCtrlHandlerEx(_NAME, ServiceControl, NULL);
	if (ServiceStatus == 0) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(803) "failed to register %s service control handler: %lu", _NAME, GetLastError());
		exit(1);
	}

	(void) SetConsoleCtrlHandler(HandlerRoutine, TRUE);

	status.dwCheckPoint = 0;
	status.dwWaitHint = 2000;
	status.dwWin32ExitCode = NO_ERROR;
	status.dwServiceSpecificExitCode = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
	SetServiceStatus(ServiceStatus, &status);

	ReportLog(EVENTLOG_INFORMATION_TYPE, LOG_NUM(804) "service running");

	openlog(_NAME, LOG_PID, LOG_MAIL);
	setlogmask(LOG_UPTO(LOG_DEBUG));

	serverMain();
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
	static char default_root[256];
	char *cwd, *backslash, *install_path;

	SC_HANDLE manager;
	SC_HANDLE service;
	SERVICE_DESCRIPTION brief = { _BRIEF };
	SERVICE_TABLE_ENTRY dispatchTable[] = {
		{ _NAME, ServiceMain },
		{ NULL, NULL }
	};

	/* Get this now so we can use the event log. */
	ReportInit();

	/* Open the log file for use now by the service start or
	 * for the application -daemon. We have to open it again
	 * in ServiceMain for +daemon. All other initialisation
	 * should happen in serverMain.
	 */
	setlogmask(LOG_UPTO(LOG_DEBUG));
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
		return 1;
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

	/* Parse any command options. */
	options(argc, argv);

#ifdef ENABLE_OPTION_QUIT
	if (optQuit.string != NULL) {
		signalThreadEvent = OpenEvent(EVENT_MODIFY_STATE , 0, QUIT_EVENT_NAME);
		if (signalThreadEvent == NULL) {
			syslog(LOG_ERR, LOG_NUM(807) "%s quit error %d", _NAME, GetLastError());
			exit(1);
		}

		SetEvent(signalThreadEvent);
		exit(0);
	}
#else
	if (optQuit.string != NULL || optRestart.string != NULL || optRestartIf.string != NULL) {
		MessageBox(
			NULL,
			_BRIEF "\n"
			"\n"
			"The +quit, +restart, and +restart-if command\n"
			"options are currently not supported. Use:\n"
			"\n"
			"net start "_NAME "\n"
			"net stop "_NAME,
			_NAME, MB_OK|MB_ICONINFORMATION
		);
		exit(2);
	}
#endif

	/* Change to the executable's directory for default configuration file. */
	if (chdir(server_root)) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(808) "failed to change directory to '%s': %s (%d)\n", server_root, strerror(errno), errno);
		return 1;
	}

	manager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	if (manager == NULL) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(809) "cannot open service manager");
		return 1;
	}

	service = OpenService(manager, _NAME, SERVICE_ALL_ACCESS);

	if (optService.string != NULL) {
		if (service == NULL && *optService.string == '+') {
			if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
				service = CreateService(
					manager,			// SCManager database
					_NAME,				// name of service
					_DISPLAY,			// name to display
					SERVICE_ALL_ACCESS,		// desired access
					SERVICE_WIN32_OWN_PROCESS,	// service type
					SERVICE_AUTO_START,		// start type
					SERVICE_ERROR_NORMAL,		// error control type
					install_path,			// service's binary
					NULL,				// no load ordering group
					NULL,				// no tag identifier
					"Tcpip\0Tcpip6\0\0",		// dependencies
					NULL,				// LocalSystem account
					NULL				// no password
				);
				if (service == NULL) {
					MessageBox(NULL, "Failed to install service " _NAME, "Error", MB_OK|MB_ICONERROR);
					return 1;
				}

				(void) ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &brief);

				MessageBox(NULL, _BRIEF "\n" _NAME " service installed.", _NAME, MB_OK|MB_ICONINFORMATION);
				ReportLog(EVENTLOG_INFORMATION_TYPE, _BRIEF "\n" _NAME "service installed.");
			} else {
				MessageBox(NULL, "Failed to find service.", _NAME, MB_OK|MB_ICONERROR);
			}
		} else if (service != NULL && *optService.string == '-') {
			if (DeleteService(service) == 0) {
				MessageBox(NULL, "Failed to remove service " _NAME, "Error", MB_OK|MB_ICONERROR);
				return 1;
			}

			MessageBox(NULL, _BRIEF "\n" _NAME " service removed.", _NAME, MB_OK|MB_ICONINFORMATION);
			ReportLog(EVENTLOG_INFORMATION_TYPE, _BRIEF "\n" _NAME "service removed.");
		}

		return 0;
	}

	if (!optDaemon.value) {
		if (service != NULL)
			(void) CloseServiceHandle(service);
		if (manager != NULL)
			(void) CloseServiceHandle(manager);

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
		serverMain();
	} else if (service == NULL) {
		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(810) "Cannot start %s service. See -daemon and +service options.", _NAME);
	} else if (!StartServiceCtrlDispatcher(dispatchTable)) {
		if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			if (StartService(service, argc-1, (LPCTSTR *) argv+1))
				return 0;
		}

		ReportLog(EVENTLOG_ERROR_TYPE, LOG_NUM(811) "service %s start error", _NAME);
	}

	return 0;
}
