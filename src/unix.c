/*
 * unix.c
 *
 * Copyright 2006, 2010 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "smtpf.h"

#if defined(__linux__) && defined(HAVE_SYS_PRCTL_H)
# include <sys/prctl.h>
#endif
#if defined(__OpenBSD__) && defined(HAVE_SYS_SYSCTL_H)
# include <sys/param.h>
# include <sys/sysctl.h>
#endif
#if defined(HAVE_PWD_H)
# include <pwd.h>
#endif
#if defined(HAVE_GRP_H)
# include <grp.h>
#endif
#if defined(HAVE_SYS_STAT_H)
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#include <com/snert/lib/sys/pthread.h>
#include <com/snert/lib/sys/pid.h>
#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/util/ProcTitle.h>

extern void rlimits(void);

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

uid_t ruid;		/* Originally user at startup. */
uid_t euid;		/* Desired user. */
gid_t gid;		/* Desired group. */
int suid_dump_core;	/* Old value */
int internal_restart;

/***********************************************************************
 *** Unix Daemon
 ***********************************************************************/

#undef syslog

void
syslog(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (logFile == NULL)
		vsyslog(level, fmt, args);
	else
		LogV(level, fmt, args);
	va_end(args);
}

#if defined(HAVE_SIGALTSTACK) && !defined(__OpenBSD__)

# if defined(HAVE_STRUCT_SIGALTSTACK)
static struct sigaltstack alt_sig_stack;
# elif defined(__APPLE__)
static stack_t alt_sig_stack;
# endif

void
initAlternateSignalStack(void)
{
	alt_sig_stack.ss_flags = 0;
	alt_sig_stack.ss_size = SIGNAL_STACK_SIZE;

	if ((alt_sig_stack.ss_sp = malloc(alt_sig_stack.ss_size)) != NULL) {
		if (sigaltstack(&alt_sig_stack, NULL) != 0) {
   			syslog(LOG_ERR, LOG_NUM(726) "sigaltstack() failed, size=%lu: %s (%d)", (unsigned long) alt_sig_stack.ss_size, strerror(errno), errno);
/*{LOG
A fatal initialisation error occured while setting up signal handlers.
}*/
			free(alt_sig_stack.ss_sp);
		}
	}
}
#endif

void
atExitCleanUp(void)
{
	/* Avoid unlinking files of an already running instance.
	 * Its the running instance's responsibility to cleanup
	 * its files.
	 */
	if (0 < pid_fd && pidLoad(optRunPidFile.string) == getpid() && unlink(optRunPidFile.string)) {
		syslog(LOG_ERR, LOG_NUM(731) "unlink(\"%s\"): %s (%d)", optRunPidFile.string, strerror(errno), errno);
/*{LOG
During process termination, the process pid file could not be removed.
See <a href="summary.html#opt_run_pid_file">run-pid-file</a> option.
}*/
	}

	_atExitCleanUp();
}

static void
atExitCleanUpOptions(void)
{
	optionFree(optTable0, optTable, lickeyOptTable, NULL);
}

void
serverOptions(int argc, char **argv)
{
	int argi;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable0, NULL);
	argi = optionArrayL(argc, argv, optTable0, NULL);

	/* Parse the option file followed by the command line options again. */
	if (optFile0.string != NULL && *optFile0.string != '\0') {
		/* Do NOT reset this option. */
		optFile.initial = optFile0.string;

		optionInit(optTable, NULL);
		(void) optionFile(optFile0.string, optTable, NULL);
		(void) optionArrayL(argc, argv, optTable, NULL);
	}

	(void) atexit(atExitCleanUpOptions);

	verboseInit(optVerbose.string);

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

	/* Show them the funny farm. */
	if (optHelp.string != NULL) {
		/* help=filepath (compatibility with Windows)
		 * equivalent to +help >filepath
		 */
		if (optHelp.string[0] != '-' && optHelp.string[0] != '+')
			(void) freopen(optHelp.string, "w", stdout);
		optionUsageL(optTable, NULL);
		exit(2);
	}

	if (optQuit.string != NULL)
		exit(pidKill(optRunPidFile.string, SIGTERM) != 0);
#ifdef ENABLE_SLOW_QUIT
	else if (optSlowQuit.string != NULL)
		exit(pidKill(optRunPidFile.string, SIGQUIT) != 0);
#endif
	if (optTestLickey.value)
		optDaemon.value = 0;
}

int
main(int argc, char **argv)
{
#ifdef NOT_YET
restart_main:
#endif
	filterRegister();
	LogSetProgramName(_NAME);
        ProcTitleInit(argc, argv);
	serverOptions(argc, argv);

	(void) umask(0007);

	if (optDaemon.value)
		openlog(_NAME, LOG_PID|LOG_NDELAY, LOG_MAIL);
	else
		LogOpen("(standard error)");

	if (optRestart.string != NULL || optRestartIf.string != NULL) {
		int count;
		pid_t old_pid = pidLoad(optRunPidFile.string);
		long seconds = strtol(optRestart.string != NULL ? optRestart.string : optRestartIf.string, NULL, 10);

		if (0 < old_pid) {
			if (pidKill(optRunPidFile.string, SIGTERM) && optRestartIf.string != NULL) {
				syslog(LOG_ERR, LOG_NUM(733) "no previous instance running: %s (%d)", strerror(errno), errno);
/*{LOG
Generated when <a href="summary.html#opt_restart_if">restart-if</a> action was issued
and no previous instance could be found to restart, in which case the process will
not start.
}*/
				exit(1);
			}

			seconds = seconds < RESTART_DELAY ? RESTART_DELAY : seconds;

			for (count = 0; count < 10; count++) {
				errno = 0;
				(void) sleep(seconds);

				/*** Note that the pid that has been killed could be
				 *** quickly recycled by the time we get here resulting
				 *** in a different process being killed below.
				 ***/
				(void) kill(old_pid, 0);

				if (errno == ESRCH)
					break;
				syslog(LOG_ERR, LOG_NUM(968) "waiting for pid=%d", old_pid);
			}

			if (10 <= count) {
				syslog(LOG_ERR, LOG_NUM(969) "force kill of pid=%d", old_pid);
				kill(old_pid, SIGKILL);
				(void) sleep(5);
			}

			syslog(LOG_ERR, LOG_NUM(970) "previous instance pid=%d", old_pid);
		}
	}

	/* The default is to always start as a daemon or Windows service.
	 *
	 * The Unix way is typically to start as an application and use an
	 * option to switch to daemon mode, but Windows services are never
	 * started with command-line options. So in order to maintain a
	 * consistent command-line interface, the default is to start as a
	 * daemon and use an option to run as an application for testing.
	 */
	if (optDaemon.value) {
		pid_t ppid;

		if ((ppid = fork()) < 0) {

			syslog(LOG_ERR, LOG_NUM(735) "fork failed: %s (%d)", strerror(errno), errno);
/*{NEXT}*/
			exit(1);
		}

		if (ppid != 0)
			exit(0);

		if (setsid() == -1) {
			syslog(LOG_ERR, LOG_NUM(736) "set process group ID failed: %s (%d)", strerror(errno), errno);
/*{LOG
A fatal initialisation error while trying to become a <em>daemon</em>
(background) process by detatching from the controlling terminal.
The <a href="summary.html#opt_daemon">-daemon</a> option can be used to
run @PACKAGE_NAME@ as a foreground application.
}*/
			exit(1);
		}

#ifndef KEEP_STDIO_OPEN
		/* Make sure we release the standard files to the current
		 * pseudo terminal. Failure to do so means scripts or
		 * terminals don't go away until the smtpf daemon exits.
		 */
		(void) freopen("/dev/null", "r", stdin);
		(void) freopen("/dev/null", "a", stdout);
		(void) freopen("/dev/null", "a", stderr);
#endif
	}

#if defined(HAVE_SIGALTSTACK) && !defined(__OpenBSD__)
	initAlternateSignalStack();
#endif

	if (verb_trace.option.value) {
		syslog(LOG_DEBUG, LOG_NUM(737) "process limits now");
		rlimits();
	}
# if defined(RLIMIT_NOFILE)
{
	struct rlimit limit;

	if (0 < optServerMaxThreads.value
	&& optRunOpenFileLimit.value < optServerMaxThreads.value * FD_PER_THREAD) {
		/* Round up to the nearest K worth of file descriptors. */
		optRunOpenFileLimit.value = (optServerMaxThreads.value * FD_PER_THREAD + 1024) / 1024 * 1024;
		syslog(LOG_WARN, LOG_NUM(738) "%s increased to %ld", optRunOpenFileLimit.name, optRunOpenFileLimit.value);
	}

	/* Compute and/or set the upper limit on the number of
	 * open file descriptors the process can have. See server
	 * accept() loop.
	 */
	if (FD_OVERHEAD + FD_PER_THREAD < optRunOpenFileLimit.value) {
		if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
			limit.rlim_cur = (rlim_t) optRunOpenFileLimit.value;
			if (limit.rlim_max < (rlim_t) optRunOpenFileLimit.value)
				limit.rlim_max = limit.rlim_cur;

			(void) setrlimit(RLIMIT_NOFILE, &limit);
		}
	}

	/* Allow core dumps of unlimited size. */
	limit.rlim_cur = opt_run_save_core.value ? RLIM_INFINITY : 0;
	limit.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &limit);

	if (verb_trace.option.value) {
		syslog(LOG_DEBUG, LOG_NUM(739) "process limits updated");
		rlimits();
	}
}
# endif
	return serverMain();
}
