/*
 * unix.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
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
 *** Signals
 ***********************************************************************/

void
signalThreadExit(int signum)
{
	pthread_exit(NULL);
}

void
signalKillAll(int signal)
{
	Session *conn, *next;

	(void) mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	for (conn = server.head; conn != NULL; conn = next) {
		next = conn->next;
#ifdef USE_PTHREAD_CANCEL
		pthread_cancel(conn->thread);
#else
		pthread_kill(conn->thread, signal);
#endif
	}

	(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);
}

#if defined(HAVE_PTHREAD_SIGMASK)

static sigset_t signal_set;

#ifdef ENABLE_SLOW_QUIT
static pthread_mutex_t slow_quit_mutex;
#endif

void *
signalThread(void *data)
{
	int signal;
	Server *srv = (Server *) data;

	while (srv->running) {
		signal = 0;
		if (sigwait(&signal_set, &signal))
			continue;

		switch (signal) {
		case SIGQUIT:
#ifdef ENABLE_SLOW_QUIT
			srv->running = 0;

			if (pthread_mutex_lock(&slow_quit_mutex) == 0) {
				while (srv->head != NULL) {
					syslog(LOG_INFO, LOG_NUM(722) "signal %d, slow quit cn=%u", signal, srv->connections);
					if (pthread_cond_wait(&slow_quit_cv, &slow_quit_mutex))
						break;
				}
				(void) pthread_mutex_unlock(&slow_quit_mutex);
			}
			/*@fallthrough@*/
#endif
#if defined(__unix__)
		case SIGHUP:
			if (signal == SIGHUP)
				internal_restart = 1;
			/*@fallthrough@*/
#endif
		case SIGINT:
		case SIGTERM:
			syslog(LOG_INFO, LOG_NUM(722) "signal %d, stopping sessions, cn=%u", signal, srv->connections);
/*{NEXT}*/
			/* Flag server shutdown. */
			srv->running = 0;
			signalKillAll(SIGUSR1);

			syslog(LOG_INFO, LOG_NUM(723) "signal %d, terminating process", signal);
/*{LOG
@PACKAGE_NAME@ is going through the process of shutting down.
}*/
			break;

#if defined(__unix__)
# ifdef SIGALRM
		case SIGALRM:
# endif
# ifdef SIGXCPU
		case SIGXCPU:
# endif
# ifdef SIGXFSZ
		case SIGXFSZ:
# endif
# ifdef SIGVTALRM
		case SIGVTALRM:
# endif
# ifdef SIGUSR1
		case SIGUSR1:
# endif
# ifdef SIGUSR2
		case SIGUSR2:
# endif
			syslog(LOG_INFO, LOG_NUM(724) "signal %d received, cn=%u", signal, srv->connections);
/*{LOG
A special signal not currently acted upon was received.
Normally this message should never be seen.
}*/
			break;
#endif
		}
	}

	return NULL;
}
#else

void
signalExit(int signum)
{
	syslog(LOG_INFO, LOG_NUM(725) "signal %d, terminating process", signum);
/*{LOG
@PACKAGE_NAME@ is going through the process of shutting down.
}*/
	exit(0);
}

#endif

/*
 * Set up a special thread to wait and act on SIGPIPE, SIGHUP, SIGINT,
 * SIGQUIT, and SIGTERM. The main server thread and all other child
 * threads will ignore them. This way we can do more interesting
 * things than are possible in a typical signal handler.
 */
void
signalInit(Server *ignore)
{
#ifdef SIGPIPE
# ifdef HAVE_SIGACTION
{
	struct sigaction signal_ignore;

	signal_ignore.sa_flags = 0;
	signal_ignore.sa_handler = SIG_IGN;
	(void) sigemptyset(&signal_ignore.sa_mask);

	if (sigaction(SIGPIPE, &signal_ignore, NULL)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "SIGPIPE", strerror(errno), errno);
		exit(1);
	}
}
# else
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "SIGPIPE", strerror(errno), errno);
		exit(1);
	}
# endif
#endif
#if defined(HAVE_PTHREAD_SIGMASK)
        (void) sigemptyset(&signal_set);
# ifdef SIGHUP
        (void) sigaddset(&signal_set, SIGHUP);
# endif
# ifdef SIGINT
        (void) sigaddset(&signal_set, SIGINT);
# endif
# ifdef SIGQUIT
	(void) sigaddset(&signal_set, SIGQUIT);
# endif
# ifdef SIGTERM
	(void) sigaddset(&signal_set, SIGTERM);
# endif
# ifdef SIGALRM
	(void) sigaddset(&signal_set, SIGALRM);
# endif
# ifdef SIGXCPU
	(void) sigaddset(&signal_set, SIGXCPU);
# endif
# ifdef SIGXFSZ
	(void) sigaddset(&signal_set, SIGXFSZ);
# endif
# ifdef SIGVTALRM
	(void) sigaddset(&signal_set, SIGVTALRM);
# endif
# ifdef DISABLE_THREAD_CONTROL
#  ifdef SIGUSR1
	(void) sigaddset(&signal_set, SIGUSR1);
#  endif
#  ifdef SIGUSR2
	(void) sigaddset(&signal_set, SIGUSR2);
#  endif
# endif
        if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}

# ifndef DISABLE_THREAD_CONTROL
#  ifdef SIGUSR1
	if (signal(SIGUSR1, signalThreadExit) == SIG_ERR) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "SIGUSR1", strerror(errno), errno);
		exit(1);
	}
#  endif
# endif
#else
	if (signal(SIGQUIT, signalExit) == SIG_ERR) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "SIGQUIT", strerror(errno), errno);
		exit(1);
	}
	if (signal(SIGTERM, signalExit) == SIG_ERR) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "SIGTERM", strerror(errno), errno);
		exit(1);
	}
	if (signal(SIGINT, signalExit) == SIG_ERR) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "SIGINT", strerror(errno), errno);
		exit(1);
	}
#endif
#ifdef ENABLE_SLOW_QUIT
	if (pthread_cond_init(&slow_quit_cv, NULL)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
	if (pthread_mutex_init(&slow_quit_mutex, NULL)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
}

void
signalFini(Server *ignore)
{
#ifdef SIGPIPE
# ifdef HAVE_SIGACTION
{
	struct sigaction signal_default;

	signal_default.sa_flags = 0;
	signal_default.sa_handler = SIG_DFL;
	(void) sigemptyset(&signal_default.sa_mask);

	(void) sigaction(SIGPIPE, &signal_default, NULL);
}
# else
	(void) signal(SIGPIPE, SIG_DFL);
# endif
#endif
#if defined(HAVE_PTHREAD_SIGMASK)
	(void) pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL);
#else
# ifdef SIGUSR1
	(void) signal(SIGUSR1, SIG_DFL);
# endif
# ifdef SIGQUIT
	(void) signal(SIGQUIT, SIG_DFL);
# endif
# ifdef SIGTERM
	(void) signal(SIGTERM, SIG_DFL);
# endif
# ifdef SIGINT
	(void) signal(SIGINT, SIG_DFL);
# endif
#endif
#ifdef ENABLE_SLOW_QUIT
	(void) pthread_mutex_destroy(&slow_quit_mutex);
	(void) pthread_cond_destroy(&slow_quit_cv);
#endif
}

/***********************************************************************
 *** Unix Daemon
 ***********************************************************************/

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

int
chownByName(const char *path, const char *user, const char *group)
{
	struct group *gr;
	struct passwd *pw;

	if ((pw = getpwnam(user)) == NULL) {
		syslog(LOG_ERR, LOG_NUM(727) "user \"%s\" not found", user);
/*{NEXT}*/
		return -1;
	}

	if ((gr = getgrnam(group)) == NULL) {
		syslog(LOG_ERR, LOG_NUM(728) "group \"%s\" not found", group);
/*{NEXT}*/
		return -1;
	}

	if (chown(path, pw->pw_uid, gr->gr_gid) && errno != ENOENT) {
		syslog(LOG_ERR, LOG_NUM(729) "chown(\"%s\", \"%s\", \"%s\") error: %s (%d)", path, user, group, strerror(errno), errno);
/*{LOG
Failure to set user and group ownership on a specific file or directory.
}*/
		return -1;
	}

	return 0;
}

int
chmodByName(const char *path, mode_t mode)
{
	if (chmod(path, mode)) {
		syslog(LOG_ERR, LOG_NUM(730) "chmod(\"%s\", %o) error: %s (%d)", path, mode, strerror(errno), errno);
/*{LOG
Failure to set file permission on a specific file or directory.
}*/
		return -1;
	}

	return 0;
}

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

	syslog(LOG_INFO, LOG_NUM(732) "terminated");
	_atExitCleanUp();
}

static void
atExitCleanUpOptions(void)
{
	optionFree(optTable0, optTable, lickeyOptTable, NULL);
}

int
main(int argc, char **argv)
{
	int argi;

#ifdef NOT_YET
restart_main:
#endif

	filterRegister();
        ProcTitleInit(argc, argv);

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
	(void) umask(0007);

	LogSetProgramName(_NAME);

	if (optDaemon.value)
		openlog(_NAME, LOG_PID|LOG_NDELAY, LOG_MAIL);
	else
		LogOpen("(standard error)");

	if (optRestart.string != NULL || optRestartIf.string != NULL) {
		if (pidKill(optRunPidFile.string, SIGTERM) && optRestartIf.string != NULL) {
			syslog(LOG_ERR, LOG_NUM(733) "no previous instance running: %s (%d)", strerror(errno), errno);
/*{LOG
Generated when <a href="summary.html#opt_restart_if">restart-if</a> action was issued
and no previous instance could be found to restart, in which case the process will
not start.
}*/
			exit(1);
		}
		sleep(2);
	}

#ifdef MOVED
/* See serverInit. */
	if (getMyDetails()) {
		syslog(LOG_ERR, LOG_NUM(734) "host info error: %s (%d)", strerror(errno), errno);
/*{LOG
A fatal initialisation error while trying to obtain the host and network interface details
of the machine @PACKAGE_NAME@ is running on, such as host name and IP address.
}*/
		exit(1);
	}

	/* REMOVAL OF THIS CODE IS IN VIOLATION OF THE TERMS OF
	 * THE SOFTWARE LICENSE AS AGREED TO BY DOWNLOADING OR
	 * INSTALLING THIS SOFTWARE.
	 */
	lickeyInit();
	if (optTestLickey.value)
		exit(0);
#else
	if (optTestLickey.value)
		optDaemon.value = 0;
#endif
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

		/* Make sure we release the standard files to the current
		 * pseudo terminal. Failure to do so means scripts or
		 * terminals don't go away until the smtpf daemon exits.
		 */
		(void) freopen("/dev/null", "r", stdin);
		(void) freopen("/dev/null", "a", stdout);
#ifndef DEBUG_MALLOC_THREAD_REPORT
		(void) freopen("/dev/null", "a", stderr);
#endif
	}

	if (pthread_attr_init(&thread_attr)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#if defined(HAVE_PTHREAD_ATTR_SETSCOPE)
	(void) pthread_attr_setscope(&thread_attr, PTHREAD_SCOPE_SYSTEM);
#endif
#if defined(HAVE_PTHREAD_ATTR_SETSTACKSIZE)
	(void) pthread_attr_setstacksize(&thread_attr, THREAD_STACK_SIZE);
#endif
#if defined(HAVE_SIGALTSTACK) && !defined(__OpenBSD__)
	initAlternateSignalStack();
#endif

	if (verb_trace.option.value) {
		syslog(LOG_DEBUG, LOG_NUM(737) "process limits now");
		rlimits();
	}
# if defined(RLIMIT_NOFILE)
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
	if (FD_OVERHEAD < optRunOpenFileLimit.value) {
		struct rlimit limit;

		if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
			limit.rlim_cur = (rlim_t) optRunOpenFileLimit.value;
			if (limit.rlim_max < (rlim_t) optRunOpenFileLimit.value)
				limit.rlim_max = limit.rlim_cur;

			(void) setrlimit(RLIMIT_NOFILE, &limit);
		}
	}

	if (verb_trace.option.value) {
		syslog(LOG_DEBUG, LOG_NUM(739) "process limits updated");
		rlimits();
	}
# endif

	serverMain();

#ifdef NOT_YET
	if (internal_restart) {
		/* Simulate the behaviour of exit() to clean up memory. */
		_atExitCleanUp();
		atExitCleanUpOptions();
		internal_restart = 0;
		goto restart_main;
	}
#endif
	return 0;
}
