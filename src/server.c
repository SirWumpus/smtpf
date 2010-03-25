/*
 * server.c
 *
 * Copyright 2007, 2010 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "smtpf.h"

#include <limits.h>

#ifdef HAVE_SQLITE3_H
# include <sqlite3.h>
#endif

#include <com/snert/lib/sys/pid.h>
#include <com/snert/lib/sys/process.h>
#include <com/snert/lib/mail/spf.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/util/ProcTitle.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_server_min_threads[] =
  "Minimum number of server threads to keep alive to handle new requests.\n"
"#"
;

static const char usage_server_max_threads[] =
  "Maximum number of server threads possible to handle new requests.\n"
"# Specify zero to allow upto the system thread limit.\n"
"#"
;

static const char usage_server_new_threads[] =
  "Number of new server threads to create when all the existing threads\n"
"# are in use.\n"
"#"
;

static const char usage_server_accept_timeout[] =
  "Time in seconds the server thread waits for a new connections.\n"
"#"
;

Option optServerMaxThreads	= { "server-max-threads",	"0",		usage_server_max_threads };
Option optServerMinThreads	= { "server-min-threads",	"10",		usage_server_min_threads };
Option optServerNewThreads	= { "server-new-threads",	"10",		usage_server_new_threads };
Option optServerAcceptTimeout	= { "smtp-accept-timeout",	"10",		usage_server_accept_timeout };

int pid_fd;
Server server;
ServerSignals signals;
pthread_mutex_t title_mutex;

/***********************************************************************
 *** Mutex Wrappers
 ***********************************************************************/

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
mutex_destroy(pthread_mutex_t *mutexp)
{
	(void) pthread_mutex_trylock(mutexp);
	(void) pthread_mutex_unlock(mutexp);
	(void) pthread_mutex_destroy(mutexp);
}
#endif

int
mutex_lock(session_id id, const char *name, unsigned long line, pthread_mutex_t *mutexp)
{
	int rc;
	TIMER_DECLARE(mark);

	if (verb_mutex.option.value) {
		TIMER_START(mark);
		syslog(LOG_DEBUG, LOG_MSG(584) "mutex locking %s(%lu) ...", id, name, line);
	}

	rc = pthread_mutex_lock(mutexp);

	if (verb_mutex.option.value) {
		TIMER_DIFF(mark);
		syslog(
			LOG_DEBUG, LOG_MSG(585) "mutex locked %s(%lu) rc=%d errno=%d time=" TIMER_FORMAT,
			id, name, line, rc, errno, TIMER_FORMAT_ARG(diff_mark)
		);
	}

	return rc;
}

int
mutex_trylock(session_id id, const char *name, unsigned long line, pthread_mutex_t *mutexp)
{
	int rc;
	TIMER_DECLARE(mark);

	if (verb_mutex.option.value) {
		TIMER_START(mark);
		syslog(LOG_DEBUG, LOG_MSG(586) "mutex locking %s(%lu) ...", id, name, line);
	}

	rc = pthread_mutex_trylock(mutexp);

	if (verb_mutex.option.value) {
		TIMER_DIFF(mark);
		syslog(
			LOG_DEBUG, LOG_MSG(587) "mutex %s %s(%lu) rc=%d errno=%d time=" TIMER_FORMAT,
			id, rc == 0 ? "locked" : "busy", name, line, rc, errno, TIMER_FORMAT_ARG(diff_mark)
		);
	}

	return rc;
}

int
mutex_unlock(session_id id, const char *name, unsigned long line, pthread_mutex_t *mutexp)
{
	int rc;
	TIMER_DECLARE(mark);

	if (verb_mutex.option.value) {
		TIMER_START(mark);
		syslog(LOG_DEBUG, LOG_MSG(588) "mutex unlocking %s(%lu) ...", id, name, line);
	}

	rc = pthread_mutex_unlock(mutexp);

	if (verb_mutex.option.value) {
		TIMER_DIFF(mark);
		syslog(
			LOG_DEBUG, LOG_MSG(589) "mutex unlocked %s(%lu) rc=%d errno=%d time=" TIMER_FORMAT,
			id, name, line, rc, errno, TIMER_FORMAT_ARG(diff_mark)
		);
	}

	return rc;
}

/***********************************************************************
 ***
 ***********************************************************************/

int
serverOptn0(Session *null, va_list ignore)
{
#ifdef ENABLE_PDQ
	pdqMaxTimeout(optDnsMaxTimeout.value);
	pdqSetRoundRobin(optDnsRoundRobin.value);
#endif
	optServerAcceptTimeout.value = strtol(optServerAcceptTimeout.string, NULL, 10) * 1000;
	optSmtpCommandTimeout.value = strtol(optSmtpCommandTimeout.string, NULL, 10) * 1000;
	optSmtpConnectTimeout.value = strtol(optSmtpConnectTimeout.string, NULL, 10) * 1000;
	optSmtpCommandTimeoutBlack.value = strtol(optSmtpCommandTimeoutBlack.string, NULL, 10) * 1000;
	if (optSmtpCommandTimeoutBlack.value  < 0 || optSmtpCommandTimeout.value < optSmtpCommandTimeoutBlack.value)
		optSmtpCommandTimeoutBlack.value = optSmtpCommandTimeout.value;
	optSmtpDataLineTimeout.value = strtol(optSmtpDataLineTimeout.string, NULL, 10) * 1000;
	optSmtpDotTimeout.value = strtol(optSmtpDotTimeout.string, NULL, 10) * 1000;

        optTestPauseAfterDot.value = strtol(optTestPauseAfterDot.string, NULL, 10);

	if (optRFC2821AngleBrackets.value)
		parse_path_flags |= STRICT_SYNTAX;
	if (optRFC2821LocalLength.value)
		parse_path_flags |= STRICT_LOCAL_LENGTH;
	if (optRFC2821DomainLength.value)
		parse_path_flags |= STRICT_DOMAIN_LENGTH;
	if (optRFC2821LiteralPlus.value)
		parse_path_flags |= STRICT_LITERAL_PLUS;

	if (optServerMinThreads.value < 1)
		optServerMinThreads.value = 1;
	if (optServerNewThreads.value < 1)
		optServerNewThreads.value = 1;
	if (optServerMaxThreads.value < 1)
		optServerMaxThreads.value = optTestMode.value ? 1 : LONG_MAX;

	return SMTPF_CONTINUE;
}

#ifdef ENABLE_LINT
int
serverOptn1(Session *null, va_list ignore)
{
	if (optLint.value && lickeyLint.value != 1) {
		syslog(LOG_ERR, LOG_NUM(813) "lint option requires special license key");
/*{LOG
The <a href="summary.html#opt_lint">lint</a> option requires a special license key
offered only for special partnership deals and is not generally available to customers.
}*/
		optLint.value = 0;
	}

	return SMTPF_CONTINUE;
}
#endif

void
_atExitCleanUp(void)
{
	filterFini();
	statsFini();
	cacheFini();
	(void) pthreadMutexDestroy(&title_mutex);

	VectorDestroy(reject_msg);
	VectorDestroy(welcome_msg);

	syslog(LOG_INFO, LOG_NUM(732) "terminated");
	/* Must come after last syslog call, since on Linux it will
	 * free the duplicated environment created by ProcTitleInit.
	 * syslog tries to get time zone information from the environment.
	 */
	ProcTitleFini();
	closelog();
}

static int
server_init(Server *server)
{
	(void) serverOptn0(NULL, NULL);

	/* Reparse the verbose option, since there may have been some
	 * late additions to the verbose list made in filterInit().
	 */
	verboseParse(optVerbose.string);

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}

	/* Be sure to specify these global SQLite settings before
	 * opening any databases.
	 */
	sqlite3_enable_shared_cache(1);
	sqlite3_soft_heap_limit(SQLITE_SOFT_HEAP_LIMIT);

	/* The stats must be loaded after all the filters have had
	 * a chance to register their stat variables.
	 */
	cacheInit();
	statsInit();
	filterInit();
	statsLoad();
	welcomeInit();

	(void) pthread_mutex_init(&title_mutex, NULL);

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(serverAtForkPrepare, serverAtForkParent, serverAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
	if (tldInit()) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		return -1;
	}

	srand(time(NULL) ^ getpid());

	/* REMOVAL OF THIS CODE IS IN VIOLATION OF THE TERMS OF
	 * THE SOFTWARE LICENSE AS AGREED TO BY DOWNLOADING OR
	 * INSTALLING THIS SOFTWARE.
	 */
	lickeyInit(server->interfaces);
#ifdef ENABLE_LINT
	(void) serverOptn1(NULL, NULL);
#endif
	/* Needs to check and set the license route counters after
	 * lickeyInit() in main(), routeInit(), and statInit().
	 */
	lickeyRouteCount();
	if (optTestLickey.value)
		exit(0);

	cacheGcStart();
	latencyInit(mcc);

	/* We have to create the .pid file after we become a daemon process
	 * but before we change process ownership, particularly if we intend
	 * to create a file in /var/run, which is owned and writeable by root.
	 */
	if (*optRunPidFile.string != '\0') {
		if (pidSave(optRunPidFile.string)) {
			syslog(LOG_ERR, LOG_NUM(598) "create \"%s\" failed: %s (%d)", optRunPidFile.string, strerror(errno), errno);
/*{NEXT}*/
			exit(1);
		}

		if ((pid_fd = pidLock(optRunPidFile.string)) < 0) {
			syslog(LOG_ERR, LOG_NUM(905) "lock \"%s\" failed: %s (%d)", optRunPidFile.string, strerror(errno), errno);
/*{LOG
See <a href="summary.html#opt_run_pid_file">run-pid-file</a> option.
}*/
			exit(1);
		}

		if (pathSetPermsByName(optRunPidFile.string, optRunUser.string, optRunGroup.string, 0664))
			exit(1);
	}

	if (processDropPrivilages(optRunUser.string, optRunGroup.string, optRunWorkDir.string, optRunJailed.value))
		exit(1);
	(void) processDumpCore(1);
/*{LOG
The SMTP service is ready to accept connections.
}*/
	return 0;
}

int
session_free(ServerSession *session)
{
	Session *sess;

	if (session != NULL) {
		sess = session->data;
		free(sess->last_reply);
		free(session->data);
	}

	return 0;
}

int
session_create(ServerSession *session)
{
	Session *sess;

	if ((sess = malloc(sizeof (*sess) + filter_context_size)) == NULL)
		return -1;

	session->data = sess;
	sess->session = session;
	sess->last_reply = NULL;

	sess->client.octets = 0;
	sess->client.name[0] = '\0';
	sess->client.helo[0] = '\0';
	sess->client.sender_domain[0] = '\0';
	sess->client.command_pause = 0;
	sess->client.auth_count = 0;
	sess->client.mail_count = 0;
	sess->client.forward_count = 0;
	sess->client.reject_count = 0;
	sess->client.reject_delay = SMTP_REJECT_DELAY;

	sess->msg.eoh = 0;
	sess->msg.mail = NULL;
	sess->msg.fwds = NULL;
	sess->msg.length = 0;
	sess->msg.rcpt_count = 0;
	sess->msg.reject[0] = '\0';
	sess->msg.count = (int) RAND_MSG_COUNT;
	sess->msg.fwd_to_queue = NULL;
	sess->msg.smtpf_code = SMTPF_UNKNOWN;
	sess->client.fwd_to_queue = NULL;

	MAIL_CLEAR_ALL(sess);
	RCPT_CLEAR_ALL(sess);

	/* This should be an SPF filter context. */
	sess->client.spf_helo = SPF_NONE;
	sess->client.spf_helo_error = "";
	sess->msg.spf_mail = SPF_NONE;
	sess->msg.spf_mail_error = "";

	sess->state = state0;
	sess->helo_state = NULL;
	sess->max_concurrent = -1;

	sess->smtp_code = 0;
#ifdef OLD_SMTP_ERROR_CODES
	sess->smtp_error = 0;
#endif

	sess->msg.id[0] = '\0';
	sess->msg.headers = NULL;

	return 0;
}

int
session_accept(ServerSession *session)
{
	Session *data = session->data;

	data->start = time(NULL);
	data->last_mark = data->start;
	data->last_test = data->start;

	if (session->client == NULL) {
		syslog(LOG_ERR, log_internal, SESSION_ID_ZERO, FILE_LINENO, "session_accept", strerror(errno), errno);
		return -1;
	}

	socketFdSetKeepAlive(socketGetFd(session->client), 1, SMTP_COMMAND_TO, 60, 3);
	socketSetTimeout(session->client, optSmtpCommandTimeout.value);
	(void) fileSetCloseOnExec(socketGetFd(session->client), 1);
	(void) socketSetLinger(session->client, 0);
	(void) socketSetNonBlocking(session->client, 1);

	switch (filterRun(data, filter_accept_table)) {
	case SMTPF_DROP:
	case SMTPF_REJECT:
	case SMTPF_TEMPFAIL:
		(void) replySend(data);
		/*@fallthrough@*/

	case SMTPF_DELAY|SMTPF_DROP:
	case SMTPF_DELAY|SMTPF_REJECT:
	case SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP:
	case SMTPF_DELAY|SMTPF_SESSION|SMTPF_REJECT:
		filterRun(data, filter_close_table);
		return -1;
	default:
		break;
	}

	return 0;
}

extern void sessionProcess(Session *);

void
serverNumbers(Server *server, unsigned numbers[2])
{
	PTHREAD_MUTEX_LOCK(&server->workers.mutex);
	numbers[0] = server->workers.length;
	numbers[1] = server->workers_active;
	PTHREAD_MUTEX_UNLOCK(&server->workers.mutex);
}

int
session_process(ServerSession *session)
{
	unsigned numbers[2];
	Session *sess = session->data;

	serverNumbers(session->server, numbers);
	statsSetHighWater(&stat_high_connections, numbers[1], verb_info.option.value);

	PTHREAD_MUTEX_LOCK(&title_mutex);
	ProcTitleSet(
#if !defined(__OpenBSD__) && !defined(__FreeBSD__)
		_NAME " "
#endif
		"th=%u cn=%u cs=%lu",
		numbers[0], numbers[1], connections_per_second
	);
	PTHREAD_MUTEX_UNLOCK(&title_mutex);

	/* Server model transition code... */
	sess->client.socket = session->client;

	memcpy(sess->client.ipv6, session->ipv6, sizeof (sess->client.ipv6));
	TextCopy(sess->client.addr, sizeof (sess->client.addr), session->address);

	sess->access_map = ((Worker *) session->worker->data)->access_map;
	sess->route_map = ((Worker *) session->worker->data)->route_map;
	sess->pdq = ((Worker *) session->worker->data)->pdq;

	filterClearAllContexts(sess);

	CLIENT_CLEAR_ALL(sess);
	CLIENT_SET(sess, CLIENT_NO_PTR);
	MSG_CLEAR_ALL(sess);

	if (isReservedIPv6(session->ipv6, IS_IP_LOCAL)) {
		CLIENT_SET(sess, CLIENT_IS_LOCALHOST);
		statsCount(&stat_connect_localhost);
	}
	if (isReservedIPv6(session->ipv6, IS_IP_LAN)) {
		CLIENT_SET(sess, CLIENT_IS_LAN);
		statsCount(&stat_connect_lan);
	}
	if (routeKnownClientAddr(sess)) {
		CLIENT_SET(sess, CLIENT_IS_RELAY);
		statsCount(&stat_connect_relay);
	}

	statsCount(&stat_connect_count);

	sessionProcess(sess);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(594) "client [%s] close", LOG_ARGS(sess), session->address);

	if (sess->state != NULL)
		(void) statsCount(&stat_connect_dropped);

	filterRun(sess, filter_close_table);
	VectorDestroy(sess->msg.headers);

	serverNumbers(session->server, numbers);
	PTHREAD_MUTEX_LOCK(&title_mutex);
	ProcTitleSet(
#if !defined(__OpenBSD__) && !defined(__FreeBSD__)
		_NAME " "
#endif
		"th=%u cn=%u cs=%lu",
		numbers[0], numbers[1], connections_per_second
	);
	PTHREAD_MUTEX_UNLOCK(&title_mutex);

	if (1 < session->server->debug.valgrind) {
		VALGRIND_PRINTF("session finish\n");
		VALGRIND_DO_LEAK_CHECK;
	}

	return 0;
}

int
worker_free(ServerWorker *worker)
{
	Worker *data;

	if (worker != NULL && worker->data != NULL) {
		data = worker->data;
		worker->data = NULL;
		pdqClose(data->pdq);
		smdbClose(data->route_map);
		smdbClose(data->access_map);
		free(data);
	}

	return 0;
}

int
worker_create(ServerWorker *worker)
{
	Worker *data;

	if ((data = calloc(1, sizeof (*data))) == NULL)
		goto error0;

	worker->data = data;

	if ((data->pdq = pdqOpen()) == NULL)
		goto error1;

	if ((data->route_map = smdbOpen(route_map_path, 1)) == NULL)
		goto error1;

	if ((data->access_map = smdbOpen(access_map_path, 1)) == NULL)
		goto error1;

	return 0;
error1:
	worker_free(worker);
error0:
	return -1;
}

int
serverMain(void)
{
	int rc, signal;

	rc = EXIT_FAILURE;

	syslog(LOG_INFO, LOG_NUM(604) "" _NAME " " _VERSION " " _COPYRIGHT);
	syslog(LOG_INFO, LOG_NUM(605) "LibSnert %s %s", LIBSNERT_VERSION, LIBSNERT_COPYRIGHT);
	syslog(LOG_INFO, LOG_NUM(606) "SQLite %s Public Domain by D. Richard Hipp", sqlite3_libversion());
	syslog(LOG_INFO, LOG_NUM(904) "Built on %s", smtpf_built);
/*{LOG
Version and copyright notices.
}*/
	if (pthreadInit())
		goto error0;

	if (serverSignalsInit(&signals, _NAME))
		goto error1;

	if (serverInit(&server, optInterfaces.string, SMTP_PORT))
		goto error2;

	if (server_init(&server))
		goto error3;

	server.hook.worker_create = worker_create;
	server.hook.worker_free = worker_free;
	server.hook.session_create = session_create;
	server.hook.session_accept = session_accept;
	server.hook.session_process = session_process;
	server.hook.session_free = session_free;

	serverSetStackSize(&server, THREAD_STACK_SIZE);

	if (serverStart(&server))
		goto error3;

	syslog(LOG_INFO, LOG_NUM(599) "ready");
	signal = serverSignalsLoop(&signals);
	serverStop(&server, signal == SIGQUIT);
	rc = EXIT_SUCCESS;
error3:
	serverFini(&server);
error2:
	serverSignalsFini(&signals);
error1:
	pthreadFini();
error0:
	return rc;
}

void
serverPrintVersion(void)
{
	printf(_NAME " " _VERSION " " _COPYRIGHT "\n");
	printf(LIBSNERT_STRING " " _COPYRIGHT "\n");
	printf("SQLite %s Public Domain by D. Richard Hipp\n", sqlite3_libversion());
	printf("Built on %s\n", smtpf_built);
}

void
serverPrintInfo(void)
{
#ifdef _NAME
	printVar(0, "SMTPF_NAME", _NAME);
#endif
#ifdef _VERSION
	printVar(0, "SMTPF_VERSION", _VERSION);
#endif
#ifdef _COPYRIGHT
	printVar(0, "SMTPF_COPYRIGHT", _COPYRIGHT);
#endif
	printVar(0, "SMTPF_BUILT", smtpf_built);
#ifdef _CONFIGURE
	printVar(LINE_WRAP, "SMTPF_CONFIGURE", _CONFIGURE);
#endif
#ifdef LIBSNERT_VERSION
	printVar(0, "LIBSNERT_VERSION", LIBSNERT_VERSION);
#endif
#ifdef LIBSNERT_BUILD_HOST
	printVar(LINE_WRAP, "LIBSNERT_BUILD_HOST", LIBSNERT_BUILD_HOST);
#endif
#ifdef LIBSNERT_CONFIGURE
	printVar(LINE_WRAP, "LIBSNERT_CONFIGURE", LIBSNERT_CONFIGURE);
#endif
#ifdef SQLITE_VERSION
	printVar(0, "SQLITE3_VERSION", SQLITE_VERSION);
#endif
#ifdef _CFLAGS
	printVar(LINE_WRAP, "CFLAGS", _CFLAGS);
#endif
#ifdef _LDFLAGS
	printVar(LINE_WRAP, "LDFLAGS", _LDFLAGS);
#endif
#ifdef _LIBS
	printVar(LINE_WRAP, "LIBS", _LIBS);
#endif
}
