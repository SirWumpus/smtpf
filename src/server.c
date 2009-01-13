/*
 * server.c
 *
 * Copyright 2007, 2008 by Anthony Howe. All rights reserved.
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
  "Time in seconds a server thread waits for a new connection.\n"
"#"
;

Option optServerMaxThreads	= { "server-max-threads",	"0",		usage_server_max_threads };
Option optServerMinThreads	= { "server-min-threads",	"10",		usage_server_min_threads };
Option optServerNewThreads	= { "server-new-threads",	"10",		usage_server_new_threads };
Option optServerAcceptTimeout	= { "smtp-accept-timeout",	"10",		usage_server_accept_timeout };

int pid_fd;
Server server;
pthread_attr_t thread_attr;

#ifdef ENABLE_SLOW_QUIT
/* Moved from unix.c to here so that lickey CLI can be compiled and linked. */
pthread_cond_t slow_quit_cv;
#endif

/***********************************************************************
 *** Mutex Wrappers
 ***********************************************************************/

#ifdef HAVE_CLOCK_GETTIME
void
timespec_subtract(struct timespec *acc, struct timespec *b)
{
	if (acc->tv_nsec < b->tv_nsec) {
		acc->tv_nsec += 1000000000;
		acc->tv_sec--;
	}

	acc->tv_nsec -= b->tv_nsec;
	acc->tv_sec -= b->tv_sec;
}
#endif

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
 *** Session Data
 ***********************************************************************/

static void
serverCheckThreadPool(Session *session)
{
	long i;
	pthread_t thread;
	TIMER_DECLARE(mark);

	if (verb_timers.option.value)
		TIMER_START(mark);
	(void) mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	server.connections++;
	statsSetHighWater(&stat_high_connections, server.connections, verb_info.option.value);

	if (!optTestMode.value
	&& server.threads <= server.connections
	&& server.threads < optServerMaxThreads.value) {
		if (verb_trace.option.value)
			syslog(LOG_DEBUG, LOG_NUM(590) "creating %ld more server threads", optServerNewThreads.value);

		for (i = 0; i < optServerNewThreads.value; i++) {
			if (pthread_create(&thread, &thread_attr, serverChild, NULL)) {
				syslog(LOG_ERR, log_internal, SESSION_ID_ZERO, FILE_LINENO, "thread create", strerror(errno), errno);
				break;
			}
			pthread_detach(thread);
			server.threads++;
		}
	}

	ProcTitleSet(
#if !defined(__OpenBSD__) && !defined(__FreeBSD__)
		_NAME " "
#endif
		"th=%u cn=%u cs=%lu gc=%d",
		server.threads, server.connections,
		connections_per_second, cacheIsGcRunning()
	);

	(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	if (verb_timers.option.value) {
		TIMER_DIFF(mark);
		if (TIMER_GE_CONST(diff_mark, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_MSG(591) "serverCheckThreadPool time-elapsed=" TIMER_FORMAT, LOG_ARGS(session), TIMER_FORMAT_ARG(diff_mark));
	}
}

/*
 * Initialise those Session structure elements required by subsequent
 * accept filters. Note that the server.accept_mutex is locked while
 * the filter_accept_table is processed. sessionStart() will initialise
 * the remaining Session structure elements require by sessionProcess()
 */
static void
sessionAccept(Session *session)
{
	static unsigned short counter = 0;

	/* Counter ID zero is reserved for server thread identification. */
	if (++counter == 0)
		counter = 1;
	session->id = counter;

	session->start = time(NULL);
	session->last_mark = session->start;
	session->last_test = session->start;

	/* The session-id is a message-id with cc=00, is composed of
	 *
	 *	ymd HMS ppppp sssss cc
	 *
	 * Since the value of sssss can roll over very quuickly on
	 * some systems, incorporating timestamp and process info
	 * in the session-id should facilitate log searches.
	 */

	time62Encode(session->start, session->long_id);
	(void) snprintf(
		session->long_id+TIME62_BUFFER_SIZE,
		sizeof (session->long_id)-TIME62_BUFFER_SIZE,
		"%05u%05u00", getpid(), session->id
	);

	/* We have the session ID now and start logging with it. */
	LOG_TRACE(session, 592, sessionAccept);
	VALGRIND_PRINTF("session %s\n", session->long_id);

	session->state = state0;
	session->helo_state = NULL;
	session->max_concurrent = -1;

	session->smtp_code = 0;
#ifdef OLD_SMTP_ERROR_CODES
	session->smtp_error = 0;
#endif

	session->msg.id[0] = '\0';
	session->msg.headers = NULL;

	filterClearAllContexts(session);

	/* cliFdCloseOnExec is mutex protected. Might not be required.
	 * Regardless it might be slowing down new connections.
	 */
	(void) fileSetCloseOnExec(socketGetFd(session->client.socket), 1);
#ifdef DISABLE_NAGLE
	(void) socketSetNagle(session->client.socket, 0);
#endif
	(void) socketSetLinger(session->client.socket, 0);
#ifdef ENABLE_KEEPALIVE
	(void) socketSetKeepAlive(session->client.socket, 1);
#endif
	(void) socketSetNonBlocking(session->client.socket, 1);
	socketSetTimeout(session->client.socket, optSmtpCommandTimeout.value);

	/* SOCKET_ADDRESS_AS_IPV4 flag: Convert (normalise) IPv4-mapped-IPv6
	 * to IPV4-compatible-IPv6 address. This avoids isses when comparing
	 * binary IP addresses in network order.
	 */
	(void) socketAddressGetIPv6(&session->client.socket->address, SOCKET_ADDRESS_AS_IPV4, session->client.ipv6);

	/* SOCKET_ADDRESS_AS_IPV4 flag: Convert IPv4-compatible-IPv6
	 * and IPv4-mapped-IPv6 to simple IPv4 dot notation. Solves
	 * issues with access-map, DNS BL lookups, IP-in-PTR tests.
	 *
	 * Since we lose information about the socket type from the
	 * logs, the CLIENT_IS_IPV6 flag was added. This might be
	 * removed in future as it is more for debugging.
	 */
	(void) socketAddressGetString(&session->client.socket->address, SOCKET_ADDRESS_AS_IPV4, session->client.addr, sizeof (session->client.addr));

{
	/* Get the local address of the connection. This is required
	 * since a dual IPv6/IPv4 network stack will be bound to one
	 * interface, but handle both types of connections. This means
	 * it is impossible to pre-assign this in serverInit and
	 * interfaceCreate.
	 */
	socklen_t slen;
	SocketAddress saddr;

	slen = sizeof (saddr);
	*session->if_addr = '\0';
	(void) getsockname(socketGetFd(session->client.socket), &saddr.sa, &slen);
	(void) socketAddressFormatIp(&saddr.sa, SOCKET_ADDRESS_AS_IPV4, session->if_addr, sizeof (session->if_addr));
}

	CLIENT_CLEAR_ALL(session);
	CLIENT_SET(session, CLIENT_NO_PTR);
	MSG_CLEAR_ALL(session);

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (session->client.socket->address.sa.sa_family == AF_INET6) {
		CLIENT_SET(session, CLIENT_IS_IPV6);
	}
#endif
	if (isReservedIPv6(session->client.ipv6, IS_IP_LOCAL)) {
		CLIENT_SET(session, CLIENT_IS_LOCALHOST);
		statsCount(&stat_connect_localhost);
	}
	if (isReservedIPv6(session->client.ipv6, IS_IP_LAN)) {
		CLIENT_SET(session, CLIENT_IS_LAN);
		statsCount(&stat_connect_lan);
	}
	if (routeKnownClientAddr(session)) {
		CLIENT_SET(session, CLIENT_IS_RELAY);
		statsCount(&stat_connect_relay);
	}

	statsCount(&stat_connect_count);

	switch (filterRun(session, filter_accept_table)) {
	case SMTPF_DROP:
	case SMTPF_REJECT:
	case SMTPF_TEMPFAIL:
		(void) replySend(session);
		/*@fallthrough@*/

	case SMTPF_DELAY|SMTPF_DROP:
	case SMTPF_DELAY|SMTPF_REJECT:
	case SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP:
	case SMTPF_DELAY|SMTPF_SESSION|SMTPF_REJECT:
		socketClose(session->client.socket);
		session->client.socket = NULL;
		filterRun(session, filter_close_table);

		/* Avoid terminating this thread just yet. See
		 * serverChild().
		 */
		errno = ETIMEDOUT;
	}
}

/*
 * Initialise the remaining Session structure elements require by
 * sessionProcess(). There is no mutex locked when this is called.
 */
int
sessionStart(Session *session)
{
	LOG_TRACE(session, 593, sessionStart);

	session->client.octets = 0;
	session->client.name[0] = '\0';
	session->client.helo[0] = '\0';
	session->client.command_pause = 0;
	session->client.auth_count = 0;
	session->client.mail_count = 0;
	session->client.forward_count = 0;
	session->client.reject_count = 0;
	session->client.reject_delay = SMTP_REJECT_DELAY;

	session->msg.eoh = 0;
	session->msg.mail = NULL;
	session->msg.fwds = NULL;
	session->msg.length = 0;
	session->msg.rcpt_count = 0;
	session->msg.reject[0] = '\0';
	session->msg.count = (int) RAND_MSG_COUNT;
	session->msg.fwd_to_queue = NULL;
	session->msg.smtpf_code = SMTPF_UNKNOWN;
	session->client.fwd_to_queue = NULL;

	MAIL_CLEAR_ALL(session);
	RCPT_CLEAR_ALL(session);

	/* This should be an SPF filter context. */
	session->client.spf_helo = SPF_NONE;
	session->client.spf_helo_error = "";
	session->msg.spf_mail = SPF_NONE;
	session->msg.spf_mail_error = "";

	return 0;
}

void
sessionFinish(Session *session)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(594) "client [%s] close", LOG_ARGS(session), session->client.addr);

	if (session->state != NULL)
		(void) statsCount(&stat_connect_dropped);

	(void) mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	server.connections--;

	/* Set to NULL to indicate to CONN command that session is inactive. */
	session->state = NULL;
	ProcTitleSet(
#if !defined(__OpenBSD__) && !defined(__FreeBSD__)
		_NAME " "
#endif
		"th=%u cn=%u cs=%lu gc=%d",
		server.threads, server.connections,
		connections_per_second, cacheIsGcRunning()
	);

	(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	socketClose(session->client.socket);
	session->client.socket = NULL;
	session->iface = NULL;

	/* */
	filterRun(session, filter_close_table);
	VectorDestroy(session->msg.headers);
	/* */

#ifdef VERB_VALGRIND
	if (1 < verb_valgrind.option.value) {
		VALGRIND_PRINTF("sessionFinish\n");
		VALGRIND_DO_LEAK_CHECK;
	}
#endif
}

Session *
sessionCreate(void)
{
	Session *session;

	LOG_TRACE0(572, sessionCreate);

	if ((session = malloc(sizeof (*session) + filter_context_size)) == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		goto error0;
	}

	if (routeMapOpen(session))
		goto error1;

	if (accessMapOpen(session))
		goto error2;
#ifdef ENABLE_PDQ
	if ((session->pdq = pdqOpen()) == NULL)
		goto error3;
#endif
#ifdef __WIN32__
	session->kill_event = CreateEvent(NULL, 0, 0, NULL);
#endif
	session->thread = pthread_self();
	session->client.socket = NULL;
	session->state = NULL;
	session->prev = NULL;
	session->next = NULL;

	(void) mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	/* Double link-list of sessions. See cmdClients(). */
	if (server.head != NULL) {
		session->prev = NULL;
		session->next = server.head;
	}
	server.head = session;
	if (session->prev != NULL)
		session->prev->next = session;
	if (session->next != NULL)
		session->next->prev = session;

	(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

	return session;
#ifdef ENABLE_PDQ
error3:
	accessMapClose(session);
#endif
error2:
	routeMapClose(session);
error1:
	free(session);
error0:
	return NULL;
}

void
sessionFree(void *_session)
{
	Session *session = _session;

	if (session != NULL) {
		(void) mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);
		server.threads--;

		/* Double link-list of sessions. */
		if (session->prev != NULL)
			session->prev->next = session->next;
		else
			server.head = session->next;
		if (session->next != NULL)
			session->next->prev = session->prev;

		(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.connections_mutex);

		/* If we are called because of pthread_cancel(), be sure
		 * to cleanup the current connection too. Ideally this
		 * could be handled with pthread_cleanup_push / pop, but
		 * those are not portable to Windows.
		 */
		if (session->client.socket != NULL)
			sessionFinish(session);
#ifdef __WIN32__
		CloseHandle(session->kill_event);
#endif
#ifdef ENABLE_PDQ
		pdqClose(session->pdq);
#endif
		accessMapClose(session);
		routeMapClose(session);
		freeThreadData();
		free(session);

#ifdef ENABLE_SLOW_QUIT
		(void) pthread_cond_signal(&slow_quit_cv);
#endif
	}

	LOG_TRACE0(573, sessionFree);
}

/*
 * Interface for application specific processing.
 */
extern void sessionProcess(Session *session);

/***********************************************************************
 *** Interfaces
 ***********************************************************************/

static void
interfaceFree(void *_interface)
{
	if (_interface != NULL) {
		socketClose(((BoundIp *) _interface)->socket);
		free(_interface);
	}
}

static BoundIp *
interfaceCreate(char *if_name)
{
	int save_errno;
	BoundIp *iface;
	SocketAddress *saddr;

	if ((iface = calloc(1, sizeof (*iface))) == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		goto error0;
	}

	/* Create the server socket. */
	if ((saddr = socketAddressCreate(if_name, SMTP_PORT)) == NULL)
		goto error1;

	iface->socket = socketOpen(saddr, 1);
	free(saddr);

	if (iface->socket == NULL)
		goto error1;

	(void) fileSetCloseOnExec(socketGetFd(iface->socket), 1);
	(void) socketSetNonBlocking(iface->socket, 1);
	(void) socketSetLinger(iface->socket, 0);
	(void) socketSetReuse(iface->socket, 1);
#ifdef DISABLE_NAGLE
/* This is disabled in 1.0. */
	(void) socketSetNagle(iface->socket, 0);
#endif

	if (socketServer(iface->socket, (int) optServerQueueSize.value))
		goto error1;
	if (socketAddressGetName(&iface->socket->address, iface->name, sizeof (iface->name)) == 0)
		goto error1;

	syslog(LOG_INFO, LOG_NUM(595) "interface=%s ready", if_name);
/*{LOG
The interface is ready to accept connections.
}*/
	return iface;
error1:
	if (h_errno == 0)
		syslog(LOG_ERR, LOG_NUM(596) "interface=%s error: %s (%d)", if_name, strerror(errno), errno);
	else
		syslog(LOG_ERR, LOG_NUM(000) "interface=%s error: %s (%d)", if_name, hstrerror(h_errno), h_errno);
/*{LOG
An error occurred when @PACKAGE_NAME@ tried to bind to the socket.
The most likely cause of this is that something else is already
bound to the socket, like another MTA.
}*/
	save_errno = errno;
	interfaceFree(iface);
	errno = save_errno;
error0:
	return NULL;
}

/***********************************************************************
 *** Server
 ***********************************************************************/

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
serverAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&server.accept_mutex);
}

void
serverAtForkParent(void)
{
	(void) pthread_mutex_unlock(&server.accept_mutex);
}

void
serverAtForkChild(void)
{
	(void) pthread_mutex_unlock(&server.accept_mutex);
	(void) pthread_mutex_unlock(&server.connections_mutex);

	mutex_destroy(&server.accept_mutex);
	mutex_destroy(&server.connections_mutex);
}
#endif

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

static int
serverInit(void)
{
	long i;
	Vector interfaces;

	(void) serverOptn0(NULL, NULL);

	/* Reparse the verbose option, since there may have been some
	 * late additions to the verbose list made in filterInit().
	 */
	verboseParse(optVerbose.string);

	if (socketInit()) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		return -1;
	}

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
	statsInit();
	cacheInit();
	filterInit();
	statsLoad();

	welcomeInit();

	(void) pthread_mutex_init(&server.accept_mutex, NULL);
	(void) pthread_mutex_init(&server.connections_mutex, NULL);
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

	if ((interfaces = TextSplit(optInterfaces.string, OPTION_LIST_DELIMS, 0)) == NULL) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		return -1;
	}

	if ((server.interfaces = VectorCreate(VectorLength(interfaces))) == NULL) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		return -1;
	}

	VectorSetDestroyEntry(server.interfaces, interfaceFree);

	if ((server.interfaces_fd = calloc(VectorLength(interfaces), sizeof (*server.interfaces_fd))) == NULL) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		return -1;
	}

	if ((server.interfaces_ready = calloc(VectorLength(interfaces), sizeof (*server.interfaces_fd))) == NULL) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		return -1;
	}

	rand_seed = 5381;

	for (i = 0; i < VectorLength(interfaces); i++) {
		int j;
		char *if_name;
		BoundIp *iface;

		if ((if_name = VectorGet(interfaces, i)) == NULL)
			continue;

		if ((iface = interfaceCreate(if_name)) == NULL) {
			syslog(LOG_WARN, LOG_NUM(597) "interface=%s disabled", if_name);
/*{LOG
On some platforms it is possible to bind two separate sockets for
IPv6 ::0 and IPv4 0.0.0.0, both on the same port. On others
platforms binding a single socket to ::0 will also include 0.0.0.0
for the same port and so generate a warning that can be ignored.
Using lsof(1), fstat(1), and/or netsat(1) one should be able to
determine if it is an error due to another process being bound to
the same port and so corrected, or simply to be ignored and the
configuration adjusted to silence the warning in future.

See <a href="summary.html#opt_interfaces">interfaces</a> option.
}*/
			continue;
		}

		/* Use the interface address pointer to generate
		 * a random number seed using Bernstien's hash.
		 */
		for (j = 0; j < sizeof (iface); j++)
			rand_seed = ((rand_seed << 5) + rand_seed) ^ ((unsigned char *) iface)[j];

		server.interfaces_fd[VectorLength(server.interfaces)] = socketGetFd(iface->socket);

		if (VectorAdd(server.interfaces, iface)) {
			syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
			return -1;
		}
	}

	if (VectorLength(server.interfaces) <= 0) {
		syslog(LOG_ERR, LOG_NUM(812) "no matching interfaces=\"%s\"", optInterfaces.string);
/*{LOG
See <a href="summary.html#opt_interfaces">interfaces</a> option.
}*/
		return -1;
	}

	srand(rand_seed ^ time(NULL) ^ getpid());

	VectorDestroy(interfaces);

	/* REMOVAL OF THIS CODE IS IN VIOLATION OF THE TERMS OF
	 * THE SOFTWARE LICENSE AS AGREED TO BY DOWNLOADING OR
	 * INSTALLING THIS SOFTWARE.
	 */
	lickeyInit(server.interfaces);
#ifdef ENABLE_LINT
	(void) serverOptn1(NULL, NULL);
#endif
	if (optTestLickey.value)
		exit(0);

	/* Needs to check and set the license route counters after
	 * lickeyInit() in main(), routeInit(), and statInit().
	 */
	lickeyRouteCount();
	cacheGcStart();

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

		if (chownByName(optRunPidFile.string, optRunUser.string, optRunGroup.string))
			exit(1);
	}

	if (processDropPrivilages(optRunUser.string, optRunGroup.string, optRunWorkDir.string, optRunJailed.value))
		exit(1);
	(void) processDumpCore(1);
	syslog(LOG_INFO, LOG_NUM(599) "ready");
/*{LOG
The SMTP service is ready to accept connections.
}*/
	/* Assume the first thread will be successfully created. */
	server.threads = 1;
	server.running = 1;

	return 0;
}

static void
serverFini(void)
{
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_NUM(600) "serverFini");

	(void) pthread_mutex_destroy(&server.connections_mutex);
	(void) pthread_mutex_destroy(&server.accept_mutex);

	VectorDestroy(server.interfaces);
	free(server.interfaces_ready);
	free(server.interfaces_fd);
	signalFini(NULL);
}

void *
serverChild(void *ignore)
{
	Session *session;

	if ((session = sessionCreate()) == NULL) {
		freeThreadData();
		return NULL;
	}

#ifdef HAVE_PTHREAD_CLEANUP_PUSH
	pthread_cleanup_push(sessionFree, session);
#endif
	while (server.running) {
		TIMER_DECLARE(mark);

		if (mutex_lock(SESSION_ID_ZERO, FILE_LINENO, &server.accept_mutex))
			break;

		if (!server.running) {
			(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.accept_mutex);
			break;
		}

		if (verb_timers.option.value)
			TIMER_START(mark);

		/* Wait for new connections. The thread is terminated
		 * if we timeout and have more threads than we need.
		 */
		if (socketTimeouts(server.interfaces_fd, server.interfaces_ready, server.interfaces->_length, optServerAcceptTimeout.value, 1)) {
			int i;

			for (i = 0; i < server.interfaces->_length; i++) {
				if (server.interfaces_fd[i] == server.interfaces_ready[i]) {
					session->iface = VectorGet(server.interfaces, i);
					session->client.socket = socketAccept(session->iface->socket);
					if (session->client.socket != NULL) {
						sessionAccept(session);
					}
					break;
				}
			}
		}

		(void) mutex_unlock(SESSION_ID_ZERO, FILE_LINENO, &server.accept_mutex);

		if (verb_timers.option.value && session->client.socket != NULL) {
			TIMER_DIFF(mark);
			if (TIMER_GE_CONST(diff_mark, 1, 0) || 1 < verb_timers.option.value)
				syslog(LOG_DEBUG, LOG_MSG(601) "accept_mutex time-elapsed=" TIMER_FORMAT " ip=%s", LOG_ARGS(session), TIMER_FORMAT_ARG(diff_mark), session->client.addr);
		}

		if (session->client.socket == NULL
		&& errno != ECONNABORTED && optServerMinThreads.value < server.threads) {
			if (errno != 0 && errno != ETIMEDOUT)
				syslog(LOG_ERR, LOG_NUM(602) "socket accept: %s (%d); th=%u cn=%u", strerror(errno), errno, server.threads, server.connections);
/*{LOG
When this error occurs, it is most likely due to two types of errors:
a timeout or the process is out of file discriptors, though other
network related errors may occur.

<p>The former case (ETIMEDOUT) is trival and occurs when there is a
lull in activity, in which case surplus threads are discontinued as
they timeout.
</p>

<p>The latter case (EMFILE) is more serious, in which case the process
is out of file descriptors, so the thread is terminated cleanly to
release resources. If this occurs in multiple threads in the accept
state, then this will terminate any surplus of threads, temporarily
preventing the server from answering more connections. This will allow
the threads with active connections to finish, release resources, and
eventually resume answering again once sufficent resources are available.
</p>
<p>
If the process got an error during socket accept and did not terminate
the thread and eliminate the surplus, it might be possible to get into
a tight busy loop, which contantly tries to accept a connection yet fails
with EMFILE. This would slow down or prevent other threads with active
connections from completing normally and possibly hang the process.
</p>
}*/
			break;
		}

		if (session->client.socket != NULL) {
			serverCheckThreadPool(session);
			if (sessionStart(session) == 0)
				sessionProcess(session);
			sessionFinish(session);
		}

		/* If the number of active connections falls below
		 * half the number of extra threads, then terminate
		 * this thread to free up excess unused resources.
		 */
		if (optServerMinThreads.value < server.threads
		&& server.connections + optServerNewThreads.value < server.threads) {
			if (verb_trace.option.value)
				syslog(LOG_ERR, LOG_NUM(603) "terminating excess thread th=%u cn=%u", server.threads, server.connections);
			break;
		}

		if (optTestMode.value)
			break;
	}

#ifdef HAVE_PTHREAD_CLEANUP_PUSH
	pthread_cleanup_pop(1);
#else
	sessionFree(session);
#endif
	return NULL;
}

/* This is a special test wrapper that is intended to exercise serverChild,
 * sessionCreate, and sessionFree, in particular with valgrind looking for
 * memory leaks.
 */
void *
serverChildTest(void *ignore)
{
	unsigned long count;

	for (count = 1; server.running; count++) {
		VALGRIND_PRINTF("serverChild begin %lu\n", count);
		(void) serverChild(NULL);
		VALGRIND_PRINTF("serverChild end %lu\n", count);
		VALGRIND_DO_LEAK_CHECK;
	}

	return NULL;
}

void
serverMain(void)
{
	pthread_t thread;

	syslog(LOG_INFO, LOG_NUM(604) "" _NAME " " _VERSION " " _COPYRIGHT);
	syslog(LOG_INFO, LOG_NUM(605) "LibSnert %s %s", LIBSNERT_VERSION, LIBSNERT_COPYRIGHT);
	syslog(LOG_INFO, LOG_NUM(606) "SQLite %s Public Domain by D. Richard Hipp", sqlite3_libversion());
#ifdef _BUILT
	syslog(LOG_INFO, LOG_NUM(904) "Built on " _BUILT);
#endif
/*{LOG
Version and copyright notices.
}*/

	if (serverInit())
		exit(1);

	signalInit(&server);

#ifdef VERB_VALGRIND
	if (1 < verb_valgrind.option.value) {
		VALGRIND_PRINTF("serverMain before 1st serverChild\n");
		VALGRIND_DO_LEAK_CHECK;
	}
#endif
	/* Start our first server thread to start handling requests. */
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_NUM(607) "creating server thread...");
	if (pthread_create(&thread, &thread_attr, optTestMode.value ? serverChildTest : serverChild, NULL)) {
		syslog(LOG_ERR, log_internal, SESSION_ID_ZERO, FILE_LINENO, "pthread_create", strerror(errno), errno);
		server.running = 0;
	}
	pthread_detach(thread);

	/* Wait for the signal thread to terminate, otherwise we
	 * end up terminating the server eventually returning
	 * from main() and exiting.
	 */
	(void) signalThread(&server);

	serverFini();
}

void
serverPrintVersion(void)
{
	printf(_NAME " " _VERSION " " _COPYRIGHT "\n");
	printf(LIBSNERT_STRING " " _COPYRIGHT "\n");
	printf("SQLite %s Public Domain by D. Richard Hipp\n", sqlite3_libversion());
#ifdef _BUILT
	printf("Built on " _BUILT "\n");
#endif
}

void
serverPrintVar(int columns, const char *name, const char *value)
{
	int length;
	Vector list;
	const char **args;

	if (columns <= 0)
		printf("%s=\"%s\"\n",  name, value);
	else if ((list = TextSplit(value, " \t", 0)) != NULL && 0 < VectorLength(list)) {
		args = (const char **) VectorBase(list);

		length = printf("%s=\"'%s'", name, *args);
		for (args++; *args != NULL; args++) {
			/* Line wrap. */
			if (columns <= length + strlen(*args) + 4) {
				(void) printf("\n\t");
				length = 8;
			}
			length += printf(" '%s'", *args);
		}
		if (columns <= length + 1) {
			(void) printf("\n");
		}
		(void) printf("\"\n");

		VectorDestroy(list);
	}
}

void
serverPrintInfo(void)
{
#ifdef _NAME
	serverPrintVar(0, "SMTPF_NAME", _NAME);
#endif
#ifdef _VERSION
	serverPrintVar(0, "SMTPF_VERSION", _VERSION);
#endif
#ifdef _COPYRIGHT
	serverPrintVar(0, "SMTPF_COPYRIGHT", _COPYRIGHT);
#endif
#ifdef _BUILT
	serverPrintVar(0, "SMTPF_BUILT", _BUILT);
#endif
#ifdef _CONFIGURE
	serverPrintVar(LINE_WRAP, "SMTPF_CONFIGURE", _CONFIGURE);
#endif
#ifdef LIBSNERT_VERSION
	serverPrintVar(0, "LIBSNERT_VERSION", LIBSNERT_VERSION);
#endif
#ifdef LIBSNERT_CONFIGURE
	serverPrintVar(LINE_WRAP, "LIBSNERT_CONFIGURE", LIBSNERT_CONFIGURE);
#endif
	serverPrintVar(0, "SQLITE3_VERSION", sqlite3_libversion());
#ifdef _CFLAGS
	serverPrintVar(LINE_WRAP, "CFLAGS", _CFLAGS);
#endif
#ifdef _LDFLAGS
	serverPrintVar(LINE_WRAP, "LDFLAGS", _LDFLAGS);
#endif
#ifdef _LIBS
	serverPrintVar(LINE_WRAP, "LIBS", _LIBS);
#endif
}
