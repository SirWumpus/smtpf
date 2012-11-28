/*
 * smtpf.h
 *
 * Copyright 2006 by Anthony Howe. All rights reserved.
 */

#ifndef __smtpf_h__
#define __smtpf_h__			1

#undef OLD_SMTP_ERROR_CODES

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#include <com/snert/lib/version.h>

#if defined(__MINGW32__)
# if !defined(HAVE_PTHREAD_CREATE)
/* LibSnert provides POSIX cover functions to the Windows thread API. */
#  define HAVE_PTHREAD_CREATE
# endif
# undef HAVE_SIGSET_T
# define SIGUSR1 SIGTERM
#elif defined(ENABLE_FORK)
# undef HAVE_PTHREAD_CREATE
#endif

#ifdef __WIN32__
/* IPv6 support such as getaddrinfo, freeaddrinfo, getnameinfo
 * only available in Windows XP or later.
 */
# define WINVER		0x0501
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>

#ifdef __sun__
# define _POSIX_PTHREAD_SEMANTICS
#endif
#include <signal.h>

#ifndef __MINGW32__
# if defined(HAVE_GRP_H)
#  include <grp.h>
# endif
# if defined(HAVE_PWD_H)
#  include <pwd.h>
# endif
# if defined(HAVE_NETDB_H)
#  include <netdb.h>
# endif
# if defined(HAVE_SYSLOG_H)
#  include <syslog.h>
# endif
# if defined(HAVE_SYS_WAIT_H)
#  include <sys/wait.h>
# endif
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_UNISTD_H
# ifdef __linux__
#  /* See Linux man setresgid */
#  define _GNU_SOURCE
# endif
# include <unistd.h>
#endif

#include <com/snert/lib/io/Log.h>
#include <com/snert/lib/io/file.h>
#include <com/snert/lib/io/socket2.h>
#include <com/snert/lib/io/socket3.h>
#include <com/snert/lib/mail/siq.h>
#ifdef OLD_SMTP_ERROR_CODES
#include <com/snert/lib/mail/smtp.h>
#else
#include <com/snert/lib/mail/smtp2.h>
#endif
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/parsePath.h>
#include <com/snert/lib/net/network.h>
#include <com/snert/lib/net/pdq.h>
#include <com/snert/lib/net/server.h>
#include <com/snert/lib/sys/pthread.h>
#include <com/snert/lib/type/kvm.h>
#include <com/snert/lib/type/mcc.h>
#include <com/snert/lib/type/Vector.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/uri.h>
#include <com/snert/lib/util/time62.h>
#include <com/snert/lib/util/timer.h>
#include <com/snert/lib/util/setBitWord.h>

#ifdef DEBUG_MALLOC
# include <com/snert/lib/util/DebugMalloc.h>
#endif
#ifdef DEBUG_MUTEX
# define KEEP_STDIO_OPEN
# include <com/snert/lib/sys/lockpick.h>
#endif

#ifdef NDEBUG
#define NVALGRIND
#endif
#include "valgrind/valgrind.h"
#include "valgrind/memcheck.h"

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.9 or better is required"
#endif

/***********************************************************************
 *** OS Specific Overrides
 ***********************************************************************/

#ifdef HAVE_PTHREAD_COND_INIT
#define ENABLE_SLOW_QUIT
extern pthread_cond_t slow_quit_cv;
#endif

#ifdef __WIN32__
extern unsigned int sleep(unsigned int);
extern void freeThreadData(void);
#else
#define freeThreadData()
#endif

#undef HAVE_PTHREAD_YIELD
#undef DISABLE_NAGLE
#define USE_PTHREAD_CANCEL

#ifdef __unix__
# define cliFdCloseOnExec(fd, close_on_exec)	(void) fileSetCloseOnExec(fd, 1)
#else
# ifdef __WIN32__
#  undef FILTER_CLI
# endif
# define cliFdCloseOnExec(fd, close_on_exec)
#endif

/***********************************************************************
 *** Constants
 ***********************************************************************/

#ifndef LINGER_ON_CLOSE
#define LINGER_ON_CLOSE		2
#endif

#ifndef SMTP_REJECT_DELAY
#define SMTP_REJECT_DELAY	1
#endif

#ifndef OPTION_LIST_DELIMS
#define OPTION_LIST_DELIMS	";, "
#endif

#ifdef HAVE_RAND_R
#define RANDOM_NUMBER(max)	((int)((double)(max) * (double) rand_r(&rand_seed) / (RAND_MAX+1.0)))
#else
#define RANDOM_NUMBER(max)	((int)((double)(max) * (double) rand() / (RAND_MAX+1.0)))
#endif

#ifndef RAND_MSG_COUNT
#define RAND_MSG_COUNT		RANDOM_NUMBER(62.0*62.0)
#endif

#define SESS_ID_ZERO		"0"

#define FILE_LINENO		__FILE__, (unsigned long) __LINE__

#define SESSION_ID_ZERO		SESS_ID_ZERO
#define LOG_FMT			"%s "
#define LOG_NUM(n)		"#" #n " "
#define LOG_MSG(n)		LOG_FMT LOG_NUM(n)

#define LOG_ARGS(s)		(s)->session->id_log
#define SESS_ID			sess->session->id_log

#define LOG_TRACE0(n, f)	if (verb_trace.option.value) syslog(LOG_DEBUG, LOG_NUM(n) #f)
#define LOG_TRACE(s, n, f)	if (verb_trace.option.value) syslog(LOG_DEBUG, LOG_MSG(n) #f, LOG_ARGS(s))

#define CLIENT_FORMAT		"%s%s[%s]"
#define CLIENT_INFO(s)		(s)->client.name, (*(s)->client.name == '\0' ? "" : " "), (s)->client.addr

#define ID_FMT			" %s"
#define ID_NUM(n)		" #" #n
#define ID_MSG(n)		ID_NUM(n) ID_FMT
#define ID_ARG(s)		(s)->session->id_log

#define NULL_TAG_STRING_LENGTH		47	/* "Null-Tag: <%32s>\r\n\0" */
#define NULL_TAG_STRING_LENGTH_S	"47"

/***
 *** NOTE that if these values change then cli.c must be updated.
 ***/
typedef enum {
	SMTPF_CONTINUE		= 0x0000,	/* Must always be 0 so memset() does the right thing. */
 	SMTPF_TAG		= 0x0001,
	SMTPF_ACCEPT		= 0x0002,	/* Must always be 2; corresponds with SMTP 2xx */
 	SMTPF_GREY		= 0x0003,
	SMTPF_TEMPFAIL		= 0x0004,	/* Must always be 4; corresponds with SMTP 4xx */
	SMTPF_REJECT		= 0x0005,	/* Must always be 5; corresponds with SMTP 5xx */
	SMTPF_DISCARD		= 0x0006,
	SMTPF_DROP		= 0x0007,
	SMTPF_SKIP_NEXT		= 0x0008,
	SMTPF_SKIP_REMAINDER	= 0x0009,	/* Similar to SMTPF_ACCEPT and SMTPF_GREY, but translates to SMTPF_CONTINUE. */
	SMTPF_UNKNOWN		= 0x000A,
	SMTPF_SESSION		= 0x4000,
	SMTPF_DELAY		= 0x8000,
} SmtpfCode;

#define SMTPF_FLAGS		(SMTPF_DELAY|SMTPF_SESSION)

extern const char *smtpf_code_names[];

#define SMTPF_CODE_NAME(smtpf_code)	smtpf_code_names[smtpf_code & ~SMTPF_DELAY]

/***********************************************************************
 ***
 ***********************************************************************/

/* Test for actual ASCII character code vs. the C compiler's
 * interpretation of some special character constants.
 */
#define ASCII_NUL		0x00
#define ASCII_BS		0x08
#define ASCII_TAB		0x09
#define ASCII_LF		0x0A
#define ASCII_FF		0x0C
#define ASCII_CR		0x0D
#define ASCII_SPACE		0x20
#define ASCII_DEL		0x7F

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct smtpf Session;
#define BoundIp ServerInterface

typedef int (*CommandFunction)(Session *);

typedef struct relay {
	struct relay *next;
	long cidr;
	const char *domain;
	unsigned char network[IPV6_BYTE_LENGTH];
} Relay;

typedef struct command {
	char *command;
	CommandFunction function;
} Command;

#define PATH_IS_WHITE		0x00000001
#define PATH_IS_BLACK		0x00000002

#define PATH_SET(p, m)		((p)->isWhiteListed.flags |= (m))
#define PATH_CLEAR(p, m)	((p)->isWhiteListed.flags &= ~(m))
#define PATH_CLEAR_ALL(p)	((p)->isWhiteListed.flags = 0)

#define PATH_IS_SET(p, m, f)	(((p)->isWhiteListed.flags & (m)) == (f))
#define PATH_ALL_SET(p, m)	PATH_IS_SET(p, m, m)
#define PATH_ANY_SET(p, m)	(((p)->isWhiteListed.flags & (m)) != 0)
#define PATH_NOT_SET(p, m)	(((p)->isWhiteListed.flags & (m)) == 0)

typedef struct rcpt {
	struct rcpt *next;
	ParsePath *rcpt;
} Rcpt;

typedef struct connection {
	struct {
		char *key;
		char *value;
	} route;
	struct connection *next;
	struct rcpt *rcpts;
	unsigned rcpt_count;
	time_t time_of_last_command;
	unsigned long length;
#ifdef OLD_SMTP_ERROR_CODES
	int smtp_error;
#endif
	int smtp_code;
	int can_quit;
	char mx_ip[IPV6_STRING_LENGTH];
	char *mx_host;
	char **reply;
	Socket2 *mx;
} Connection;

typedef struct {
	unsigned long length;
	unsigned char data[SMTP_MINIMUM_MESSAGE_LENGTH];
} Chunk;

#define FLAG_SET(f, m)			((f) |= (m))
#define FLAG_CLEAR(f, m)		((f) &= ~(m))
#define FLAG_CLEAR_ALL(f)		((f) = 0)
#define FLAG_IS_SET(f, m, n)		(((f) & (m)) == (n))
#define FLAG_NOT_SET(f, m)		(((f) & (m)) == 0)
#define FLAG_ANY_SET(f, m)		(((f) & (m)) != 0)
#define FLAG_ALL_SET(f, m)		FLAG_IS_SET(f, m, m)

#define MSG_GREY_CONTENT		0x00000001
#define MSG_GREY_HASH_MISMATCH		0x00000002
#define MSG_IS_DNSBL			0x00000004
#define MSG_IS_URIBL			0x00000008
#define MSG_IS_URI_IMPLICIT		0x00000010
#define MSG_EMEW_OK			0x00000020
#define MSG_DISCARD			0x00000040
#define MSG_POLICY			0x00000080
#define MSG_TAG				0x00000100
#define MSG_TAGGED			0x00000200
#define MSG_QUEUE			0x00000400
#define MSG_SAVE			0x00000800
#define MSG_TRAP			0x00001000
#define MSG_INFECTED			0x00002000
#define MSG_OK_AV			0x00004000
#define MSG_OK				0x00008000

#define MSG_END_BIT			MSG_TRAP

#define MSG_SET(s, m)			FLAG_SET((s)->msg.flags, m)
#define MSG_CLEAR(s, m)			FLAG_CLEAR((s)->msg.flags, m)
#define MSG_CLEAR_ALL(s)		FLAG_CLEAR_ALL((s)->msg.flags)
#define MSG_IS_SET(s, m, n)		FLAG_IS_SET((s)->msg.flags, m, n)
#define MSG_NOT_SET(s, m)		FLAG_NOT_SET((s)->msg.flags, m)
#define MSG_ANY_SET(s, m)		FLAG_ANY_SET((s)->msg.flags, m)
#define MSG_ALL_SET(s, m)		MSG_IS_SET(s, m, m)

#define MAIL_SET(s, m)			FLAG_SET((s)->msg.mail_flags, m)
#define MAIL_CLEAR(s, m)		FLAG_CLEAR((s)->msg.mail_flags, m)
#define MAIL_CLEAR_ALL(s)		FLAG_CLEAR_ALL((s)->msg.mail_flags)
#define MAIL_IS_SET(s, m, n)		FLAG_IS_SET((s)->msg.mail_flags, m, n)
#define MAIL_NOT_SET(s, m)		FLAG_NOT_SET((s)->msg.mail_flags, m)
#define MAIL_ANY_SET(s, m)		FLAG_ANY_SET((s)->msg.mail_flags, m)
#define MAIL_ALL_SET(s, m)		MAIL_IS_SET(s, m, m)

#define MAIL_IS_BLACK			0x00000001
#define MAIL_IS_WHITE			0x00000002
#define MAIL_IS_TEMPFAIL		0x00000004
#define MAIL_HAS_EXTRA_SPACES		0x00000008
#define MAIL_IS_LOCAL_BLACK		0x00000010
#define MAIL_IS_8BITMIME		0x00000020
#define MAIL_IS_BINARYMIME		0x00000040

#define RCPT_SET(s, m)			FLAG_SET((s)->msg.rcpt_flags, m)
#define RCPT_CLEAR(s, m)		FLAG_CLEAR((s)->msg.rcpt_flags, m)
#define RCPT_CLEAR_ALL(s)		FLAG_CLEAR_ALL((s)->msg.rcpt_flags)
#define RCPT_IS_SET(s, m, n)		FLAG_IS_SET((s)->msg.rcpt_flags, m, n)
#define RCPT_NOT_SET(s, m)		FLAG_NOT_SET((s)->msg.rcpt_flags, m)
#define RCPT_ANY_SET(s, m)		FLAG_ANY_SET((s)->msg.rcpt_flags, m)
#define RCPT_ALL_SET(s, m)		RCPT_IS_SET(s, m, m)

#define RCPT_IS_BLACK			0x00000001
#define RCPT_IS_WHITE			0x00000002
#define RCPT_IS_TEMPFAIL		0x00000004
#define RCPT_HAS_EXTRA_SPACES		0x00000008
#define RCPT_IS_LOCAL_BLACK		0x00000010
#define RCPT_FAILED			0x00000020

typedef struct {
	char id[20];
	unsigned long flags;
	unsigned long mail_flags;
	unsigned long rcpt_flags;
	int count;
	int spf_mail;
	int seen_final_dot;
	int seen_crlf_before_dot;
	SmtpfCode bw_state;
	SmtpfCode smtpf_code;
	ParsePath *mail;
	Vector headers;
	Connection *fwds;
	Connection *fwd_to_queue;
	char *msg_id;
	char *subject;
	const char *spf_mail_error;
	char reject[SMTP_REPLY_LINE_LENGTH+1];
	unsigned rcpt_count;
	unsigned bad_rcpt_count;
	unsigned long eoh;		/* chunk0 offset of end of header including CRLF. */
	unsigned long length;		/* Original message length excluding DOT-CRLF. */
	unsigned long max_size;
	unsigned long max_size_rcpt;
	unsigned long mail_size;
	unsigned long chunk0_length;
	unsigned char chunk0[SMTP_MINIMUM_MESSAGE_LENGTH];
	unsigned long chunk1_length;
	unsigned char chunk1[SMTP_MINIMUM_MESSAGE_LENGTH];
} Message;

#define CLIENT_IS_MX			0x00000001
#define CLIENT_IS_LAN			0x00000002
#define CLIENT_IS_RELAY			0x00000004
#define CLIENT_IS_2ND_MX		0x00000008	/* Client is our secondary MX. */
#define CLIENT_IS_FORGED		0x00000010	/* IP -> PTR name != A name -> IP */
#define CLIENT_IS_LOCALHOST		0x00000020
#define CLIENT_IS_BLACK			0x00000040	/* Black listed, reject earliest possible. */
#define CLIENT_IS_GREY			0x00000080	/* Grey listed, by-pass pre-DATA tests only. */
#define CLIENT_IS_SAVE			0x00000100	/* Save message to save-dir if content sent. */
#define CLIENT_IS_TAG			0x00000200	/* Tag subject if policy reject occurs. */
#define CLIENT_IS_WHITE			0x00000400	/* White listed, by-pass remaining tests. */
#define CLIENT_IS_DISCARD		0x00000800	/* Accept and discard the message. */
#define CLIENT_IS_IP_IN_PTR		0x00001000
#define CLIENT_IS_HELO_IP		0x00002000	/* HELO is an IP address string */
#define CLIENT_IS_HELO_HOSTNAME		0x00004000	/* HELO has A / AAAA record matching client IP. */
#define CLIENT_IS_PTR_MULTIDOMAIN	0x00008000	/* True if the PTR is multihomed for multiple domains. */
#define CLIENT_NO_PTR			0x00010000	/* Has no PTR record. */
#define CLIENT_NO_PTR_ERROR		0x00020000	/* Has no PTR record due to an error. */
#define CLIENT_IS_EHLO_NO_HELO		0x00040000	/* Has sent EHLO and no HELO. */
#define CLIENT_IS_SCHIZO		0x00080000	/* *  Different HELO/EHLO arguments used. */
#define CLIENT_IS_GREY_EXEMPT		0x00100000	/* * Client exempt from grey-listing. */
#define CLIENT_PASSED_GREY		0x00200000	/* Client has previously passed grey-listing. */
#define CLIENT_PIPELINING		0x00400000	/* Client sent next command before end of reply. */
#define CLIENT_SMTP_LOWER_CASE		0x00800000	/* * SMTP command contains lower case */
#define CLIENT_IO_ERROR			0x01000000
#define CLIENT_RATE_LIMIT		0x02000000
#define CLIENT_CONCURRENCY_LIMIT	0x04000000
#define CLIENT_IS_LOCAL_BLACK		0x08000000	/* Black listed locally. */
#define CLIENT_IS_TRAP			0x10000000
#define CLIENT_IS_TEMPFAIL		0x20000000
#define CLIENT_HAS_AUTH			0x40000000	/* Has sucessfully authenticated. */
#define CLIENT_HAS_QUIT			0x80000000

#define CLIENT_END_BIT			CLIENT_HAS_QUIT

#define CLIENT_HOLY_TRINITY		(CLIENT_IS_LOCALHOST|CLIENT_IS_LAN|CLIENT_IS_RELAY)
#define CLIENT_USUAL_SUSPECTS		(CLIENT_HOLY_TRINITY|CLIENT_IS_WHITE)

#define CLIENT_SET(s, m)		FLAG_SET((s)->client.flags, m)
#define CLIENT_CLEAR(s, m)		FLAG_CLEAR((s)->client.flags, m)
#define CLIENT_CLEAR_ALL(s)		FLAG_CLEAR_ALL((s)->client.flags)
#define CLIENT_IS_SET(s, m, n)		FLAG_IS_SET((s)->client.flags, m, n)
#define CLIENT_NOT_SET(s, m)		FLAG_NOT_SET((s)->client.flags, m)
#define CLIENT_ANY_SET(s, m)		FLAG_ANY_SET((s)->client.flags, m)
#define CLIENT_ALL_SET(s, m)		CLIENT_IS_SET(s, m, m)

typedef struct {
	unsigned long flags;
	SmtpfCode bw_state;
	int ok_av;
	int spf_helo;
	int auth_count;
	int mail_count;
	int forward_count;
	int reject_count;
	long reject_delay;
	long command_pause;
	Socket2 *socket;		/* OLD_SERVER_MODEL, copy */
	unsigned long octets;
	unsigned long max_size;
	Connection *fwd_to_queue;
	const char *spf_helo_error;
	char addr[SOCKET_ADDRESS_STRING_SIZE];
	char name[SMTP_DOMAIN_LENGTH+1];
	char auth[SMTP_TEXT_LINE_LENGTH+1];
	char helo[SMTP_COMMAND_LINE_LENGTH+1];
	char sender_domain[SMTP_DOMAIN_LENGTH+1];
	unsigned char ipv6[IPV6_BYTE_LENGTH];
} Client;

typedef struct {
	PDQ *pdq;
	smdb *route_map;
	smdb *access_map;
	mcc_handle *mcc;
} Worker;

typedef char (session_id)[20];

#include "reply.h"

#define SESS_GET_MCC(sess)		((Worker *) ((sess)->session->worker->data))->mcc;

struct smtpf {
	ServerSession *session;
# define iface	session->iface
# define long_id session->id_log
	time_t start;
	time_t last_mark;
	time_t last_test;
	Command *state;
	Command *helo_state;
	struct {
		Reply *delayed;
		Reply *immediate;
	} response;
	JMP_BUF on_error;
	int smtp_code;
#ifdef OLD_SMTP_ERROR_CODES
	int smtp_error;
#endif
#ifdef ENABLE_LINT
	Reply *lint_replies;
#endif
	PDQ *pdq;			/* OLD_SERVER_MODEL, copy */
	smdb *route_map;        	/* OLD_SERVER_MODEL, copy */
	smdb *access_map;       	/* OLD_SERVER_MODEL, copy */
	char *last_reply;
	Message msg;
	Client client;
	long input_length;
	long max_concurrent;
	char input[SMTP_TEXT_LINE_LENGTH+1];
	char reply[SMTP_TEXT_LINE_LENGTH+1];
};

#ifdef __unix__
extern uid_t ruid;
extern uid_t euid;
#endif

#include "options.h"
#include "verbose.h"
#include "cache.h"
#include "stats.h"
#include "route.h"
#include "filter.h"
#include "latency.h"
#include "lickey.h"
#include "summary.h"

extern unsigned rand_seed;
extern int parse_path_flags;

extern char *route_map_path;
extern char *access_map_path;

extern const char smtpf_built[];
extern volatile unsigned long connections_per_second;

extern struct command state0[];
extern struct command stateHelo[];
extern struct command stateEhlo[];
extern struct command stateMail[];
extern struct command stateRcpt[];
extern struct command stateData[];
extern struct command stateQuit[];
extern struct command stateSink[];

extern int cmdData(Session *sess);
extern int cmdDrop(Session *sess);
extern int cmdUnknown(Session *sess);
extern int cmdOutOfSequence(Session *sess);
extern int cmdTryAgainLater(Session *sess);
extern int cmdReject(Session *sess);
extern int getReceivedHeader(Session *sess, char *buffer, size_t size);
extern void sendDSN(Session *sess, Connection *fwd);

extern int send_report(Session *sess, const char *subj, const char  *fmt, ...);
extern int send_report_v(Session *sess, const char *subj, const char  *fmt, va_list args);

extern int mxPrint(Session *sess, Connection *relay, const char *line, size_t length);
extern int mxResponse(Session *sess, Connection *relay);
extern int mxCommand(Session *sess, Connection *relay, const char *line, int expect);
extern Socket2 *mxOpen(Session *sess, const char *domain, Vector hosts);
extern Socket2 *mxConnect(Session *sess, const char *domain, is_ip_t is_ip_mask);

/* Used only for constant strings. The C compiler can compute the string
 * length for us. Nice little performance boost avoiding many strlen()s.
 */
#define SENDCLIENT(sess, line)		sendClient(sess, line, sizeof (line)-1)

extern size_t smtpGetReplyCodes(const char *line, char *buffer, size_t size);
extern int sendClientReply(Session *sess, const char *fmt, ...);
extern int sendClient(Session *sess, const char *line, size_t length);
extern void sessionReset(Session *sess);

extern int isIPv4InClientName(const char *client_name, unsigned char *ipv4);

extern void _atExitCleanUp(void);
extern void atExitCleanUp(void);
extern int dropPrivilages(void);
extern int getMyDetails(void);

extern long addPtrOrIpSuffix(Session *sess, char *buffer, long size);
extern long headerFind(Vector headers, const char *name, char **header);
extern void headerAddPrefix(Session *sess, const char *name, const char *prefix);
extern void headerReplace(Vector headers, const char *hdr_name, char *replacement);
extern int headerRemove(Vector headers, const char *name);
extern void keepAlive(Session *sess);

/***********************************************************************
 ***
 ***********************************************************************/

extern int pid_fd;
extern Server server;
extern ServerSignals signals;
extern int internal_restart;
extern void serverPrintVersion(void);
extern void serverPrintInfo(void);
extern void serverNumbers(Server *server, unsigned numbers[2]);

extern void welcomeInit(void);
extern void smtpRejectTextInit(void);

extern int writeInit(Session *null, va_list ignore);
extern int writeReplyLog(Session *sess, va_list args);

extern int forwardDot(Session *sess, va_list ignore);
extern int serverOptn0(Session *null, va_list ignore);
extern int serverOptn1(Session *null, va_list ignore);

extern int getRFC2821DateTime(struct tm *local, char *buffer, size_t size);
extern ParsePath *rcptFindFirstValid(Session *sess);
extern int welcome(Session *sess);

extern long smtpDataToDaemon(FILE *fp, Socket2 *daemon, long max_out, Vector headers, size_t eoh, unsigned char *tmpbuf, size_t tmpsiz);

extern Vector reject_msg;
extern Vector welcome_msg;

extern SmtpfCode tlsRcpt(Session *sess, va_list args);


#ifdef NOT_COMPLETE
/***********************************************************************
 *** Result List
 ***********************************************************************/

typedef struct result {
	struct result *next;
	const char *text;
} Result;

extern void resultPush(Result **head, const char *description);
extern void resultFree(void *_head);
extern void resultLog(Result *head);

#define RESULT_CLIENT(s, n)	resultPush(&(s)->client.results, (n))
#define RESULT_MAIL(s, n)	resultPush(&(s)->msg.mail_results, (n))
#define RESULT_RCPT(s, n)	resultPush(&(s)->msg.rcpt_results, (n))
#define RESULT_MSG(s, n)	resultPush(&(s)->msg.results, (n))
#endif

#ifdef  __cplusplus
}
#endif

#endif /* __smtpf_h__ */
