/*
 * filter.h
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __filter_h__
#define __filter_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 *** Filter API
 ***********************************************************************/

typedef size_t FilterContext;

typedef int (*filter_fn)(Session *sess, va_list args);

typedef struct {
	char *name;
	filter_fn handler;
} FilterHandler;

#define FILTER_TABLE_BEGIN(n)	{ #n, NULL }
#define FILTER_HANDLER(fn)	{ #fn, fn }
#define FILTER_TABLE_END	{ NULL, NULL }

extern Verbose verb_timers;

/**
 * Number of extra bytes to allocate with a Session for registered filters.
 */
extern size_t filter_context_size;

/**
 * Registration. Each filter should register options, verbose flags,
 * stats counters, and contexts they require. Any errors should be
 * written to standard error and exit(1) called. This is called in
 * main() before the options are parsed.
 *
 * @param sess
 *	Always NULL.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Always SMTPF_CONTINUE.
 *
 * @example
 *	filterRun(NULL, filter_register_table)
 */
extern FilterHandler filter_register_table	[];

/**
 * Program Initialisation. This is called in serverMain(). Any errors
 * should be written to the system log and exit(1) called.
 *
 * @param sess
 *	Always NULL.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Ignored.
 *
 * @example
 *	filterRun(NULL, filter_init_table)
 */
extern FilterHandler filter_init_table	[];	/* int fn(sess, void) */

/**
 * Program Termination. Each filter should release any global data
 * structures and files. Any errors should be written to the system
 * log.
 *
 * @param sess
 *	Always NULL.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Ignored.
 *
 * @example
 *	filterRun(NULL, filter_fini_table)
 */
extern FilterHandler filter_fini_table	[];	/* int fn(sess, void) */

/**
 * Called in cache_gc_thread() just before garbage collection of expired
 * rows from the cache. Can be used by modules to prepocess certain row
 * types before the general expire.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Passed an "mcc_handle *" context and a "time_t *" referencing
 *	the timestamp in seconds when the GC run began.
 *
 * @return
 *	Always returns SMTPF_TEMPFAIL.
 *
 * @example
 *	mcc_handle *mcc;
 *	time_t *time_now;
 *
 *	filterRun(NULL, filter_cache_gc_table, mcc, time_now)
 */
extern FilterHandler filter_cache_gc_table[];

/**
 * Reset or adjust options after OPTN command.
 *
 * @param sess
 *	Always NULL.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Ignored.
 *
 * @example
 *	filterRun(NULL, filter_optn_table)
 */
extern FilterHandler filter_optn_table	[];	/* int fn(sess, void) */

/**
 * Server listener loop just after a client connection has been
 * accepted.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_accept_table)
 */
extern FilterHandler filter_accept_table	[];	/* int fn(sess, void) */

/**
 * Start of service thread, after client IP tests and before welcome
 * banner and command input loop.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_connect_table)
 */
extern FilterHandler filter_connect_table	[];	/* int fn(sess, void) */

/**
 * Called for NOOP, HELP, unknown command, missing argument.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_idle_table)
 */
extern FilterHandler filter_idle_table	[];	/* int fn(sess, void) */

/**
 * Called in sendClient() just before the a reply is sent to the
 * client. Intended as a means to do any special logging, modify
 * the reply, and/or take additional action based on the reply.
 *
 * The reply (and length) may be replaced by an alternative one.
 * The original reply string must not be modified; instead a copy
 * must be made, altered, and passed back via the "const char **"
 * reply and "size_t *" reply_length pointer arguments.
 *
 * If a module allocates memory for a new reply, it must save the
 * pointer in its own context. A call to filter_reply_clean_table
 * is made after the reply is sent so that the module can then
 * free the memory.
 *
 * Alternatively a module could define SMTP_REPLY_LINE_LENGTH+1
 * sized buffer in its context and use that to make a working copy
 * and alterations. The buffer would be allocated and deallocated
 * with the session thread and reused for each reply sent.
 *
 * Currently as of 2.0.54, 4xy and 5xy replies passed to sendClient()
 * are a single line prior to any appending of a multiline message as
 * given by the smtp-reject-file. However, some 2xy replies, are
 * multiline replies: EHLO, HELP, CONN, STAT, OPTN, VERB. With the
 * addition of the reply_log and reply_clean handlers, the code for
 * smtp-reject-file could be converted into a module that would change
 * single line 5xy replies into 5xy multlline replies. Therefore a
 * module must be prepared for this.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	A "const char **" of the pointer to the reply line to be sent,
 *	and a "size_t *" of the length of the reply line. Both can be
 * 	altered. See above.
 *
 * @return
 *	Always returns SMTPF_CONTINUE.
 *
 * @example
 *	const char ** reply;
 *	size_t * reply_length;
 *
 *	filterRun(sess, filter_reply_log_table, reply, reply_length)
 */
extern FilterHandler filter_reply_log_table[];

/**
 * Called ins sendClient() after the reply has been sent to allow
 * modules to clean up any dynamic memory assigned for replies.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Always returns SMTPF_TEMPFAIL.
 *
 * @example
 *	filterRun(sess, filter_reply_clean_table)
 */
extern FilterHandler filter_reply_clean_table[];

/**
 * Called when the connection is dropped for any reason. Intended as
 * a means to take additional action based on this result.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Always returns SMTPF_DROP.
 *
 * @example
 *	filterRun(sess, filter_drop_table)
 */
extern FilterHandler filter_drop_table	[];

/**
 * Called for HELO, EHLO.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	A "const char *" of the HELO argument.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	const char *helo_arg;
 *
 *	filterRun(sess, filter_helo_table, "helo.example.com")
 */
extern FilterHandler filter_helo_table	[];	/* int fn(sess, const char *helo) */

/**
 * Called for RSET.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_rset_table)
 */
extern FilterHandler filter_rset_table	[];	/* int fn(sess, void) */

/**
 * Called for MAIL FROM:. Starts a new transaction following any RSET,
 * HELO, or EHLO (the latter two behave like RSET). Any previous mail
 * transaction data should be released and reinitialised.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	A "ParsePath *" generated from the MAIL FROM: argument.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_mail_table, mail_path)
 */
extern FilterHandler filter_mail_table	[];	/* int fn(sess, ParsePath *mail) */

/**
 * Called for RCPT TO:.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	A "ParsePath *" generated from the RCPT TO: argument.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_rcpt_table, rcpt_path)
 */
extern FilterHandler filter_rcpt_table	[];	/* int fn(sess, ParsePath *rcpt) */

/**
 * Called for DATA.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_data_table)
 */
extern FilterHandler filter_data_table	[];	/* int fn(sess, void) */

/**
 * Called after filter_data_table.for SMTPF_ACCEPT or SMTPF_CONTINUE
 * results in order to initialise modules, like anti-viurs, which
 * are always applied, even for white listed content.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Ignored.
 *
 * @example
 *	(void) filterRun(sess, filter_data_init_table)
 */
extern FilterHandler filter_data_init_table	[];	/* void fn(sess, void) */

/**
 * Called after the first chunk of message content has been received
 * and the original headers parsed into a Vector of char *.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	A "Vector" of char * strings containing all the heders. Headers
 *	may be inserted, appended, removed, or modified. Later filters
 *	will see the changes of earlier filters.
 *
 * @return
 *	Return an SMTPF_CONTINUE or SMTPF_DROP code. All other results
 *	will be held until after the final dot and before the filter_dot
 *	handlers are called.
 *
 * @example
 *	filterRun(sess, filter_headers_table, vector_of_headers)
 */
extern FilterHandler filter_headers_table	[];	/* int fn(sess, Vector headers) */

/**
 * Called after each chunk of message content has been received. For
 * the first chunk, the pointer given is set to first octet following
 * the end of headers.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	A "unsigned char *" to the start of the data buffer and a
 *	"size_t" for the length of data in the buffer.
 *
 * @return
 *	Return an SMTPF_CONTINUE or SMTPF_DROP code. All other results
 *	will be held until after the final dot and before the filter_dot
 *	handlers are called.
 *
 * @example
 *	filterRun(sess, filter_content_table, chunk, size)
 */
extern FilterHandler filter_content_table	[];	/* int fn(sess, unsigned char *chunk, size_t size) */

/**
 * Called following the end-of-message dot, but before the dot has been
 * forwarded. If the message is discarded, rejected, or temp.failed then
 * the connections to the forward hosts are dropped in order not to complete
 * the transaction.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Return an SMTPF_* code. If a filter is going to SMTPF_TEMPFAIL,
 *	SMTPF_REJECT, SMTPF_DROP, SMTPF_REJECT_POLICY, or SMTPF_DROP_POLICY,
 *	then a reply should be queued.
 *
 * @example
 *	filterRun(sess, filter_dot_table)
 */
extern FilterHandler filter_dot_table	[];	/* int fn(sess, void) */

/**
 * End of service thread. Any per session and per transaction data should
 * be released. Note that these handlers can be called in the event of an
 * early end to the session, so care should be taken to only access and
 * release data that has been properly initialised.
 *
 * @param sess
 *	A pointer to an initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Ignored.
 *
 * @example
 *	filterRun(sess, filter_close_table)
 */
extern FilterHandler filter_close_table	[];	/* int fn(sess, void) */

/*
extern int 	filterInit(void);
extern void 	filterFini(void);
extern int 	filterConnect(Session *sess);
extern int 	filterIdle(Session *sess);
extern int 	filterHelo(Session *sess);
extern void	filterRset(Session *sess);
extern int 	filterMail(Session *sess);
extern int 	filterRcpt(Session *sess, Rcpt *rcpt);
extern int 	filterData(Session *sess);
extern int 	filterContent(Session *sess, unsigned char *chunk, long size);
extern int 	filterDot(Session *sess);
extern void	filterClose(Session *sess);
*/

extern void filterInit(void);
extern void filterFini(void);
extern void filterRegister(void);
extern int filterRun(Session *sess, FilterHandler table[], ...);

extern FilterContext filterRegisterContext(size_t size);
extern size_t filterSizeOfContext(FilterContext ctx);
extern void *filterGetContext(Session *sess, FilterContext ctx);
extern void filterClearContext(Session *sess, FilterContext ctx);
extern void filterClearAllContexts(Session *sess);

/***********************************************************************
 *** Filter Modules
 ***********************************************************************/

#include "access.h"
#ifdef FILTER_CLAMD
# include "clamd.h"
#endif
#ifdef FILTER_AVASTD
# include "avastd.h"
#endif
#ifdef FILTER_FPSCAND
# include "fpscand.h"
#endif
#ifdef FILTER_SAVDID
# include "savdid.h"
#endif
#ifdef FILTER_ATTACHMENT
# include "attachment.h"
#endif
#ifdef FILTER_CLI
# include "cli.h"
#endif
#ifdef FILTER_CLICK
# include "click.h"
#endif
#ifdef FILTER_CONCURRENT
# include "concurrent.h"
#endif
#ifdef FILTER_DIGEST
# include "digest.h"
#endif
#ifdef FILTER_DUPMSG
# include "dupmsg.h"
#endif
#ifdef FILTER_EMEW
# include "emew.h"
#endif
#ifdef FILTER_FREEMAIL
# include "freemail.h"
#endif
#ifdef FILTER_FOUR21
# include "four21.h"
#endif
#ifdef FILTER_GREY
# include "grey.h"
#endif
#include "misc.h"
#ifdef FILTER_MSG_LIMIT
# include "msglimit.h"
#endif
#ifdef FILTER_NULL
# include "null.h"
#endif
#include "rate.h"
#ifdef FILTER_RBL
# include "rbl.h"
#endif
#ifdef FILTER_PAD
# include "pad.h"
#endif
#ifdef FILTER_P0F
# include "p0f.h"
#endif
#ifdef FILTER_SAV
# include "sav.h"
#endif
#ifdef FILTER_SAVE
# include "save.h"
#endif
#ifdef FILTER_SIZE
# include "siq.h"
#endif
#ifdef FILTER_SIZE
# include "size.h"
#endif
#if defined(FILTER_SPAMD) && !defined(FILTER_SPAMD2)
# include "spamd.h"
#endif
#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
# include "spamd2.h"
#endif
#ifdef FILTER_SPF
# include "spf.h"
#endif
#ifdef FILTER_TIMELIMIT
# include "timelimit.h"
#endif
#ifdef FILTER_URIBL
# include "uribl.h"
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __filter_h__ */
