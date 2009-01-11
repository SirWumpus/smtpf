/*
 * filter2.c
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

#include <ctype.h>
#include <com/snert/lib/mail/spf.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/sys/Time.h>


/***********************************************************************
 *** Filter Driver
 ***********************************************************************/

static const char usage_smtp_delay_checks[] =
  "Postpone any policy based 5xy rejections until after the first RCPT\n"
"# has been specified. Temporary failures and rejections due to syntax\n"
"# or protocol errors are still reported immediately. This allows\n"
"# recipient white-listing to override policy rejections based on\n"
"# connection, HELO, AUTH, or MAIL arguments.\n"
"#"
;

Option optSmtpDelayChecks	= { "smtp-delay-checks",	"-",	usage_smtp_delay_checks };

/***********************************************************************
 *** Reserved Filter Space
 ***********************************************************************/

/*
 * Align reserved filter space on an integer type boundary, which
 * will be a power of 2.
 */
#define ALIGNMENT_TYPE		size_t
#define ALIGNMENT_SIZE		sizeof (ALIGNMENT_TYPE)
#define ALIGNMENT_MASK		(ALIGNMENT_SIZE-1)
#define ALIGNMENT_OVERHEAD(s)	(((s) | ALIGNMENT_MASK) + 1 + ALIGNMENT_SIZE)

/*
 * Number of extra bytes to allocate with a Session for registered filters.
 */
size_t filter_context_size = ALIGNMENT_OVERHEAD(sizeof (Session)) - sizeof (Session);

/*
 * A map of filter contexts. See filterSizeOfContext().
 */
static unsigned char *filter_context_sizeof;

Verbose verb_timers = { { "timers", "-", "" } };

/***********************************************************************
 *** Filter Driver
 ***********************************************************************/

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
FilterHandler filter_register_table	[] = {
	FILTER_TABLE_BEGIN(register),
	FILTER_HANDLER(optionsRegister0),
	FILTER_HANDLER(verboseRegister0),
	FILTER_HANDLER(statsRegister0),
	FILTER_HANDLER(accessRegister),
#ifdef FILTER_AVASTD
	FILTER_HANDLER(avastdRegister),
#endif
	FILTER_HANDLER(cacheRegister),
#ifdef FILTER_CLI
	FILTER_HANDLER(cliRegister),
#endif
#ifdef FILTER_CLICK
	FILTER_HANDLER(clickRegister),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdRegister),
#endif
#ifdef FILTER_CONCURRENT
	FILTER_HANDLER(concurrentRegister),
#endif
#ifdef FILTER_DIGEST
	FILTER_HANDLER(digestRegister),
#endif
#ifdef FILTER_RBL
	FILTER_HANDLER(rblRegister),
#endif
#ifdef FILTER_DUPMSG
	FILTER_HANDLER(dupmsgRegister),
#endif
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewRegister),
#endif
#ifdef FILTER_ATTACHMENT
	FILTER_HANDLER(attachmentRegister),
#endif
#ifdef FILTER_FOUR21
	FILTER_HANDLER(four21Register),
#endif
#ifdef FILTER_FPSCAND
	FILTER_HANDLER(fpscandRegister),
#endif
#ifdef FILTER_SAVDID
	FILTER_HANDLER(savdidRegister),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyRegister),
#endif
#ifdef FILTER_MISC
	FILTER_HANDLER(miscRegister),
#endif
#ifdef FILTER_MSG_LIMIT
	FILTER_HANDLER(msgLimitRegister),
#endif
#ifdef FILTER_NULL
	FILTER_HANDLER(nullRegister),
#endif
#ifdef FILTER_PAD
	FILTER_HANDLER(padRegister),
#endif
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	FILTER_HANDLER(p0fRegister),
#endif
	FILTER_HANDLER(rateRegister),
#ifdef FILTER_SAV
	FILTER_HANDLER(savRegister),
#endif
#ifdef FILTER_SAVE
	FILTER_HANDLER(saveRegister),
#endif
#ifdef FILTER_SIQ
	FILTER_HANDLER(siqRegister),
#endif
#ifdef FILTER_SIZE
	FILTER_HANDLER(sizeRegister),
#endif
#if defined(FILTER_SPAMD) || defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdRegister),
#endif
#ifdef FILTER_SPF
	FILTER_HANDLER(spfRegister),
#endif
#ifdef FILTER_TIMELIMIT
	FILTER_HANDLER(timeLimitRegister),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriRegister),
#endif
	FILTER_HANDLER(optionsRegister1),
	FILTER_TABLE_END
};

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
FilterHandler filter_init_table	[] = {
	FILTER_TABLE_BEGIN(init),
	FILTER_HANDLER(routeInit),
	FILTER_HANDLER(replyInit),
	FILTER_HANDLER(rateInit),
#ifdef FILTER_AVASTD
	FILTER_HANDLER(avastdInit),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdInit),
#endif
#ifdef FILTER_FPSCAND
	FILTER_HANDLER(fpscandInit),
#endif
#ifdef FILTER_SAVDID
	FILTER_HANDLER(savdidInit),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliInit),
#endif
#ifdef FILTER_CLICK
	FILTER_HANDLER(clickInit),
#endif
#ifdef FILTER_CONCURRENT
	FILTER_HANDLER(concurrentInit),
#endif
#ifdef FILTER_DIGEST
	FILTER_HANDLER(digestInit),
#endif
#ifdef FILTER_RBL
	FILTER_HANDLER(dnswlInit),
	FILTER_HANDLER(dnsglInit),
	FILTER_HANDLER(rblInit),
#endif
	FILTER_HANDLER(accessInit),
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewInit),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyInit),
#endif
#ifdef FILTER_MSG_LIMIT
	FILTER_HANDLER(msgLimitInit),
#endif
#ifdef FILTER_MISC
	FILTER_HANDLER(miscInit),
#endif
#ifdef FILTER_NULL
	FILTER_HANDLER(nullInit),
#endif
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	FILTER_HANDLER(p0fInit),
#endif
#ifdef FILTER_SAV
	FILTER_HANDLER(savInit),
#endif
#ifdef FILTER_SAVE
	FILTER_HANDLER(saveInit),
#endif
#ifdef FILTER_SIQ
	FILTER_HANDLER(siqInit),
#endif
#if defined(FILTER_SPAMD) || defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdInit),
#endif
#ifdef FILTER_SPF
	FILTER_HANDLER(spfInit),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblInit),
#endif
	FILTER_HANDLER(writeInit),
	FILTER_TABLE_END
};

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
FilterHandler filter_fini_table	[] = {
	FILTER_TABLE_BEGIN(fini),
	FILTER_HANDLER(routeFini),
	FILTER_HANDLER(rateFini),
#ifdef FILTER_CONCURRENT
	FILTER_HANDLER(concurrentFini),
#endif
#ifdef FILTER_DIGEST
	FILTER_HANDLER(digestFini),
#endif
#ifdef FILTER_RBL
	FILTER_HANDLER(dnswlFini),
	FILTER_HANDLER(dnsglFini),
	FILTER_HANDLER(rblFini),
#endif
	FILTER_HANDLER(accessFini),
#ifdef FILTER_GREY
	FILTER_HANDLER(greyFini),
#endif
#ifdef FILTER_MSG_LIMIT
	FILTER_HANDLER(msgLimitFini),
#endif
#ifdef FILTER_NULL
	FILTER_HANDLER(nullFini),
#endif
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	FILTER_HANDLER(p0fFini),
#endif
#ifdef FILTER_SIQ
	FILTER_HANDLER(siqFini),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblFini),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_cache_gc_table[] = {
	FILTER_TABLE_BEGIN(cache_gc),
#ifdef ENABLE_GREY_TO_BLACK
	FILTER_HANDLER(greyGc),
#endif
	/* This must be last as it will delete all expireded rows. */
	FILTER_HANDLER(cacheGc),
	FILTER_TABLE_END
};

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
FilterHandler filter_optn_table	[] = {
	FILTER_TABLE_BEGIN(optn),
	FILTER_HANDLER(serverOptn0),
#ifdef FILTER_AVASTD
	FILTER_HANDLER(avastdOptn),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdOptn),
#endif
#ifdef FILTER_FPSCAND
	FILTER_HANDLER(fpscandOptn),
#endif
#ifdef FILTER_SAVDID
	FILTER_HANDLER(savdidOptn),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliOptn),
#endif
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	FILTER_HANDLER(p0fOptn),
#endif
#ifdef FILTER_PAD
	FILTER_HANDLER(padOptn),
#endif
#if defined(FILTER_SPAMD) || defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdOptn),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblOptn),
#endif
#ifdef ENABLE_LINT
	FILTER_HANDLER(serverOptn1),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_reply_log_table[] = {
	FILTER_TABLE_BEGIN(reply_log),
	FILTER_HANDLER(smtpReplyLog),
#ifdef FILTER_DUPMSG
	FILTER_HANDLER(dupmsgReplyLog),
#endif
#ifdef FILTER_CLICK
	FILTER_HANDLER(clickReplyLog),
#endif
#ifdef FILTER_PAD
	FILTER_HANDLER(padReplyLog),
#endif
	/* This MUST be last as the reply is actually sent at this point. */
	FILTER_HANDLER(writeReplyLog),
	FILTER_TABLE_END
};

/**
 * Called in sendClient() after the reply has been sent to allow
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
FilterHandler filter_reply_clean_table[] = {
	FILTER_TABLE_BEGIN(reply_clean),
	FILTER_TABLE_END
};

/**
 * Called when the connection is dropped for any reason.
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
FilterHandler filter_drop_table	[] = {
	FILTER_TABLE_BEGIN(drop),
#ifdef FILTER_AUTO
	FILTER_HANDLER(autoDrop),
#endif
	FILTER_TABLE_END
};

/**
 * New server thread.
 *
 * @param sess
 *	A pointer to a partialy initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Always returns SMTPF_CONTINUE.
 *
 * @example
 *	filterRun(sess, filter_thread_create_table)
 */
FilterHandler filter_thread_create_table	[] = {
	FILTER_TABLE_BEGIN(thread_create),
#ifdef NOT_YET
	FILTER_HANDLER(routeThreadCreate),
	FILTER_HANDLER(accessThreadCreate),
#endif
	FILTER_TABLE_END
};

/**
 * New server thread.
 *
 * @param sess
 *	A pointer to a partialy initialised session structure.
 *
 * @param args
 *	Always empty.
 *
 * @return
 *	Always returns SMTPF_CONTINUE.
 *
 * @example
 *	filterRun(sess, filter_thread_create_table)
 */
FilterHandler filter_thread_free_table	[] = {
	FILTER_TABLE_BEGIN(thread_free),
#ifdef NOT_YET
	FILTER_HANDLER(accessThreadFree),
	FILTER_HANDLER(routeThreadFree),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_accept_table	[] = {
	FILTER_TABLE_BEGIN(accept),
	FILTER_HANDLER(replyAccept),
	FILTER_HANDLER(rateAccept),
	FILTER_TABLE_END
};

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
FilterHandler filter_connect_table	[] = {
	FILTER_TABLE_BEGIN(connect),
	FILTER_HANDLER(rateConnect),
#ifdef FILTER_CONCURRENT
	FILTER_HANDLER(concurrentConnect),
#endif
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	FILTER_HANDLER(p0fConnect),
#endif
	/* These have to be called now in the event we return
	 * with a drop and jump straight to filterClose() since
	 * they have to close files or release memory.
	 */
#ifdef FILTER_SIZE
	FILTER_HANDLER(sizeConnect),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdConnect),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliConnect),
#endif
#ifdef FILTER_MSG_LIMIT
	FILTER_HANDLER(msgLimitConnect),
#endif
#ifdef FILTER_SAVE
	FILTER_HANDLER(saveConnect),
#endif
#if defined(FILTER_SPAMD) && !defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdConnect),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblConnect),
#endif
	FILTER_HANDLER(accessConnect),
#ifdef FILTER_RBL
	FILTER_HANDLER(dnswlConnect),
	FILTER_HANDLER(dnsglConnect),
#endif
#ifdef FILTER_AUTO
	FILTER_HANDLER(autoConnect),
#endif
#ifdef FILTER_FOUR21
	FILTER_HANDLER(four21Connect),
#endif
#ifdef FILTER_MISC
	FILTER_HANDLER(noPtrConnect),
	FILTER_HANDLER(ipInPtrConnect),
#endif
#ifdef FILTER_RBL
	FILTER_HANDLER(rblConnect),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblPtrConnect),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_idle_table	[] = {
	FILTER_TABLE_BEGIN(idle),
#ifdef FILTER_MISC
	FILTER_HANDLER(idleRetestIdle),
#endif
	FILTER_HANDLER(accessIdle),
#ifdef FILTER_RBL
	FILTER_HANDLER(rblIdle),
#endif
	FILTER_TABLE_END
};

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
 *	filterRun(sess, filter_helo_table, "helo.example.com")
 */
FilterHandler filter_helo_table	[] = {
	FILTER_TABLE_BEGIN(helo),
	FILTER_HANDLER(accessHelo),
#ifdef FILTER_MISC
	FILTER_HANDLER(heloSyntaxHelo),
	FILTER_HANDLER(heloTestsHelo),
	FILTER_HANDLER(heloIsPtrHelo),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblHeloHelo),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_rset_table	[] = {
	FILTER_TABLE_BEGIN(rset),
	FILTER_HANDLER(replyRset),
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdRset),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliRset),
#endif
#ifdef FILTER_DIGEST
	FILTER_HANDLER(digestRset),
#endif
#ifdef FILTER_DUPMSG
	FILTER_HANDLER(dupmsgRset),
#endif
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewRset),
#endif
#ifdef FILTER_ATTACHMENT
	FILTER_HANDLER(attachmentRset),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyRset),
#endif
#ifdef FILTER_SIQ
	FILTER_HANDLER(siqRset),
#endif
#ifdef FILTER_SAVE
	FILTER_HANDLER(saveRset),
#endif
#ifdef FILTER_SIZE
	FILTER_HANDLER(sizeRset),
#endif
#if defined(FILTER_SPAMD) || defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdRset),
#endif
#ifdef FILTER_SPF
	FILTER_HANDLER(spfRset),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblRset),
#endif
	FILTER_TABLE_END
};

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
 *	filterRun(sess, filter_mail_table, mail_path, Vector of parameters)
 */
FilterHandler filter_mail_table	[] = {
	FILTER_TABLE_BEGIN(mail),
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewMailRcpt),
#endif
#ifdef FILTER_SIZE
	FILTER_HANDLER(sizeMail),
#endif
#ifdef FILTER_SPF
	/* SPF based rejections happen at RCPT time. However),
	 * we can use the SPF result for a new access-map
	 * action.
	 */
	FILTER_HANDLER(spfMail),
#endif
	FILTER_HANDLER(accessMail),
#ifdef FILTER_CLICK
	FILTER_HANDLER(clickMail),
#endif
#ifdef FILTER_MSG_LIMIT
	FILTER_HANDLER(msgLimitMail),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblPtrMail),
#endif
#ifdef FILTER_MISC
	FILTER_HANDLER(heloTestsMail),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblHeloMail),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblMailMail),
#endif
#ifdef FILTER_MISC
	FILTER_HANDLER(mailTestsMail),
#endif
#ifdef FILTER_MISC
	/* These come after mailTestsMail where CLIENT_IS_MX might be set. */
	FILTER_HANDLER(noPtrMail),
	FILTER_HANDLER(ipInPtrMail),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_rcpt_table	[] = {
	FILTER_TABLE_BEGIN(rcpt),
#ifdef FILTER_TIMELIMIT
	FILTER_HANDLER(timeLimitRcpt),
#endif
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewMailRcpt),
#endif
#ifdef FILTER_SIZE
	FILTER_HANDLER(sizeRcpt),
#endif
	FILTER_HANDLER(accessRcpt),
#ifdef FILTER_CLICK
	/* A previously white listed connection or sender means we'd
	 * by-pass the remaining filters. Therefore repeated attempts
	 * from sender to a CLICK- address will result in user unknown
	 * from the forward/call-ahead host. If we move this test
	 * ahead of accessRcpt), then a successful CLICK- validation
	 * could by-pass local access-map blacklist entries that must
	 * take precedence.
	 */
	FILTER_HANDLER(clickRcpt),
#endif
#if defined(FILTER_GREY) && defined(ENABLE_GREY_DNSBL_RESET)
	FILTER_HANDLER(greyRcpt),
#endif
#ifdef FILTER_MISC
	FILTER_HANDLER(rcptTestsRcpt),
	FILTER_HANDLER(heloIsPtrRcpt),
#endif
#ifdef FILTER_SPF
	FILTER_HANDLER(spfRcpt),
#endif
#ifdef FILTER_MSG_LIMIT
	FILTER_HANDLER(msgLimitRcpt),
#endif
#if defined(FILTER_NULL) && !defined(FILTER_NULL_DEFER)
	FILTER_HANDLER(nullRcpt),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_data_table	[] = {
	FILTER_TABLE_BEGIN(data),
	FILTER_HANDLER(replyData),
	FILTER_HANDLER(accessData),
#ifdef FILTER_SAV
	/* NOTE that savData can return SMTPF_SKIP_NEXT to by-pass
	 * traditional grey-listing), which must be the next test
	 * to follow. SAV does not by-pass grey-content.
	 */
	FILTER_HANDLER(savData),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyData),
#endif
	FILTER_HANDLER(accessData),
#if defined(FILTER_NULL) && defined(FILTER_NULL_DEFER)
	FILTER_HANDLER(nullData),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblData),
#endif
#ifdef FILTER_SIQ
	FILTER_HANDLER(siqData),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliData),
#endif
#ifdef ENABLE_LINT
	FILTER_HANDLER(replyData1),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_data_init_table[] = {
	FILTER_TABLE_BEGIN(data-init),
#ifdef __FILTER_CLAMD__see_clamdHeaders
	/* Always virus scan mail), even for white listed messages. */
	FILTER_HANDLER(clamdData),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_headers_table	[] = {
	FILTER_TABLE_BEGIN(headers),
	FILTER_HANDLER(summaryHeaders),
#ifdef FILTER_SAVE
	/* Save handlers before anything that might temp. fail,
	 * reject, or discard.
	 */
	FILTER_HANDLER(saveHeaders),
#endif
#ifdef FILTER_DUPMSG
	FILTER_HANDLER(dupmsgHeaders),
#endif
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	FILTER_HANDLER(p0fHeaders),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyHeaders),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdHeaders),
#endif
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewHeaders),
#endif
	FILTER_HANDLER(accessHeaders),
	/* Functions that add headers called first. */
#ifdef FILTER_RBL
	FILTER_HANDLER(rblHeaders),
#endif
#ifdef FILTER_SIQ
	FILTER_HANDLER(siqHeaders),
#endif
#ifdef FILTER_SPF
	FILTER_HANDLER(spfHeaders),
#endif
	/* Functions that reject based on headers. */
#ifdef FILTER_MISC
	FILTER_HANDLER(rfc2822Headers),
#endif
#ifdef FILTER_ATTACHMENT
	FILTER_HANDLER(attachmentHeaders),
#endif
#ifdef FILTER_DIGEST
	FILTER_HANDLER(digestHeaders),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblHeaders),
#endif
	/* Functions that pass headers to daemons. */
#ifdef FILTER_CLI
	FILTER_HANDLER(cliHeaders),
#endif
#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdHeaders),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_content_table	[] = {
	FILTER_TABLE_BEGIN(content),
#ifdef FILTER_SAVE
	/* Save handlers before anything that might temp. fail,
	 * reject, or discard.
	 */
	FILTER_HANDLER(saveContent),
#endif
	/* Can short-circuit filterRun if there is an immediate
	 * reply already set. See FILTER_*_CONTENT_SHORTCUT.
	 */
	FILTER_HANDLER(replyContent),
#ifdef FILTER_DUPMSG
	FILTER_HANDLER(dupmsgContent),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdContent),
#endif
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewContent),
#endif
	FILTER_HANDLER(accessContent),
#ifdef FILTER_ATTACHMENT
	FILTER_HANDLER(attachmentContent),
#endif
#ifdef FILTER_DIGEST
	FILTER_HANDLER(digestContent),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblContent),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyContent),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliContent),
#endif
#if defined(FILTER_SPAMD) && !defined(FILTER_SPAMD2)
	/* This filter should be last in order to allow previous filters
	 * to reject the message and save an expensive connection to spamd.
	 */
	FILTER_HANDLER(spamdContent),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_dot_table	[] = {
	FILTER_TABLE_BEGIN(dot),
#ifdef FILTER_SAVE
	/* Save handlers before anything that might temp. fail,
	 * reject, or discard.
	 */
	FILTER_HANDLER(saveDot),
#endif
	/* Can short-circuit filterRun if there is an immediate
	 * reply already set. See FILTER_*_CONTENT_SHORTCUT.
	 */
	FILTER_HANDLER(replyDot),
#ifdef FILTER_DUPMSG
	FILTER_HANDLER(dupmsgDot),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdDot),
#endif
#ifdef FILTER_EMEW
	FILTER_HANDLER(emewDot),
#endif
#ifdef FILTER_SIZE
	FILTER_HANDLER(sizeDot),
#endif
#ifdef FILTER_AVASTD
	FILTER_HANDLER(avastdDot),
#endif
#ifdef FILTER_FPSCAND
	FILTER_HANDLER(fpscandDot),
#endif
#ifdef FILTER_SAVDID
	FILTER_HANDLER(savdidDot),
#endif
	FILTER_HANDLER(accessDot),
#if defined(FILTER_ATTACHMENT) && !defined(FILTER_ATTACHMENT_CONTENT_SHORTCUT)
	FILTER_HANDLER(attachmentDot),
#endif
#if defined(FILTER_DIGEST) && !defined(FILTER_DIGEST_CONTENT_SHORTCUT)
	FILTER_HANDLER(digestDot),
#endif
#if defined(FILTER_URIBL) && !defined(FILTER_URIBL_CONTENT_SHORTCUT)
	FILTER_HANDLER(uriblDot),
#endif
#if defined(FILTER_GREY) && !defined(FILTER_GREY_CONTENT_SHORTCUT)
	FILTER_HANDLER(greyDot),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliDot),
#endif
#if defined(FILTER_SPAMD) || defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdDot),
#endif
	FILTER_TABLE_END
};

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
FilterHandler filter_close_table	[] = {
	FILTER_TABLE_BEGIN(close),
	FILTER_HANDLER(replyClose),
#ifdef FILTER_FOUR21
	FILTER_HANDLER(four21Close),
#endif
#ifdef FILTER_CONCURRENT
	FILTER_HANDLER(concurrentClose),
#endif
#ifdef FILTER_CLAMD
	FILTER_HANDLER(clamdClose),
#endif
#ifdef FILTER_CLI
	FILTER_HANDLER(cliClose),
#endif
#ifdef FILTER_GREY
	FILTER_HANDLER(greyClose),
#endif
#ifdef FILTER_SAVE
	FILTER_HANDLER(saveClose),
#endif
#if defined(FILTER_SPAMD) && !defined(FILTER_SPAMD2)
	FILTER_HANDLER(spamdClose),
#endif
#ifdef FILTER_URIBL
	FILTER_HANDLER(uriblClose),
#endif
	FILTER_TABLE_END
};

/***********************************************************************
 *** Filter API
 ***********************************************************************/

/**
 * @note
 *	This function should only be called during filterInit().
 *
 * @param size
 *	Number of octets to allocate with the Session structure.
 *
 * @return
 *	An int aligned offset into the reserved filter space.
 *	Use filterGetContext() to convert this offset into
 *	a pointer to the reserved space.
 */
FilterContext
filterRegisterContext(size_t size)
{
	size_t aligned_size;
	size_t offset = filter_context_size;

	/* Adjust size of context space to be multiples of the ALIGNMENT_TYPE. */
	aligned_size = (size & ALIGNMENT_MASK) == 0 ? size : ALIGNMENT_OVERHEAD(size);

	filter_context_size = offset + aligned_size;

	/* Build map of reserved filter context space. */
	filter_context_sizeof = realloc(filter_context_sizeof, filter_context_size);
	if (filter_context_sizeof == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}

	/* The reserved contexts are aligned on an integer type and are
	 * at least as large as the integer type, so we can save the size
	 * of context at its start offset. See filterSizeOfContext().
	 */
	*((ALIGNMENT_TYPE *) &filter_context_sizeof[offset]) = size;

	return (FilterContext) offset;
}

void *
filterGetContext(Session *sess, FilterContext offset)
{
	if (offset == 0) {
		syslog(LOG_ERR, log_internal, LOG_ARGS(sess), FILE_LINENO, "filterGetContext", strerror(EINVAL), EINVAL);
		longjmp(sess->on_error, SMTPF_DROP);
	}

	return (char *) &sess[1] + offset;
}

size_t
filterSizeOfContext(FilterContext offset)
{
	return (size_t) *(ALIGNMENT_TYPE *) &filter_context_sizeof[offset];
}

void
filterClearContext(Session *sess, FilterContext offset)
{
	memset(filterGetContext(sess, offset), 0, filterSizeOfContext(offset));
}

void
filterClearAllContexts(Session *sess)
{
	memset(&sess[1], 0, filter_context_size);
}

void
filterRegister(void)
{
	/* Windows calls filterRegister twice, once for the service start or
	 * application -daemon mode, and again for ServiceMain +daemon mode.
	 * The service mode appears to be a separate process space, but
	 * we assert this by resetting the affects of filterRegister just
	 * to be sure.
	 */
	filter_context_size = ALIGNMENT_OVERHEAD(sizeof (Session)) - sizeof (Session);
	free(filter_context_sizeof);
	filter_context_sizeof = NULL;

	(void) filterRun(NULL, filter_register_table);
	verboseRegister(&verb_timers);
}

void
filterInit(void)
{
	(void) filterRun(NULL, filter_init_table);
}

void
filterFini(void)
{
	(void) filterRun(NULL, filter_fini_table);
}

int
filterRun(Session *sess, FilterHandler table[], ...)
{
	va_list args;
	char *table_name;
	int rc = SMTPF_CONTINUE;
	TIMER_DECLARE(mark);

	table_name = table->name;
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(360) "filterRun(%lx, %s)", sess == NULL ? SESSION_ID_ZERO : LOG_ARGS(sess), (long) sess, table_name);

	for (table++; table->name != NULL; table++) {
		if (rc == SMTPF_SKIP_NEXT) {
			rc = SMTPF_CONTINUE;
			continue;
		}

		if (verb_timers.option.value)
			TIMER_START(mark);
		va_start(args, table);
		rc = (*table->handler)(sess, args);
		va_end(args);

		if (verb_timers.option.value) {
			TIMER_DIFF(mark);
			if (TIMER_GE_CONST(diff_mark, 1, 0) || 1 < verb_timers.option.value)
				syslog(LOG_DEBUG, LOG_MSG(361) "filter-table=%s handler=%s time-elapsed=" TIMER_FORMAT, sess == NULL ? SESSION_ID_ZERO : LOG_ARGS(sess), table_name, table->name, TIMER_FORMAT_ARG(diff_mark));
		}

		switch (rc) {
		case SMTPF_CONTINUE:
			break;

		case SMTPF_ACCEPT:
		case SMTPF_GREY:
		case SMTPF_TEMPFAIL:
		case SMTPF_REJECT:
		case SMTPF_DISCARD:
		case SMTPF_DROP:
			/* Immediate action. */
			return rc;

		case SMTPF_DELAY|SMTPF_TEMPFAIL:
		case SMTPF_DELAY|SMTPF_SESSION|SMTPF_TEMPFAIL:
			/* Rejections based on policy, not syntax. */
			if (optSmtpDelayChecks.value)
				return SMTPF_CONTINUE;
			return SMTPF_TEMPFAIL;

		case SMTPF_DELAY|SMTPF_REJECT:
		case SMTPF_DELAY|SMTPF_SESSION|SMTPF_REJECT:
			/* Rejections based on policy, not syntax. */
			if (optSmtpDelayChecks.value)
				return SMTPF_CONTINUE;
			return SMTPF_REJECT;

		case SMTPF_DELAY|SMTPF_DROP:
		case SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP:
			/* Drops based on policy, not syntax. */
			if (optSmtpDelayChecks.value)
				return SMTPF_CONTINUE;
			return SMTPF_DROP;

		case SMTPF_SKIP_REMAINDER:
			/* Skip remainder of function table and return. */
			return SMTPF_CONTINUE;
		}
	}

	return SMTPF_CONTINUE;
}

