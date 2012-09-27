/*
 * reply.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __reply_h__
#define __reply_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define CRLF			"\x0D\x0A"
#define CRLF_LENGTH		(sizeof (CRLF)-1)

#define REPLY_SUBJECT_TAG	"[SUSPECT]"

extern const char crlf[];

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct reply {
	void (*free)(void *);
	SmtpfCode code;
	size_t size;
	size_t length;
	char *string;
	struct reply *next;
} Reply;

extern const char log_init[];
extern const char log_oom[];
extern const char log_internal[];
extern const char log_overflow[];
extern const char log_pipeline[];

extern const char log_cache_get[];
extern const char log_cache_put[];
extern const char log_cache_delete[];
extern const char log_cache_get_error[];
extern const char log_cache_put_error[];
extern const char log_cache_delete_error[];

#define LOG_CACHE_GET(p)		MCC_FMT_K_ARG(p), MCC_FMT_V_ARG(p)
#define LOG_CACHE_PUT(p)		LOG_CACHE_GET(p)
#define LOG_CACHE_DELETE(p)		MCC_FMT_K_ARG(p)
#define LOG_CACHE_GET_ERROR(p)		LOG_CACHE_DELETE(p)
#define LOG_CACHE_PUT_ERROR(p)		LOG_CACHE_PUT(p)
#define LOG_CACHE_DELETE_ERROR(p)	LOG_CACHE_DELETE(p)

extern const char msg_ok[];
extern const char msg_end[];
extern const char msg_proceed[];

extern const char msg_421_unavailable[];
extern const char msg_421_internal[];
extern const char msg_451_internal[];
extern const char msg_resources[];
extern const char msg_450_try_again[];
extern const char msg_451_try_again[];

extern const char msg_250_accepted[];
extern const char msg_550_rejected[];

extern Reply reply_ok;
extern Reply reply_end;
extern Reply reply_closing;
extern Reply reply_proceed;
extern Reply reply_no_reply;

extern Reply reply_unavailable;
extern Reply reply_internal;
extern Reply reply_resources;
extern Reply reply_try_again;


#define REPLY_CONST(c, m)		replyFmt(c, "%s", m)
#define REPLY_APPEND_CONST(r, m)	replyAppendFmt(r, "%s", m)
#define REPLY_PUSH(s, c, m)		replyPushMsg(s, c, m, strlen(m))
#define REPLY_PUSH_CONST(s, c, m)	replyPushMsg(s, c, m, sizeof (m)-1)

#define replyGetCode(r)			((r)->code & ~(SMTPF_DELAY|SMTPF_SESSION))
#define replySetCode(r, c)		if ((r) != NULL) (r)->code = c;
#define replyIsDelayed(r)		((r)->code & SMTPF_DELAY)
#define replyIsSession(r)		((r)->code & SMTPF_SESSION)
#define replyDefined(s)			((s)->response.immediate != NULL || (s)->response.delayed != NULL)

#ifndef replySetCode
extern void replySetCode(Reply *reply, int code);
#endif

extern void replyDelayFree(Session *sess);

/*
 * Create a reply with a constant message string.
 */
extern Reply *replyMsg(int code, const char *msg, size_t length);

/*
 * Create a reply with a variable length (max. 512 octets) message string.
 */
extern Reply *replyFmtV(int code, const char *fmt, va_list args);
extern Reply *replyFmt(int code, const char *fmt, ...);
extern Reply *replyAppendMsg(Reply *reply, const char *msg, size_t length);
extern Reply *replyAppendFmt(Reply *reply, const char *fmt, ...);

/*
 * Send an internal error reply to the client and throw
 * an exception (longjmp) to the current on_error point
 * to drop the client connection.
 */
extern void replyInternalError(Session *sess, const char *file, unsigned long lineno);
extern void replyResourcesError(Session *sess, const char *file, unsigned long lineno);

/*
 * Set the next reply to send.
 */
extern int replySetMsg(Session *sess, int code, const char *msg, size_t length);
extern int replySetFmtV(Session *sess, int code, const char *fmt, va_list args);
extern int replySetFmt(Session *sess, int code, const char *fmt, ...);
extern int replySet(Session *sess, Reply *reply);

/* Old implementation. */
#define replyPushMsg	replySetMsg
#define replyPushFmt	replySetFmt
#define replyPush	replySet

/*
 * Send the last reply to the client.
 */
extern int replySend(Session *sess);

/*
 * Query what the next reply to the client would be without
 * actually sending a reply. Used to check for previously
 * queued reject/drop responses.
 *
 * @param sess
 *	A session pointer.
 *
 * @param first_delayed
 *	When true return first delayed reply regardless of
 *	SMTP state. Otherwise, return the same result as
 *	replySend() would at this point, based on SMTP state.
 *
 * @return
 *	An SMTPF_* code.
 */
extern int replyQuery(Session *sess, int first_delayed);

/*
 * Query what the next reply to the client would be without
 * actually sending a reply. Used to check for previously
 * queued reject/drop responses.
 *
 * @param sess
 *	A session pointer.
 *
 * @param first_delayed
 *	When true return first delayed reply regardless of
 *	SMTP state. Otherwise, return the same result as
 *	replySend() would at this point, based on SMTP state.
 *
 * @return
 *	True if the next reply would be SMTPF_DROP or SMTPF_REJECT.
 */
extern int replyIsNegative(Session *sess, int first_delayed);

extern Reply *replyGetReply(Session *sess);

/*
 * Reply init, reset, and clean-up routines.
 */
extern int replyInit(Session *null, va_list ignore);
extern int replyAccept(Session *sess, va_list ignore);
extern int replyData(Session *sess, va_list ignore);
extern int replyData1(Session *sess, va_list ignore);
extern int replyContent(Session *sess, va_list args);
extern int replyDot(Session *sess, va_list ignore);
extern int replyRset(Session *sess, va_list ignore);
extern int replyClose(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __reply_h__ */
