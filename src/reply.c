/*
 * reply.c
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

#include <com/snert/lib/mail/smtp2.h>
#include <com/snert/lib/sys/Time.h>

/***********************************************************************
 ***
 ***********************************************************************/

const char crlf[] = CRLF;

const char log_init[] = /* LOG_ERR */ LOG_NUM(537) "init error %s(%lu) %s: %s (%d)";
/*{LOG
A generic initialisation error reporting file and line number where it occured.
}*/
const char log_oom[] = /* LOG_ERR */ LOG_NUM(538) "out of memory %s(%lu)";
/*{LOG
A generic out of memory error reporting file and line number where it occured.
}*/
const char log_internal[] = /* LOG_ERR */ LOG_MSG(539) "internal error %s(%lu) %s: %s (%d)";
/*{LOG
A generic internal error reporting file and line number where it occured
and some extra context. Not expected to occur outside of code development.
}*/
const char log_pipeline[] = /* LOG_INFO */ LOG_MSG(540) "pipeline input=%ld:%s";
/*{LOG
Log any premature input from the connected client.
}*/
const char log_overflow[] = /* LOG_ERR */ LOG_MSG(000) "buffer overflow %s(%lu) size=%lu length=%lu";
/*{LOG
A buffer overflow check failed reporting file and line number where it occured.
Not expected to occur outside of code development.
}*/

const char log_cache_get[] = /* LOG_DEBUG */ LOG_MSG(541) "cache get key={%s} value={%s} %s(%lu)";
const char log_cache_get_error[] = /* LOG_ERR */ LOG_MSG(542) "cache get error key={%s} %s(%lu)";
/*{LOG
A generic error where a module could not get a cache record for unspecified reasons.
This is not the same as record not found.
}*/
const char log_cache_put[] = /* LOG_DEBUG */ LOG_MSG(543) "cache put key={%s} value={%s} %s(%lu)";
const char log_cache_put_error[] = /* LOG_ERR */ LOG_MSG(544) "cache put error key={%s} value={%s} %s(%lu)";
/*{LOG
A generic error where a module failed to update a cache record for unspecified reasons.
}*/
const char log_cache_delete[] = /* LOG_DEBUG */ LOG_MSG(545) "cache delete key={%s} %s(%lu)";
const char log_cache_delete_error[] = /* LOG_ERR */ LOG_MSG(546) "cache delete error key={%s} %s(%lu)";
/*{LOG
A generic error where a module failed to delete a cache record for unspecified reasons.
}*/

const char msg_ok[] 		= "250 2.0.0 OK" ID_MSG(547) CRLF;
/*{REPLY
Generic response that indicates the command was accepted.
}*/
const char msg_end[]		= "214 2.0.0 end" ID_MSG(548) CRLF;
/*{REPLY
Generic end of a multiline response.
}*/
const char msg_proceed[] 	= "250 2.0.0 proceed" ID_NUM(507) CRLF;
/*{REPLY
There is is a delayed rejection/drop response that will be reported
when the RCPT TO: is sent. See <a href="summary.html#opt_smtp_delay_checks">smtp-delay-checks</a>.
}*/

const char msg_421_unavailable[]= "421 4.3.2 service temporarily unavailable" ID_MSG(000) CRLF;
/*{REPLY
}*/
const char msg_421_internal[]	= "421 4.3.0 internal server error" ID_MSG(549) CRLF;
/*{REPLY
}*/
const char msg_451_internal[]	= "451 4.3.0 internal server error" ID_MSG(550) CRLF;
/*{REPLY
}*/
const char msg_resources[]	= "421 4.3.2 system resources exceeded" ID_MSG(551) CRLF;
/*{REPLY
Some serious condition such as out-of-memory, no more disk space, or similar resource
related issue has occured. The connected client will be dropped as it is not possible
to proceed until the condition has been resolved by the destination postmaster.
}*/

/* http://lists.puremagic.com/pipermail/greylist-users/2004-September/000766.html
 *
 * Evan Harris eharris at puremagic.com
 * Tue Sep 21 14:07:33 PDT 2004
 *
 * After getting several whitelist submissions that I can confirm
 * don't actually need a whitelist entry (based on my sites
 * logs), I think I have narrowed down an issue/detail that may
 * need attention from developers of alternate implementations.
 *
 * When doing the initial testing of my implementation, I tested
 * the use of several different SMTP codes, and 451 was found to
 * be the least problematic in that it caused the fewest number
 * of problems with various sites.
 *
 * Some implementations appear to be returning an SMTP error code
 * 450 or other 4xx code rather than 451 which is what I used in
 * relaydelay.  Some major sites (MSN/Hotmail and others) trying
 * to deliver mail appear to try several times in a very short
 * time period, and then bounce mail if they get a 450 error code
 * rather than a 451.
 *
 * The actual behavior varies by site, but since most sites that
 * have undesired behavior have this pattern, my guess is that it
 * is because a 450 is generally used for a mailbox lock failure,
 * and is considered a failure that should be able to be resolved
 * within seconds, and thus the short retry delay.  451 seems to
 * be handled as a more generic temporary failure, and seems to
 * produce the desired result much more often.
 *
 * So, if you're using or developing an implementation that uses
 * an error other than 451, you might want to check into
 * changing, or at least testing further.
 *
 * Evan
 */
const char msg_451_try_again[]	= "451 4.7.0 try again later" ID_MSG(552) CRLF;
/*{REPLY
This is a generic response, typicall issued by grey-listing during the
<a href="summary.html#opt_grey_temp_fail_period">grey-temp-fail-period</a>,
however other tests such as SIQ support may also issue this response.
}*/
const char msg_450_try_again[]	= "450 4.4.5 try again later" ID_MSG(553) CRLF;
/*{REPLY
This is an alternate response issued by <a href="summary.html#opt_grey_content">grey-content</a>
after the <a href="summary.html#opt_grey_temp_fail_period">grey-temp-fail-period</a> when
the hashed message content does not match previously saved message hash.
}*/

const char msg_250_accepted[]	= "250 2.0.0 message %s accepted" ID_MSG(554) CRLF;
/*{REPLY
The message transaction has reached the final dot to end the message and was accepted for delivery.
}*/
const char msg_550_rejected[]	= "550 5.7.1 message %s rejected" ID_MSG(555) CRLF;
/*{REPLY
The message transaction has reached the final dot to end the message and was NOT accepted for delivery.
}*/

static void
replyNoFree(void *_r)
{
	/* Do nothing. */
}

const Reply reply_ok 		= { replyNoFree, SMTPF_CONTINUE, 0, sizeof (msg_ok)-1, (char *) msg_ok };
const Reply reply_end 		= { replyNoFree, SMTPF_CONTINUE, 0, sizeof (msg_end)-1, (char *) msg_end };
const Reply reply_proceed	= { replyNoFree, SMTPF_CONTINUE, 0, sizeof (msg_proceed)-1, (char *) msg_proceed };

const Reply reply_no_reply	= { replyNoFree, SMTPF_CONTINUE, 0, 0, "" };

const Reply reply_unavailable 	= { replyNoFree, SMTPF_TEMPFAIL, 0, sizeof (msg_421_unavailable)-1, (char *) msg_421_unavailable };
const Reply reply_internal 	= { replyNoFree, SMTPF_TEMPFAIL, 0, sizeof (msg_421_internal)-1, (char *) msg_421_internal };
const Reply reply_resources 	= { replyNoFree, SMTPF_TEMPFAIL, 0, sizeof (msg_resources)-1, (char *) msg_resources };
const Reply reply_try_again 	= { replyNoFree, SMTPF_TEMPFAIL, 0, sizeof (msg_451_try_again)-1, (char *) msg_451_try_again };


static Verbose verb_reply	= { { "reply", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

#ifndef replySetCode
void
replySetCode(Reply *reply, int code)
{
	if (reply != NULL)
		reply->code = code;
}
#endif

void
replyFree(void *_reply)
{
	if (_reply != NULL) {
		if (0 < ((Reply *) _reply)->size)
			free(((Reply *) _reply)->string);
		free(_reply);
	}
}

/*
 * Create a reply with a constant message string.
 */
Reply *
replyMsg(int code, const char *msg, size_t length)
{
	Reply *reply;

	if ((reply = malloc(sizeof (*reply))) != NULL) {
		reply->free = replyFree;
		reply->string = (char *) msg;
		reply->length = length;
		reply->code = code;
		reply->size = 0;
		reply->next = NULL;
	}

	return reply;
}

Reply *
replyClone(Reply *reply)
{
	Reply *clone;

	if ((clone = malloc(sizeof (*clone))) != NULL) {
		if ((clone->string = malloc(reply->length+1)) == NULL) {
			free(clone);
			return NULL;
		}

		clone->next = NULL;
		clone->free = replyFree;
		clone->code = reply->code;
		clone->size = reply->length+1;
		clone->length = TextCopy(clone->string, clone->size, reply->string);
	}

	return clone;
}

Reply *
replyFmtV(int code, const char *fmt, va_list args)
{
	Reply *reply;

	if ((reply = malloc(sizeof (*reply))) != NULL) {
		if ((reply->string = malloc(SMTP_REPLY_LINE_LENGTH)) == NULL) {
			free(reply);
			return NULL;
		}

		reply->free = replyFree;
		reply->size = SMTP_REPLY_LINE_LENGTH;
		reply->length = vsnprintf(reply->string, reply->size, fmt, args);
		reply->code = code;
		reply->next = NULL;
	}

	return reply;
}

/*
 * Create a reply with a variable length (max. 512 octets) message string.
 */
Reply *
replyFmt(int code, const char *fmt, ...)
{
	Reply *reply;
	va_list args;

	va_start(args, fmt);
	reply = replyFmtV(code, fmt, args);
	va_end(args);

	return reply;
}

Reply *
replyAppendFmt(Reply *reply, const char *fmt, ...)
{
	int length;
	char *copy;
	va_list args;

	if (reply == NULL) {
		va_start(args, fmt);
		reply = replyFmtV(SMTPF_CONTINUE, fmt, args);
		va_end(args);
		return reply;
	}

	va_start(args, fmt);
	length = 0 < reply->size ? reply->size : reply->length;
	length = vsnprintf(reply->string + reply->length, length - reply->length, fmt, args);
	va_end(args);

	if (reply->size <= reply->length + length) {
		/* Duplicate the static string into a dynamic memory buffer.
		 * After we'll then enlarged the buffer as required. I know
		 * it is not optimal, but it works and I was in a hurry.
		 */
		if (reply->size == 0 && (reply->string = strdup(reply->string)) == NULL)
			return NULL;

		if ((copy = realloc(reply->string, reply->length + length + SMTP_REPLY_LINE_LENGTH)) == NULL)
			return NULL;

		va_start(args, fmt);
		reply->string = copy;
		reply->size = reply->length + length + SMTP_REPLY_LINE_LENGTH;
		length = vsnprintf(reply->string + reply->length, reply->size - reply->length, fmt, args);
		va_end(args);
	}

	reply->length += length;

	return reply;
}

void
replyDelayFree(Session *sess)
{
	if (sess->response.delayed != NULL) {
		(*sess->response.delayed->free)(sess->response.delayed);
		sess->response.delayed = NULL;
	}
}

/***********************************************************************
 ***
 ***********************************************************************/

/*
 * Send an internal error reply to the client and throw
 * an exception (longjmp) to the current on_error point
 * to drop the client connection.
 */
void
replyInternalError(Session *sess, const char *file, unsigned long lineno)
{
	syslog(LOG_ERR, log_internal, LOG_ARGS(sess), file, lineno, "", strerror(errno), errno);
	(void) sendClientReply(sess, msg_421_internal, ID_ARG(sess));
	SIGLONGJMP(sess->on_error, SMTPF_DROP);
}

void
replyResourcesError(Session *sess, const char *file, unsigned long lineno)
{
	syslog(LOG_ERR, LOG_MSG(556) "resources error %s(%lu): %s (%d)", LOG_ARGS(sess), file, lineno, strerror(errno), errno);
/*{LOG
A runtime error reporting file and line number.
Check the process status and ulimit settings.
Typically the only solution is to restart the process.
}*/
	(void) sendClientReply(sess, msg_resources, ID_ARG(sess));
	SIGLONGJMP(sess->on_error, SMTPF_DROP);
}

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef ENABLE_LINT
static void
replyListFree(Session *sess, int flags)
{
	Reply *reply, *next;

	for (reply = sess->lint_replies; reply != NULL; reply = next) {
		if (reply->code & flags)
			break;
		next = reply->next;
		(*reply->free)(reply);
	}

	sess->lint_replies = reply;
}

void
replyListFreeAll(Session *sess)
{
	replyListFree(sess, 0);
	sess->lint_replies = NULL;
}

void
replyListFreeMsg(Session *sess)
{
	replyListFree(sess, SMTPF_SESSION);
}

#include <com/snert/lib/mail/smtp2.h>

static void
replySendLintLine(SMTP2 *smtp, Reply *reply)
{
	if (reply != NULL) {
		replySendLintLine(smtp, reply->next);
		(void) smtp2Printf(smtp, "%s" CRLF, reply->string);
	}
}

void
replySendLintReport(Session *sess, const char *report_rcpt)
{
	Rcpt *rcpt;
	SMTP2 *smtp;
	Vector hosts;
	char **table;
	Connection *fwd;
	char timestamp[40];

	if (sess->lint_replies == NULL)
		return;

	if ((hosts = routeGetLocalHosts()) == NULL)
		return;

	/* Try to connect to one of the local routes. */
	smtp = NULL;
	for (table = (char **) VectorBase(hosts); *table != NULL; table++) {
		if ((smtp = smtp2Open(*table, optSmtpConnectTimeout.value, optSmtpCommandTimeout.value, SMTP_FLAG_LOG)) != NULL)
			break;
	}

	VectorDestroy(hosts);

	if (smtp == NULL) {
		syslog(LOG_ERR, log_internal, LOG_ARGS(sess), FILE_LINENO, "lint report", strerror(errno), errno);
		return;
	}

	if (smtp2Mail(smtp, "") != SMTP_OK)
		goto error1;

	if (smtp2Rcpt(smtp, report_rcpt) != SMTP_OK)
		goto error1;

	TimeStamp(&smtp->start, timestamp, sizeof (timestamp));
	(void) smtp2Printf(smtp, "Date: %s" CRLF, timestamp);
	(void) smtp2Printf(smtp, "To: <%s>" CRLF, report_rcpt);
	(void) smtp2Printf(smtp, "From: \"%s\" <postmaster@%s>" CRLF, _NAME, sess->iface->name);

	(void) smtp2Printf(smtp, "Message-ID: <%s@[%s]>" CRLF, smtp->id_string, smtp->local_ip);
	if (*sess->msg.id == '\0')
		(void) smtp2Printf(smtp, "Subject: %s lint report session %s." CRLF, _NAME, sess->long_id);
	else
		(void) smtp2Printf(smtp, "Subject: %s lint report message %s." CRLF, _NAME, sess->msg.id);

	(void) smtp2Printf(smtp, "MIME-Version: 1.0" CRLF);
	(void) smtp2Printf(smtp, "Content-Type: text/plain" CRLF);
	(void) smtp2Printf(smtp, "Content-Transfer-Encoding: 8bit" CRLF);
	(void) smtp2Printf(smtp, "Auto-Submitted: auto-generated (failure)" CRLF);
	(void) smtp2Printf(smtp, "Precedence: first-class" CRLF);
	(void) smtp2Printf(smtp, "Priority: normal" CRLF);
	(void) smtp2Print(smtp, CRLF, sizeof (CRLF)-1);

	if (sess->msg.mail != NULL) {
		(void) smtp2Printf(smtp, "SENDER: <%s>" CRLF, sess->msg.mail->address.string);

		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt->next)
				(void) smtp2Printf(smtp, "RECIPIENT: <%s>" CRLF, rcpt->rcpt->address.string);
		}
	}

	if (sess->msg.headers != NULL) {
		(void) smtp2Printf(smtp, CRLF "HEADERS:" CRLF "" CRLF);
		for (table = (char **) VectorBase(sess->msg.headers); *table != NULL; table++)
			smtp2Print(smtp, *table, strlen(*table));
	}

	(void) smtp2Printf(smtp, CRLF "REPORT:" CRLF "" CRLF);

	/* Depth first recusion of link list of replies. */
	replySendLintLine(smtp, sess->lint_replies);

	(void) smtp2Dot(smtp);
error1:
	smtp2Close(smtp);
}
#endif

/*
 *
 */
int
replySet(Session *sess, Reply *reply)
{
	int rc;

	if (reply == NULL)
		replyInternalError(sess, FILE_LINENO);

	rc = reply->code;

#ifdef ENABLE_LINT
	if (optLint.value && replyGetCode(reply) != SMTPF_CONTINUE) {
		Reply *clone = replyClone(reply);
		clone->next = sess->lint_replies;
		sess->lint_replies = clone;

		if (replyIsDelayed(reply)) {
			reply = (Reply *) &reply_proceed;
			rc = reply->code;
		}
	}
#endif
	if (optSmtpDelayChecks.value && replyIsDelayed(reply)) {
		/* Only save the delayed reply if we haven't
		 * already registered one previously.
		 */
		if (sess->response.delayed == NULL) {
			sess->response.delayed = reply;
		} else {
			(*reply->free)(reply);
		}

		if (MSG_ANY_SET(sess, MSG_TAG)
		&& sess->response.delayed->code != (SMTPF_DELAY|SMTPF_CONTINUE)) {
			sess->msg.bw_state = SMTPF_ACCEPT;
			rc = SMTPF_CONTINUE;
		}
	} else {
		if (sess->response.immediate != NULL)
			(*sess->response.immediate->free)(sess->response.immediate);
		sess->response.immediate = reply;
	}

	return rc;
}

int
replySetMsg(Session *sess, int code, const char *msg, size_t length)
{
	return replySet(sess, replyMsg(code, msg, length));
}

int
replySetFmtV(Session *sess, int code, const char *fmt, va_list args)
{
	return replySet(sess, replyFmtV(code, fmt, args));
}

int
replySetFmt(Session *sess, int code, const char *fmt, ...)
{
	int rc;
	va_list args;

	va_start(args, fmt);
	rc = replySetFmtV(sess, code, fmt, args);
	va_end(args);

	return rc;
}

Reply *
replyGetReply(Session *sess)
{
	Reply *reply;

	/* Immediate replies take precedence over delayed. */
	if (sess->response.immediate != NULL) {
		reply = sess->response.immediate;
	} else if (sess->response.delayed != NULL) {
		/* A delayed reply is sent in response to RCPT. */
		if (sess->state == stateRcpt) {
			reply = sess->response.delayed;
		} else {
			reply = (Reply *) &reply_proceed;
		}
	} else {
		reply = (Reply *) &reply_internal;
	}

	return reply;
}

/*
 * Send the last reply to the client.
 *
 *	*** This function is similar to replyQuery(). Changes  ***
 *	*** to replySend() should be made to replyQuery() too. ***
 */
int
replySend(Session *sess)
{
	Reply *reply;
	int error, rc = SMTPF_CONTINUE;

	/* Immediate replies take precedence over delayed. */
	if (sess->response.immediate != NULL) {
		reply = sess->response.immediate;
		sess->response.immediate = NULL;
		rc = replyGetCode(reply);

		/* Always free an immediate reply after it has been
		 * sent. Delayed replies are held for repeated use.
		 */
		error = sendClient(sess, reply->string, reply->length);
		(*reply->free)(reply);

		if (error) {
			/* Server I/O error while writing to client. */
			SIGLONGJMP(sess->on_error, SMTPF_DROP);
		}
	} else if (sess->response.delayed != NULL) {
		/* A delayed reply is sent in response to RCPT. */
		if (MSG_NOT_SET(sess, MSG_TAG) && sess->state == stateRcpt) {
			reply = sess->response.delayed;

			switch (replyGetCode(reply)) {
			/* Once in the RCPT state, convert drop replies into
			 * rejections in order to allow other, possibly white
			 * listed, recipients to be accepted.
			 */
			case SMTPF_DROP:
				reply->code = (reply->code & (SMTPF_DELAY|SMTPF_SESSION)) | SMTPF_REJECT;
				/*@fallthrough@*/

			/* For a reject in the RCPT state, downgrade the
			 * state to prevent advancing to DATA when we have
			 * no recipients.
			 */
			case SMTPF_REJECT:
				if (sess->msg.rcpt_count <= 1) {
					sess->state = stateMail;
					sess->msg.rcpt_count = 0;
				}
			}
		} else {
			reply = (Reply *) &reply_proceed;
		}

		rc = replyGetCode(reply);
		error = sendClient(sess, reply->string, reply->length);

		/* SMTPF_DELAY|SMTPF_CONTINUE is intended to signal
		 * that this reply should be reported only if there
		 * is no delayed message waiting. In which case this
		 * is not really a delayed reply and should be freed.
		 * See cmdRcpt().
		 */
		if (rc == SMTPF_CONTINUE) {
			sess->response.delayed = NULL;
			(*reply->free)(reply);
		}
		if (error) {
			/* Server I/O error while writing to client. */
			SIGLONGJMP(sess->on_error, SMTPF_DROP);
		}
	} else {
		replyInternalError(sess, FILE_LINENO);
	}

	/* Sendmail when it is dropped will defer connections for a
	 * period of time. Since localhost and relays are more trusted
	 * machines, there is no need to drop.
	 */
	if (CLIENT_ANY_SET(sess, CLIENT_IS_LOCALHOST|CLIENT_IS_RELAY) && rc == SMTPF_DROP)
		return SMTPF_REJECT;

	return rc;
}

/*
 * Query what the next reply to the client would be without
 * actually sending a reply. Used to check for previously
 * queued reject/drop responses.
 *
 *	*** This function similar is to replySend().Changes ***
 *	*** to replySend() should be made here too.         ***
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
int
replyQuery(Session *sess, int first_delayed)
{
	/* Immediate replies take precedence over delayed. */
	if (!first_delayed && sess->response.immediate != NULL) {
		return replyGetCode(sess->response.immediate);
	} else if (sess->response.delayed != NULL) {
		/* A delayed reply is sent in response to RCPT. */
		if (MSG_NOT_SET(sess, MSG_TAG) && (first_delayed || sess->state == stateRcpt)) {
			/* Once in the RCPT state, convert drop replies into
			 * rejections in order to allow other, possibly white
			 * listed, recipients to be accepted.
			 */
			if (replyGetCode(sess->response.delayed) == SMTPF_DROP)
				return SMTPF_REJECT;

			return replyGetCode(sess->response.delayed);
		} else {
			return reply_proceed.code;
		}
	}

	return SMTPF_CONTINUE;
}

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
int
replyIsNegative(Session *sess, int first_delayed)
{
	switch (replyQuery(sess, first_delayed)) {
	case SMTPF_DROP:
	case SMTPF_REJECT:
		return 1;
	}

	return 0;
}

/***********************************************************************
 *** Reply SMTP states
 ***********************************************************************/

int
replyInit(Session *null, va_list ignore)
{
	verboseRegister(&verb_reply);
	return SMTPF_CONTINUE;
}

int
replyAccept(Session *sess, va_list ignore)
{
	sess->response.immediate = NULL;
	sess->response.delayed = NULL;
#ifdef ENABLE_LINT
	sess->lint_replies = NULL;
#endif

	return SMTPF_CONTINUE;
}

int
replyData(Session *sess, va_list ignore)
{
	if (sess->response.delayed != NULL
	&& !replyIsSession(sess->response.delayed)
	&& (MSG_NOT_SET(sess, MSG_TAG) || sess->response.delayed->code == (SMTPF_DELAY|SMTPF_CONTINUE)))
		replyDelayFree(sess);

	return SMTPF_CONTINUE;
}

#ifdef ENABLE_LINT
int
replyData1(Session *sess, va_list ignore)
{
	if (sess->lint_replies != NULL) {
		MSG_SET(sess, MSG_DISCARD);
		return sess->msg.bw_state = SMTPF_DISCARD;
	}

	return SMTPF_CONTINUE;
}
#endif

int
replyContent(Session *sess, va_list args)
{
	/* We read the message content in chunks, running the
	 * header filters on the first chunk and content filters
	 * on the remainder periodically. If a message is to be
	 * rejected, because of a header problem or a previous
	 * bad content chunk, then there is no need to continue
	 * with the content filters for the current chunk.
	 *
	 * This implies that replyContent should be FIRST in the
	 * filter_content_table for this short-circuit to work.
	 */
	if (sess->response.immediate == NULL)
		return SMTPF_CONTINUE;

	return sess->response.immediate->code;
}

int
replyDot(Session *sess, va_list ignore)
{
	return replyContent(sess, ignore);
}

int
replyRset(Session *sess, va_list ignore)
{
#ifdef ENABLE_LINT
	replySendLintReport(sess, "postmaster");
	replyListFreeMsg(sess);
#endif
	if (sess->response.delayed != NULL
	&& (!replyIsSession(sess->response.delayed) || (optMailRetestClient.value && 0 < sess->client.forward_count)))
		replyDelayFree(sess);

	return SMTPF_CONTINUE;
}

int
replyClose(Session *sess, va_list ignore)
{
	if (sess->response.immediate != NULL)
		(*sess->response.immediate->free)(sess->response.immediate);
	replyDelayFree(sess);

#ifdef ENABLE_LINT
	replyListFreeAll(sess);
#endif
	return SMTPF_CONTINUE;
}

