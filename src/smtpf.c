/*
 * smtpf.c
 *
 * Copyright 2006 by Anthony Howe. All rights reserved.
 *
 * Description
 * -----------
 *
 * 	smtpf [options][arguments ...]
 *
 * A specialised SMTP proxy server that sits on port 25 and filters
 * mail to and from a local SMTP server. Intended as an alternative
 * fitlering solution that can be placed in front of any mail transfer
 * agent (MTA) without having to deal with a variety of different MTA
 * plugin and/or API filtering solutions. One product fits all.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

#include "smtpf.h"

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <ctype.h>
#include <limits.h>
#include <com/snert/lib/net/pdq.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/sys/pthread.h>
#include <com/snert/lib/sys/pid.h>
#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/util/Token.h>
#include <com/snert/lib/util/setBitWord.h>
#include <com/snert/lib/util/ProcTitle.h>

extern void rlimits(void);

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

Socket2 *listener;
unsigned rand_seed;
int parse_path_flags;

const char *smtpf_code_names[] = {
	"CONTINUE",
	"TAG",
	"ACCEPT",
	"GREY",
	"TEMPFAIL",
	"REJECT",
	"DISCARD",
	"DROP",
	"SKIP_NEXT",
	"SKIP_REMAINDER",
	"UNKNOWN",
	NULL
};

Vector reject_msg;
Vector welcome_msg;

/***********************************************************************
 *** Routines
 ***********************************************************************/

ParsePath *
rcptFindFirstValid(Session *sess)
{
	Connection *fwd;

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
		if (fwd->rcpts != NULL && fwd->rcpts->rcpt != NULL) {
			return fwd->rcpts->rcpt;
		}
	}

	return NULL;
}

/***********************************************************************
 *** Header Functions
 ***********************************************************************/

long
headerFind(Vector headers, const char *name, char **header)
{
	char *hdr;
	long i, len;

	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (0 < (len = TextInsensitiveStartsWith(hdr, name)) && hdr[len] == ':') {
			if (header != NULL)
				*header = hdr;
			return i;
		}
	}

	return -1;
}

int
headerRemove(Vector headers, const char *name)
{
	char *hdr;
	long i, len;

	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (0 < (len = TextInsensitiveStartsWith(hdr, name)) && hdr[len] == ':') {
			(void) VectorRemove(headers, i);
			return 1;
		}
	}

	return 0;
}

void
headerReplace(Vector headers, const char *hdr_name, char *replacement)
{
	long hdr_index;

	if (hdr_name != NULL && replacement != NULL) {
		if (0 <= (hdr_index = headerFind(headers, hdr_name, NULL)))
			VectorSet(headers, hdr_index, replacement);
		else if (VectorAdd(headers, replacement))
			free(replacement);
	}
}

void
headerAddPrefix(Session *sess, const char *hdr_name, const char *prefix)
{
	int length;
	long hdr_index;
	char *replacement, *hdr, *colon;

	if (prefix == NULL || *prefix == '\0')
		return;

	if ((hdr_index = headerFind(sess->msg.headers, hdr_name, &hdr)) == -1) {
		/* Add the missing header. */
		(void) snprintf(sess->input, sizeof (sess->input), "%s: \r\n", hdr_name);
		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr)) {
			free(hdr);
			return;
		}
		hdr_index = headerFind(sess->msg.headers, hdr_name, &hdr);
	}

	/* Is the header already prefixed? */
	if (strstr(hdr, prefix) != NULL)
		return;

	/* Find start of header value. */
	if ((colon = strchr(hdr, ':')) == NULL)
		return;
	colon += strspn(colon, " \t:");

	/* Recreate the header with prefix. */
	length = strlen(hdr) + strlen(prefix) + 2;
	if ((replacement = malloc(length + 1)) == NULL)
		return;

	/* Replace the header. */
	(void) snprintf(replacement, length, "%s: %s %s", hdr_name, prefix, colon);
	VectorSet(sess->msg.headers, hdr_index, replacement);

	if (TextInsensitiveCompare(hdr_name, "Subject") == 0)
		sess->msg.subject = &replacement[colon - hdr];
}

/***********************************************************************
 ***
 ***********************************************************************/

long
addPtrOrIpSuffix(Session *sess, char *buffer, long size)
{
	char *first_dot;
	long tld_offset;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_IP_IN_PTR|CLIENT_IS_PTR_MULTIDOMAIN)
	&& (CLIENT_NOT_SET(sess, CLIENT_NO_PTR) || CLIENT_ANY_SET(sess, CLIENT_IS_HELO_HOSTNAME))
	&& (first_dot = strchr(sess->client.name, '.')) != NULL
	) {
		/* Consider when the PTR for [89.234.6.38]
		 * is pcspecialist.co.uk, which is both a
		 * domain name and a host.
		 */
		tld_offset = indexValidTLD(sess->client.name);
		if (first_dot+1 == &sess->client.name[tld_offset] || strchr(++first_dot, '.') == NULL)
			first_dot = sess->client.name;

		return snprintf(buffer, size, "%s", first_dot);
	}

	return snprintf(buffer, size, "%s", sess->client.addr);
}

/*
 * Get the SMTP reply code, extended reply code, and trailing space.
 */
size_t
smtpGetReplyCodes(const char *line, char *buffer, size_t size)
{
	int span;
	char *space;
	size_t length;

	span = strcspn(line, " -");
	if (line[span] != '\0') {
		space = (char *) &line[span];
		length = space - line + 1;

		if (isdigit(space[1]) && (space = strchr(space+1, ' ')) != NULL)
			length = space - line + 1;

		if (buffer == NULL)
			return length;

		if (length < size) {
			(void) TextCopy(buffer, length+1, line);
			return length;
		}
	}

	return 0;
}

static int
writeClient(Session *sess, const char *line, long length)
{
	long sent, offset, n;
#ifdef REPORT_NEGATIVES
	if (verb_smtp.option.value || SMTP_ISS_PERM(line) || SMTP_ISS_TEMP(line)) {
#else
	if (verb_smtp.option.value) {
#endif
		/* Display last line of multiline response. */
		int offset = strlrcspn(line, length-1, "\n");
		if (0 < offset)
			syslog(LOG_DEBUG, LOG_MSG(626) "multiline response...", LOG_ARGS(sess));
		syslog(LOG_DEBUG, LOG_MSG(627) "< %ld:%s", LOG_ARGS(sess), length-offset, line+offset);
	}

	errno = 0;

	/* For each line of output check if the client has started
	 * sending input before the reply has been completed.
	 */
	if (CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY|CLIENT_PASSED_GREY|CLIENT_PIPELINING)

	/* Ignore any subsequent input that follows the QUIT command
	 * as something in the TCP shutdown sequence appears to trigger
	 * this test.
	 *
	 * Also due to a stupid bug in some brain dead versions of
	 * Microsoft Exchange, we have to ignore pipeline input that
	 * might immediately follow the DATA command.
	 *
	 * A related issue to this would be bad SMTP implementations
	 * that simply assume a 354 response will always be sent and
	 * proceed to pipeline the content. Their assumption is broken
	 * since it's perfectly reasonable to perform some additional
	 * tests at DATA and return 4xy or 5xy response instead of 354.
	 */
	&& sess->state != stateData && sess->state != stateQuit && sess->state != NULL

	&& socketHasInput(sess->client.socket, SMTP_PIPELINING_TIMEOUT)) {
		/*** I'm being lazy by using a buffer intended for another
		 *** purpose, but that I know to be idle at this stage.
		 ***/
		n = socketPeek(sess->client.socket, sess->msg.chunk1, sizeof (sess->msg.chunk1)-1);

		/* A disconnect appears as a zero length packet and should
		 * not be considered pipelined input. Also ignore pipelined
		 * newlines.
		 */
		if (0 < n && *sess->msg.chunk1 != ASCII_CR && *sess->msg.chunk1 != ASCII_LF) {
			sess->msg.chunk1[n] = '\0';

			if (verb_info.option.value)
				syslog(LOG_INFO, log_pipeline, LOG_ARGS(sess), n, sess->msg.chunk1);

			statsCount(&stat_client_pipelining_seen);
			CLIENT_SET(sess, CLIENT_PIPELINING);

			/* Save a rejection message if pipelining seen
			 * during pre-greeting traffic, following a HELO
			 * where it cannot be assumed, or following EHLO
			 * with the PIPELINING indicator disabled.
			 */
			if (sess->helo_state != stateEhlo || !optRFC2920Pipelining.value) {
				(void) replyPushFmt(sess, SMTPF_DELAY|SMTPF_SESSION|SMTPF_DROP, "550 5.3.3 pipelining not allowed" ID_MSG(643) "\r\n", ID_ARG(sess));
/*{REPLY
See the <a href="access-map.html#access_tags">access-map</a> concerning the
<a href="access-map.html#tag_connect"><span class="tag">Connect:</span></a> tag.
}*/
			}
		}
	}

	errno = 0;

	for (offset = 0; offset < length; offset += sent) {
		n = length-offset;

		/* When the amount remaining is within SMTP_SLOW_REPLY_SIZE
		 * plus the size CRLF, then send N bytes in order not to
		 * have an orphan CRLF on the next cycle. This is to deal
		 * with stupid PIX firewalls.
		 */
		if (optSmtpSlowReply.value
		&& CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY|CLIENT_PASSED_GREY)
		&& SMTP_SLOW_REPLY_SIZE + 2 < n)
			n = SMTP_SLOW_REPLY_SIZE;

		if ((sent = socketWrite(sess->client.socket, (unsigned char *)line+offset, n)) < 0) {
			UPDATE_ERRNO;
			if (!ERRNO_EQ_EAGAIN) {
				if (offset == 0) {
					if (verb_info.option.value) {
						syslog(LOG_ERR, LOG_MSG(628) "server I/O error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{LOG
While trying to send a reply back to the client, the server had an I/O error.
Typical cause is "broken pipe", ie. the connection with the client was lost,
most likely due to the client voluntarily dropping the connection. A lot of
spamware reacts on the first digit of the response, dropping the connection
as soon as it gets a 4xy or 5xy indication and ignoring the rest.
<p>
Sometimes the client might disconnect during the welcome banner, because
of an option like <a href="summary.html#opt_smtp_slow_reply">smtp-slow-reply</a>
which impose delays. A lot of spamware is impatient and will drop the
connection as a result.
</p>
}*/
					}
					statsCount(&stat_server_io_error);
					CLIENT_SET(sess, CLIENT_IO_ERROR);
					return -1;
				}
				break;
			}
			sent = 0;
		}

		if (optSmtpSlowReply.value
		&& CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY|CLIENT_PASSED_GREY))
			pthreadSleep(0, 500000000);
	}

	return 0;
}

static int
load_file(const char *filename, Vector *lines)
{
	FILE *fp;
	char line[SMTP_REPLY_LINE_LENGTH+1], *copy;

	if (lines == NULL)
		return SMTPF_CONTINUE;

	if ((fp = fopen(filename, "r")) == NULL) {
		*lines = NULL;
		return SMTPF_CONTINUE;
	}

	if ((*lines = VectorCreate(5)) != NULL) {
		VectorSetDestroyEntry(*lines, free);

		while (0 <= TextInputLine(fp, line, sizeof (line))) {
			if (VectorAdd(*lines, copy = strdup(line)))
				free(copy);
		}
	}

	(void) fclose(fp);

	return SMTPF_CONTINUE;
}

int
writeInit(Session *null, va_list ignore)
{
	return load_file(optSmtpRejectFile.string, &reject_msg);
}

int
writeReplyLog(Session *sess, va_list args)
{
	char **p, status[20];
	const char **reply, *line;
	size_t *reply_length, length;

	LOG_TRACE(sess, 629, writeReplyLog);

	reply = va_arg(args, const char **);
	reply_length = va_arg(args, size_t *);
	length = *reply_length;
	line = *reply;

	if (length == 0)
		return SMTPF_CONTINUE;

	/* RFC 2821 section 4.2 paragraph 3:
	 *
	 *	"Only the EHLO, EXPN, and HELP commands are expected
	 *	to result in multiline replies in normal circumstances,
	 *	however, multiline replies are allowed for any command.
	 *
	 * Some broken MTAs, like FirstClass, fail to handle multiline
	 * replies entirely, fail to handle negative multiline replies,
	 * or handle only those that are expected to be multiline.
	 *
	 * So when -smtp-enable-esmtp and smtp-reject-file are both
	 * specified, these legitimate senders using a broken MTA will
	 * choke on a multiline rejection to EHLO, but would otherwise
	 * behave normally by following up with a HELO etc.
	 *
	 * As much as I loath having to working around other people's
	 * broken software, doing so makes commercial sense and was a
	 * simple extra condition. So negative multiline replies are
	 * disabled while a connection is still in the initial state,
	 * then once past EHLO/HELO they are then applied.
	 */
	if (sess->state != state0
	&& CLIENT_NOT_SET(sess,	CLIENT_USUAL_SUSPECTS)
	&& SMTP_ISS_PERM(*reply) && 0 < VectorLength(reject_msg)) {
		if ((length = smtpGetReplyCodes(line, status, sizeof (status))) == 0)
			return SMTPF_UNKNOWN;

		/* Convert it to multiline reply. */
		status[3] = '-';

		length = snprintf(sess->input, sizeof (sess->input), "%s%s", status, line+length);
		if (writeClient(sess, sess->input, length))
			return SMTPF_UNKNOWN;

		/* Send the custom message. */
		for (p = (char **) VectorBase(reject_msg); p[1] != NULL; p++) {
			length = snprintf(sess->input, sizeof (sess->input), "%s%s\r\n", status, *p);
			if (writeClient(sess, sess->input, length))
				return SMTPF_UNKNOWN;
		}

		/* Last line of custom message has no hyphen after the reply code. */
		status[3] = ' ';
		line = sess->input;
		length = (size_t) snprintf(sess->input, sizeof (sess->input), "%s%s\r\n", status, *p);
	}

	if (writeClient(sess, line, length))
		return SMTPF_UNKNOWN;

	return SMTPF_CONTINUE;
}

int
sendClient(Session *sess, const char *line, size_t length)
{
	int rc;

	/* Allow for no reply to be sent. Part of the STARTTLS
	 * handshake. After the 220 proceed response to STARTTLS
	 * the TLS handshake is done, after which no banner or
	 * reply is sent. Thus we should simply ignore the call.
	 */
	if (line == NULL || length == 0)
		return 0;

	/*** Do NOT longjmp() for any errors until after
	 *** filter_reply_clean_table has been processed
	 *** to avoid potential memory leaks.
	 ***/

	rc = filterRun(sess, filter_reply_log_table, &line, &length);
	(void) filterRun(sess, filter_reply_clean_table);

	return rc == SMTPF_CONTINUE ? 0 : -1;
}

int
sendClientReply(Session *sess, const char *fmt, ...)
{
	int length;
	va_list args;

	va_start(args, fmt);
	length = vsnprintf(sess->reply, sizeof (sess->reply), fmt, args);
	va_end(args);

	/* vsnprintf() returns the length it would write if the buffer
	 * were big enough to hold the string. We have to check this
	 * to ensure that we don't cause a segmentation fault reading
	 * off the end of the buffer and make sure we don't try to
	 * write more data than we have which could cause undefined
	 * behaviour.
	 */
	if (sizeof (sess->reply) <= length)
		length = sizeof (sess->reply) - 1;

	return sendClient(sess, sess->reply, length);
}

void
sessionReset(Session *sess)
{
	Connection *fwd, *fwd_next;

#ifdef STATS_ROUTE
	statsRoute(sess, sess->msg.smtpf_code);
	sess->msg.smtpf_code = SMTPF_UNKNOWN;
#endif

	(void) filterRun(sess, filter_rset_table);

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd_next) {
		fwd_next = fwd->next;

		if (fwd == sess->client.fwd_to_queue) {
			fwd->next = NULL;
			continue;
		}

#ifdef OLD_SMTP_ERROR_CODES
		if (fwd->can_quit && !(fwd->smtp_error & SMTP_ERROR_IO_MASK))
#else
		if (fwd->can_quit && fwd->smtp_code != SMTP_ERROR_IO)
#endif
			(void) mxCommand(sess, fwd, "QUIT\r\n", 221);

		connectionFree(fwd);
	}

	VectorRemoveAll(sess->msg.headers);
	free(sess->msg.mail);

	MSG_CLEAR_ALL(sess);
	MAIL_CLEAR_ALL(sess);
	RCPT_CLEAR_ALL(sess);

	sess->msg.eoh = 0;
	sess->msg.mail = NULL;
	sess->msg.fwds = sess->client.fwd_to_queue;
	sess->msg.fwd_to_queue = NULL;
	sess->msg.length = 0;
	sess->msg.rcpt_count = 0;
	sess->msg.bad_rcpt_count = 0;
	sess->msg.reject[0] = '\0';
	sess->msg.id[0] = '\0';
	sess->msg.msg_id = NULL;
	sess->msg.subject = NULL;
}

int
isPrintableASCII(const char *s)
{
	for ( ; *s != '\0'; s++) {
		switch (*s) {
		case ASCII_CR:
			if (s[1] == ASCII_LF || s[1] == '\0')
				continue;
			return 0;
		case ASCII_LF:
			if (s[1] == '\0')
				break;
			return 0;
		case ASCII_TAB:
			break;
		default:
			if (*s < ASCII_SPACE || ASCII_DEL <= *s)
				return 0;
		}
	}

	return 1;
}

void
welcomeInit(void)
{
	(void) load_file(optSmtpWelcomeFile.string, &welcome_msg);
}

static char *welcome_default[] = {
	"Welcome to " _DISPLAY,
	_COPYRIGHT,
	NULL
};

int
welcome(Session *sess)
{
	char **p;
	Reply *reply;

	/* Some broken SMTP client software (Trend Micro?) cannot
	 * handle multiple line banners, and so get out of sync
	 * with the response codes. So if we white list a host,
	 * just give them a simple one line banner.
	 */
	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY)) {
		return replySetFmt(
				sess, SMTPF_CONTINUE, "220 %s %sSMTP" ID_MSG(632) CRLF,
				sess->iface->name, optSmtpEnableEsmtp.value ? "E" : "",
				ID_ARG(sess)
		);
/*{REPLY
A stripped down single line welcome banner sent to only localhost, LAN, and relays.
}*/
	}

	p = 0 < VectorLength(welcome_msg) ? (char **) VectorBase(welcome_msg) : welcome_default;
	reply = replyFmt(
		SMTPF_CONTINUE, "220%c%s %sSMTP %s" ID_MSG(633) CRLF,
		p[1] == NULL ? ' ' : '-', sess->iface->name,
		optSmtpEnableEsmtp.value || CLIENT_ANY_SET(sess, CLIENT_HOLY_TRINITY) ? "E" : "",
		*p, ID_ARG(sess)
	);
/*{REPLY
The first line of possible a multiline welcome banner.
}*/

	for (p++; *p != NULL; p++) {
		reply = replyAppendFmt(reply, "220%c%s" CRLF, p[1] == NULL ? ' ' : '-', *p);
	}

	return replyPush(sess, reply);
}

void
keepAlive(Session *sess)
{
	time_t now;
	int sent, count;
	Connection *fwd;

	if (optSmtpKeepAliveTimeout.value <= 0)
		return;

	now = time(NULL);
	sent = count = 0;

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
#ifdef OLD_SMTP_ERROR_CODES
		if (!(fwd->smtp_error & SMTP_ERROR_IO) && fwd->time_of_last_command + optSmtpKeepAliveTimeout.value <= now) {
#else
		if (fwd->smtp_code != SMTP_ERROR_IO && fwd->time_of_last_command + optSmtpKeepAliveTimeout.value <= now) {
#endif
			count++;
			fwd->time_of_last_command = now;
			socketSetTimeout(fwd->mx, KEEP_ALIVE_TIMEOUT_MS);
			if (fwd->can_quit)
				(void) mxPrint(sess, fwd, "NOOP\r\n", sizeof ("NOOP\r\n")-1);
			else
				socketWrite(fwd->mx, (unsigned char *) "", 0);
		}
	}

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
#ifdef OLD_SMTP_ERROR_CODES
		if (fwd->can_quit && !(fwd->smtp_error & SMTP_ERROR_IO) && socketGetTimeout(fwd->mx) == KEEP_ALIVE_TIMEOUT_MS) {
#else
		if (fwd->can_quit && fwd->smtp_code != SMTP_ERROR_IO && socketGetTimeout(fwd->mx) == KEEP_ALIVE_TIMEOUT_MS) {
#endif
			(void) mxResponse(sess, fwd);
			if (fwd->smtp_code == 250)
				sent++;
		}
		socketSetTimeout(fwd->mx, optSmtpCommandTimeout.value);
	}

	if (verb_debug.option.value)
		syslog(LOG_DEBUG, LOG_MSG(634) "keep-alive relays=%d sent=%d fail=%d", LOG_ARGS(sess),  count, sent, count - sent);
}

void
checkClientIP(Session *sess)
{
	int type;
	long length;
	PDQ_rr *rr = NULL, *rr_list;

	/* Assume the client is forged or unconfirmed,
	 * excluding localhost and the private LAN IPs.
	 */
	if (CLIENT_NOT_SET(sess, CLIENT_IS_LAN|CLIENT_IS_LOCALHOST))
		CLIENT_SET(sess, CLIENT_IS_FORGED);

	/* Assume the client has one PTR record or if multihomed that
	 * they are all for the same domain. Used for grey-listing PTR
	 * key.
	 */
	CLIENT_CLEAR(sess, CLIENT_IS_PTR_MULTIDOMAIN);

	if (CLIENT_ANY_SET(sess, CLIENT_IS_LOCALHOST)) {
		/* Skip the lookup and assign the localhost name ourselves. */
		length = TextCopy(sess->client.name, sizeof (sess->client.name), "localhost.localhost");
		CLIENT_CLEAR(sess, CLIENT_NO_PTR|CLIENT_NO_PTR_ERROR|CLIENT_IS_FORGED);
		return;
	}

	if ((rr_list = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_PTR, sess->client.addr, NULL)) != NULL) {
		for (rr = rr_list; rr != NULL; rr = rr->next) {
			if (rr->section == PDQ_SECTION_QUERY
			&& ((PDQ_QUERY *)rr)->rcode != PDQ_RCODE_OK
			&& ((PDQ_QUERY *)rr)->rcode != PDQ_RCODE_UNDEFINED) {
#ifdef FILTER_MISC
				statsCount(&stat_client_ptr_required_error);
#endif
				CLIENT_SET(sess, CLIENT_NO_PTR|CLIENT_NO_PTR_ERROR);
				break;
			} else if (rr->section == PDQ_SECTION_QUERY) {
				continue;
			} else if (rr->type == PDQ_TYPE_PTR) {
				CLIENT_CLEAR(sess, CLIENT_NO_PTR|CLIENT_NO_PTR_ERROR);
				break;
			} else if (verb_info.option.value && rr->type == PDQ_TYPE_CNAME) {
				syslog(
					LOG_INFO, LOG_MSG(635) "client [%s] has CNAME/PTR delegation %s",
					LOG_ARGS(sess), sess->client.addr, ((PDQ_PTR *) rr)->host.string.value
				);
/*{LOG
}*/
			}
		}
	}

	if (rr == NULL || CLIENT_ANY_SET(sess, CLIENT_NO_PTR)) {
#ifdef FILTER_MISC
		statsCount(&stat_client_ptr_required);
#endif
		pdqFree(rr_list);
		return;
	}

	/* Copy the client's host name into our buffer. This name will
	 * almost certainly have a trailing dot for the root domain, as
	 * will any additional records returned from the DNS lookup.
	 */
	length = TextCopy(sess->client.name, sizeof (sess->client.name), ((PDQ_PTR *) rr)->host.string.value);

#ifdef FILTER_GREY
	/* Consider dig -x 63.84.135.34, which has a multihomed PTR
	 * record for many different unrelated domains. This affects
	 * our choice to use the grey-listing PTR key or not. If the
	 * multihomed PTR were all for the same domain suffix, then
	 * the grey-listing PTR key will work, otherwise we have to
	 * fall back on just using the IP address.
	 */
	if (1 < pdqListLength(rr_list) && 0 < greyPtrSuffix(sess, sess->input, sizeof (sess->input))) {
		for (rr = rr_list; rr != NULL; rr = rr->next) {
			if (rr->section != PDQ_SECTION_ANSWER)
				continue;

			if (rr->type == PDQ_TYPE_PTR
			&& TextInsensitiveEndsWith(((PDQ_PTR *) rr)->host.string.value, sess->input) == -1) {
				CLIENT_SET(sess, CLIENT_IS_PTR_MULTIDOMAIN);
				break;
			}
		}
	}
#endif
	/* Wait to remove the trailing dot for the root domain from
	 * the client's host name until after any multihomed PTR list
	 * is reviewed above.
	 */
	if (0 < length && sess->client.name[length-1] == '.')
		sess->client.name[length-1] = '\0';
	TextLower(sess->client.name, length);

	/* Now we can discard our result from the PTR lookup. */
	pdqFree(rr_list);

	type = isReservedIPv6(sess->client.ipv6, IS_IP_V4) ? PDQ_TYPE_A : PDQ_TYPE_AAAA;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_RELAY) && type == PDQ_TYPE_A
	&& isIPv4InClientName(sess->client.name, sess->client.ipv6+IPV6_OFFSET_IPV4))
		CLIENT_SET(sess, CLIENT_IS_IP_IN_PTR);

	if ((rr_list = pdqGet(sess->pdq, PDQ_CLASS_IN, type, sess->client.name, NULL)) != NULL) {
		for (rr = rr_list; rr != NULL; rr = rr->next) {
			if (rr->section != PDQ_SECTION_ANSWER)
				continue;

			if (rr->type == type
			&& memcmp(sess->client.ipv6, ((PDQ_A *) rr)->address.ip.value, sizeof (sess->client.ipv6)) == 0) {
				CLIENT_CLEAR(sess, CLIENT_IS_FORGED);
				break;
			}
		}

		pdqFree(rr_list);
	}

#ifdef FILTER_GREY
{
	mcc_row row;
	mcc_handle *mcc = ((Worker *) sess->session->worker->data)->mcc;

	/* Check the cache to see if this client has previously passed grey-listing.
	 * and set a flag if true. This flag can then be used to disable certain
	 * tests and controls such as smtp-greet-pause or smtp-slow-reply.
	 */
	sess->msg.spf_mail = SPF_NONE;
	row.key_size = greyMakeKey(sess, optGreyKey.value & ~(GREY_TUPLE_HELO|GREY_TUPLE_MAIL|GREY_TUPLE_RCPT), NULL, (char *) row.key_data, sizeof (row.key_data));
	if (mccGetRow(mcc, &row) == MCC_OK) {
		row.value_data[row.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		if (row.value_data[0] == SMTPF_CONTINUE+'0')
			CLIENT_SET(sess, CLIENT_PASSED_GREY);
	}
}
#endif
}

#ifdef UPDATE
char this_ip[IPV6_STRING_LENGTH];

int
getMyDetails(void)
{
	int length;
	char ipv6[IPV6_BYTE_LENGTH];

	if (*optInterfaceName.string == '\0') {
		if ((optInterfaceName.string = malloc(DOMAIN_STRING_LENGTH)) == NULL)
			return -1;
		networkGetMyName(optInterfaceName.string);
	}

	networkGetHostIp(optInterfaceName.string, this_ip);

	if (*optInterfaceIp.string == '\0') {
		if ((optInterfaceIp.string = strdup(this_ip)) == NULL)
			return -1;
	} else {
		length = parseIPv6(optInterfaceIp.string, ipv6);
		length = length+1 < sizeof (this_ip) ? length+1 : sizeof (this_ip);
		if (!isReservedIPv6(ipv6, IS_IP_THIS_HOST|IS_IP_LOCALHOST))
			(void) TextCopy(this_ip, length, optInterfaceIp.string);
	}

	return 0;
}
#endif

#ifdef ENABLE_TEST_ON_COMMAND
static Command *states[] = {
	state0,
	stateHelo,
	stateEhlo,
	stateMail,
	stateRcpt,
	NULL
};

static void
testOnCommandInit(void)
{
	Command cmd, **s;

	/* Special case. */
	if (TextInsensitiveCompare(optTestOnCommand.string, "reject,.") == 0) {
		optTestOnCommand.value = 1;
		return;
	}

	cmd.command = optTestOnCommand.string;
	cmd.command += strcspn(cmd.command, ", ;");
	cmd.command += strspn(cmd.command, ", ;");

	if (*cmd.command == '\0')
		return;

	switch (*optTestOnCommand.string) {
	case 't': case 'T':
		cmd.function = cmdTryAgainLater;
		break;
	case 'r': case 'R':
		cmd.function = cmdReject;
		break;
	case 'd': case 'D':
		cmd.function = cmdDrop;
		break;
	default:
		return;
	}

	/* First entry contains state table name. Skip it.
	 * Second entry used to testOnCommand action.
	 */
	for (s = states; *s != NULL; s++)
		(*s)[1] = cmd;
}
#endif

/***********************************************************************
 ***
 ***********************************************************************/

void
sessionProcess(Session *sess)
{
	int n;
	char *p;
	Command *s;
	time_t elapsed;
	SmtpfCode code;
	TIMER_DECLARE(banner);
	unsigned numbers[2];

	if (verb_timers.option.value)
		TIMER_START(banner);
	if (0 < SIGSETJMP(sess->on_error, 1))
		goto error0;


	/* We need at least N file descriptors per client. More are
	 * required for forwarding and some other tests, but its
	 * assumed that not all connections will require the max
	 * possible.
	 */
	serverNumbers(sess->session->server, numbers);
	if (optRunOpenFileLimit.value <= numbers[1] * FD_PER_THREAD + FD_OVERHEAD) {
		errno = EMFILE;
		replyResourcesError(sess, FILE_LINENO);
	}

	if ((sess->msg.headers = VectorCreate(25)) == NULL)
		replyResourcesError(sess, FILE_LINENO);
	VectorSetDestroyEntry(sess->msg.headers, free);

	checkClientIP(sess);

	if (routeKnownClientName(sess))
		CLIENT_SET(sess, CLIENT_IS_RELAY);

	if (verb_info.option.value) {
		syslog(
			LOG_INFO, LOG_MSG(637) "start " CLIENT_FORMAT " f=\"%s\" th=%u cn=%u cs=%lu",
			LOG_ARGS(sess), CLIENT_INFO(sess), clientFlags(sess),
			numbers[0], numbers[1],
			connections_per_second
		);
/*{LOG
The start of the session after the client IP checks, but before the welcome banner.
When the <a href="summary.html#opt_verbose">verbose</a> option is set to an
empty string (terse mode), then the information found here is available in
the session "end" log line only.
}*/
	}

	if (verb_timers.option.value) {
		TIMER_DIFF(banner);
		if (TIMER_GE_CONST(diff_banner, 1, 0) || 1 < verb_timers.option.value)
			syslog(LOG_DEBUG, LOG_MSG(638) "before welcome time-elapsed=" TIMER_FORMAT, LOG_ARGS(sess), TIMER_FORMAT_ARG(diff_banner));
	}

 	switch (filterRun(sess, filter_connect_table)) {
	default:
		(void) welcome(sess);
		/*@fallthrough@*/

	case SMTPF_TEMPFAIL:
		break;

 	case SMTPF_DROP:
 	case SMTPF_REJECT:
		(void) replySend(sess);
		goto error0;
	}

	if ((code = replySend(sess)) != SMTPF_CONTINUE) {
		if (verb_info.option.value)
			syslog(LOG_ERR, LOG_MSG(1031) "banner error code=%d " CLIENT_FORMAT ": %s (%d)", LOG_ARGS(sess), code, CLIENT_INFO(sess), strerror(errno), errno);
	}

	/* Black listed clients get less priority. */
	if (CLIENT_ANY_SET(sess, CLIENT_IS_BLACK))
		socketSetTimeout(sess->client.socket, optSmtpCommandTimeoutBlack.value);

	if (SIGSETJMP(sess->on_error, 1) == 0) {
		while (sess->state != stateQuit && sess->state != NULL) {
			sess->input_length = socketReadLine2(sess->client.socket, sess->input, sizeof (sess->input), 1);

			if (sess->input_length < 0) {
				if (verb_info.option.value) {
					syslog(LOG_ERR, LOG_MSG(639) "client " CLIENT_FORMAT " I/O error: %s (%d)", LOG_ARGS(sess), CLIENT_INFO(sess), strerror(errno), errno);
/*{LOG
The client appears to have disconnected. A read error occured in the SMTP command loop.
Similar to "server I/O error" in nature.
<p>
Typical cause is "broken pipe", ie. the connection with the client was lost,
most likely due to the client voluntarily dropping the connection. A lot of
spamware reacts to the last response they receive, dropping the connection
if they get a 4xy or 5xy reply.
</p>
<p>
Sometimes the client disconnects during the welcome banner, because
of an option like <a href="summary.html#opt_smtp_slow_reply">smtp-slow-reply</a>
which imposes delays. A lot of spamware is impatient and will drop the
connection as a result.
</p>
}*/
				}
				CLIENT_SET(sess, CLIENT_IO_ERROR);
				if (errno != 0)
					statsCount((errno == ETIMEDOUT) ? &stat_client_timeout : &stat_client_io_error);
				break;
			}

			/* Tally the byte length of SMTP commands sent
			 * by client towards the session counter.
			 */
			sess->client.octets += sess->input_length;

			if (optRFC2821CommandLength.value && SMTP_COMMAND_LINE_LENGTH < sess->input_length) {
				(void) sendClientReply(sess, "500 5.5.2 RFC 2821 max. command line length exceeded (%ld)" ID_MSG(640) CRLF, sess->input_length, ID_ARG(sess));

/*{REPLY
See <a href="summary.html#opt_rfc2821_command_length">rfc2821-command-length</a>.
}*/
				statsCount(&stat_rfc2821_command_length);
				break;
			}

			if (!isPrintableASCII(sess->input)) {
				(void) sendClientReply(sess, "500 5.5.2 " CLIENT_FORMAT " sent non-printable characters in SMTP command" ID_MSG(641) CRLF, CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
SMTP commands and their arguments can only consist of printable ASCII characters.
}*/
				statsCount(&stat_smtp_command_non_ascii);
				break;
			}

			if (verb_smtp.option.value)
				syslog(LOG_DEBUG, LOG_MSG(642) "> %ld:%s", LOG_ARGS(sess), sess->input_length, sess->input);

			/* First entry contains state table name. Skip it. */
			for (s = &sess->state[1]; s->command != NULL; s++) {
				if (0 < (n = TextInsensitiveStartsWith(sess->input, s->command)) && isspace(sess->input[n]))
					break;
			}

			for (p = sess->input; !isspace(*p) && *p != '\0'; p++) {
				if (islower(*p)) {
					CLIENT_SET(sess, CLIENT_SMTP_LOWER_CASE);
					break;
				}
			}

			/* Check for already saved immediate replies, ie
			 * pipelining having been set in writeClient.
			 */
			if (replyIsNegative(sess, 0) && s->function != cmdData) {
				(void) replySend(sess);
				break;
			}

#ifdef ENABLE_CRLF_CHECKING
			/* Remove trailing CRLF */
			if (0 < sess->input_length && sess->input[sess->input_length-1] == '\n') {
				sess->input[--sess->input_length] = '\0';
				if (0 < sess->input_length && sess->input[sess->input_length-1] == '\r') {
					sess->input[--sess->input_length] = '\0';
				}
			}
#endif
			(void) time(&sess->last_mark);
			/* Commands must not do any client I/O, only set a
			 * reply. All client I/O handled  here, except for
			 * DATA 354 and AUTH LOGIN dialogue.
			 */
			(void) (*s->function)(sess);

			if (replySend(sess) == SMTPF_DROP || sess->msg.smtpf_code == SMTPF_DROP) {
				(void) filterRun(sess, filter_drop_table);
				break;
			}

			if (0 < optSmtpDropAfter.value && optSmtpDropAfter.value <= sess->client.reject_count) {
				if (verb_info.option.value) {
					syslog(LOG_INFO, LOG_MSG(644) "dropping " CLIENT_FORMAT " after %d errors", LOG_ARGS(sess), CLIENT_INFO(sess), sess->client.reject_count);
/*{LOG
See <a href="summary.html#opt_smtp_drop_after">smtp-drop-after</a> option.
}*/
				}
				(void) filterRun(sess, filter_drop_table);
				statsCount(&stat_smtp_drop_after);
				break;
			}

			keepAlive(sess);
		}
	}

	if (CLIENT_ANY_SET(sess, CLIENT_IS_EHLO_NO_HELO))
		statsCount(&stat_ehlo_no_helo);

	/* Round up to the next kilo byte. This is NOT exact of course and
	 * penalises the HELO, MAIL. RCPT, DATA commands which typically
	 * are less than 256 bytes if we rejected before or at DATA.
	 */
	statsAddValue(&stat_total_kb, sess->client.octets / 1024 + 1);

	sessionReset(sess);

	if (sess->client.fwd_to_queue != NULL) {
#ifdef OLD_SMTP_ERROR_CODES
		if (sess->client.fwd_to_queue->can_quit && !(sess->client.fwd_to_queue->smtp_error & SMTP_ERROR_IO_MASK))
#else
		if (sess->client.fwd_to_queue->can_quit && sess->client.fwd_to_queue->smtp_code != SMTP_ERROR_IO)
#endif
			(void) mxCommand(sess, sess->client.fwd_to_queue, "QUIT\r\n", 221);
		connectionFree(sess->client.fwd_to_queue);
	}
error0:
	elapsed = time(NULL);
	if (verb_debug.option.value)
		syslog(LOG_DEBUG, LOG_MSG(645) "end timestamp %lu", LOG_ARGS(sess), (unsigned long) elapsed);

	/* Handle radical time shift that could skew high-session-time stat. */
	elapsed = sess->start <= elapsed ? (elapsed - sess->start) : 0;
	statsSetHighWater(&stat_high_session_time, elapsed, verb_info.option.value);
	summarySession(sess, elapsed);
}
