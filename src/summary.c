/*
 * summary.c
 *
 * Copyright 2007 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

/***********************************************************************
 ***
 ***********************************************************************/

static const char *mail_flags[] = {
	"black,",
	"white,",
	"tempfail,",
	"extra_spaces,",
	"local_black,",
	NULL
};

static const char *rcpt_flags[] = {
	"black,",
	"white,",
	"tempfail,",
	"extra_spaces,",
	"local_black,",
	"failed,",
	NULL
};

static const char *message_flags[] = {
	"grey_content,",
	"grey_hash_mismatch,",
	"uri_dns_bl,",
	"uri_bl,",
	"emew_pass,",
	"discard,",
	"policy,",
	"tag,",
	"tagged,",
	"queued,",
	"save,",
	"trap,",
	NULL
};

static const char *client_flags[] = {
	"mx,",
	"lan,",
	"relay,",
	"2nd_mx,",
	"forged,",
	"localhost,",
	"black,",
	"grey,",
	"save,",
	"tag,",
	"white,",
	"discard,",
	"ip_in_ptr,",
	"helo_ip,",
	"helo_host,",
	"ptr_multidomain,",
	"no_ptr,",
	"no_ptr_error,",
	"ehlo_no_helo,",
	"schizo,",
	"exempt_grey_list,",
	"passed_grey_list,",
	"pipelining,",
	"smtp_lower_case,",
	"io_error,",
	"rate_limit,",
	"concurrency_limit,",
	"local_black,",
	"trap,",
	"tempfail,",
	"auth,",
	"quit,",
	NULL
};

const char *
getFlagString(const char **table, unsigned long flags, char *buffer, size_t size, long *length)
{
	unsigned long bit, offset;

	offset = 0;
	buffer[0] = '\0';

	for (bit = 1; *table != NULL; table++, bit <<= 1) {
		if (flags & bit)
			offset += TextCopy(buffer+offset, size-offset, *table);
	}

	/* Strip trailing comma. */
	if (0 < offset)
		buffer[--offset] = '\0';

	if (length != NULL)
		*length = offset;

	return buffer;
}

const char *
clientFlags(Session *sess)
{
	long length;

	(void) getFlagString(client_flags, sess->client.flags, sess->reply, sizeof (sess->reply), &length);

	if (sess->client.socket->address.sa.sa_family == AF_INET6)
		TextCat(sess->reply, sizeof (sess->reply), ",ipv6");

	return sess->reply;
}

const char *
messageFlags(Session *sess)
{
	return getFlagString(message_flags, sess->msg.flags, sess->reply, sizeof (sess->reply), NULL);
}

const char *
mailFlags(Session *sess)
{
	return getFlagString(mail_flags, sess->msg.mail_flags, sess->reply, sizeof (sess->reply), NULL);
}

const char *
rcptFlags(Session *sess)
{
	return getFlagString(rcpt_flags, sess->msg.rcpt_flags, sess->reply, sizeof (sess->reply), NULL);
}

void
summarySender(Session *sess, const char *sender)
{
	long length;

	length = TextCopy((char *) sess->msg.chunk1, sizeof (sess->msg.chunk1), replyGetReply(sess)->string);
	sess->msg.chunk1[length-2] = '\0';

	syslog(
		LOG_INFO, LOG_MSG(717) "sender %s tid=%s f=\"%s\" spf-mail=%s spf-helo=%s x=\"%s\"", LOG_ARGS(sess),
		/* In the event parsePath fails, we need to still log the sender arg. */
		/* sess->msg.mail->address.string */ sender, sess->msg.id, mailFlags(sess),
		spfResultString[sess->msg.spf_mail],
		spfResultString[sess->client.spf_helo],
		sess->msg.chunk1
	);
/*{LOG
The start of a message transaction. This line gives a summary of sender highlights.
It cannot be suppressed.
The fields are: f= flags, spf-mail= SPF result for the MAIL FROM: argument,
spf-helo= SPF result for the HELO argument, and x= SMTP response.
}*/
}

void
summaryRecipient(Session *sess, const char *recipient)
{
	long length;

	length = TextCopy((char *) sess->msg.chunk1, sizeof (sess->msg.chunk1), replyGetReply(sess)->string);
	sess->msg.chunk1[length-2] = '\0';

	syslog(
		LOG_INFO, LOG_MSG(718) "recipient %s tid=%s f=\"%s\" x=\"%s\"", LOG_ARGS(sess),
		/* In the event parsePath fails, we need to still log the recipient arg. */
		/* rcpt->address.string*/ recipient, sess->msg.id, rcptFlags(sess), sess->msg.chunk1
	);
/*{LOG
This line gives a summary of recipient highlights.
It cannot be suppressed.
The fields are: f= flags and x= SMTP response.
}*/
}

void
summaryData(Session *sess)
{
	long length;

	length = TextCopy(sess->input, sizeof (sess->input), replyGetReply(sess)->string);
	sess->input[length-2] = '\0';

	syslog(LOG_INFO, LOG_MSG(719) "data tid=%s f=\"%s\" x=\"%s\"", LOG_ARGS(sess), sess->msg.id, messageFlags(sess), sess->input);
/*{LOG
The start of message content.
It cannot be suppressed.
The fields are: x= SMTP response.
}*/
}

void
summarySetMsgId(Session *sess, char *hdr)
{
	sess->msg.msg_id = hdr + sizeof ("Message-ID:")-1;
	sess->msg.msg_id += strspn(sess->msg.msg_id, " \t");
}

void
summarySetSubject(Session *sess, char *hdr)
{
	sess->msg.subject = hdr + sizeof ("Subject:")-1;
	sess->msg.subject += strspn(sess->msg.subject, " \t");
}

int
summaryHeaders(Session *sess, va_list args)
{
	long i;
	int length;
	char *hdr, *client, *mail, *rcpt;
	Vector headers = va_arg(args, Vector);

	sess->msg.msg_id = NULL;
	sess->msg.subject = NULL;

	for (i = 0; i < VectorLength(headers); i++) {
		if ((hdr = VectorGet(headers, i)) == NULL)
			continue;

		if (sess->msg.msg_id == NULL && TextMatch(hdr, "Message-ID:*", -1, 1))
			summarySetMsgId(sess, hdr);
		else if (sess->msg.subject == NULL && TextMatch(hdr, "Subject:*", -1, 1))
			summarySetSubject(sess, hdr);
		else if (*optSmtpReportHeader.string != '\0' && 0 <= TextInsensitiveStartsWith(hdr, optSmtpReportHeader.string)) {
			syslog(LOG_WARN, LOG_MSG(851) "removed previous instance of header \"%s\"", LOG_ARGS(sess), hdr);
/*{LOG
}*/
			VectorRemove(headers, i--);
		}
	}

	/* Added X-smtpf-Report header. */
	if (*optSmtpReportHeader.string != '\0') {
		client = strdup(clientFlags(sess));
		mail = strdup(mailFlags(sess));
		rcpt = strdup(rcptFlags(sess));

		length = snprintf(
			sess->input, sizeof (sess->input), "%s: sid=%s; tid=%s; client=%s; mail=%s; rcpt=%s; nrcpt=%u:%u; fails=%d\r\n",
			optSmtpReportHeader.string, sess->long_id, sess->msg.id,
			TextEmpty(client), TextEmpty(mail), TextEmpty(rcpt),
			sess->msg.rcpt_count, sess->msg.bad_rcpt_count,
			sess->client.reject_count
		);

		free(client);
		free(mail);
		free(rcpt);

		if (strlen(optSmtpReportHeader.string) < length && length < sizeof (sess->input)) {
			if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
				free(hdr);
		}
	}

	return SMTPF_CONTINUE;
}

void
summaryMessage(Session *sess)
{
	long length;

	if (sess->msg.msg_id == NULL)
		sess->msg.msg_id = "<>";
	else
		sess->msg.msg_id[strcspn(sess->msg.msg_id, CRLF)] = '\0';

	if (sess->msg.subject == NULL)
		sess->msg.subject = "";
	else
		sess->msg.subject[strcspn(sess->msg.subject, CRLF)] = '\0';

	length = TextCopy(sess->input, sizeof (sess->input), replyGetReply(sess)->string);
	sess->input[length-2] = '\0';

	/* Paranoid privacy nutters argue that the Subject: header is
	 * content and therefore cannot be logged.
	 *
	 * The opposing view is that the Subject: header is part of
	 * "envelope" or "traffic data" and serves as a title or form
	 * of human recognisable message-id, title, or "file name" used
	 * to identify and sort mail.
	 *
	 * The UK's Regulation of Investigatory Powers Act 2000 (RIPA)
	 *
	 * http://www.opsi.gov.uk/acts/acts2000/plain/ukpga_20000023_en
	 *
	 * Section 2.(5)(b) appears to allow for my claim that Subject:
	 * header is "traffic data", is part of the "envelope", and
	 * that the interception of the Subject: is not an offence.
	 *
	 * Section 2.(9) defining "traffic data". A Subject: header could
	 * be viewed a "file name" and many MUA when saving messages will
	 * default to "$subject.eml" as the file name. It serves as a means
	 * of reference like a book title and not communication. This is
	 * re-iterated in 21.(6).
	 *
	 * Section 2.(10) also about "traffic data", in particular the
	 * last line. If headers are part of the "traffic data" and/or
	 * "envelope", then the Subject: can be considered as having been
	 * written on the outside of the envelope. While they are referring
	 * to postal items, I believe it is possible to argue in favour of
	 * my interpretation.
	 *
	 * Section 3.(2) talks about consent. The request by the majority
	 * of users to filter spam can be taken to be consent, though not
	 * specifically given by individual users, in the name of public
	 * good, simplicity, and efficiency I would assume such.
	 *
	 * Section 81.(1) "communication" (c) is the closest thing I found
	 * that might support the view that the "Subject: header is content",
	 * because it might be seen to impart something between sender and
	 * recipient. Clear that conflicts with the view taken with respect
	 * to 2.(9) where the Subject: is seen like a title or file name.
	 *
	 * Currently I'm told there is no case law that address this issue.
	 */
	if (verb_subject.option.value)
		(void) snprintf((char *) sess->msg.chunk0, sizeof (sess->msg.chunk0), "s=\"%.60s\" ", sess->msg.subject);
	else
		*sess->msg.chunk0 = '\0';

	syslog(
		LOG_INFO, LOG_MSG(720) "message tid=%s f=\"%s\" b=%lu r=%u m=%s R=%d %sx=\"%s\"", LOG_ARGS(sess),
		sess->msg.id, messageFlags(sess), sess->msg.length, sess->msg.rcpt_count,
		sess->msg.msg_id, sess->client.reject_count, sess->msg.chunk0, sess->input
	);
/*{LOG
The end of a message transaction. This line gives a summary of message highlights.
It cannot be suppressed.
The fields are: f= flags, b= bytes sent for the message, r= RCPT TO: count,
m= @PACKAGE_NAME@ message-id, s= the subject header, and x= SMTP response.
}*/
}

static char *
p0fSummary(Session *sess)
{
#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
	int length;
	P0F *data = filterGetContext(sess, p0f_context);

	length = snprintf(sess->input, sizeof (sess->input), " p0f=\"");

	if (data->p_response.magic != QUERY_MAGIC
	|| data->p_response.type != RESP_OK
	|| *data->p_response.genre == '\0')
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "(unknown)");
	else
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "%s", data->p_response.genre);

	if (data->p_response.dist != -1)
		length += snprintf(sess->input+length, sizeof (sess->input)-length, " hops %d", data->p_response.dist);

	length += snprintf(sess->input+length, sizeof (sess->input)-length, "\"");

	return sess->input;
#else
	return "";
#endif
}

void
summarySession(Session *sess, time_t elapsed)
{
	syslog(
		LOG_INFO, LOG_MSG(721) "end i=%s p=\"%s\" f=\"%s\" h=\"%s\" m=%u/%u b=%lu R=%d t=%lu l=\"%s\"%s", LOG_ARGS(sess),
		sess->client.addr, sess->client.name, clientFlags(sess),
		sess->client.helo, sess->client.forward_count, sess->client.mail_count,
		sess->client.octets, sess->client.reject_count, (unsigned long) elapsed,
		TextEmpty(sess->last_reply),
		p0fSummary(sess)
	);
/*{LOG
The end of a connected client's session. This line gives a summary of client information.
It cannot be suppressed.
The fields are:
i= connected client IP,
p= client PTR name,
f= session flags,
h= HELO argument,
m= total foward / message count,
b= total bytes sent,
R= total reject count,
t= session time in seconds,
l= last reject or temp. fail reply sent to client,
and
p0f= p0f information if available.
}*/
}
