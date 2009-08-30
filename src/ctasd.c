/*
 * ctasd.c
 *
 * Copyright 2009 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_CTASD
#include "smtpf.h"

#include <ctype.h>
#include <limits.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <com/snert/lib/net/network.h>
#include <com/snert/lib/net/http.h>

#ifndef CTASD_PORT
#define CTASD_PORT			8088
#endif

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_ctasd_socket[] =
  "The unix domain socket or Internet host[:port] of the ctasd\n"
"# server. Specify the empty string to disable ctasd scan. The\n"
"# default ctasd port is " QUOTE(CTASD_PORT) ".\n"
"#"
;
Option optCtasdSocket	= { "ctasd-socket",	"",		usage_ctasd_socket };

Option optCtasdTimeout	= { "ctasd-timeout",	"120",		"The ctasd I/O timeout in seconds." };

static const char usage_ctasd_policy[] =
  "Policy to apply if message is infected. Specify either none,\n"
"# reject, or discard.\n"
"#"
;
Option optCtasdPolicy	= { "ctasd-policy",	"reject",	usage_ctasd_policy };

static const char usage_ctasd_stream[] =
  "When set, the message is streamed to the ctasd server, otherwiese\n"
"# the message is passed by temporary file reference.\n"
"#"
;
Option optCtasdStream	= { "ctasd-stream",	"-",		usage_ctasd_stream };

static const char usage_ctasd_subject_tag[] =
  "When the ctasd server reports the message as suspicious then the Subject\n"
"# header is prepended with this tag to identify suspect messages. Specify\n"
"# the empty string to disable the subject tag.\n"
"#"
;
Option optCtasdSubjectTag	= { "ctasd-subject-tag",	"[SUSPECT]",	usage_ctasd_subject_tag };

typedef struct {
	Socket2 *socket;
} Ctasd;

static FilterContext ctasd_context;
static Verbose verb_ctasd = { { "ctasd", "-", "" } };

Stats stat_ctasd_spam	= { STATS_TABLE_MSG, "ctasd-spam" };
Stats stat_ctasd_virus	= { STATS_TABLE_MSG, "ctasd-virus" };
Stats stat_ctasd_tag	= { STATS_TABLE_MSG, "ctasd-tag" };

/***********************************************************************
 ***
 ***********************************************************************/

static void
ctasdError(Session *sess, Ctasd *ctx, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vsnprintf(sess->msg.reject, sizeof (sess->msg.reject), fmt, args);
	va_end(args);

	socketClose(ctx->socket);
	ctx->socket = NULL;
}

int
ctasdOptn(Session *null, va_list ignore)
{
	optCtasdTimeout.value = strtol(optCtasdTimeout.string, NULL, 10) * 1000;

	if (!optCtasdStream.value) {
		optSaveData.value |= 2;
		if (*optSaveDir.string == '\0')
			optionSet(&optSaveDir, "/tmp");
	}

	return SMTPF_CONTINUE;
}

int
ctasdRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_ctasd);

	optionsRegister(&optCtasdPolicy, 	0);
	optionsRegister(&optCtasdSocket, 	0);
	optionsRegister(&optCtasdStream, 	0);
	optionsRegister(&optCtasdSubjectTag,	0);
	optionsRegister(&optCtasdTimeout, 	0);

	(void) statsRegister(&stat_ctasd_spam);
	(void) statsRegister(&stat_ctasd_virus);
	(void) statsRegister(&stat_ctasd_tag);

	ctasd_context = filterRegisterContext(sizeof (Ctasd));

	return SMTPF_CONTINUE;
}

int
ctasdInit(Session *null, va_list ignore)
{
	(void) ctasdOptn(null, ignore);

	return SMTPF_CONTINUE;
}

int
ctasdConnect(Session *sess, va_list ignore)
{
	LOG_TRACE(sess, 000, ctasdConnect);

	filterClearContext(sess, ctasd_context);

	return SMTPF_CONTINUE;
}

int
ctasdRset(Session *sess, va_list ignore)
{
	Ctasd *ctx;

	LOG_TRACE(sess, 000, ctasdRset);

	ctx = filterGetContext(sess, ctasd_context);

	/* Assert that these are closed between messages. */
	socketClose(ctx->socket);
	ctx->socket = NULL;

	return SMTPF_CONTINUE;
}

int
ctasdHeaders(Session *sess, va_list args)
{
	Ctasd *ctx;
	Vector headers;
	char buffer[512];
	HttpRequest request;

	LOG_TRACE(sess, 000, ctasdHeaders);

	if (!optCtasdStream.value)
		return SMTPF_CONTINUE;

	ctx = filterGetContext(sess, ctasd_context);
	headers = va_arg(args, Vector);
	*sess->msg.reject = '\0';

	memset(&request, 0, sizeof (request));

	if ((request.url = uriParse(optCtasdSocket.string, -1)) == NULL)
		return SMTPF_CONTINUE;

	request.method = "POST";
	request.timeout = optCtasdTimeout.value;
	request.if_modified_since = 0;
	request.post_buffer = buffer;
	request.content_length = 0;
	request.post_size = snprintf(
		buffer, sizeof (buffer),
		"X-CTCH-PVer: 0000001" CRLF
		"X-CTCH-MailFrom: %s" CRLF
		"X-CTCH-SenderIP: %s" CRLF
		CRLF,
		sess->msg.mail->address.string,
		sess->client.addr
	);

	ctx->socket = httpSend(&request);
	free(request.url);

	if (ctx->socket == NULL)
		return SMTPF_CONTINUE;

	if (socketWrite(ctx->socket, sess->msg.chunk0, sess->msg.eoh) != sess->msg.eoh)
		ctasdError(sess, ctx, "451 4.4.0 ctasd session write error after %lu bytes" ID_MSG(000), sess->msg.length, ID_ARG(sess));

	if (verb_ctasd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "ctasd >> (wrote %ld bytes)", LOG_ARGS(sess), sess->msg.eoh);

	return SMTPF_CONTINUE;
}

int
ctasdContent(Session *sess, va_list args)
{
	Ctasd *ctx;
	long length;
	unsigned char *chunk;

	ctx = filterGetContext(sess, ctasd_context);
	chunk = va_arg(args, unsigned char *);
	length = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "ctasdContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, length);

	if (ctx->socket == NULL)
		return SMTPF_CONTINUE;

	if (socketWrite(ctx->socket, chunk, length) != length) {
		ctasdError(sess, ctx, "451 4.4.0 ctasd session write error after %lu bytes" ID_MSG(000), sess->msg.length, ID_ARG(sess));
/*{NEXT}*/
		return SMTPF_CONTINUE;
	}

	if (verb_ctasd.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "ctasd >> (wrote %ld bytes)", LOG_ARGS(sess), length);

#ifdef FILTER_CTASD_CONTENT_SHORTCUT
	/* As an optimisation concerning spamd, when we see the
	 * final dot in a chunk, then call dot handler immediately,
	 * instead of in the dot handler phase. So if the entire
	 * message fits in the first chunk, we can avoid connecting
	 * to spamd entirely, which is last in filter_content_table.
	 */
	if (sess->msg.seen_final_dot)
		return ctasdDot(sess, NULL);
#endif

	return SMTPF_CONTINUE;
}

int
ctasdDot(Session *sess, va_list ignore)
{
	int rc;
	Ctasd *ctx;
	HttpCode result;
	HttpResponse response;
	char *hdr, *x_ctch_refid, *x_ctch_spam, *x_ctch_vod, *is_virus, *is_spam, buffer[512];

	LOG_TRACE(sess, 000, ctasdDot);

	ctx = filterGetContext(sess, ctasd_context);

	rc = SMTPF_CONTINUE;

	if (!optCtasdStream.value) {
		HttpRequest request;

		memset(&request, 0, sizeof (request));

		if ((request.url = uriParse(optCtasdSocket.string, -1)) == NULL)
			goto error0;

		request.method = "POST";
		request.timeout = optCtasdTimeout.value;
		request.post_buffer = buffer;

		request.post_size = snprintf(
			buffer, sizeof (buffer),
			"X-CTCH-PVer: 0000001" CRLF
			"X-CTCH-MailFrom: %s" CRLF
			"X-CTCH-SenderIP: %s" CRLF
			"X-CTCH-Filename: %s" CRLF,
			sess->msg.mail->address.string,
			sess->client.addr,
			saveGetName(sess)
		);
		request.content_length = request.post_size;
		ctx->socket = httpSend(&request);
		free(request.url);
	}

	if (ctx->socket == NULL)
		goto error0;

	httpResponseInit(&response);
	result = httpRead(ctx->socket, &response);
	if (result < 200 || 299 < result)
		goto error1;

	x_ctch_vod = httpGetHeader(response.content, "*X-CTCH-VOD:*", sizeof ("X-CTCH-VOD:")-1);
	x_ctch_spam = httpGetHeader(response.content, "*X-CTCH-Spam:*", sizeof ("X-CTCH-Spam:")-1);
	x_ctch_refid = httpGetHeader(response.content, "*X-CTCH-RefID:*", sizeof ("X-CTCH-RefID:")-1);

	if (verb_info.option.value)
		syslog(LOG_INFO, LOG_MSG(000) "ctasd vod=%s spam=%s refid=%s", LOG_ARGS(sess), TextEmpty(x_ctch_vod), TextEmpty(x_ctch_spam), TextEmpty(x_ctch_refid));

	if (x_ctch_refid != NULL) {
		(void) snprintf(sess->input, sizeof (sess->input), "X-CTCH-RefID: %s" CRLF, x_ctch_refid);
		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	is_virus = (strcmp(x_ctch_vod, "Virus") == 0 || strcmp(x_ctch_vod, "High") == 0) ? "INFECTED" : NULL;
	is_spam = (strcmp(x_ctch_spam, "Confirmed") == 0 || strcmp(x_ctch_spam, "Bulk") == 0) ? "spam" : NULL;

	if (is_virus || is_spam) {
		MSG_SET(sess, MSG_POLICY);
		(void) snprintf(sess->input, sizeof (sess->input), "message %s is %s", sess->msg.id, is_virus != NULL ? is_virus : is_spam);

		if (is_virus == NULL) {
			statsCount(&stat_ctasd_spam);
		} else {
			statsCount(&stat_ctasd_virus);
			statsCount(&stat_virus_infected);
		}

		switch (*optCtasdPolicy.string) {
		case 'd':
			rc = SMTPF_DISCARD;
			/*@fallthrough@*/
		default:
			syslog(LOG_ERR, LOG_MSG(000) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
The ctasd daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_ctasd_policy">ctasd-policy</a>.
}*/
			break;
		case 'r':
			rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 %s" ID_MSG(000) CRLF, sess->input, ID_ARG(sess));
/*{REPLY
The ctasd daemon found a virus or suspicious content in the message.
See <a href="summary.html#opt_ctasd_policy">ctasd-policy</a>.
}*/
		}
	} else if (strcmp(x_ctch_spam, "Suspected") == 0 || strcmp(x_ctch_vod, "Medium") == 0) {
		statsCount(&stat_ctasd_tag);
		headerAddPrefix(sess, "Subject", optCtasdSubjectTag.string);
		headerReplace(sess->msg.headers, "Precedence", strdup("Precedence: bulk" CRLF));
	}

	free(x_ctch_refid);
	free(x_ctch_spam);
	free(x_ctch_vod);
error1:
	httpResponseFree(&response);
	socketClose(ctx->socket);
	ctx->socket = NULL;
error0:
	return rc;
}

int
ctasdClose(Session *sess, va_list ignore)
{
	Ctasd *ctx;

	LOG_TRACE(sess, 000, ctasdClose);

	ctx = filterGetContext(sess, ctasd_context);

	/* Assert that these are closed at end of connection in case
	 * ctasdDot() is not called ,because of a rejection or dropped
	 * connection betweem DATA and DOT.
	 */
	socketClose(ctx->socket);
	ctx->socket = NULL;

	return SMTPF_CONTINUE;
}

#endif /* FILTER_CTASD */
