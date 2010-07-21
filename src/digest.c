/*
 * digest.c
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_DIGEST

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/mime.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/net/dnsList.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_digest_bl[] =
  "A list of MD5 digest based BL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;

Option optDigestBL = { "digest-bl", "", usage_digest_bl };

Stats stat_digest_bl = { STATS_TABLE_MSG, "digest-bl" };

static Verbose verb_digest = { { "digest", "-", "" } };

typedef struct {
	Mime *mime;
	md5_state_t md5;
	Session *session;
	char digest_string[33];
	const char *digest_found;
} Digest;

static FilterContext digest_context;
static DnsList *digest_bl;

/***********************************************************************
 ***
 ***********************************************************************/

SmtpfCode
digestRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_digest);
	optionsRegister(&optDigestBL, 1);
	(void) statsRegister(&stat_digest_bl);
	digest_context = filterRegisterContext(sizeof (Digest));

	return SMTPF_CONTINUE;
}

SmtpfCode
digestInit(Session *null, va_list ignore)
{
	digest_bl = dnsListCreate(optDigestBL.string);
	return SMTPF_CONTINUE;
}

SmtpfCode
digestFini(Session *null, va_list ignore)
{
	dnsListFree(digest_bl);
	return SMTPF_CONTINUE;
}

SmtpfCode
digestRset(Session *sess, va_list ignore)
{
	Digest *ctx;

	LOG_TRACE(sess, 867, digestRset);

	ctx = filterGetContext(sess, digest_context);
	ctx->digest_found = NULL;
	mimeFree(ctx->mime);
	ctx->mime = NULL;

	return SMTPF_CONTINUE;
}

static const char *
digestListLookup(Session *sess, DnsList *dnslist, const char *name)
{
	PDQ_rr *answers;
	const char *list_name = NULL;

	if (dnslist == NULL)
		return NULL;

	answers = pdqFetchDnsList(
		PDQ_CLASS_IN, PDQ_TYPE_A, name,
		(const char **) VectorBase(dnslist->suffixes), pdqWait
	);

	if (answers != NULL) {
		list_name = dnsListIsNameListed(dnslist, name, answers);
		pdqFree(answers);
	}

	return list_name;
}

static void
digestMimePartStart(Mime *m)
{
	Digest *ctx = m->mime_data;

	if (ctx->digest_found == NULL) {
		ctx->digest_string[0] = '\0';
		md5_init(&ctx->md5);
	}
}

static void
digestMimePartFinish(Mime *m)
{
	unsigned char digest[16];
	Digest *ctx = m->mime_data;

	if (ctx->digest_found != NULL)
		return;

	md5_finish(&ctx->md5, (md5_byte_t *) digest);
	md5_digest_to_string(digest, ctx->digest_string);

	if (verb_digest.option.value)
		syslog(LOG_DEBUG, LOG_MSG(868) "digest=%s", LOG_ARGS(ctx->session), ctx->digest_string);

	if ((ctx->digest_found = digestListLookup(ctx->session, digest_bl, ctx->digest_string)) != NULL) {
		if (verb_digest.option.value)
			syslog(LOG_DEBUG, LOG_MSG(869) "found digest=%s list=%s", LOG_ARGS(ctx->session), ctx->digest_string, ctx->digest_found);

		statsCount(&stat_digest_bl);

		/* Discontinue any further attachment processing. */
		m->mime_body_start = NULL;
		m->mime_body_finish = NULL;
		m->mime_decoded_octet = NULL;
	}
}

static void
digestMimeDecodedOctet(Mime *m, int octet)
{
	Digest *ctx = m->mime_data;
	unsigned char byte = octet;

	md5_append(&ctx->md5, (md5_byte_t *) &byte, 1);
}

SmtpfCode
digestHeaders(Session *sess, va_list args)
{
	Digest *ctx;

	LOG_TRACE(sess, 823, digestHeaders);

	ctx = filterGetContext(sess, digest_context);
	ctx->digest_found = NULL;
	ctx->mime = NULL;

	if (*optDigestBL.string == '\0')
		goto error0;

	if ((ctx->mime = mimeCreate(ctx)) == NULL)
		goto error0;

	ctx->mime->mime_body_start = digestMimePartStart;
	ctx->mime->mime_body_finish = digestMimePartFinish;
	ctx->mime->mime_decoded_octet = digestMimeDecodedOctet;
	ctx->digest_found = NULL;
	ctx->session = sess;

	return SMTPF_CONTINUE;
error0:
	return digestRset(sess, args);
}

SmtpfCode
digestContent(Session *sess, va_list args)
{
	long size;
	Digest *ctx;
	unsigned char *chunk;

	ctx = filterGetContext(sess, digest_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(824) "digestContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	if (ctx->mime == NULL || ctx->digest_found != NULL)
		return SMTPF_CONTINUE;

	/* Be sure to scan the original message headers in order
	 * correctly parse a MIME message.
	 */
	if (chunk == sess->msg.chunk0 + sess->msg.eoh) {
		chunk = sess->msg.chunk0;
		size += sess->msg.eoh;
	}

	for ( ; 0 < size; size--, chunk++) {
		if (mimeNextCh(ctx->mime, *chunk))
			break;
	}

#ifdef FILTER_DIGEST_CONTENT_SHORTCUT
	/* As an optimisation concerning spamd, when we see the
	 * final dot in a chunk, then call dot handler immediately,
	 * instead of in the dot handler phase. So if the entire
	 * message fits in the first chunk, we can avoid connecting
	 * to spamd entirely, which is last in filter_content_table.
	 */
	if (sess->msg.seen_final_dot)
		return digestDot(sess, NULL);
#endif
	return SMTPF_CONTINUE;
}

SmtpfCode
digestDot(Session *sess, va_list ignore)
{
	SmtpfCode rc;
	Digest *ctx;

	rc = SMTPF_CONTINUE;
	LOG_TRACE(sess, 825, digestDot);

	ctx = filterGetContext(sess, digest_context);

	if (ctx->mime != NULL)
		digestMimePartFinish(ctx->mime);

	if (ctx->digest_found != NULL) {
		MSG_SET(sess, MSG_POLICY);
		rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.0 message contains blocked MIME part (%s)" ID_MSG(870) "\r\n", ctx->digest_found, ID_ARG(sess));
	}

	return rc;
}

#endif /* FILTER_DIGEST */
