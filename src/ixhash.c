/*
 * ixhash.c
 *
 * Copyright 2010 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_IXHASH

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/mime.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/ixhash.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/net/dnsList.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_ixhash_bl[] =
  "A list of MD5 iXhash based BL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;

Option opt_ixhash_bl = { "ixhash-bl", "", usage_ixhash_bl };

Stats stat_ixhash_bl = { STATS_TABLE_MSG, "ixhash-bl" };

static Verbose verb_ixhash = { { "ixhash", "-", "" } };

typedef struct {
	unsigned count_lf;
	unsigned count_ws;
	unsigned count_html_chars;
	md5_state_t ixhash[3];
} Ixhash;

static FilterContext ixhash_context;
static DnsList *ixhash_bl;

/***********************************************************************
 ***
 ***********************************************************************/

SmtpfCode
ixhashRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_ixhash);
	optionsRegister(&opt_ixhash_bl, 1);
	(void) statsRegister(&stat_ixhash_bl);
	ixhash_context = filterRegisterContext(sizeof (Ixhash));

	return SMTPF_CONTINUE;
}

SmtpfCode
ixhashInit(Session *null, va_list ignore)
{
	ixhash_bl = dnsListCreate(opt_ixhash_bl.string);
	return SMTPF_CONTINUE;
}

SmtpfCode
ixhashFini(Session *null, va_list ignore)
{
	dnsListFree(ixhash_bl);
	return SMTPF_CONTINUE;
}

SmtpfCode
ixhashData(Session *sess, va_list ignore)
{
	Ixhash *ctx;

	LOG_TRACE(sess, 984, ixhashData);

	ctx = filterGetContext(sess, ixhash_context);

	md5_init(&ctx->ixhash[0]);
	md5_init(&ctx->ixhash[1]);
	md5_init(&ctx->ixhash[2]);

	ctx->count_lf = 0;
	ctx->count_ws = 0;
	ctx->count_html_chars = 0;

	return SMTPF_CONTINUE;
}

SmtpfCode
ixhashContent(Session *sess, va_list args)
{
	long size;
	Ixhash *ctx;
	unsigned char *chunk;

	ctx = filterGetContext(sess, ixhash_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(985) "ixhashContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	/* Be sure to scan the original message headers in order
	 * correctly parse a MIME message.
	 */
	if (chunk == sess->msg.chunk0 + sess->msg.eoh) {
		ctx->count_lf = ixhash_count_lf(chunk, size);
		ctx->count_ws = ixhash_count_space_tab(chunk, size);
		ctx->count_html_chars = ixhash_count_delims_or_abs_url(chunk, size);
	}

#ifdef KLUDGE
	/* KLUDGE: smtpf incorrectly counts the final dot and CRLF in
	 * the chunk size, which throws off the ixhash1 computation.
	 */
	if (3 <= size && memcmp(chunk+size-3, ".\r\n", 3) == 0)
		size -= 3;
#endif
	ixhash_hash1(&ctx->ixhash[0], chunk, size);
	ixhash_hash2(&ctx->ixhash[1], chunk, size);
	ixhash_hash3(&ctx->ixhash[2], chunk, size);

	return SMTPF_CONTINUE;
}

SmtpfCode
ixhashDot(Session *sess, va_list ignore)
{
	int i;
	Ixhash *ctx;
	SmtpfCode rc;
	unsigned char digest[3][16];
	const char *hash_string, *list_name;
	char hash_number, digest_string[3][33];

	rc = SMTPF_CONTINUE;
	LOG_TRACE(sess, 986, ixhashDot);

	ctx = filterGetContext(sess, ixhash_context);

	for (i = 0; i < 3; i++) {
		md5_finish(&ctx->ixhash[i], (md5_byte_t *) digest[i]);
		md5_digest_to_string(digest[i], digest_string[i]);
	}

	if (20 <= ctx->count_ws && 2 <= ctx->count_lf) {
		hash_string = digest_string[0];
		hash_number = '1';
	} else if (3 <= ctx->count_html_chars) {
		hash_string = digest_string[1];
		hash_number = '2';
	} else if (8 <= sess->msg.length - sess->msg.eoh) {
		hash_string = digest_string[2];
		hash_number = '3';
	} else {
		hash_string = NULL;
		hash_number = ' ';
	}

	if (verb_ixhash.option.value) {
		syslog(
			LOG_DEBUG, LOG_MSG(987) "lf=%lu ws=%lu html-chars=%lu ix1=%s ix2=%s ix3=%s hash=%c",
			LOG_ARGS(sess),
			(unsigned long) ctx->count_lf,
			(unsigned long) ctx->count_ws,
			(unsigned long) ctx->count_html_chars,
			digest_string[0], digest_string[1], digest_string[2],
			hash_number
		);
/*{LOG
Debug output for verb +ixhash.
See the section <a href="runtime.html#runtime_config">Runtime Configuration</a>
and <a href="summary.html#opt_verbose">verbose</a> option.
}*/
	}

	if ((list_name = dnsListQueryString(ixhash_bl, sess->pdq, NULL, hash_string)) != NULL) {
		MSG_SET(sess, MSG_POLICY);
		statsCount(&stat_ixhash_bl);
		dnsListSysLog(sess, "ixhash-bl", hash_string, list_name);
		rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.0 message blocked by %s" ID_MSG(988) CRLF, list_name, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_ixhash_bl">ixhash-bl</a> option.
}*/
	}

	return rc;
}

#endif /* FILTER_IXHASH */
