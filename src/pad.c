/*
 * pad.c
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

#ifdef FILTER_PAD

#include "smtpf.h"

#include <ctype.h>
#include <limits.h>
#include <com/snert/lib/mail/smdb.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_rfc2821_pad_reply_octet[] =
  "Specify a printable padding octet, then SMTP replies are padded out\n"
"# to the maximum reply line length of 512 bytes as sepecified in RFC\n"
"# 2821 section 4.5.3.1. Specify an empty string to disable padding.\n"
"#"
;

Option optRFC2821PadReplyOctet	= { "rfc2821-pad-reply-octet",	"", usage_rfc2821_pad_reply_octet };

typedef struct {
	char reply[SMTP_REPLY_LINE_LENGTH+1];
} Pad;

static FilterContext pad_context;

/***********************************************************************
 ***
 ***********************************************************************/

int
padRegister(Session *null, va_list ignore)
{
	optionsRegister(&optRFC2821PadReplyOctet,	0);

	pad_context = filterRegisterContext(sizeof (Pad));

	return SMTPF_CONTINUE;
}

int
padOptn(Session *sess, va_list ignore)
{
	if (*optRFC2821PadReplyOctet.string != '\0' && !isprint(*optRFC2821PadReplyOctet.string))
		optionSet(&optRFC2821PadReplyOctet, " ");

	return SMTPF_CONTINUE;
}

int
padReplyLog(Session *sess, va_list args)
{
	Pad *ctx;
	size_t length;
	const char *lf;
	const char **reply;
	size_t *reply_length;

	LOG_TRACE(sess, 518, padReplyLog);

	if (*optRFC2821PadReplyOctet.string == '\0'
	|| CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY|CLIENT_PASSED_GREY))
		return SMTPF_CONTINUE;

	reply = va_arg(args, const char **);
	reply_length = va_arg(args, size_t *);
	ctx = filterGetContext(sess, pad_context);

	/* Only pad the welcome message banner reply. If an MTA is
	 * going to blow up, because of buffer overflow, it will
	 * happen sooner than later. No point penalising legit MTA
	 * beyond the banner.
	 */
	if (sess->state != state0

	/* Skip multiline messages too. */
	|| (lf = strchr(*reply, '\n')) == NULL || strchr(lf+1, '\n') != NULL)
		return SMTPF_CONTINUE;

	/*** We're assuming the rejection message is a single
	 *** line terminated by CRLF.
	 ***/
	length = TextCopy(ctx->reply, sizeof (ctx->reply), *reply);
	if (sizeof (ctx->reply) <= length)
		return SMTPF_CONTINUE;

	memset(
		ctx->reply + length - CRLF_LENGTH, *optRFC2821PadReplyOctet.string,
		sizeof (ctx->reply)-1 - length
	);

	ctx->reply[sizeof (ctx->reply)-3] = ASCII_CR;
	ctx->reply[sizeof (ctx->reply)-2] = ASCII_LF;
	ctx->reply[sizeof (ctx->reply)-1] = '\0';

	*reply_length = sizeof (ctx->reply)-1;
	*reply = (const char *) ctx->reply;

	return SMTPF_CONTINUE;
}

#endif /* FILTER_PAD */
