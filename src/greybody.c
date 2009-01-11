/*
 * greybody.c
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

#include <com/snert/lib/version.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
# include <stdint.h>
# endif
#endif

#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/mail/mime.h>

enum {
	STATE_TEXT,
	STATE_CONTENT,
	STATE_HTML_START,
	STATE_HTML_TAG,
};

typedef struct {
	int state;
	Mime *mime;
	md5_state_t md5;
	int skip_mime_part;
} Grey;

static int hash_only;

static const char usage[] =
"usage: greybody [-H] <message\n"
"\n"
"-H\t\thash only\n"
"\n"
_COPYRIGHT "\n"
;

static const char hex_digit[] = "0123456789abcdef";

static void
digestToString(unsigned char digest[16], char digest_string[33])
{
	int i;

	for (i = 0; i < 16; i++) {
		digest_string[i << 1] = hex_digit[(digest[i] >> 4) & 0x0F];
		digest_string[(i << 1) + 1] = hex_digit[digest[i] & 0x0F];
	}
	digest_string[32] = '\0';
}

static void
greyHashChar(Grey *grey, unsigned char ch)
{
	/* Ignore whitespace. */
	if (!isspace(ch)) {
		if (!hash_only)
			(void) fputc(ch, stdout);
		md5_append(&grey->md5, (md5_byte_t *) &ch, 1);
	}
}

static void
greyHashLine(Mime *m)
{
	unsigned char *decode;
	Grey *grey = m->mime_data;

	if (grey->skip_mime_part || (m->is_multipart && m->mime_part_number == 0))
		return;

	for (decode = m->decode.buffer; *decode != '\0'; decode++) {
		switch (grey->state) {
		case STATE_HTML_TAG:
			if (*decode == '>')
				grey->state = STATE_CONTENT;
			continue;

		case STATE_HTML_START:
			if (*decode == '!') {
				grey->state = STATE_HTML_TAG;
			} else {
				grey->state = STATE_CONTENT;
				greyHashChar(grey, '<');
				decode--;
			}
			continue;

		case STATE_CONTENT:
			if (*decode == '<') {
				grey->state = STATE_HTML_START;
				break;
			}
			/*@fallthrough@*/

		case STATE_TEXT:
			greyHashChar(grey, *decode);
		}
	}
}

static void
greyMimeResetPart(Mime *m)
{
	Grey *grey = m->mime_data;

	grey->state = STATE_TEXT;
	grey->skip_mime_part = 0;
}

static void
greyMimeHeader(Mime *m)
{
	Grey *grey = m->mime_data;

	if (TextMatch(m->source.buffer, "Content-Type:*text/html*", m->source.length, 1))
		grey->state = STATE_CONTENT;
	else if (TextMatch(m->source.buffer, "Content-Type:*application/ms-tnef*", m->source.length, 1))
		grey->skip_mime_part = 1;
}

static int
greyMimeInit(Grey *grey)
{
	grey->state = STATE_TEXT;
	grey->skip_mime_part = 0;

	if ((grey->mime = mimeCreate(grey)) == NULL)
		return -1;

	grey->mime->mime_header = greyMimeHeader;
	grey->mime->mime_source_line = greyHashLine;
	grey->mime->mime_part_finish = greyMimeResetPart;

	return 0;
}

int
main(int argc, char **argv)
{
	int ch;
	Grey grey;
	uint8_t digest[16];
	char digest_string[33];

	while ((ch = getopt(argc, argv, "H")) != -1) {
		switch (ch) {
		case 'H':
			hash_only = 1;
			break;
		default:
			printf(usage);
			return 2;
		}
	}

	md5_init(&grey.md5);

	if (greyMimeInit(&grey)) {
		fprintf(stderr, "mimeCreate error\n");
		exit(1);
	}

	while ((ch = fgetc(stdin)) != EOF) {
		if (mimeNextCh(grey.mime, ch))
			break;
	}

	mimeFree(grey.mime);

	md5_finish(&grey.md5, (md5_byte_t *) digest);
	digestToString(digest, digest_string);
	printf("\ngrey-content hash %s\n", digest_string);

	return 0;
}
