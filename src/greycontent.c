/*
 * greycontent.c
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

enum {
	STATE_CHUNK_MODE,
	STATE_FIRST_BOUNDARY,
	STATE_FIRST_BOUNDARY_HYPHEN,
	STATE_CONTENT,
	STATE_NEWLINE,
	STATE_BOUNDARY,
	STATE_BOUNDARY_HYPHEN,
	STATE_BOUNDARY_NEWLINE,
	STATE_QP_EQUAL,
	STATE_HTML_START,
	STATE_HTML_TAG,
};

int debug;
int strip_html;
char buffer[1024];
char *content_type;

static const char usage[] =
"usage: greycontent [-h][-c type] <message\n"
"\n"
"-c type\t\tmessage has no headers, assume this Content-Type\n"
"-h\t\tstrip html\n"
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

long
HeaderInputLine(FILE *fp, char *buf, long size)
{
	int ch;
	long length, totalLength;

	totalLength = 0;
	while (0 < (length = TextInputLine(fp, buf + totalLength, size - totalLength))) {
		if (size <= totalLength + length)
			return -1;

		totalLength += length;

		if ((ch = fgetc(fp)) == EOF) {
			if (ferror(fp))
				return -1;
			return totalLength;
		}

		if (ch != ' ' && ch != '\t') {
			ungetc(ch, fp);
			break;
		}
	}

	if (debug)
		fprintf(stderr, "length=%ld header=%s\n", totalLength, buf);

	return length < 0 && totalLength == 0 ? -1 : totalLength;
}

static void
greyHashChar(md5_state_t *md5, char ch)
{
	/* Ignore whitespace. */
	if (!isspace(ch)) {
		(void) fputc(ch, stdout);
		md5_append(md5, (md5_byte_t *) &ch, 1);
	}
}

int
main(int argc, char **argv)
{
	int state, ch;
	md5_state_t md5;
	uint8_t digest[16];
	char digest_string[33];

	strip_html = 0;

	while ((ch = getopt(argc, argv, "c:h")) != -1) {
		switch (ch) {
		case 'c':
			content_type = optarg;
			break;
		case 'h':
			strip_html = 1;
			break;
		default:
			printf(usage);
			return 2;
		}
	}

	md5_init(&md5);
	state = STATE_CHUNK_MODE;

	if (content_type == NULL) {
		/* Read header section looking for the Content-Type. */
		while (0 < HeaderInputLine(stdin, buffer, sizeof (buffer))) {
			if (TextMatch(buffer, "Content-Type:*multipart/*", -1, 1))
				state = STATE_FIRST_BOUNDARY;
			else if (TextMatch(buffer, "Content-Type:*text/html*", -1, 1))
				state = STATE_CONTENT;
		}

		if (ferror(stdin)) {
			fprintf(stderr, "error reading message headers\n");
			return 1;
		}
	} else if (TextMatch(content_type, "multipart/*", -1, 1)) {
		state = STATE_FIRST_BOUNDARY;
	} else if (TextMatch(content_type, "text/html*", -1, 1)) {
		state = STATE_CONTENT;
	}

	if (feof(stdin)) {
		fprintf(stderr, "unexpected EOF during message headers\n");
		return 1;
	}

	while ((ch = fgetc(stdin)) != EOF) {
		if (state == STATE_CHUNK_MODE) {
			(void) fputc(ch, stdout);
			md5_append(&md5, (md5_byte_t *) &ch, 1);
		} else {
			/* It has been observed that some stupid yet legit
			 * MTAs will:
			 *
			 * a) change whitespacing, ie. adding/removing
			 *    leading or trailing blank lines and/or
			 *    change white space in some headers.
			 *    (fucking Microsoft-Entourage and Exhcange)
			 *
			 * b) change Date: headers on retries
			 *
			 * c) change Message-ID: header on retries
			 *
			 * d) change MIME boundaries on retries
			 *
			 * e) change the leading text before the first
			 *    boundary (fucking Microsoft-Entourage and
			 *    Exchange) from whatever the MUA specified.
 			 *
			 * Currently we ignore the headers altogether, but
			 * the change in whitespacing, MIME boundaries and
			 * text before the first and possibly after the
			 * last boundary is problematic.
			 */
			switch (state) {
			case STATE_FIRST_BOUNDARY:
				if (ch == '-')
					state = STATE_FIRST_BOUNDARY_HYPHEN;

				/* Ignore everything up to the first boundary. */
				continue;

			case STATE_FIRST_BOUNDARY_HYPHEN:
				if (ch == '-')
					state = STATE_BOUNDARY;
				else
					state = STATE_FIRST_BOUNDARY;
				continue;

			case STATE_BOUNDARY:
				if (ch == '\n')
					state = STATE_BOUNDARY_NEWLINE;

				/* Ignore boundaries and MIME part headers. */
				continue;

			case STATE_BOUNDARY_NEWLINE:
				if (ch == '\r')
					continue;
				if (ch == '\n')
					/* End of MIME part headers. */
					state = STATE_CONTENT;
				else
					state = STATE_BOUNDARY;
				continue;

			case STATE_NEWLINE:
				if (ch == '-')
					state = STATE_BOUNDARY_HYPHEN;
				else {
					state = STATE_CONTENT;
					ungetc(ch, stdin);
				}
				continue;

			case STATE_QP_EQUAL:
				if (ch == '\r')
					continue;
				if (ch == '\n')
					state = STATE_NEWLINE;
				else {
					state = STATE_CONTENT;
					greyHashChar(&md5, '=');
					ungetc(ch, stdin);
				}
				continue;

			case STATE_HTML_START:
				if (ch == '/' || ch == '!' || isalpha(ch)) {
					state = STATE_HTML_TAG;
				} else {
					state = STATE_CONTENT;
					greyHashChar(&md5, '<');
					ungetc(ch, stdin);
				}
				continue;

			case STATE_HTML_TAG:
				if (ch == '>')
					state = STATE_CONTENT;
				continue;

			case STATE_BOUNDARY_HYPHEN:
				/* Ignore hyphens. */
				if (ch == '-') {
					state = STATE_BOUNDARY;
				} else {
					state = STATE_CONTENT;
					ungetc(ch, stdin);
				}
				continue;

			case STATE_CONTENT:
				switch (ch) {
				case '\n':
					state = STATE_NEWLINE;
					break;
				case '=':
					state = STATE_QP_EQUAL;
					break;
				case '<':
					if (strip_html) {
						state = STATE_HTML_START;
						break;
					}
					/*@fallthrough@*/
				default:
					greyHashChar(&md5, ch);
				}
			}
		}
	}

	md5_finish(&md5, (md5_byte_t *) digest);
	digestToString(digest, digest_string);
	printf("\ngrey-content hash %s\n", digest_string);

	return 0;
}
