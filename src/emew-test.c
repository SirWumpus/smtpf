
#include <com/snert/lib/version.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/mime.h>
#include <com/snert/lib/mail/parsePath.h>
#include <com/snert/lib/util/md5.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/time62.h>
#include <com/snert/lib/util/getopt.h>

#define EMEW3_DELIM		'|'
#define EMEW3_DELIM_S		"|"
#define EMEW3_STRING		"EMEW3" EMEW3_DELIM_S
#define EMEW3_HASH_OFFSET	(sizeof (EMEW3_STRING)-1)
#define EMEW3_TIME_OFFSET	(EMEW3_HASH_OFFSET+32)
#define EMEW3_SIZE_OFFSET	(EMEW3_TIME_OFFSET+TIME62_BUFFER_SIZE)
#define EMEW3_MAIL_OFFSET	(EMEW3_SIZE_OFFSET+2)	/* EMEW3|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmttttttxx */
#define EMEW3_BUFFER_LENGTH	(EMEW3_MAIL_OFFSET+SMTP_PATH_LENGTH+1+SMTP_PATH_LENGTH)
#define EMEW3_PRINTF_FORMAT	EMEW3_STRING "%.32s%." QUOTE(TIME62_BUFFER_SIZE) "s%.2x%s%%%s" EMEW3_DELIM_S "%s"

const char *emew_code_strings[] = { "none", "pass", "fail", "expired" };

enum {
	EMEW_NONE,
	EMEW_PASS,
	EMEW_FAIL,
	EMEW_TTL
};

static const char hex_digit[] = "0123456789abcdef";

/* Generate an EMEW 3 formatted messages-id:
 *
 * 	EMEW3|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmttttttxxoriginal_sender|original_msg_id
 *
 *	m..m is the MD5 hash of the tttttt, xx, original_sender,
 *	and original_msg_id.
 *
 *	tttttt is the year, month, day, hour, minute, second as a
 *	base62 number. The year is modulo 62.
 *
 *	xx is the offset in hex of the at-sign within the original_sender.
 *	We need to know this in case the original_sender contains the
 *	EMEW delimiter within the local-part of the address. Since the
 *	EMEW delimiter can not be a valid domain name character, we can
 *	find the start of the original_msg_id by looking for the next
 *	EMEW delimiter from the at-sign position.
 *
 *	original_sender replaces the at-sign with an EMEW delimter, since
 *	the original_msg_id will already have an at-sign and a message-id
 *	can only have one at-sign.
 */
void
emew3Make(const char *our_id, ParsePath *mail, const char *msgid, size_t msgid_length, const char *secret, char *buffer, size_t size)
{
	md5_state_t md5;
	long i, at_offset;
	unsigned char digest[16];

	/* Start building the EMEW string. */
	(void) TextCopy(buffer, size, EMEW3_STRING);

	/* Copy the time stamp portion of our message-id into the buffer. */
	(void) memcpy(buffer+EMEW3_TIME_OFFSET, our_id, TIME62_BUFFER_SIZE);

	/* Save offset of the at-sign within the sender address in hex. */
	at_offset = mail->address.length - mail->domain.length - 1;
	buffer[EMEW3_SIZE_OFFSET  ] = hex_digit[(at_offset >> 4) & 0x0F];
	buffer[EMEW3_SIZE_OFFSET+1] = hex_digit[ at_offset       & 0x0F];

	/* Save the original sender and convert the @ sign. */
	(void) TextCopy(buffer+EMEW3_MAIL_OFFSET, size-EMEW3_MAIL_OFFSET, mail->address.string);
	if (buffer[EMEW3_MAIL_OFFSET + at_offset] == '@')
		buffer[EMEW3_MAIL_OFFSET + at_offset] = EMEW3_DELIM;

	/* Append a delimiter and append the original message-id. */
	buffer[EMEW3_MAIL_OFFSET + mail->address.length] = EMEW3_DELIM;
	strncpy(buffer+EMEW3_MAIL_OFFSET+mail->address.length+1, msgid, msgid_length);
	buffer[EMEW3_MAIL_OFFSET + mail->address.length + 1 + msgid_length] = '\0';


	md5_init(&md5);

	/* Hash the buffer from the encoded timestamp through
	 * to the end of the EMEW string.
	 */
	md5_append(
		&md5,
		(md5_byte_t *) buffer+EMEW3_TIME_OFFSET,
		EMEW3_MAIL_OFFSET-EMEW3_TIME_OFFSET+mail->address.length+1+msgid_length
	);

	/* Factor in original sender's secret phrase. */
	md5_append(&md5, (md5_byte_t *) secret, strlen(secret));

	/* That's all folks. */
	md5_finish(&md5, (md5_byte_t *) digest);

	/* Insert the digest as a readable hex string. */
	for (i = 0; i < 16; i++) {
		buffer[EMEW3_HASH_OFFSET + (i << 1)    ] = hex_digit[(digest[i] >> 4) & 0x0F];
		buffer[EMEW3_HASH_OFFSET + (i << 1) + 1] = hex_digit[digest[i] & 0x0F];
	}
}

/* Verify it's an EMEW message-id, which is formatted as
 *
 * 	<EMEW|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmttttttxxoriginal_sender|original_msg_id>
 */
int
emew3Valid(char *msgid, const char *secret, long ttl)
{
	time_t when;
	long i, length;
	md5_state_t md5;
	int at_offset;
	char *orig_msgid;
	const char *their_digest;
	unsigned char our_digest[16];

	if (*msgid == '<')
		msgid++;

	/* Have we exceeded the EMEW freshness date? */
	when = time62Decode(msgid + EMEW3_TIME_OFFSET);
	if (0 < ttl && when + ttl < time(NULL)) {
		return EMEW_TTL;
	}

	/* Get the at-sign offset. */
	at_offset = qpHexDigit(msgid[EMEW3_SIZE_OFFSET]) * 16 + qpHexDigit(msgid[EMEW3_SIZE_OFFSET+1]);

	/* Convert the delimiter to an at-sign. */
	if (msgid[EMEW3_MAIL_OFFSET + at_offset] != EMEW3_DELIM)
		return EMEW_FAIL;
	msgid[EMEW3_MAIL_OFFSET + at_offset] = '@';

	/* Find the delimiter between original-sender domain and original-msg-id.
	 * Note that the EMEW delimiter cannot be a valid domain name character
	 * and so should be the first one found following the at-sign.
	 */
	if ((orig_msgid = strchr(msgid + EMEW3_MAIL_OFFSET + at_offset + 1, '|')) == NULL)
		return EMEW_FAIL;

	/* Terminate the original-sender string. */
	*orig_msgid = '\0';

	/* Restore the EMEW delimiters. */
	msgid[EMEW3_MAIL_OFFSET + at_offset] = EMEW3_DELIM;
	*orig_msgid = EMEW3_DELIM;

	/* Skip EMEW check if an empty secret? */
	if (*secret == '\0') {
		return EMEW_NONE;
	}

	md5_init(&md5);
	length = strcspn(msgid+EMEW3_TIME_OFFSET, ">");
	md5_append(&md5, (md5_byte_t *) msgid+EMEW3_TIME_OFFSET, length);
	md5_append(&md5, (md5_byte_t *) secret, strlen(secret));
	md5_finish(&md5, (md5_byte_t *) our_digest);

	/* Jump to the MD5 portion of the EMEW. */
	their_digest = msgid + EMEW3_HASH_OFFSET;

	/* Compare our expected result with the supplied digest. */
	for (i = 0; i < 16; i++) {
		if (*their_digest++ != hex_digit[(our_digest[i] >> 4) & 0x0F])
			return EMEW_FAIL;
		if (*their_digest++ != hex_digit[our_digest[i] & 0x0F])
			return EMEW_FAIL;
	}

	return EMEW_PASS;
}

const char usage[] =
"usage: emew-test -t ttl secret emew-string\n"
"       emew-test -i message-id -m mail -t seconds secret\n"
;

int
main(int argc, char **argv)
{
	long ttl;
	int ch, code;
	ParsePath *mail;
	const char *error;
	char *msgid, *timestamp, *fmt, time_buf[TIME62_BUFFER_SIZE], buffer[EMEW3_BUFFER_LENGTH];

	mail = NULL;
	msgid = NULL;
	timestamp = NULL;

	while ((ch = getopt(argc, argv, "i:m:t:")) != -1) {
		switch (ch) {
		case 'i':
			msgid = optarg;
			break;
		case 'm':
			error = parsePath(optarg, 0, 1, &mail);
			if (error != NULL) {
				fprintf(stderr, "parse error <%s>: %s\n", optarg, error);
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			if (optarg[strspn(optarg, "0123456789")] == '\0') {
				timestamp = time_buf;
				ttl = strtol(optarg, NULL, 10);
				time62Encode((time_t) ttl, time_buf);
			} else {
				timestamp = optarg;
			}
			break;
		default:
			fprintf(stderr, usage);
			exit(EXIT_FAILURE);
		}
	}

	if (mail != NULL && msgid != NULL && timestamp != NULL) {
		if (argc < optind+1) {
			fprintf(stderr, usage);
			exit(EXIT_FAILURE);
		}

		emew3Make(
			timestamp, mail,
			msgid + (*msgid == '<'), strcspn(msgid, ">"),
			argv[optind], buffer, sizeof (buffer)
		);

		printf("<%s>\n", buffer);
		code = EMEW_NONE;
	} else {
		if (argc < optind+2) {
			fprintf(stderr, usage);
			exit(EXIT_FAILURE);
		}

		code = emew3Valid(argv[optind+1], argv[optind], ttl);
		fmt = argv[optind+1][0] == '<' ? "%s %s\n" : "<%s> %s\n";
		printf(fmt, argv[optind+1], emew_code_strings[code]);
	}

	return (code == EMEW_NONE || code == EMEW_PASS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
