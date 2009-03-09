/*
 * emew.c
 *
 * Enhanced Message-ID as Electronic Watermark
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 *
 * Note that patent application 20060085505 by Microsoft was
 * filed after our own patent application for EMEW.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_EMEW

#include "smtpf.h"

#include <com/snert/lib/util/md5.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define ACCESS_TAG		"emew:"

static const char usage_emew_dsn_policy[] =
  "If the message is a DSN or MDN and does not contain a reference to\n"
"# an enhanced Message-ID that originated here, then apply the given\n"
"# policy, which can be either reject or none.\n"
"#"
;

static const char usage_emew_ttl[] =
  "Time-to-live in seconds for an enhanced Message-ID header. Messages\n"
"# referring to stale mail that originated here are rejected. This limits\n"
"# the window of opportunity for replay attacks.\n"
"#"
;

static const char usage_emew_secret[] =
  "Specify a phrase used to generate and validate an enhanced Message-ID.\n"
"# Be sure to quote the string if it contains white space. Specify the\n"
"# empty string to disable enhanced Message-ID support.\n"
"#"
;

Option optEmewDsnPolicy	= { "emew-dsn-policy",	"none",		usage_emew_dsn_policy };
Option optEmewSecret	= { "emew-secret",	"",		usage_emew_secret };
Option optEmewTTL	= { "emew-ttl",		"604800",	usage_emew_ttl };

Stats stat_emew_pass	= { STATS_TABLE_MSG, "emew-pass" };
Stats stat_emew_fail	= { STATS_TABLE_MSG, "emew-fail" };
Stats stat_emew_ttl	= { STATS_TABLE_MSG, "emew-ttl" };

Verbose verb_emew	= { { "emew",		"-", "" } };

#define EMEW1_DELIM		'-'
#define EMEW1_STRING		"EMEW-"
#define EMEW1_PREFIX_LENGTH	44	/* EMEW-ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm- */
#define EMEW1_STRING_LENGTH	(EMEW1_PREFIX_LENGTH+SMTP_PATH_LENGTH)
#define EMEW1_PRINTF_FORMAT	EMEW1_STRING "%.6s%.32s-%s"

/* RFC 5322 defines specials that cannot appear in atoms (note dot-atom)
 * Each of the characters in specials can be used to indicate a tokenization
 * point in lexical analysis.
 *
 *	specials = "(" / ")" /        ; Special characters that do
 *                 "<" / ">" /        ;  not appear in atext
 *                 "[" / "]" /
 *                 ":" / ";" /
 *                 "@" / "\" /
 *                 "," / "." /
 *                 DQUOTE
 */

#define EMEW2_DELIM		','
#define EMEW2_STRING		"EMEW,"
#define EMEW2_PREFIX_LENGTH	44	/* EMEW,ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm, */
#define EMEW2_STRING_LENGTH	(EMEW2_PREFIX_LENGTH+SMTP_PATH_LENGTH+1+SMTP_PATH_LENGTH)
#define EMEW2_PRINTF_FORMAT	EMEW2_STRING "%." QUOTE(TIME62_BUFFER_SIZE) "s%.32s,%s,%s"

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

FilterContext emew_context;

/***********************************************************************
 ***
 ***********************************************************************/

static const char hex_digit[] = "0123456789abcdef";

int
emewRegister(Session *null, va_list ignore)
{
	verboseRegister(&verb_emew);

	optionsRegister(&optEmewDsnPolicy, 		0);
	optionsRegister(&optEmewSecret, 		0);
	optionsRegister(&optEmewTTL, 			0);

	(void) statsRegister(&stat_emew_pass);
	(void) statsRegister(&stat_emew_fail);
	(void) statsRegister(&stat_emew_ttl);

	emew_context = filterRegisterContext(sizeof (EMEW));

	return SMTPF_CONTINUE;
}

int
emewInit(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}

#ifdef NOT_USED
static int
emew1Set(time_t when, char *msgid, char *buffer, size_t size)
{
	long i, length;
	md5_state_t md5;
	unsigned char digest[16];

	if (size < EMEW1_STRING_LENGTH)
		return 0;

	(void) TextCopy(buffer, size, EMEW1_STRING);
	time62Encode(when, buffer + sizeof (EMEW1_STRING)-1);

	md5_init(&md5);

	/* Encode the date the message was sent. This used to be
	 * the time_t binary value of `when'. However, the time_t
	 * type can be signed or unsigend 32 or 64-bits long. Newer
	 * systems appear to be moving towards signed 64-bit. This
	 * can cause problems when trying to compare EMEW strings
	 * generated by a system using a time_t with a different size.
	 *
	 * To resolve this, we now use the ASCII encoded 62-year
	 * cycle of the timestamp. For our purposes that is more
	 * than sufficient resolution and portable.
	 */
	md5_append(&md5, (md5_byte_t *) buffer + sizeof (EMEW1_STRING)-1, TIME62_BUFFER_SIZE);

	/* Find the start of message-id value. Note that there are some
	 * mailers that do not conform to RFC 2822 Message-ID syntax,
	 * in particular, they may have neglected the angle brackets.
	 * We assume that the message-id contains no white space.
	 */
	msgid += sizeof ("Message-ID:")-1;
	msgid += strspn(msgid, " \t");
	if (*msgid == '<')
		msgid++;
	length = strcspn(msgid, "> \t\r\n");

	/* This should never happen. */
	if (length <= 0 || size <= EMEW1_PREFIX_LENGTH + length)
		return 0;

	/* Encode the original (or our added) message-id. */
	md5_append(&md5, (md5_byte_t *) msgid, length);

	/* Factor in our secret phrase. */
	md5_append(&md5, (md5_byte_t *) optEmewSecret.string, optEmewSecret.length);

	/* That's all folks. */
	md5_finish(&md5, (md5_byte_t *) digest);

	/* Convert digest into a readable string. */
	for (i = 0; i < 16; i++) {
		buffer[sizeof (EMEW1_STRING)-1+TIME62_BUFFER_SIZE+(i << 1)] = hex_digit[(digest[i] >> 4) & 0x0F];
		buffer[sizeof (EMEW1_STRING)-1+TIME62_BUFFER_SIZE+(i << 1) + 1] = hex_digit[digest[i] & 0x0F];
	}
	buffer[EMEW1_PREFIX_LENGTH-1] = '-';
	strncpy(buffer+EMEW1_PREFIX_LENGTH, msgid, length);
	buffer[EMEW1_PREFIX_LENGTH+length] = '\0';

	return EMEW1_PREFIX_LENGTH + length;
}
#endif
#ifdef NOT_USED
/* Generate an EMEW 2 formatted messages-id:
 *
 * 	EMEW,ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm,original_sender,original_msg_id
 */
static int
emew2Set(Session *sess, time_t when, char *msgid, char *buffer, size_t size)
{
	long i, length;
	md5_state_t md5;
	char *secret, *sender;
	unsigned char digest[16];

	if (size < EMEW2_STRING_LENGTH)
		return 0;

	/* Find the start of message-id value. Note that there are some
	 * mailers that do not conform to RFC 2822 Message-ID syntax,
	 * in particular, they may have neglected the angle brackets.
	 * We assume that the message-id contains no white space.
	 */
	msgid += sizeof ("Message-ID:")-1;
	msgid += strspn(msgid, " \t");
	if (*msgid == '<')
		msgid++;
	length = strcspn(msgid, "> \t\r\n");

	/* This should never happen. */
	if (length <= 0 || size <= EMEW2_PREFIX_LENGTH + sess->msg.mail->address.length + 1 + length)
		return 0;

	if (accessEmail(sess, ACCESS_TAG, sess->msg.mail->address.string, NULL, &secret) == SMDB_ACCESS_NOT_FOUND)
		secret = optEmewSecret.string;

	if (*secret == '\0' || (sender = malloc(sess->msg.mail->address.length+1)) == NULL) {
		if (secret != optEmewSecret.string)
			free(secret);
		return 0;
	}

	/* Convert the @ sign in the sender address. */
	TextCopy(sender, sess->msg.mail->address.length+1, sess->msg.mail->address.string);
	if (sender[sess->msg.mail->address.length - sess->msg.mail->domain.length - 1] == '@')
		sender[sess->msg.mail->address.length - sess->msg.mail->domain.length - 1] = '%';

	(void) TextCopy(buffer, size, EMEW2_STRING);
	time62Encode(when, buffer + sizeof (EMEW2_STRING)-1);

	md5_init(&md5);

	/* Encode the date the message was sent. This used to be
	 * the time_t binary value of `when'. However, the time_t
	 * type can be signed or unsigend 32 or 64-bits long. Newer
	 * systems appear to be moving towards signed 64-bit. This
	 * can cause problems when trying to compare EMEW strings
	 * generated by a system using a time_t with a different size.
	 *
	 * To resolve this, we now use the ASCII encoded 62-year
	 * cycle of the timestamp. For our purposes that is more
	 * than sufficient resolution and portable.
	 */
	md5_append(&md5, (md5_byte_t *) buffer + sizeof (EMEW2_STRING)-1, TIME62_BUFFER_SIZE);

	/* Encode the original sender. */
	md5_append(&md5, (md5_byte_t *) sender, sess->msg.mail->address.length);

	/* Encode the delimiter between original sender and original message-id. */
	digest[0] = EMEW2_DELIM;
	md5_append(&md5, (md5_byte_t *) digest, 1);

	/* Encode the original (or our added) message-id. */
	md5_append(&md5, (md5_byte_t *) msgid, length);

	/* Factor in original sender's secret phrase. */
	md5_append(&md5, (md5_byte_t *) secret, strlen(secret));

	/* That's all folks. */
	md5_finish(&md5, (md5_byte_t *) digest);

	/* Append the digest as a readable string. */
	for (i = 0; i < 16; i++) {
		buffer[sizeof (EMEW2_STRING)-1+TIME62_BUFFER_SIZE+(i << 1)] = hex_digit[(digest[i] >> 4) & 0x0F];
		buffer[sizeof (EMEW2_STRING)-1+TIME62_BUFFER_SIZE+(i << 1) + 1] = hex_digit[digest[i] & 0x0F];
	}
	buffer[EMEW2_PREFIX_LENGTH-1] = EMEW2_DELIM;
	(void) TextCopy(buffer+EMEW2_PREFIX_LENGTH, size-EMEW2_PREFIX_LENGTH, sender);
	buffer[EMEW2_PREFIX_LENGTH+sess->msg.mail->address.length] = EMEW2_DELIM;
	strncpy(buffer+EMEW2_PREFIX_LENGTH+sess->msg.mail->address.length+1, msgid, length);
	buffer[EMEW2_PREFIX_LENGTH+sess->msg.mail->address.length+1+length] = '\0';

	if (secret != optEmewSecret.string)
		free(secret);

	free(sender);

	return EMEW2_PREFIX_LENGTH+sess->msg.mail->address.length+1+length;
}
#endif

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
static int
emew3Set(Session *sess, time_t when, char *msgid, char *buffer, size_t size)
{
	char *secret;
	md5_state_t md5;
	unsigned char digest[16];
	long i, msgid_length, at_offset;

	/* Find the start of message-id value. Note that there are some
	 * mailers that do not conform to RFC 2822 Message-ID syntax,
	 * in particular, they may have neglected the angle brackets.
	 * We assume that the message-id contains no white space.
	 */
	msgid += sizeof ("Message-ID:")-1;
	msgid += strspn(msgid, " \t");
	if (*msgid == '<')
		msgid++;
	msgid_length = strcspn(msgid, "> \t\r\n");

	/* This should never happen. */
	if (msgid_length <= 0 || size <= EMEW3_MAIL_OFFSET + sess->msg.mail->address.length + 1 + msgid_length)
		return 0;

	if (accessEmail(sess, ACCESS_TAG, sess->msg.mail->address.string, NULL, &secret) == SMDB_ACCESS_NOT_FOUND)
		secret = optEmewSecret.string;

	if (*secret == '\0') {
		if (secret != optEmewSecret.string)
			free(secret);
		return 0;
	}

	/* Start building the EMEW string. */
	(void) TextCopy(buffer, size, EMEW3_STRING);

	time62Encode(when, buffer+EMEW3_TIME_OFFSET);

	/* Save offset of the at-sign within the sender address in hex. */
	at_offset = sess->msg.mail->address.length - sess->msg.mail->domain.length - 1;
	buffer[EMEW3_SIZE_OFFSET  ] = hex_digit[(at_offset >> 4) & 0x0F];
	buffer[EMEW3_SIZE_OFFSET+1] = hex_digit[ at_offset       & 0x0F];

	/* Save the original sender and convert the @ sign. */
	(void) TextCopy(buffer+EMEW3_MAIL_OFFSET, size-EMEW3_MAIL_OFFSET, sess->msg.mail->address.string);
	if (buffer[EMEW3_MAIL_OFFSET + at_offset] == '@')
		buffer[EMEW3_MAIL_OFFSET + at_offset] = EMEW3_DELIM;

	/* Append a delimiter and append the original message-id. */
	buffer[EMEW3_MAIL_OFFSET+sess->msg.mail->address.length] = EMEW3_DELIM;
	strncpy(buffer+EMEW3_MAIL_OFFSET+sess->msg.mail->address.length+1, msgid, msgid_length);
	buffer[EMEW3_MAIL_OFFSET+sess->msg.mail->address.length+1+msgid_length] = '\0';

	md5_init(&md5);

	/* Hash the buffer from the encoded timestamp through
	 * to the end of the EMEW string.
	 */
	md5_append(
		&md5,
		(md5_byte_t *) buffer+EMEW3_TIME_OFFSET,
		EMEW3_MAIL_OFFSET-EMEW3_TIME_OFFSET+sess->msg.mail->address.length+1+msgid_length
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

	if (secret != optEmewSecret.string)
		free(secret);

	return EMEW3_MAIL_OFFSET+sess->msg.mail->address.length+1+msgid_length;
}

/* Verify it's an EMEW message-id, which is formatted as
 *
 * 	<EMEW-ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm-original_msg_id>
 */
static int
emew1IsValid(Session *sess, char *ret)
{
	int rc;
	time_t when;
	long i, length;
	md5_state_t md5;
	const char *their_digest;
	unsigned char our_digest[16];

	if (*optEmewSecret.string == '\0')
		return EMEW_NONE;

	rc = EMEW_FAIL;

	length = strcspn(ret+EMEW1_PREFIX_LENGTH, ">");
	when = time62Decode(ret+sizeof (EMEW1_STRING)-1);

	md5_init(&md5);
	md5_append(&md5, (md5_byte_t *) ret+sizeof (EMEW1_STRING)-1, TIME62_BUFFER_SIZE);
	md5_append(&md5, (md5_byte_t *) ret+EMEW1_PREFIX_LENGTH, length);
	md5_append(&md5, (md5_byte_t *) optEmewSecret.string, optEmewSecret.length);
	md5_finish(&md5, (md5_byte_t *) our_digest);

	/* Jump to the MD5 portion of the RET. */
	their_digest = ret + sizeof (EMEW1_STRING)-1+TIME62_BUFFER_SIZE;

	/* Compare our expected result with the supplied digest. */
	for (i = 0; i < 16; i++) {
		if (*their_digest++ != hex_digit[(our_digest[i] >> 4) & 0x0F])
			goto error0;
		if (*their_digest++ != hex_digit[our_digest[i] & 0x0F])
			goto error0;
	}

	rc = EMEW_PASS;
	MSG_SET(sess, MSG_EMEW_OK);

	/* Have we exceeded the RET freshness date? */
	if (0 < optEmewTTL.value && when + optEmewTTL.value < time(NULL))
		rc = EMEW_TTL;

	if (verb_emew.option.value)
		syslog(LOG_DEBUG, LOG_MSG(343) "emew1IsValid(%s) rc=%d (%s)", LOG_ARGS(sess), TextNull(ret), rc, emew_code_strings[rc]);
error0:
	return rc;
}

/* Verify it's an EMEW message-id, which is formatted as
 *
 * 	<EMEW,ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm,original_sender,original_msg_id>
 */
static int
emew2IsValid(Session *sess, char *msgid)
{
	int rc;
	time_t when;
	Vector fields;
	long i, length;
	md5_state_t md5;
	const char *their_digest;
	unsigned char our_digest[16];
	char *secret, *original_sender, *at_sign;
	EMEW *emew = filterGetContext(sess, emew_context);

	if (!emew->required)
		return EMEW_NONE;

	rc = EMEW_FAIL;

	if ((fields = TextSplit(msgid, ",", 0)) == NULL)
		goto error0;

	if ((original_sender = VectorGet(fields, 2)) == NULL)
		goto error1;

	if ((at_sign = strchr(original_sender, '%')) != NULL)
		*at_sign = '@';

	if (accessEmail(sess, ACCESS_TAG, original_sender, NULL, &secret) == SMDB_ACCESS_NOT_FOUND)
		secret = optEmewSecret.string;

	if (*secret == '\0')
		goto error1;

	if (at_sign != NULL)
		*at_sign = '%';

	md5_init(&md5);
	length = strcspn(msgid+EMEW2_PREFIX_LENGTH, ">");
	md5_append(&md5, (md5_byte_t *) msgid+sizeof (EMEW2_STRING)-1, TIME62_BUFFER_SIZE);
	md5_append(&md5, (md5_byte_t *) msgid+EMEW2_PREFIX_LENGTH, length);
	md5_append(&md5, (md5_byte_t *) secret, strlen(secret));
	md5_finish(&md5, (md5_byte_t *) our_digest);

	/* Jump to the MD5 portion of the EMEW. */
	their_digest = msgid + sizeof (EMEW2_STRING)-1+TIME62_BUFFER_SIZE;

	/* Compare our expected result with the supplied digest. */
	for (i = 0; i < 16; i++) {
		if (*their_digest++ != hex_digit[(our_digest[i] >> 4) & 0x0F])
			goto error1;
		if (*their_digest++ != hex_digit[our_digest[i] & 0x0F])
			goto error1;
	}

	rc = EMEW_PASS;
	MSG_SET(sess, MSG_EMEW_OK);

	/* Have we exceeded the EMEW freshness date? */
	when = time62Decode(msgid+sizeof (EMEW2_STRING)-1);
	if (0 < optEmewTTL.value && when + optEmewTTL.value < time(NULL))
		rc = EMEW_TTL;

	if (verb_emew.option.value)
		syslog(LOG_DEBUG, LOG_MSG(343) "emew2IsValid(%s) rc=%d (%s)", LOG_ARGS(sess), msgid, rc, emew_code_strings[rc]);

	if (secret != optEmewSecret.string)
		free(secret);
error1:
	VectorDestroy(fields);
error0:
	return rc;
}

/* Verify it's an EMEW message-id, which is formatted as
 *
 * 	<EMEW|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmttttttxxoriginal_sender|original_msg_id>
 */
static int
emew3IsValid(Session *sess, char *msgid)
{
	time_t when;
	long i, length;
	md5_state_t md5;
	int rc, at_offset;
	const char *their_digest;
	char *secret, *orig_msgid;
	unsigned char our_digest[16];
	EMEW *emew = filterGetContext(sess, emew_context);

	rc = EMEW_FAIL;

	if (!emew->required) {
		rc = EMEW_NONE;
		goto error0;
	}

	if (*msgid == '<')
		msgid++;

	/* Have we exceeded the EMEW freshness date? */
	when = time62Decode(msgid + EMEW3_TIME_OFFSET);
	if (0 < optEmewTTL.value && when + optEmewTTL.value < time(NULL)) {
		rc = EMEW_TTL;
		goto error0;
	}

	/* Get the at-sign offset. */
	at_offset = qpHexDigit(msgid[EMEW3_SIZE_OFFSET]) * 16 + qpHexDigit(msgid[EMEW3_SIZE_OFFSET+1]);

	/* Convert the delimiter to an at-sign. */
	if (msgid[EMEW3_MAIL_OFFSET + at_offset] != EMEW3_DELIM)
		goto error0;
	msgid[EMEW3_MAIL_OFFSET + at_offset] = '@';

	/* Find the delimiter between original-sender domain and original-msg-id.
	 * Note that the EMEW delimiter cannot be a valid domain name character
	 * and so should be the first one found following the at-sign.
	 */
	if ((orig_msgid = strchr(msgid + EMEW3_MAIL_OFFSET + at_offset + 1, '|')) == NULL)
		goto error0;

	/* Terminate the original-sender string. */
	*orig_msgid = '\0';

	/* Lookup the secret of the original-sender address. */
	if (accessEmail(sess, ACCESS_TAG, msgid+EMEW3_MAIL_OFFSET, NULL, &secret) == SMDB_ACCESS_NOT_FOUND)
		secret = optEmewSecret.string;

	/* Restore the EMEW delimiters. */
	msgid[EMEW3_MAIL_OFFSET + at_offset] = EMEW3_DELIM;
	*orig_msgid = EMEW3_DELIM;

	/* Skip EMEW check if an empty secret? */
	if (*secret == '\0') {
		rc = EMEW_NONE;
		goto error1;
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
			goto error1;
		if (*their_digest++ != hex_digit[our_digest[i] & 0x0F])
			goto error1;
	}

	MSG_SET(sess, MSG_EMEW_OK);
	rc = EMEW_PASS;
error1:
	if (secret != optEmewSecret.string)
		free(secret);
error0:
	if (verb_emew.option.value)
		syslog(LOG_DEBUG, LOG_MSG(343) "emew3IsValid(%s) rc=%d (%s)", LOG_ARGS(sess), msgid, rc, emew_code_strings[rc]);

	return rc;
}

typedef struct {
	const char *leadin;
	size_t leadin_length;
	int (*is_valid_fn)(Session *sess, char *msgid);
} EmewValidTable;

static EmewValidTable emew_valid_table[] =
{
	{ EMEW3_STRING, sizeof (EMEW3_STRING)-1, emew3IsValid },
	{ EMEW2_STRING, sizeof (EMEW2_STRING)-1, emew2IsValid },
	{ EMEW1_STRING, sizeof (EMEW1_STRING)-1, emew1IsValid },
	{ NULL, 0, NULL }

};

/* Verify it's an EMEW message-id, which is formatted as
 *
 * 	<EMEW-ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm-original_msg_id>
 * 	<EMEW,ttttttmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm,original_sender,original_msg_id>
 *	<EMEW3|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmttttttxxoriginal_sender|original_msg_id>
 */
static int
emewIsValid(Session *sess, char *msgid)
{
	EmewValidTable *emew;

	if (msgid == NULL)
		return EMEW_NONE;

	if (*msgid == '<')
		msgid++;

	for (emew = emew_valid_table; emew->leadin != NULL; emew++) {
		if (strncmp(msgid, emew->leadin, emew->leadin_length) == 0)
			return (*emew->is_valid_fn)(sess, msgid);
	}

	return EMEW_NONE;
}

int
emewRset(Session *sess, va_list ignore)
{
	EMEW *emew = filterGetContext(sess, emew_context);

	LOG_TRACE(sess, 344, emewRset);
	emew->result = EMEW_NONE;
	emew->required = 0;

	return SMTPF_CONTINUE;
}

int
emewMailRcpt(Session *sess, va_list args)
{
	EMEW *emew;
	ParsePath *rcpt;

	LOG_TRACE(sess, 871, emewRcpt);
	rcpt = va_arg(args, ParsePath *);
	emew = filterGetContext(sess, emew_context);

	if (emew->required)
		return SMTPF_CONTINUE;

	/* Ignore double bounce messages that are sent to postmaster. */
	if (sess->msg.mail->address.length == 0 && TextInsensitiveCompare(rcpt->localLeft.string, "postmaster") == 0)
		return SMTPF_CONTINUE;

	if (*optEmewSecret.string != '\0')
		emew->required = 1;

	else if (accessEmail(sess, ACCESS_TAG, rcpt->address.string, NULL, NULL) != SMDB_ACCESS_NOT_FOUND)
		emew->required = 1;

	return SMTPF_CONTINUE;
}

int
emewHeader(Session *sess, Vector headers)
{
	EMEW *emew;
	time_t when;
	char *msgid, *hdr;
	int length, msgid_index, ref_index;

	LOG_TRACE(sess, 345, emewHeader);
	emew = filterGetContext(sess, emew_context);

	if (!emew->required || (CLIENT_NOT_SET(sess, CLIENT_HAS_AUTH) && MSG_NOT_SET(sess, MSG_QUEUE)))
		return SMTPF_CONTINUE;

	if ((msgid_index = headerFind(headers, "Message-Id", &msgid)) == -1)
		return SMTPF_CONTINUE;

	/* Has EMEW already been applied. */
	if (strstr(msgid, "EMEW") != NULL)
		return SMTPF_CONTINUE;

	when = time62Decode(sess->msg.id);

	if ((length = emew3Set(sess, when, msgid, sess->input, sizeof (sess->input))) == 0) {
		if (verb_warn.option.value) {
			syslog(LOG_WARN, LOG_MSG(346) "EMEW Message-ID buffer error or no secret set", LOG_ARGS(sess));
/*{LOG
The buffer used to generate the EMEW Message-ID is too small.
}*/
		}
		return SMTPF_CONTINUE;
	}

	if ((hdr = malloc(length + sizeof ("Message-ID: <>\r\n"))) == NULL)
		return SMTPF_CONTINUE;

	(void) snprintf(hdr, length + sizeof ("Message-ID: <>\r\n"), "Message-ID: <%s>\r\n", sess->input);

	if (verb_emew.option.value)
		syslog(LOG_DEBUG, LOG_MSG(347) "replacing %s", LOG_ARGS(sess), hdr);
	VectorSet(headers, msgid_index, hdr);
	summarySetMsgId(sess, hdr);

	msgid += sizeof ("Message-ID:")-1;
	msgid += strspn(msgid, " \t");

	/* No CRLF is added to References header since the original
	 * message-id header will already have a CRLF that will be
	 * copied.
	 */
	if ((ref_index = headerFind(sess->msg.headers, "References", &hdr)) == -1) {
		(void) snprintf(sess->input, sizeof (sess->input), "References: %s", msgid);
		headerReplace(sess->msg.headers, "References", strdup(sess->input));
	} else {
		char *ref;
		size_t msgid_len, ref_len;

		ref_len = strlen(hdr);
		msgid_len = strlen(sess->msg.msg_id);

		if ((ref = malloc(ref_len + 1 + msgid_len + 1)) != NULL) {
			(void) snprintf(ref, ref_len + 1 + msgid_len + 1, "%s\t%s", hdr, msgid);
			headerReplace(sess->msg.headers, "References", ref);
		}
	}

	return SMTPF_CONTINUE;
}

int
emewHeaders(Session *sess, va_list args)
{
	char *hdr;
	EMEW *emew;
	long offset;
	Vector headers;

	LOG_TRACE(sess, 348, emewHeaders);

	emew = filterGetContext(sess, emew_context);
	headers = va_arg(args, Vector);

	/* Generate EMEW Message-ID. */
	(void) emewHeader(sess, headers);

#ifdef NO_REFERENCES_IN_DSN
/* Typically a DSN has no References: or In-Reply-To: headers, but there
 * is no reason they could not appear and therefore white-wash the DSN
 * through the content filters.
 */
	if (sess->msg.mail->address.length == 0)
		return SMTPF_CONTINUE;
#endif
	/* Recipient white wash. Check if this message is a reply
	 * to a previous message sent through our mail system. This
	 * only allows us to auto white list the message through
	 * some expensive content filtering tests. It is NOT used
	 * to reject the message with.
	 */
	emew->result = EMEW_NONE;

	if (headerFind(headers, "References", &hdr) != -1) {
		/* Check only the last message-id in the References: header. */
		offset = strlrcspn(hdr, strlen(hdr), ": \t");
		if (verb_emew.option.value)
			syslog(LOG_DEBUG, LOG_MSG(349) "got %s", LOG_ARGS(sess), hdr);
		if (emewIsValid(sess, hdr+offset) == EMEW_PASS)
			emew->result = EMEW_PASS;
	}

	/*** Consider dropping the check of In-Reply-To header.
	 *** Concern that spammer could attempt a reply attack
	 *** by including multiple message-ids. The References
	 *** header is the far more interesting one.
	 ***/
	else if (headerFind(headers, "In-Reply-To", &hdr) != -1) {
		if (verb_emew.option.value)
			syslog(LOG_DEBUG, LOG_MSG(350) "got %s", LOG_ARGS(sess), hdr);

		while ((hdr = strstr(hdr, "EMEW")) != NULL) {
			if (emewIsValid(sess, hdr) == EMEW_PASS) {
				emew->result = EMEW_PASS;
				break;
			}
			hdr += sizeof ("EMEW")-1;
		}
	}

	/* We can only return EMEW_NONE or EMEW_PASS for a message
	 * that is not a DSN nor MDN. It's possible to get a legit
	 * reply to a message outside the emew-ttl period so we
	 * ignore EMEW_TTL, and we cannot return EMEW_FAIL since
	 * a message might have multiple RET-ID in a message
	 * thread from multiple participants.
	 */
	if (emew->result == EMEW_PASS) {
		if (verb_emew.option.value)
			syslog(LOG_DEBUG, LOG_MSG(351)  "message originated here", LOG_ARGS(sess));
		statsCount(&stat_emew_pass);
		return SMTPF_ACCEPT;
	}

	return SMTPF_CONTINUE;
}

int
emewContent(Session *sess, va_list args)
{
	long size;
	EMEW *emew;
	long offset;
	unsigned char *chunk;

	emew = filterGetContext(sess, emew_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(352) "emewContent(%lx, chunk=%lx, size=%ld) required=%d", LOG_ARGS(sess), (long) sess, (long) chunk, size, emew->required);

	if (!emew->required)
		return SMTPF_CONTINUE;

	/* Once passed, we should by-pass the other content filters
	 * when processing subsequent body chunks.
	 */
	if (emew->result == EMEW_PASS)
		return SMTPF_ACCEPT;

	/* The DSN with it's original message headers is assumed
	 * to be within the first chunk received.
	 */
	if (chunk != sess->msg.chunk0+sess->msg.eoh || sess->msg.mail->address.length != 0) {
		if (verb_emew.option.value)
			syslog(LOG_DEBUG, LOG_MSG(353)  "EMEW result=%d not-chunk0=%d is-DSN=%d", LOG_ARGS(sess), emew->result, chunk != sess->msg.chunk0+sess->msg.eoh, sess->msg.mail->address.length == 0);
		return SMTPF_CONTINUE;
	}

	/* Bounce backscatter control of DSN or MDN messages
	 * that are suppose to be in response to a message
	 * that has passed through our mail system.
	 */

	/* DSN or MDN must have the original Message-Id header. */
	offset = TextFind(chunk, "*\nMessage-Id: *", size, 1);
	if (0 <= offset) {
		if (verb_emew.option.value)
			syslog(LOG_DEBUG, LOG_MSG(354) "got %.60s", LOG_ARGS(sess), chunk+offset+1);
		emew->result = emewIsValid(sess, chunk+offset+1);
	} else {
		emew->result = EMEW_FAIL;
	}

	switch (*optEmewDsnPolicy.string) {
	case 'r':
		/* No RET-ID in the DSN is counted as a failure. */
		if (emew->result == EMEW_NONE)
			emew->result = EMEW_FAIL;
		break;
	default:
		/* If the policy is something other than reject,
		 * then any RET-ID failures must be ignored.
		 */
		if (emew->result == EMEW_FAIL)
			emew->result = EMEW_NONE;
		break;
	}

	if (verb_emew.option.value)
		syslog(LOG_DEBUG, LOG_MSG(355)  "EMEW result=%s", LOG_ARGS(sess), emew_code_strings[emew->result]);

	switch (emew->result) {
	case EMEW_NONE:
		break;

	case EMEW_PASS:
		statsCount(&stat_emew_pass);
		return SMTPF_ACCEPT;

	case EMEW_TTL:
		statsCount(&stat_emew_ttl);
		/* Set immediate reply now to take advantage of the
		 * replyContent and replyDot filter table short-circuit.
		 */
		return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 DSN or MDN in response to an old message" ID_MSG(357) "\r\n", ID_ARG(sess));
/*{REPLY
See the <a href="summary.html#opt_emew_ttl">emew-ttl</a> option.
}*/
	case EMEW_FAIL:
		statsCount(&stat_emew_fail);
		/* Set immediate reply now to take advantage of the
		 * replyContent and replyDot filter table short-circuit.
		 */
		return replyPushFmt(sess, SMTPF_REJECT, "550 5.7.1 DSN or MDN for message that did not originate here" ID_MSG(358) "\r\n", ID_ARG(sess));
/*{REPLY
See the <a href="summary.html#opt_emew_secret">emew-secret</a> and
<a href="summary.html#opt_emew_dsn_policy">emew-dsn-policy</a> options.
}*/
	}

	return SMTPF_CONTINUE;
}

int
emewDot(Session *sess, va_list ignore)
{
	EMEW *emew = filterGetContext(sess, emew_context);

	LOG_TRACE(sess, 356, emewDot);

	/* Originally EMEW was excluded from white listing checks. The
	 * logic being that a) you need to be able to generate an EMEW
	 * for outbound messages and b) if an remote host sends you a
	 * bounce, then that bounce must have been generated in response
	 * to a message sent from your EMEW enabled host, otherwise it
	 * is backscatter; if you white listed that host, then backscatter
	 * could bleed through.
	 */
	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS))
		return SMTPF_CONTINUE;

	if (emew->result == EMEW_PASS)
		return SMTPF_ACCEPT;

	/* If the result is EMEW_TTL or EMEW_FAIL, then we'll never reach
	 * emewDot, because of the replyDot filter table short-circuit.
	 */

	return SMTPF_CONTINUE;
}

#endif /* FILTER_EMEW */
