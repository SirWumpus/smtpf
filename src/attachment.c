/*
 * attachment.c
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

#ifdef FILTER_ATTACHMENT

#include "smtpf.h"

#include <limits.h>
#include <com/snert/lib/mail/mime.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Text.h>

/***********************************************************************
 ***
 ***********************************************************************/

Option optDenyContent = { "deny-content", "-", "When enabled, then deny-content-* options are applied." };

static const char usage_deny_content_type[] =
  "A list of unacceptable attachment MIME types to reject. Specify an\n"
"# empty list to disable.\n"
"#"
;

Option optDenyContentType = {
	"deny-content-type",

	 "application/*executable"
	";application/*msdos-program"
	";application/*msdownload"
	";message/partial"

	, usage_deny_content_type
};

static const char usage_deny_top_content_type[] =
  "A list of unacceptable message MIME types to reject. Specify an\n"
"# empty list to disable.\n"
"#"
;

Option optDenyTopContentType = {
	"deny-top-content-type",

	 "application/*"

	, usage_deny_top_content_type
};

static const char usage_deny_content_name[] =
  "A list of unacceptable file patterns to reject when found as\n"
"# MIME attachments. The default list consists of unsafe Windows\n"
"# file extensions as given by Microsoft. Specify an empty list to\n"
"# disable.\n"
"#"
;

Option optDenyContentName = {
	"deny-content-name",

	/* Microsfot list of unsafe file extensions.
	 *
	 * http://support.microsoft.com/default.aspx?scid=kb;EN-US;q262617
	 */

	 "*.ade"		/* Microsoft Access project extension */
	";*.adp"		/* Microsoft Access project */
	";*.bas"		/* Microsoft Visual Basic class module */
	";*.bat"		/* Batch file */
	";*.chm"		/* Compiled HTML Help file */
	";*.cmd"		/* Microsoft Windows NT Command script */
	";*.com"		/* Microsoft MS-DOS program */
	";*.cpl"		/* Control Panel extension */
	";*.crt"		/* Security certificate */
	";*.exe"		/* Program */
	";*.hlp"		/* Help file */
	";*.hta"		/* HTML program */
	";*.inf"		/* Setup Information */
	";*.ins"		/* Internet Naming Service */
	";*.isp"		/* Internet Communication settings */
	";*.js"			/* JScript file */
	";*.jse"		/* Jscript Encoded Script file */
	";*.lnk"		/* Shortcut */
	";*.mdb"		/* Microsoft Access program */
	";*.mde"		/* Microsoft Access MDE database */
	";*.msc"		/* Microsoft Common Console document */
	";*.msi"		/* Microsoft Windows Installer package */
	";*.msp"		/* Microsoft Windows Installer patch */
	";*.mst"		/* Microsoft Visual Test source files */
	";*.pcd"		/* Photo CD image, Microsoft Visual compiled script */
	";*.pif"		/* Shortcut to MS-DOS program */
	";*.reg"		/* Registration entries */
	";*.scr"		/* Screen saver */
	";*.sct"		/* Windows Script Component */
	";*.shs"		/* Shell Scrap object */
	";*.shb"		/* Shell Scrap object */
	";*.url"		/* Internet shortcut */
	";*.vb"			/* VBScript file */
	";*.vbe"		/* VBScript Encoded script file */
	";*.vbs"		/* VBScript file */
	";*.wsc"		/* Windows Script Component */
	";*.wsf"		/* Windows Script file */
	";*.wsh"		/* Windows Script Host Settings file	 */

	, usage_deny_content_name
};

static const char usage_deny_zip_name[] =
  "A list of unacceptable file patterns to reject when found RAR or\n"
"# ZIP attachments. The default list consists of unsafe Windows file\n"
"# extensions as given by Microsoft. Specify an empty list to disable.\n"
"#"
;

Option optDenyZipName = {
	"deny-compressed-name",

	/* Microsfot list of unsafe file extensions.
	 *
	 * http://support.microsoft.com/default.aspx?scid=kb;EN-US;q262617
	 */

	 "*.bat"		/* Batch file */
	";*.com"		/* Microsoft MS-DOS program */
	";*.cpl"		/* Control Panel extension */
	";*.exe"		/* Program */
	";*.inf"		/* Setup Information */
	";*.msi"		/* Microsoft Windows Installer package */
	";*.msp"		/* Microsoft Windows Installer patch */
	";*.pif"		/* Shortcut to MS-DOS program */
	";*.scr"		/* Screen saver */

	, usage_deny_zip_name
};

Stats statDenyTopContentType = { STATS_TABLE_MSG, "deny-top-content-type" };
Stats statDenyContentType = { STATS_TABLE_MSG, "deny-content-type" };
Stats statDenyContentName = { STATS_TABLE_MSG, "deny-content-name" };
Stats statDenyZipName = { STATS_TABLE_MSG, "deny-compressed-name" };

/***********************************************************************
 *** ZIP File Format
 ***********************************************************************/

#define ZIP_LOCAL_FILE_HEADER_SIG		0x04034b50L
#define ZIP_DATA_DESCRIPTOR_SIG			0x08074b50L
#define ZIP_ARCHIVE_EXTRA_DATA_SIG		0x08064b50L
#define ZIP_DIRECTORY_FILE_HEADER_SIG		0x02014b50L
#define ZIP_DIRECTORY_DIGITAL_SIG		0x05054b50L
#define ZIP_DIRECTORY_ZIP64_RECORD_SIG		0x06064b50L
#define ZIP_DIRECTORY_ZIP64_LOCATOR_SIG		0x07064b50L
#define ZIP_DIRECTORY_END_RECORD_SIG		0x06054b50L

#define ZIP_EXTRA_ZIP64				0x0001

/*
 *  	MS DOS Time
 * 	0..4 	5..10 	11..15
 * 	second	minute 	hour
 *
 * 	MS DOS Date
 * 	0..4		5..8		9..15
 * 	day (1 - 31) 	month (1 - 12) 	years from 1980
 */

#define MSDOS_DATE_Y(d)		(((d) >> 9  & 0x007f) + 1980)	/* 1980 .. 2108 */
#define MSDOS_DATE_M(d)		( (d) >> 5  & 0x000f)		/* 1 .. 12 */
#define MSDOS_DATE_D(d)		( (d)       & 0x001f)       	/* 1 .. 31 */

#define MSDOS_TIME_H(t)		( (t) >> 11 & 0x001f)		/* 0 .. 23 */
#define MSDOS_TIME_M(t)		( (t) >> 5  & 0x003f)		/* 0 .. 59 */
#define MSDOS_TIME_S(t)		(((t)       & 0x001f) << 1)	/* 2 second units */

/*
 * .zip file format use little-endian integers.
 */

typedef struct {
	uint32_t signature;
} __attribute__((packed)) ZipSignature;

typedef struct {
	uint32_t signature;
	uint16_t version;
	uint16_t flags;
	uint16_t compression_method;
	uint16_t msdos_time;
	uint16_t msdos_date;
	uint32_t crc;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t filename_length;
	uint16_t extra_length;
} __attribute__((packed)) ZipLocalFileHeader;

typedef struct {
	uint32_t signature;
	uint32_t crc32;
	uint64_t compressed_size;
	uint64_t uncompressed_size;
} __attribute__((packed)) ZipDataDescriptor2;

typedef struct {
	uint32_t signature;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
} __attribute__((packed)) ZipDataDescriptor1;

typedef struct {
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
} __attribute__((packed)) ZipDataDescriptor0;

typedef struct {
	uint16_t header_id;
	uint16_t data_size;
} __attribute__((packed)) ZipExtraBlock;

typedef struct {
	uint16_t header_id;
	uint16_t data_size;
	uint64_t uncompressed_size;
	uint64_t compressed_size;
	uint64_t offset_local_header;
	uint32_t disk_number;
} __attribute__((packed)) ZipExtraZip64;

typedef union {
	unsigned char base[sizeof (ZipLocalFileHeader) + USHRT_MAX + 1];
	ZipSignature sig;
	ZipLocalFileHeader file;
	ZipDataDescriptor1 data;
} ZipHeaders;

/***********************************************************************
 *** RAR File Format
 ***********************************************************************/

#define RAR_FLAG_SALT			0x0400
#define RAR_FLAG_EXTENDED_TIME		0x1000
#define RAR_FLAG_REMOVE			0x4000
#define RAR_FLAG_ADD_SIZE		0x8000

#define RAR_TYPE_MARKER			0x72
#define RAR_TYPE_ARCHIVE		0x73
#define RAR_TYPE_FILE			0x74
#define RAR_TYPE_COMMENT		0x75
#define RAR_TYPE_EXTRA			0x76
#define RAR_TYPE_SUBBLOCK		0x77
#define RAR_TYPE_RECOVERY		0x78
#define RAR_TYPE_END			0x7b

typedef struct {
	uint16_t head_crc;
	uint8_t	 head_type;
	uint16_t head_flags;
	uint16_t head_size;
} __attribute__((packed)) RarHeader;

typedef struct {
	uint16_t head_crc;
	uint8_t	 head_type;
	uint16_t head_flags;
	uint16_t head_size;
	uint16_t add_size;
} __attribute__((packed)) RarBlockHeader;

typedef struct {
	uint16_t head_crc;
	uint8_t	 head_type;
	uint16_t head_flags;
	uint16_t head_size;
	uint32_t pack_size;
	uint32_t unp_size;
	uint8_t  host_os;
	uint32_t file_crc;
	uint16_t msdos_time;
	uint16_t msdos_date;
	uint8_t  unp_ver;
	uint8_t  method;
	uint16_t name_size;
	uint32_t attr;
} __attribute__((packed)) RarFileHeader;

static uint8_t rar_marker[] = { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 };

static uint8_t rar_end_marker[] = { 0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00 };

typedef union {
	unsigned char base[sizeof (RarFileHeader) + USHRT_MAX + 1];
	RarHeader head;
	RarFileHeader file;
	RarBlockHeader block;
} RarHeaders;

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct {
	uint64_t value;
	int shift;
} LittleEndian;

typedef union {
	RarHeaders rar;
	ZipHeaders zip;
} ArchiveHeaders;

typedef struct {
	Mime *mime;
	Session *session;
	char *filename;
	char *mimetype;
	char *archname;
	char *top_mime_type;
	Vector compressed_names;
	Vector top_content_types;
	Vector content_types;
	Vector content_names;
	char *attachment_found;
#ifdef NOT_USED
	LittleEndian word;
#endif
	int found_marker;
	size_t hdr_length;
	ArchiveHeaders hdr;
} Attachment;

static FilterContext attachment_context;

Verbose verb_attachment = { { "attachment", "-", "" } };

#ifdef NOT_USED
static void littleEndianReset(LittleEndian *);
static int littleEndianAddByte(LittleEndian *, unsigned);
#endif
static void attachmentMimeHeader(Mime *m);
static void attachmentZipMimePartStart(Mime *m);
static void attachmentZipMimeDecodedOctet(Mime *m, int octet);

static void attachmentMimeHeader(Mime *m);
static void attachmentRarMimePartStart(Mime *m);
static void attachmentRarMimeDecodedOctet(Mime *m, int octet);

/***********************************************************************
 ***
 ***********************************************************************/

SmtpfCode
attachmentRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_attachment);

	optionsRegister(&optDenyContent, 0);
	optionsRegister(&optDenyContentType, 0);
	optionsRegister(&optDenyContentName, 0);
	optionsRegister(&optDenyZipName, 0);
	optionsRegister(&optDenyTopContentType, 0);

	(void) statsRegister(&statDenyTopContentType);
	(void) statsRegister(&statDenyContentType);
	(void) statsRegister(&statDenyContentName);
	(void) statsRegister(&statDenyZipName);

	attachment_context = filterRegisterContext(sizeof (Attachment));

	return SMTPF_CONTINUE;
}

SmtpfCode
attachmentRset(Session *sess, va_list ignore)
{
	Attachment *ctx;

	LOG_TRACE(sess, 819, attachmentRset);

	ctx = filterGetContext(sess, attachment_context);

	if (ctx->filename != optDenyContentName.string)
		free(ctx->filename);
	ctx->filename = NULL;

	if (ctx->mimetype != optDenyContentType.string)
		free(ctx->mimetype);
	ctx->mimetype = NULL;

	if (ctx->archname != optDenyZipName.string)
		free(ctx->archname);
	ctx->archname = NULL;

	if (ctx->top_mime_type != optDenyTopContentType.string)
		free(ctx->top_mime_type);
	ctx->top_mime_type = NULL;

	VectorDestroy(ctx->content_names);
	ctx->content_names = NULL;

	VectorDestroy(ctx->content_types);
	ctx->content_types = NULL;

	VectorDestroy(ctx->top_content_types);
	ctx->top_content_types = NULL;

	VectorDestroy(ctx->compressed_names);
	ctx->compressed_names = NULL;

	mimeFree(ctx->mime);
	ctx->mime = NULL;

	return SMTPF_CONTINUE;
}

SmtpfCode
attachmentConnect(Session *sess, va_list ignore)
{
	Attachment *ctx;

	ctx = filterGetContext(sess, attachment_context);

	ctx->filename = ctx->mimetype = ctx->archname = ctx->top_mime_type = NULL;
	(void) accessClient(sess, ACCESS_FILENAME_CONN_TAG, sess->client.name, sess->client.addr, NULL, &ctx->filename, 1);
	(void) accessClient(sess, ACCESS_MIMETYPE_CONN_TAG, sess->client.name, sess->client.addr, NULL, &ctx->mimetype, 1);
	(void) accessClient(sess, ACCESS_ARCHNAME_CONN_TAG, sess->client.name, sess->client.addr, NULL, &ctx->archname, 1);
	(void) accessClient(sess, ACCESS_TOPMIMETYPE_CONN_TAG, sess->client.name, sess->client.addr, NULL, &ctx->top_mime_type, 1);

	return SMTPF_CONTINUE;
}

SmtpfCode
attachmentMail(Session *sess, va_list args)
{
	char *value;
	ParsePath *mail;
	Attachment *ctx;

	mail = va_arg(args, ParsePath *);
	ctx = filterGetContext(sess, attachment_context);

	if (0 < mail->address.length) {
		if (accessEmail(sess, ACCESS_FILENAME_MAIL_TAG, mail->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->filename);
			ctx->filename = value;
		}
		if (accessEmail(sess, ACCESS_MIMETYPE_MAIL_TAG, mail->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->mimetype);
			ctx->mimetype = value;
		}
		if (accessEmail(sess, ACCESS_ARCHNAME_MAIL_TAG, mail->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->archname);
			ctx->archname = value;
		}
		if (accessEmail(sess, ACCESS_TOPMIMETYPE_MAIL_TAG, mail->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->top_mime_type);
			ctx->top_mime_type = value;
		}
	}

	return SMTPF_CONTINUE;
}

SmtpfCode
attachmentRcpt(Session *sess, va_list args)
{
	char *value;
	ParsePath *rcpt;
	Attachment *ctx;

	rcpt = va_arg(args, ParsePath *);
	ctx = filterGetContext(sess, attachment_context);

	if (0 < rcpt->address.length) {
		if (accessEmail(sess, ACCESS_FILENAME_RCPT_TAG, rcpt->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->filename);
			ctx->filename = value;
		}
		if (accessEmail(sess, ACCESS_MIMETYPE_RCPT_TAG, rcpt->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->mimetype);
			ctx->mimetype = value;
		}
		if (accessEmail(sess, ACCESS_ARCHNAME_RCPT_TAG, rcpt->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->archname);
			ctx->archname = value;
		}
		if (accessEmail(sess, ACCESS_TOPMIMETYPE_RCPT_TAG, rcpt->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->top_mime_type);
			ctx->top_mime_type = value;
		}
	}

	return SMTPF_CONTINUE;
}

SmtpfCode
attachmentData(Session *sess, va_list ignore)
{
	Attachment *ctx;

	ctx = filterGetContext(sess, attachment_context);

	if (ctx->filename == NULL)
		ctx->filename = optDenyContentName.string;
	if (ctx->mimetype == NULL)
		ctx->mimetype = optDenyContentType.string;
	if (ctx->archname == NULL)
		ctx->archname = optDenyZipName.string;
	if (ctx->top_mime_type == NULL)
		ctx->top_mime_type = optDenyTopContentType.string;

	return SMTPF_CONTINUE;
}

static int
attachmentMimeCheck(Attachment *ctx, const char *string, Vector table)
{
	char **pat;

	if (table == NULL)
		return 0;

	if (verb_attachment.option.value)
		syslog(LOG_DEBUG, LOG_MSG(820) "content=\"%s\"", LOG_ARGS(ctx->session), string);

	for (pat = (char **) VectorBase(table); *pat != NULL; pat++) {
		if (TextMatch(string, *pat, -1, 1)) {
			if (verb_attachment.option.value)
				syslog(LOG_DEBUG, LOG_MSG(821) "found content=%s pattern=%s", LOG_ARGS(ctx->session), string, *pat);
			ctx->attachment_found = *pat;
			return 1;
		}
	}

	return 0;
}

static void
attachmentMimeHeader(Mime *m)
{
	long offset;
	int has_quote, span, ch;
	Attachment *ctx = m->mime_data;

	if (verb_headers.option.value)
		syslog(LOG_DEBUG, LOG_MSG(822) "MIME header buffer=\"%s\"", LOG_ARGS(ctx->session), m->source.buffer);

	/* RFC 2045, 2046 MIME part 1 & 2 Content-Type */
	if (0 <= (offset = TextFind((char *) m->source.buffer, "Content-Type:*", m->source.length, 1))) {
		/* New Content-Type header, disable the decoded octet handler. */
		m->mime_decoded_octet = NULL;

		offset += sizeof ("Content-Type:")-1;
		offset += strspn((char *) m->source.buffer+offset, " \t");

		span = strcspn((char *) m->source.buffer+offset, "; \t\r\n");

		ch = m->source.buffer[offset+span];
		m->source.buffer[offset+span] = '\0';

		if (attachmentMimeCheck(ctx, (char *) m->source.buffer+offset, ctx->content_types))
			statsCount(&statDenyContentType);

		/* application/x-zip-compressed application/zip */
		else if (0 <= TextFind((char *) m->source.buffer+offset, "*application/*zip*", m->source.length-offset, 1)) {
			/* Decoded .zip attachments on the fly. */
			m->mime_body_start = attachmentZipMimePartStart;
		}

		else if (0 <= TextFind((char *) m->source.buffer+offset, "*application/x-rar*", m->source.length-offset, 1)) {
			/* Decoded .rar attachments on the fly. */
			m->mime_body_start = attachmentRarMimePartStart;
		}

		m->source.buffer[offset+span] = ch;
		offset += span;

		if (0 <= TextFind((char *) m->source.buffer+offset, "*name=*.zip*", m->source.length-offset, 1)) {
			/* Decoded .zip attachments on the fly. */
			m->mime_body_start = attachmentZipMimePartStart;
		} else if (0 <= TextFind((char *) m->source.buffer+offset, "*name=*.rar*", m->source.length-offset, 1)) {
			/* Decoded .rar attachments on the fly. */
			m->mime_body_start = attachmentRarMimePartStart;
		}

		if (0 <= (span = TextFind((char *) m->source.buffer+offset, "*name=*", m->source.length-offset, 1))) {
			offset += span + sizeof ("name=")-1;
			has_quote = m->source.buffer[offset] == '"';

			if (has_quote) {
				offset++;
				span = strcspn((char *) m->source.buffer+offset, "\"");
			} else {
				span = strcspn((char *) m->source.buffer+offset, "; \t\r\n");
			}

			ch = m->source.buffer[offset+span];
			m->source.buffer[offset+span] = '\0';
			if (attachmentMimeCheck(ctx, (char *) m->source.buffer+offset, ctx->content_names))
				statsCount(&statDenyContentName);
			m->source.buffer[offset+span] = ch;
		}
	}

	/* RFC 2183 Content-Disposition */
	if (0 <= (offset = TextFind((char *) m->source.buffer, "Content-Disposition:*filename=*", m->source.length, 1))) {
		offset += TextFind((char *) m->source.buffer+offset, "*filename=*", m->source.length-offset, 1) + sizeof ("filename=")-1;
		has_quote = m->source.buffer[offset] == '"';

		if (has_quote) {
			offset++;
			span = strcspn((char *) m->source.buffer+offset, "\"");
		} else {
			span = strcspn((char *) m->source.buffer+offset, "; \t\r\n");
		}

		ch = m->source.buffer[offset+span];
		m->source.buffer[offset+span] = '\0';
		if (attachmentMimeCheck(ctx, (char *) m->source.buffer+offset, ctx->content_names))
			statsCount(&statDenyContentName);
		m->source.buffer[offset+span] = ch;
	}
}

SmtpfCode
attachmentHeaders(Session *sess, va_list args)
{
	Vector headers;
	Attachment *ctx;
	char **hdr, *type;

	LOG_TRACE(sess, 823, attachmentHeaders);

	ctx = filterGetContext(sess, attachment_context);
	ctx->attachment_found = NULL;
	ctx->session = sess;

	if ((ctx->top_content_types = TextSplit(ctx->top_mime_type, OPTION_LIST_DELIMS, 0)) != NULL) {
		headers = va_arg(args, Vector);
		for (hdr = (char **) VectorBase(headers); *hdr != NULL; hdr++) {
			if (0 < TextInsensitiveStartsWith(*hdr, "Content-Type:")) {
				type = *hdr + sizeof ("Content-Type:")-1;
				type += strspn(type, " \t");
				if (attachmentMimeCheck(ctx, type, ctx->top_content_types))
					statsCount(&statDenyTopContentType);
				break;
			}
		}
	}

#ifdef FILTER_ATTACHMENT_CONTENT_SHORTCUT
	/* As an optimisation concerning spamd, when we see the
	 * final dot in a chunk, then call dot handler immediately,
	 * instead of in the dot handler phase. So if the entire
	 * message fits in the first chunk, we can avoid connecting
	 * to spamd entirely, which is last in filter_content_table.
	 */
	if (ctx->attachment_found != NULL)
		return attachmentDot(sess, NULL);
#endif
	if (!optDenyContent.value)
		goto error0;

	if ((ctx->mime = mimeCreate(ctx)) == NULL)
		goto error0;

	if ((ctx->compressed_names = TextSplit(ctx->archname, OPTION_LIST_DELIMS, 0)) == NULL)
		goto error0;

	if ((ctx->content_names = TextSplit(ctx->filename, OPTION_LIST_DELIMS, 0)) == NULL)
		goto error0;

	if ((ctx->content_types = TextSplit(ctx->mimetype, OPTION_LIST_DELIMS, 0)) == NULL)
		goto error0;

	/* Are BOTH lists empty? */
	if (VectorLength(ctx->content_types) == 0 && VectorLength(ctx->content_names))
		goto error0;

	ctx->mime->mime_header = attachmentMimeHeader;
#ifdef NOT_USED
	littleEndianReset(&ctx->word);
#endif
	ctx->hdr_length = 0;

	return SMTPF_CONTINUE;
error0:
	return attachmentRset(sess, args);
}

SmtpfCode
attachmentContent(Session *sess, va_list args)
{
	long size;
	Attachment *ctx;
	unsigned char *chunk;

	ctx = filterGetContext(sess, attachment_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(824) "attachmentContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	if (ctx->mime == NULL || ctx->attachment_found != NULL)
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

#ifdef FILTER_ATTACHMENT_CONTENT_SHORTCUT
	/* As an optimisation concerning spamd, when we see the
	 * final dot in a chunk, then call dot handler immediately,
	 * instead of in the dot handler phase. So if the entire
	 * message fits in the first chunk, we can avoid connecting
	 * to spamd entirely, which is last in filter_content_table.
	 */
	if (ctx->attachment_found != NULL)
		return attachmentDot(sess, NULL);
#endif
	return SMTPF_CONTINUE;
}

SmtpfCode
attachmentDot(Session *sess, va_list ignore)
{
	SmtpfCode rc;
	Attachment *ctx;

	rc = SMTPF_CONTINUE;
	LOG_TRACE(sess, 825, attachmentDot);

	ctx = filterGetContext(sess, attachment_context);

	if (ctx->attachment_found != NULL) {
		MSG_SET(sess, MSG_POLICY);
		rc = replyPushFmt(sess, SMTPF_REJECT, "550 5.7.0 message contains blocked content (%s)" ID_MSG(826) CRLF, ctx->attachment_found, ID_ARG(sess));
/*{REPLY
See
<a href="summary.html#opt_deny_content">deny-content</a>,
<a href="summary.html#opt_deny_content_type">deny-content-type</a>,
<a href="summary.html#opt_deny_content_name">deny-content-name</a>,
<a href="summary.html#opt_deny_compressed_name">deny-compressed-name</a>, and
<a href="summary.html#opt_deny_top_content_type">deny-top-content-type</a>,
options.
}*/
	}

	return rc;
}

/***********************************************************************
 *** ZIP Attachments
 ***********************************************************************/

static const int little_endian_test = 1;
#define is_bigendian() (*(char*) &little_endian_test == 0)

#ifdef NOT_USED
void
littleEndianReset(LittleEndian *word)
{
	word->value = 0;
	word->shift = 0;
}

int
littleEndianAddByte(LittleEndian *word, unsigned byte)
{
	word->value |= (byte & 0xFF) << word->shift;
	word->shift += CHAR_BIT;
	return word->shift;
}
#endif

static void
attachmentZipMimePartStart(Mime *m)
{
	Attachment *ctx = m->mime_data;

	m->mime_decoded_octet = attachmentZipMimeDecodedOctet;
	m->mime_body_start = NULL;
	ctx->hdr_length = 0;
}

static void
attachmentZipMimeDecodedOctet(Mime *m, int octet)
{
	Attachment *ctx = m->mime_data;

	/* Read enough bytes to fill the header signature. */
	if (ctx->hdr_length < sizeof (ZipSignature)) {
		ctx->hdr.zip.base[ctx->hdr_length++] = octet;

		if (ctx->hdr_length == sizeof (ZipSignature)) {
			if (is_bigendian())
				TextReverse((char *) &ctx->hdr.zip.sig.signature, sizeof (ctx->hdr.zip.sig.signature));
			if (verb_attachment.option.value)
				syslog(LOG_DEBUG, LOG_MSG(858) "zip-sig=0x%08lx", LOG_ARGS(ctx->session), (long) ctx->hdr.zip.sig.signature);
		}
		return;
	}

	if (ctx->hdr.zip.sig.signature != ZIP_LOCAL_FILE_HEADER_SIG) {
		ctx->hdr.zip.base[0] = octet;
		ctx->hdr_length = 1;
		return;
	}

	/* Read enough bytes to fill the header. */
	if (ctx->hdr_length < sizeof (ZipLocalFileHeader)) {
		ctx->hdr.zip.base[ctx->hdr_length++] = octet;

		/* Convert header fields from little endian to host. */
		if ( ctx->hdr_length == sizeof (ZipLocalFileHeader) && is_bigendian()) {
			TextReverse((char *) &ctx->hdr.zip.file.version, sizeof (ctx->hdr.zip.file.version));
			TextReverse((char *) &ctx->hdr.zip.file.flags, sizeof (ctx->hdr.zip.file.flags));
			TextReverse((char *) &ctx->hdr.zip.file.compression_method, sizeof (ctx->hdr.zip.file.compression_method));
			TextReverse((char *) &ctx->hdr.zip.file.msdos_time, sizeof (ctx->hdr.zip.file.msdos_time));
			TextReverse((char *) &ctx->hdr.zip.file.msdos_date, sizeof (ctx->hdr.zip.file.msdos_date));
			TextReverse((char *) &ctx->hdr.zip.file.crc, sizeof (ctx->hdr.zip.file.crc));
			TextReverse((char *) &ctx->hdr.zip.file.compressed_size, sizeof (ctx->hdr.zip.file.compressed_size));
			TextReverse((char *) &ctx->hdr.zip.file.uncompressed_size, sizeof (ctx->hdr.zip.file.uncompressed_size));
			TextReverse((char *) &ctx->hdr.zip.file.filename_length, sizeof (ctx->hdr.zip.file.filename_length));
			TextReverse((char *) &ctx->hdr.zip.file.extra_length, sizeof (ctx->hdr.zip.file.extra_length));
		}

		return;
	}

	/* Read enough bytes for the filename. */
	if (0 < ctx->hdr.zip.file.filename_length) {
		ctx->hdr.zip.file.filename_length--;
		ctx->hdr.zip.base[ctx->hdr_length++] = octet;

		if (ctx->hdr.zip.file.filename_length == 0) {
			ctx->hdr.zip.base[ctx->hdr_length++] = '\0';
			if (attachmentMimeCheck(ctx, (char *) ctx->hdr.zip.base + sizeof (ZipLocalFileHeader), ctx->compressed_names))
				statsCount(&statDenyZipName);
		}

		return;
	}

	/* Read and ignore the extra field. */
	if (0 < ctx->hdr.zip.file.extra_length)
		ctx->hdr.zip.file.extra_length--;

	/* At the end of extra field, resume looking for signatures. */
	if (ctx->hdr.zip.file.extra_length == 0)
		ctx->hdr_length = 0;
}

/***********************************************************************
 *** RAR Attachments
 ***********************************************************************/

static void
attachmentRarMimePartStart(Mime *m)
{
	Attachment *ctx = m->mime_data;

	m->mime_decoded_octet = attachmentRarMimeDecodedOctet;
	m->mime_body_start = NULL;
	ctx->found_marker = 0;
	ctx->hdr_length = 0;
}

static void
attachmentRarMimeDecodedOctet(Mime *m, int octet)
{
	Attachment *ctx = m->mime_data;

	/* Read enough bytes to fill the header signature. */
	if (ctx->hdr_length < sizeof (RarHeader)) {
		ctx->hdr.rar.base[ctx->hdr_length++] = octet;

		if (ctx->hdr_length == sizeof (RarHeader)) {
			if (is_bigendian())
				TextReverse((char *) &ctx->hdr.rar.head.head_type, sizeof (ctx->hdr.rar.head.head_type));
			if (verb_attachment.option.value)
				syslog(
					LOG_DEBUG, LOG_MSG(859) "rar-type=0x%02x flags=%hx hdr-size=%hu",
					LOG_ARGS(ctx->session), ctx->hdr.rar.head.head_type,
					ctx->hdr.rar.head.head_flags, ctx->hdr.rar.head.head_size
				);

			if (ctx->found_marker) {
				if (memcmp(ctx->hdr.rar.base, rar_end_marker, sizeof (rar_end_marker)) == 0) {
					if (verb_attachment.option.value)
						syslog(LOG_DEBUG, LOG_MSG(860) "RAR end marker found", LOG_ARGS(ctx->session));

					m->mime_decoded_octet = NULL;
					ctx->found_marker = 0;
					ctx->hdr_length = 0;
				}
				ctx->hdr.rar.head.head_size -= sizeof (RarHeader);
			}

			/* Find the RAR start marker. */
			else if (memcmp(ctx->hdr.rar.base, rar_marker, sizeof (rar_marker)) == 0) {
				if (verb_attachment.option.value)
					syslog(LOG_DEBUG, LOG_MSG(861) "RAR start marker found", LOG_ARGS(ctx->session));
				ctx->found_marker = 1;
				ctx->hdr_length = 0;
			}

			/* Shift header left one byte while we look for the marker. */
			else {
				memmove(ctx->hdr.rar.base, ctx->hdr.rar.base+1, --ctx->hdr_length);
			}
		}

		return;
	}

	if (ctx->hdr.rar.head.head_type != RAR_TYPE_FILE) {
		if ((ctx->hdr.rar.head.head_flags & RAR_FLAG_ADD_SIZE)
		&& ctx->hdr_length < sizeof (RarBlockHeader)) {
			ctx->hdr.rar.base[ctx->hdr_length++] = octet;

			if (ctx->hdr_length == sizeof (RarBlockHeader)) {
				if (is_bigendian())
					TextReverse((char *) &ctx->hdr.rar.block.add_size, sizeof (ctx->hdr.rar.block.add_size));
				ctx->hdr.rar.head.head_size -= 2;
			}
			return;
		}

		if (ctx->hdr_length == sizeof (RarBlockHeader)) {
			/* Read and ignore the header block. */
			if (0 < ctx->hdr.rar.block.add_size)
				ctx->hdr.rar.block.add_size--;

			if (ctx->hdr.rar.block.add_size == 0)
				ctx->hdr_length -= 2;
			return;
		}

		/* Read and ignore the header block. */
		if (0 < ctx->hdr.rar.head.head_size)
			ctx->hdr.rar.head.head_size--;

		/* At the end of the block, read the next header. */
		if (ctx->hdr.rar.head.head_size == 0)
			ctx->hdr_length = 0;

		return;
	}

	/* Read enough bytes to fill the header. */
	if (ctx->hdr_length < sizeof (RarFileHeader)) {
		ctx->hdr.rar.head.head_size--;
		ctx->hdr.rar.base[ctx->hdr_length++] = octet;

		/* Convert header fields from little endian to host. */
		if (ctx->hdr_length == sizeof (RarFileHeader) && is_bigendian()) {
			TextReverse((char *) &ctx->hdr.rar.file.head_crc, sizeof (ctx->hdr.rar.file.head_crc));
			TextReverse((char *) &ctx->hdr.rar.file.head_flags, sizeof (ctx->hdr.rar.file.head_flags));
			TextReverse((char *) &ctx->hdr.rar.file.head_size, sizeof (ctx->hdr.rar.file.head_size));
			TextReverse((char *) &ctx->hdr.rar.file.msdos_time, sizeof (ctx->hdr.rar.file.msdos_time));
			TextReverse((char *) &ctx->hdr.rar.file.msdos_date, sizeof (ctx->hdr.rar.file.msdos_date));
			TextReverse((char *) &ctx->hdr.rar.file.file_crc, sizeof (ctx->hdr.rar.file.file_crc));
			TextReverse((char *) &ctx->hdr.rar.file.pack_size, sizeof (ctx->hdr.rar.file.pack_size));
			TextReverse((char *) &ctx->hdr.rar.file.unp_size, sizeof (ctx->hdr.rar.file.unp_size));
			TextReverse((char *) &ctx->hdr.rar.file.name_size, sizeof (ctx->hdr.rar.file.name_size));
			TextReverse((char *) &ctx->hdr.rar.file.attr, sizeof (ctx->hdr.rar.file.attr));
		}

		return;
	}

	/* Read enough bytes for the filename. */
	if (0 < ctx->hdr.rar.file.name_size) {
		ctx->hdr.rar.file.name_size--;
		ctx->hdr.rar.head.head_size--;
		ctx->hdr.rar.base[ctx->hdr_length++] = octet;

		if (ctx->hdr.rar.file.name_size == 0) {
			ctx->hdr.rar.base[ctx->hdr_length++] = '\0';
			if (attachmentMimeCheck(ctx, (char *) ctx->hdr.rar.base + sizeof (RarFileHeader), ctx->compressed_names))
				statsCount(&statDenyZipName);

			if (verb_attachment.option.value) {
				syslog(
					LOG_DEBUG, LOG_MSG(862) "rar-pack-size=%lu rar-unpack-size=%lu",
					LOG_ARGS(ctx->session), (unsigned long) ctx->hdr.rar.file.pack_size,
					(unsigned long) ctx->hdr.rar.file.unp_size
				);
			}
		}

		return;
	}

	if (0 < ctx->hdr.rar.head.head_size)
		ctx->hdr.rar.head.head_size--;

	/* Read and ignore the compressed file. */
	else if (0 < ctx->hdr.rar.file.pack_size)
		ctx->hdr.rar.file.pack_size--;

	/* At the end of file, read the next header. */
	if (ctx->hdr.rar.head.head_size == 0 && ctx->hdr.rar.file.pack_size == 0)
		ctx->hdr_length = 0;
}
#endif /* FILTER_ATTACHMENT */
