/*
 * tls.c
 *
 * Copyright 2011 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#ifdef HAVE_OPENSSL_SSL_H

#include <limits.h>
#include <com/snert/lib/mail/mime.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Text.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_cert_chain[] =
  "The file path for a collection of CA root certificates as a PEM\n"
"# formatted chain file.\n"
"#"
;
Option opt_cert_chain		= { "tls-cert-chain-file",	"", 	usage_cert_chain };

static const char usage_cert_dir[] =
  "The directory path for individual CA certificates in PEM format.\n"
"#"
;
Option opt_cert_dir		= { "tls-cert-dir",		"", 	usage_cert_dir };

static const char usage_server_cert[] =
  "The file path of the server's public certificate in PEM format.\n"
"#"
;
Option opt_server_cert		= { "tls-server-cert",		"",	usage_server_cert };

static const char usage_server_key[] =
  "The file path of the server's private key in PEM format.\n"
"#"
;
Option opt_server_key		= { "tls-server-key",		"",	usage_server_key };

static const char usage_server_key_pass[] =
  "The server key password, if required; otherwise an empty string.\n"
"#"
;
Option opt_server_key_pass	= { "tls-server-key-pass",	"",	usage_server_key_pass };

static const char usage_dh_pem[] =
  "The path of an optional Diffie-Hellman parameter file in PEM format.\n"
"#"
;
Option opt_server_dh		= { "tls-server-dh",		"",	usage_dh_pem };

static const char usage_smtp_auth_tls[] =
  "When set true, ESMTP AUTH is only available over TLS connection.\n"
"#"
;
Option optSmtpAuthTls		= { "smtp-auth-tls",	"+",		usage_smtp_auth_tls };

Stats stat_tls_error		= { STATS_TABLE_CONNECT, "tls-error" };
Stats stat_tls_pass		= { STATS_TABLE_CONNECT, "tls-pass" };
Stats stat_tls_fail		= { STATS_TABLE_CONNECT, "tls-fail" };
Stats stat_tls_none		= { STATS_TABLE_CONNECT, "tls-none" };

Verbose verb_tls		= { { "tls",		"+", "" } };

/* Access-Map tags and related words:
 *
 *	tls-connect:ip	REQUIRE | VERIFY | VERIFY:CN=name,...;XX=... | SKIP
 *	tls-connect:ptr	REQUIRE | VERIFY | VERIFY:CN=name,...;XX=... | SKIP
 *	tls-from:mail	REQUIRE | VERIFY | VERIFY:CN=name,...;XX=...
 *	tls-to:mail	REQUIRE | VERIFY | VERIFY:CN=name,...;XX=...
 *
 *	SKIP		do not offer STARTTLS to the given host(s)
 *	REQUIRE		STARTTLS required
 *	VERIFY		STARTTLS required, client certificate validated
 *	VERIFY:CN=name	STARTTLS required, client certificate validated,
 *			and CN of client certificate must match name.
 *
 * Possible furture combo-tag variants:
 *
 * 	tls-connect:ip/ptr:from:mail	...
 *	tls-connect:ip/ptr:to:mail	... VERIFY:CN=name,...;XX=...
 * 	tls-from:ip/ptr:to:mail		... VERIFY:CN=name,...;XX=...
 */

typedef struct {
	unsigned flags;
	char *connect;
	char *mail;
	char *rcpt;
} TLS;

static FilterContext tls_context;

/***********************************************************************
 ***
 ***********************************************************************/

unsigned
tls_get_flags(Session *sess)
{
	TLS *ctx = filterGetContext(sess, tls_context);
	return ctx->flags;
}

void
tls_set_flags(Session *sess, unsigned flags)
{
	TLS *ctx = filterGetContext(sess, tls_context);
	ctx->flags |= flags;
}

void
tls_clear_flags(Session *sess, unsigned flags)
{
	TLS *ctx = filterGetContext(sess, tls_context);
	ctx->flags &= ~flags;
}

SmtpfCode
tlsRegister(Session *sess, va_list args)
{
	tls_context = filterRegisterContext(sizeof (TLS));

	optionsRegister(&opt_cert_chain,	1);
	optionsRegister(&opt_cert_dir,		1);
	optionsRegister(&opt_server_cert, 	1);
	optionsRegister(&opt_server_dh,		1);
	optionsRegister(&opt_server_key,	1);
	optionsRegister(&opt_server_key_pass,	1);
	optionsRegister(&optSmtpAuthTls,	0);

	(void) statsRegister(&stat_tls_error);
	(void) statsRegister(&stat_tls_none);
	(void) statsRegister(&stat_tls_fail);
	(void) statsRegister(&stat_tls_pass);

	verboseRegister(&verb_tls);

	return SMTPF_CONTINUE;
}

SmtpfCode
tlsRset(Session *sess, va_list args)
{
	TLS *ctx = filterGetContext(sess, tls_context);

	free(ctx->mail);
	ctx->mail = NULL;

	return SMTPF_CONTINUE;
}

SmtpfCode
tlsClose(Session *sess, va_list args)
{
	TLS *ctx = filterGetContext(sess, tls_context);

	free(ctx->connect);
	ctx->connect = NULL;

	free(ctx->mail);
	ctx->mail = NULL;

	return SMTPF_CONTINUE;
}

SmtpfCode
tlsConnect(Session *sess, va_list args)
{
	TLS *ctx = filterGetContext(sess, tls_context);

	ctx->connect = ctx->mail = ctx->rcpt = NULL;

	if (accessClient(sess, ACCESS_TLS_CONN_TAG, sess->client.name, sess->client.addr, NULL, &ctx->connect, 1) != ACCESS_NOT_FOUND) {
		if (TextInsensitiveCompare(ctx->connect, "SKIP") == 0)
			ctx->flags |= TLS_FLAG_SKIP;
	}

	return SMTPF_CONTINUE;
}

SmtpfCode
tlsMail(Session *sess, va_list args)
{
	char *value;
	ParsePath *mail = va_arg(args, ParsePath *);
	TLS *ctx = filterGetContext(sess, tls_context);

	if (0 < mail->address.length) {
		if (accessEmail(sess, ACCESS_TLS_MAIL_TAG, mail->address.string, NULL, &value) != ACCESS_NOT_FOUND) {
			free(ctx->mail);
			ctx->mail = value;
		}
	}

	return SMTPF_CONTINUE;
}

SmtpfCode
tlsRcpt(Session *sess, va_list args)
{
	int fd;
	ParsePath *rcpt;
	char *value, **t;
	SmtpfCode rc = SMTPF_CONTINUE;
	TLS *ctx = filterGetContext(sess, tls_context);

	LOG_TRACE(sess, 1026, tlsRcpt);

	rcpt = va_arg(args, ParsePath *);

	value = NULL;

	if (accessEmail(sess, ACCESS_TLS_RCPT_TAG, rcpt->address.string, NULL, &ctx->rcpt) != ACCESS_NOT_FOUND)
		value = ctx->rcpt;
	else if (ctx->mail != NULL)
		value = ctx->mail;
	else if (ctx->connect != NULL)
		value = ctx->connect;

	if (value == NULL)
		return SMTPF_CONTINUE;

	fd = socketGetFd(sess->client.socket);
	if (TextSensitiveCompare(value, ACCESS_REQUIRE_WORD) == 0 && !socket3_is_tls(fd)) {
		rc = replySetFmt(sess, SMTPF_REJECT, "530 5.7.0 Must issue a STARTTLS command first" ID_MSG(1026) "\r\n", ID_ARG(sess));
	}

	else if (TextSensitiveCompare(value, ACCESS_VERIFY_WORD) == 0 && !socket3_is_peer_ok(fd)) {
		rc = replySetFmt(sess, SMTPF_REJECT, "535 5.7.8 TLS certificate invalid" ID_MSG(1027) "\r\n", ID_ARG(sess));
	}

	else if (0 < TextSensitiveStartsWith(value, ACCESS_VERIFY_WORD)
	&& 0 < TextSensitiveStartsWith(value+sizeof (ACCESS_VERIFY_WORD)-1, ":CN=")) {
		Vector table = TextSplit(value + sizeof (ACCESS_VERIFY_WORD)-1 + sizeof (":CN=")-1, ",", 0);

		for (t = (char **)VectorBase(table); *t != NULL; t++) {
			if (socket3_is_cn_tls(fd, *t)) {
				break;
			}
		}

		if (*t == NULL) {
			syslog(LOG_ERR, LOG_MSG(1028) "no CN match: %s", LOG_ARGS(sess), value);
			rc = replySetFmt(sess, SMTPF_REJECT, "535 5.7.8 TLS certificate invalid" ID_MSG(1029) "\r\n", ID_ARG(sess));
		}

		VectorDestroy(table);
	}

	free(ctx->rcpt);
	ctx->rcpt = NULL;

	return rc;
}

int
cmdStartTLS(Session *sess)
{
	SOCKET fd = socketGetFd(sess->client.socket);

	if (socket3_is_tls(fd))
		return cmdOutOfSequence(sess);

	SENDCLIENT(sess, "220 ready to start TLS\r\n");

	if (socket3_start_tls(fd, 2, optSmtpConnectTimeout.value)) {
		char error[SOCKET_ERROR_STRING_SIZE];
		statsCount(&stat_tls_error);
		tls_set_flags(sess, TLS_FLAG_ERROR);
		socket3_get_error_tls(fd, error, sizeof (error));
		syslog(LOG_ERR, LOG_MSG(1021) "TLS negotiation %s", LOG_ARGS(sess), error);
/*{LOG
}*/
		return replySetFmt(sess, SMTPF_REJECT, "550 5.7.5 TLS negotiation failed" ID_MSG(1022) "\r\n", ID_ARG(sess));
/*{REPLY
}*/
	}

	tls_set_flags(sess, TLS_FLAG_STARTED);
	(void) socket3_set_sess_id_ctx(fd, (unsigned char *)sess->session->id_log, 16);

	switch (socket3_get_valid_tls(fd)) {
	case 1:
		statsCount(&stat_tls_none);
		tls_set_flags(sess, TLS_FLAG_NONE);
		break;
	case 2:
		statsCount(&stat_tls_fail);
		tls_set_flags(sess, TLS_FLAG_FAIL);
		break;
	case 3:
		statsCount(&stat_tls_pass);
		tls_set_flags(sess, TLS_FLAG_PASS);
		break;
	case 0:
		/* No TLS. Should never happen.*/
		break;
	}

	if (verb_tls.option.value) {
		char buffer[SOCKET_INFO_STRING_SIZE];
		(void) socket3_get_cipher_tls(fd, buffer, sizeof (buffer));
		syslog(LOG_INFO, LOG_MSG(1023) "started %s", LOG_ARGS(sess), buffer);
		if (0 < socket3_get_issuer_tls(fd, buffer, sizeof (buffer)))
			syslog(LOG_INFO, LOG_MSG(1024) "issuer=%s", LOG_ARGS(sess), buffer);
		if (0 < socket3_get_subject_tls(fd, buffer, sizeof (buffer)))
			syslog(LOG_INFO, LOG_MSG(1025) "subject=%s", LOG_ARGS(sess), buffer);
/*{LOG
}*/
	}

	return replySet(sess, &reply_no_reply);
}

#endif /* HAVE_OPENSSL_SSL_H */
