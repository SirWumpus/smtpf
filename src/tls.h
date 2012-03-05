/*
 * tls.h
 *
 * Copyright 2011 by Anthony Howe. All rights reserved.
 */

#ifndef __tls_h__
#define __tls_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define TLS_FLAG_SKIP			0x00000001
#define TLS_FLAG_STARTED		0x00000002
#define TLS_FLAG_ERROR			0x00000010
#define TLS_FLAG_NONE			0x00000020
#define TLS_FLAG_FAIL			0x00000040
#define TLS_FLAG_PASS			0x00000080
#define TLS_FLAG_ENABLE_EHLO		0x00000100

extern Option opt_cert_chain;
extern Option opt_cert_dir;
extern Option opt_server_cert;
extern Option opt_server_key;
extern Option opt_server_key_pass;
extern Option opt_server_dh;
extern Option optSmtpAuthTls;

extern Stats stat_tls_error;
extern Stats stat_tls_pass;
extern Stats stat_tls_fail;
extern Stats stat_tls_none;

extern Verbose verb_tls;

extern SmtpfCode tlsRegister(Session *null, va_list ignore);
extern SmtpfCode tlsRset(Session *sess, va_list ignore);
extern SmtpfCode tlsConnect(Session *sess, va_list ignore);
extern SmtpfCode tlsMail(Session *sess, va_list args);
extern SmtpfCode tlsRcpt(Session *sess, va_list args);
extern SmtpfCode tlsClose(Session *sess, va_list args);

extern unsigned tls_get_flags(Session *sess);
extern void tls_set_flags(Session *sess, unsigned flags);
extern void tls_clear_flags(Session *sess, unsigned flags);

extern int cmdStartTLS(Session *sess);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __tls_h__ */
