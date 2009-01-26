/*
 * misc.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __misc_h__
#define __misc_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optClientIpInPtr;
extern Option optClientIsMx;
extern Option optClientPtrRequired;
extern Option optHeloClaimsUs;
extern Option optHeloIpMismatch;
extern Option optHeloIsPtr;
extern Option optIdleRetestTimer;
extern Option optOneRcptPerNull;
extern Option optMailIpInNs;
extern Option optMailNsNxDomain;
extern Option optMailRequireMx;
extern Option optMailRetestClient;
extern Option optRFC2821StrictHelo;
extern Option optRFC28227bitHeaders;
extern Option optRFC2822MinHeaders;
extern Option optRFC2822StrictDate;
extern Option optSmtpCommandPause;
extern Option optSmtpGreetPause;
extern Option optSmtpRejectDelay;

extern Stats stat_client_is_mx;
extern Stats stat_client_ip_in_ptr;
extern Stats stat_client_ptr_required;
extern Stats stat_client_ptr_required_error;
extern Stats stat_bogus_helo;
extern Stats stat_helo_claims_us;
extern Stats stat_helo_ip_mismatch;
extern Stats stat_helo_is_ptr;
extern Stats stat_mail_ip_in_ns;
extern Stats stat_mail_ns_nxdomain;
extern Stats stat_mail_require_mx;
extern Stats stat_mail_require_mx_error;
extern Stats stat_one_rcpt_per_null;
extern Stats stat_smtp_command_pause;
extern Stats stat_smtp_greet_pause;
extern Stats stat_smtp_reject_delay;
extern Stats stat_rfc2821_strict_helo;
extern Stats stat_rfc2822_7bit_headers;
extern Stats stat_rfc2822_min_headers;
extern Stats stat_rfc2822_strict_date;

extern Verbose verb_headers;

extern int infoCommand(Session *sess);

extern int miscRegister(Session *sess, va_list ignore);
extern int miscInit(Session *null, va_list ignore);

extern int commandPauseConnect(Session *null, va_list ignore);
extern int greetPauseConnect(Session *sess, va_list ignore);

extern int noPtrConnect(Session *null, va_list ignore);
extern int ipInPtrConnect(Session *null, va_list ignore);

extern int noPtrMail(Session *sess, va_list args);
extern int ipInPtrMail(Session *sess, va_list args);

extern int idleRetestIdle(Session *sess, va_list ignore);

extern int heloSyntaxHelo(Session *sess, va_list ignore);
extern int heloTestsHelo(Session *sess, va_list ignore);
extern int heloTestsMail(Session *sess, va_list ignore);
extern int heloIsPtrHelo(Session *sess, va_list ignore);
extern int heloIsPtrRcpt(Session *sess, va_list ignore);

extern int mailTestsMail(Session *sess, va_list args);

extern int rcptTestsRcpt(Session *sess, va_list args);

extern int sevenBitHeaders(Session *sess, va_list args);
extern int sevenBitDot(Session *sess, va_list args);

extern int rfc2822Headers(Session *sess, va_list args);

extern int msgHeaders(Session *sess, va_list args);
extern void msgSummary(Session *sess);

extern int smtpReplyLog(Session *sess, va_list args);

extern int isNxDomain(Session *sess, const char *host);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __misc_h__ */
