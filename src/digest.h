/*
 * digest.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __digest_h__
#define __digest_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FILTER_DIGEST_CONTENT_SHORTCUT

extern Option optDigestBL;

extern Stats statDigestBL;

extern SmtpfCode digestRegister(Session *null, va_list ignore);
extern SmtpfCode digestInit(Session *null, va_list ignore);
extern SmtpfCode digestFini(Session *sess, va_list ignore);
extern SmtpfCode digestRset(Session *sess, va_list ignore);
extern SmtpfCode digestHeaders(Session *sess, va_list args);
extern SmtpfCode digestContent(Session *sess, va_list args);
extern SmtpfCode digestDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __digest_h__ */
