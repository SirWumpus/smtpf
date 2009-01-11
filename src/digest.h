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

extern int digestRegister(Session *null, va_list ignore);
extern int digestInit(Session *null, va_list ignore);
extern int digestFini(Session *sess, va_list ignore);
extern int digestRset(Session *sess, va_list ignore);
extern int digestHeaders(Session *sess, va_list args);
extern int digestContent(Session *sess, va_list args);
extern int digestDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __digest_h__ */
