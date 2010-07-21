/*
 * ixhash.h
 *
 * Copyright 2010 by Anthony Howe. All rights reserved.
 */

#ifndef __ixhash_h__
#define __ixhash_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FILTER_IXHASH_CONTENT_SHORTCUT

extern Option opt_ixhash_bl;

extern SmtpfCode ixhashRegister(Session *null, va_list ignore);
extern SmtpfCode ixhashInit(Session *null, va_list ignore);
extern SmtpfCode ixhashFini(Session *sess, va_list ignore);
extern SmtpfCode ixhashData(Session *sess, va_list ignore);
extern SmtpfCode ixhashContent(Session *sess, va_list args);
extern SmtpfCode ixhashDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __ixhash_h__ */
