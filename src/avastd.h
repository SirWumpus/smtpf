/*
 * avastd.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __avastd_h__
#define __avastd_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optAvastdPolicy;
extern Option optAvastdSocket;
extern Option optAvastdTimeout;

extern int avastdRegister(Session *null, va_list ignore);
extern int avastdInit(Session *null, va_list ignore);
extern int avastdOptn(Session *null, va_list ignore);
extern int avastdDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __avastd_h__ */
