/*
 * clamd.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __clamd_h__
#define __clamd_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optClamdMaxSize;
extern Option optClamdPolicy;
extern Option optClamdPolicyIo;
extern Option optClamdSocket;
extern Option optClamdTimeout;

extern int clamdRegister(Session *null, va_list ignore);
extern int clamdInit(Session *null, va_list ignore);
extern int clamdOptn(Session *null, va_list ignore);
extern int clamdConnect(Session *sess, va_list ignore);
extern int clamdRset(Session *sess, va_list ignore);
extern int clamdData(Session *sess, va_list ignore);
extern int clamdHeaders(Session *sess, va_list args);
extern int clamdContent(Session *sess, va_list args);
extern int clamdDot(Session *sess, va_list ignore);
extern int clamdClose(Session *null, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __clamd_h__ */
