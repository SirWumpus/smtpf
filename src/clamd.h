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

extern SmtpfCode clamdRegister(Session *null, va_list ignore);
extern SmtpfCode clamdInit(Session *null, va_list ignore);
extern SmtpfCode clamdOptn(Session *null, va_list ignore);
extern SmtpfCode clamdConnect(Session *sess, va_list ignore);
extern SmtpfCode clamdRset(Session *sess, va_list ignore);
extern SmtpfCode clamdData(Session *sess, va_list ignore);
extern SmtpfCode clamdHeaders(Session *sess, va_list args);
extern SmtpfCode clamdContent(Session *sess, va_list args);
extern SmtpfCode clamdDot(Session *sess, va_list ignore);
extern SmtpfCode clamdClose(Session *null, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __clamd_h__ */
