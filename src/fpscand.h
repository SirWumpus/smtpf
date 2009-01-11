/*
 * fpscand.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __fpscand_h__
#define __fpscand_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef NOT_USED
extern Option optFpscandMaxSize;
#endif
extern Option optFpscandPolicy;
extern Option optFpscandSocket;
extern Option optFpscandTimeout;

extern int fpscandRegister(Session *sess, va_list ignore);
extern int fpscandInit(Session *null, va_list ignore);
extern int fpscandOptn(Session *null, va_list ignore);
extern int fpscandDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __fpscand_h__ */
