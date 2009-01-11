/*
 * timelimit.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __timelimit_h__
#define __timelimit_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optTimeLimitDelimiters;

extern int timeLimitRegister(Session *sess, va_list ignore);
extern int timeLimitRcpt(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __timelimit_h__ */
