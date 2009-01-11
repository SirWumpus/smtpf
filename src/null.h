/*
 * null.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __null_h__
#define __null_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optNullRateTag;

extern Stats stat_null_rate_to;

extern int nullRegister(Session *sess, va_list ignore);
extern int nullInit(Session *null, va_list ignore);
extern int nullFini(Session *null, va_list ignore);
extern int nullRcpt(Session *sess, va_list args);
extern int nullData(Session *sess, va_list ignore);


/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __null_h__ */
