/*
 * concurrent.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __concurrent_h__
#define __concurrent_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optConcurrentTag;
extern Option optConcurrentDrop;

extern int concurrentRegister(Session *null, va_list ignore);
extern int concurrentInit(Session *null, va_list ignore);
extern int concurrentFini(Session *null, va_list ignore);
extern int concurrentConnect(Session *sess, va_list ignore);
extern int concurrentClose(Session *sess, va_list ignore);


/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __concurrent_h__ */
