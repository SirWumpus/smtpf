/*
 * savdid.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __savdid_h__
#define __savdid_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef NOT_USED
extern Option optSavdiddMaxSize;
#endif
extern Option optSavdiddPolicy;
extern Option optSavdiddSocket;
extern Option optSavdiddTimeout;

extern int savdidRegister(Session *sess, va_list ignore);
extern int savdidInit(Session *null, va_list ignore);
extern int savdidOptn(Session *null, va_list ignore);
extern int savdidDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __savdid_h__ */
