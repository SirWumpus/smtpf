/*
 * dupmsg.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __dupmsg_h__
#define __dupmsg_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define DUPMSG_CACHE_TAG		"dupmsg:"

extern Option optDupMsgTTL;

extern Stats stat_dupmsg_hit;

extern int dupmsgRegister(Session *null, va_list ignore);
extern int dupmsgRset(Session *sess, va_list ignore);
extern int dupmsgHeaders(Session *sess, va_list args);
extern int dupmsgDot(Session *sess, va_list ignore);
extern int dupmsgContent(Session *sess, va_list args);
extern int dupmsgReplyLog(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __dupmsg_h__ */
