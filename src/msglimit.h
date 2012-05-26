/*
 * msglimit.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __msglimit_h__
#define __msglimit_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define MSG_LIMIT_CACHE_TAG		"msg-limit:"

extern Option optMsgLimitPolicy;
extern Option optMsgLimitTags;

extern Stats stat_message_limit;

extern int msgLimitRegister(Session *sess, va_list ignore);
extern int msgLimitOptn(Session *null, va_list ignore);
extern int msgLimitInit(Session *null, va_list ignore);
extern int msgLimitFini(Session *null, va_list ignore);
extern int msgLimitConnect(Session *sess, va_list ignore);
extern int msgLimitMail(Session *sess, va_list args);
extern int msgLimitRcpt(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __msglimit_h__ */
