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

extern SmtpfCode dupmsgRegister(Session *null, va_list ignore);
extern SmtpfCode dupmsgConnect(Session *sess, va_list ignore);
extern SmtpfCode dupmsgRset(Session *sess, va_list ignore);
extern SmtpfCode dupmsgHeaders(Session *sess, va_list args);
extern SmtpfCode dupmsgDot(Session *sess, va_list ignore);
extern SmtpfCode dupmsgContent(Session *sess, va_list args);
extern SmtpfCode dupmsgReplyLog(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __dupmsg_h__ */
