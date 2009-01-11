/*
 * pad.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __pad_h__
#define __pad_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optRFC2821PadReply;
extern Option optRFC2821PadReplyOctet;

extern int padRegister(Session *sess, va_list ignore);
extern int padOptn(Session *sess, va_list ignore);
extern int padReplyLog(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __pad_h__ */
