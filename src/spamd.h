/*
 * spamd.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __spamd_h__
#define __spamd_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optSpamdCommand;
extern Option optSpamdMaxSize;
extern Option optSpamdSocket;
extern Option optSpamdTimeout;
extern Option optSpamdPolicy;

extern Stats stat_junk_mail;

extern Verbose verb_spamd;

extern int spamdRegister(Session *sess, va_list ignore);
extern int spamdInit(Session *null, va_list ignore);
extern int spamdOptn(Session *null, va_list ignore);
extern int spamdConnect(Session *sess, va_list ignore);
extern int spamdRset(Session *sess, va_list ignore);
extern int spamdContent(Session *sess, va_list args);
extern int spamdDot(Session *sess, va_list ignore);
extern int spamdClose(Session *null, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __spamd_h__ */
