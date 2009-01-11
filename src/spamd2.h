/*
 * spamd2.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __spamd2_h__
#define __spamd2_h__			1

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
extern Option optSpamdScoreReject;
extern Option optSpamdSubjectTag;
extern Option optSpamdRejectSenderMarkedSpam;

extern Option optSpamdFlagHeader;
extern Option optSpamdLevelHeader;
extern Option optSpamdStatusHeader;
extern Option optSpamdReportHeader;

extern Stats stat_spamd_tag;
extern Stats stat_spamd_reject;
extern Stats stat_sender_marked_spam;
extern Stats stat_spamd_connect;

extern Verbose verb_spamd;

extern int spamdRegister(Session *sess, va_list ignore);
extern int spamdInit(Session *null, va_list ignore);
extern int spamdOptn(Session *null, va_list ignore);
extern int spamdConnect(Session *sess, va_list ignore);
extern int spamdRset(Session *sess, va_list ignore);
extern int spamdHeaders(Session *sess, va_list args);
extern int spamdDot(Session *sess, va_list ignore);
extern int spamdClose(Session *null, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __spamd2_h__ */
