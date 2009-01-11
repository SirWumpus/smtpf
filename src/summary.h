/*
 * summary.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __summary_h__
#define __summary_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern const char *clientFlags(Session *sess);

extern int summaryHeaders(Session *sess, va_list args);

extern void summarySender(Session *sess, const char *sender);
extern void summaryRecipient(Session *sess, const char *recipient);
extern void summaryData(Session *sess);
extern void summaryMessage(Session *sess);
extern void summarySession(Session *sess, time_t elapsed);

extern void summarySetMsgId(Session *sess, char *hdr);
extern void summarySetSubject(Session *sess, char *hdr);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __summary_h__ */
