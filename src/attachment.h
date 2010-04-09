/*
 * attachment.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __attachment_h__
#define __attachment_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FILTER_ATTACHMENT_CONTENT_SHORTCUT

extern Option optDenyContent;
extern Option optDenyContentName;
extern Option optDenyContentType;

extern Stats statDenyContentType;
extern Stats statDenyContentName;

extern SmtpfCode attachmentRegister(Session *null, va_list ignore);
extern SmtpfCode attachmentRset(Session *sess, va_list ignore);
extern SmtpfCode attachmentConnect(Session *sess, va_list ignore);
extern SmtpfCode attachmentMail(Session *sess, va_list args);
extern SmtpfCode attachmentRcpt(Session *sess, va_list args);
extern SmtpfCode attachmentData(Session *sess, va_list ignore);
extern SmtpfCode attachmentHeaders(Session *sess, va_list args);
extern SmtpfCode attachmentContent(Session *sess, va_list args);
extern SmtpfCode attachmentDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __attachment_h__ */
