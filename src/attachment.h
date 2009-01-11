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

extern int attachmentRegister(Session *null, va_list ignore);
extern int attachmentRset(Session *sess, va_list ignore);
extern int attachmentHeaders(Session *sess, va_list args);
extern int attachmentContent(Session *sess, va_list args);
extern int attachmentDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __attachment_h__ */
