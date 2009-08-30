/*
 * ctasd.h
 *
 * Copyright 2009 by Anthony Howe. All rights reserved.
 */

#ifndef __ctasd_h__
#define __ctasd_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FILTER_CTASD_CONTENT_SHORTCUT

extern Option optCtasdPolicy;
extern Option optCtasdSocket;
extern Option optCtasdStream;
extern Option optCtasdSubjectTag;
extern Option optCtasdTimeout;

extern int ctasdRegister(Session *null, va_list ignore);
extern int ctasdInit(Session *null, va_list ignore);
extern int ctasdOptn(Session *null, va_list ignore);
extern int ctasdConnect(Session *sess, va_list ignore);
extern int ctasdRset(Session *sess, va_list ignore);
extern int ctasdData(Session *sess, va_list ignore);
extern int ctasdHeaders(Session *sess, va_list args);
extern int ctasdContent(Session *sess, va_list args);
extern int ctasdDot(Session *sess, va_list ignore);
extern int ctasdClose(Session *null, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __ctasd_h__ */
