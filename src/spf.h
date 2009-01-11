/*
 * spf.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __spf_h__
#define __spf_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#include <com/snert/lib/mail/spf.h>

extern Option optSpfHeloPolicy;
extern Option optSpfMailPolicy;
extern Option optSpfReceivedSpfHeaders;
extern Option optSpfBestGuessTxt;

extern Stats stat_spf_pass;
extern Stats stat_spf_fail;
extern Stats stat_spf_softfail;

extern Verbose verb_spf;

extern int spfRegister(Session *sess, va_list ignore);
extern int spfInit(Session *null, va_list ignore);
extern int spfRset(Session *sess, va_list ignore);
extern int spfMail(Session *sess, va_list args);
extern int spfRcpt(Session *sess, va_list ignore);
extern int spfHeaders(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __spf_h__ */
