/*
 * emew.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __emew_h__
#define __emew_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct {
	int result;
	int required;
} EMEW;

extern FilterContext emew_context;

extern const char *emew_code_strings[];

extern Option optEmewDsnPolicy;
extern Option optEmewSecret;
extern Option optEmewTTL;

extern Stats stat_emew_pass;
extern Stats stat_emew_fail;
extern Stats stat_emew_ttl;

extern Verbose verb_emew;

extern int emewRegister(Session *null, va_list ignore);
extern int emewInit(Session *null, va_list ignore);
extern int emewRset(Session *sess, va_list ignore);
extern int emewMailRcpt(Session *sess, va_list args);
extern int emewHeaders(Session *sess, va_list args);
extern int emewContent(Session *sess, va_list args);
extern int emewDot(Session *sess, va_list ignore);

extern int emewHeader(Session *sess, Vector headers);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __emew_h__ */
