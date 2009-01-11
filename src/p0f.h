/*
 * p0f.h
 *
 * Copyright 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __p0f_h__
#define __p0f_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)
# include <p0f-query.h>

typedef struct {
	struct p0f_query p_query;
	struct p0f_response p_response;
} P0F;

extern FilterContext p0f_context;

extern Option optP0fMutex;
extern Option optP0fSocket;
extern Option optP0fTimeout;
extern Option optP0fReportHeader;

extern int p0fRegister(Session *sess, va_list ignore);
extern int p0fInit(Session *null, va_list ignore);
extern int p0fFini(Session *null, va_list ignore);
extern int p0fOptn(Session *null, va_list ignore);
extern int p0fConnect(Session *sess, va_list ignore);
extern int p0fHeaders(Session *sess, va_list args);

#endif

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __p0f_h__ */
