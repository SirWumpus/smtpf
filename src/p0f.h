/*
 * p0f.h
 *
 * Copyright 2007, 2012 by Anthony Howe. All rights reserved.
 */

#ifndef __p0f_h__
#define __p0f_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_P0F)
# if defined HAVE_API_H
/* p0f 3.05b or better */
#  include <api.h>

typedef struct {
	struct p0f_api_query p_query;
	struct p0f_api_response p_response;
} P0F;

# elif defined HAVE_P0F_QUERY_H
/* p0f 2.0.8 */
#  include <p0f-query.h>

typedef struct {
	struct p0f_query p_query;
	struct p0f_response p_response;
} P0F;

# else
#  error "Please specify the p0f source directory using --with-p0f."
# endif

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
extern int p0fGenerateReport(Session *sess, P0F *data, char *buf, size_t size, int brief);
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __p0f_h__ */
