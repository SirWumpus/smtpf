/*
 * siq.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __siq_h__
#define __siq_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define SIQ_CACHE_TAG		"siq:"

extern Option optSiqScoreReject;
extern Option optSiqScoreTag;
extern Option optSiqServers;
extern Option optSiqSubjectTag;

extern Stats stat_siq_query_cache;
extern Stats stat_siq_query_made;
extern Stats stat_siq_score_reject;
extern Stats stat_siq_score_tag;

extern int siqRegister(Session *sess, va_list ignore);
extern int siqInit(Session *null, va_list ignore);
extern int siqFini(Session *null, va_list ignore);
extern int siqRset(Session *sess, va_list ignore);
extern int siqData(Session *sess, va_list ignore);
extern int siqHeaders(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __siq_h__ */
