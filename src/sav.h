/*
 * sav.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __sav_h__
#define __sav_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define SAV_CACHE_TAG		"sav:"

extern Option optCallBack;
extern Option optCallBackPassGrey;

extern Stats stat_call_back_made;
extern Stats stat_call_back_skip;
extern Stats stat_call_back_cache;
extern Stats stat_call_back_accept;
extern Stats stat_call_back_reject;
extern Stats stat_call_back_tempfail;

extern Verbose verb_sav;

extern int savRegister(Session *sess, va_list ignore);
extern int savInit(Session *null, va_list ignore);
extern int savData(Session *sess, va_list ignore);

extern int savExpire(kvm_data *key, kvm_data *value, void *data);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __sav_h__ */
