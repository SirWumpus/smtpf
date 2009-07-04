/*
 * rate.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __rate_h__
#define __rate_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optRateTag;
extern Option optRateDrop;
extern Option optRateThrottle;

extern Stats stat_rate_client;
extern Stats stat_rate_throttle;

extern int rateRegister(Session *sess, va_list ignore);
extern int rateInit(Session *null, va_list ignore);
extern int rateFini(Session *null, va_list ignore);
extern int rateAccept(Session *sess, va_list ignore);
extern int rateConnect(Session *sess, va_list ignore);

extern unsigned long djb_hash_index(unsigned char *buffer, size_t size, size_t table_size);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __rate_h__ */
