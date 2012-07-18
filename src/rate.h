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
extern Option opt_rate_421_delay;

extern Stats stat_rate_client;
extern Stats stat_rate_throttle;

extern SmtpfCode rateRegister(Session *sess, va_list ignore);
extern SmtpfCode rateInit(Session *null, va_list ignore);
extern SmtpfCode rateFini(Session *null, va_list ignore);
extern SmtpfCode rateAccept(Session *sess, va_list ignore);
extern SmtpfCode rateConnect(Session *sess, va_list ignore);

extern unsigned long djb_hash_index(unsigned char *buffer, size_t size, size_t table_size);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __rate_h__ */
