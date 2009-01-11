/*
 * four21.h
 *
 * Copyright 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __four21_h__
#define __four21_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FOUR21_CACHE_TAG		"421:"

extern Option opt421UnknownIp;

extern Stats stat_421_unknown_ip_bad;
extern Stats stat_421_unknown_ip_good;
extern Stats stat_421_unknown_ip_reject;

extern int four21Register(Session *sess, va_list ignore);
extern int four21Connect(Session *sess, va_list null);
extern int four21Close(Session *sess, va_list null);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __four21_h__ */
