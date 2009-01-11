/*
 * click.h
 *
 * Copyright 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __click_h__
#define __click_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define CLICK_CACHE_TAG		"click:"

extern Option optClickPolicy;
extern Option optClickSecret;
extern Option optClickTTL;

extern Stats stat_click_accept;
extern Stats stat_click_pass;
extern Stats stat_click_fail;
extern Stats stat_click_ttl;

extern int clickRegister(Session *null, va_list ignore);
extern int clickInit(Session *null, va_list ignore);
extern int clickMail(Session *sess, va_list args);
extern int clickRcpt(Session *sess, va_list args);
extern int clickReplyLog(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __click_h__ */
