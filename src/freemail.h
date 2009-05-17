/*
 * freemail.h
 *
 * Copyright 2009 by Anthony Howe. All rights reserved.
 */

#ifndef __freemail_h__
#define __freemail_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct {
	const char *mail;
	const char *ptr;
} FreemailTable;

extern FreemailTable freemail_table[];

extern Option optMailStrict;

extern Stats stat_mail_strict_pass;
extern Stats stat_mail_strict_fail;

extern int freemailRegister(Session *sess, va_list ignore);
extern int freemailRcpt(Session *sess, va_list args);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __freemail_h__ */
