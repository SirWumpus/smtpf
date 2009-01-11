/*
 * size.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __size_h__
#define __size_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optLengthTags;

extern Stats stat_message_size;

extern int sizeRegister(Session *sess, va_list ignore);
extern int sizeConnect(Session *sess, va_list ignore);
extern int sizeRset(Session *sess, va_list ignore);
extern int sizeMail(Session *sess, va_list args);
extern int sizeRcpt(Session *sess, va_list args);
extern int sizeDot(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __size_h__ */
