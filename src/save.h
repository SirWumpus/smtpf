/*
 * save.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __save_h__
#define __save_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optSaveData;
extern Option optSaveDir;

extern int saveRegister(Session *sess, va_list ignore);
extern int saveInit(Session *null, va_list ignore);
extern int saveConnect(Session *sess, va_list ignore);
extern int saveRset(Session *sess, va_list ignore);
extern int saveHeaders(Session *sess, va_list args);
extern int saveContent(Session *sess, va_list args);
extern int saveDot(Session *sess, va_list ignore);
extern int saveClose(Session *sess, va_list ignore);

extern int save_data_internal;
extern const char * saveGetName(Session *sess);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __save_h__ */
