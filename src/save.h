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

extern long saveGetEOH(Session *sess);
extern const char * saveGetName(Session *sess);
extern void saveSetSaveDir(Session *sess, const char *dir);
extern void saveSetTrapDir(Session *sess, const char *dir);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __save_h__ */
