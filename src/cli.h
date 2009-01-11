/*
 * cli.h
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __cli_h__
#define __cli_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optCliContent;
extern Option optCliEnvelope;
extern Option optCliTimeout;

extern Stats stat_cli_envelope;
extern Stats stat_cli_content;

extern int cliRegister(Session *null, va_list ignore);
extern int cliInit(Session *null, va_list ignore);
extern int cliOptn(Session *null, va_list ignore);
extern int cliConnect(Session *sess, va_list ignore);
extern int cliRset(Session *sess, va_list ignore);
extern int cliData(Session *sess, va_list ignore);
extern int cliHeaders(Session *sess, va_list args);
extern int cliContent(Session *sess, va_list args);
extern int cliDot(Session *sess, va_list ignore);
extern int cliClose(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __cli_h__ */
