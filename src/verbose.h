/*
 * verbose.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __verbose_h__
#define __verbose_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

typedef struct verbose {
	Option option;
	struct verbose *next;
} Verbose;

/* Verbose levels */
extern Verbose verb_warn;
extern Verbose verb_info;
extern Verbose verb_trace;
extern Verbose verb_debug;

/* Verbose API */
extern Verbose verb_cache;
extern Verbose verb_db;
extern Verbose verb_dns;
extern Verbose verb_kvm;
extern Verbose verb_mutex;
extern Verbose verb_socket;
extern Verbose verb_subject;

#ifdef __linux__
#define VERB_VALGRIND
extern Verbose verb_valgrind;
#endif

/* Verbose SMTP command */
extern Verbose verb_connect;
extern Verbose verb_helo;
extern Verbose verb_auth;
extern Verbose verb_mail;
extern Verbose verb_rcpt;
extern Verbose verb_data;
extern Verbose verb_noop;
extern Verbose verb_rset;

/* Verbose SMTP client. */
extern Verbose verb_smtp;

extern Option optVerbose;

extern int verboseRegister0(Session *null, va_list ignore);

extern void verbose_at_exit(void);
extern void verboseInit(const char *s);
extern void verboseParse(const char *s);
extern int verboseCommand(Session *sess);
extern int verboseRegister(Verbose *v);
extern int verboseSet(char *s);


/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __verbose_h__ */
