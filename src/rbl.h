/*
 * rbl.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __rbl_h__
#define __rbl_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optDnsBL;
extern Option optDnsGL;
extern Option optDnsWL;

extern Stats stat_dns_bl;
extern Stats stat_dns_gl;
extern Stats stat_dns_wl;
extern Stats stat_idle_retest_timer;

extern int dnsglInit(Session *null, va_list ignore);
extern int dnsglFini(Session *null, va_list ignore);
extern int dnsglConnect(Session *sess, va_list ignore);
extern int dnswlInit(Session *null, va_list ignore);
extern int dnswlFini(Session *null, va_list ignore);
extern int dnswlConnect(Session *sess, va_list ignore);
extern int rblRegister(Session *null, va_list ignore);
extern int rblInit(Session *null, va_list ignore);
extern int rblFini(Session *null, va_list ignore);
extern int rblConnect(Session *sess, va_list ignore);
extern int rblIdle(Session *sess, va_list ignore);
extern int rblHeaders(Session *sess, va_list args);

#ifdef ENABLE_PDQ
typedef struct {
	Option *option;
	Vector suffixes;
	unsigned long *masks;
} DnsList;

extern void dnsListFree(void *_list);
extern DnsList *dnsListCreate(Option *option);
extern const char *dnsListIsListed(Session *sess, DnsList *dnslist, const char *name, PDQ_rr *list);
extern const char *dnsListLookup(Session *sess, DnsList *dnslist, Vector names_seen, const char *name);
extern const char *dnsListQueryIp(Session *sess, DnsList *dns_list, Vector names_seen, const char *name);
extern const char *dnsListQueryMail(Session *sess, DnsList *dns_list, Vector mails_seen, const char *mail);
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __rbl_h__ */
