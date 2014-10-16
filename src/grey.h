/*
 * grey.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __grey_h__
#define __grey_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FILTER_GREY_CONTENT_SHORTCUT

#define GREY_CACHE_TAG		"grey:"

#define GREY_TUPLE_IP		1	/* complete IP address */
#define GREY_TUPLE_PTR		2	/* IP or PTR shortened */
#define GREY_TUPLE_PTRN		4	/* IP or numerics in PTR compressed to # */
#define GREY_TUPLE_HELO		8	/* HELO/EHLO argument */
#define GREY_TUPLE_HELOS	16	/* HELO/EHLO argument shortened */
#define GREY_TUPLE_P0F		32	/* reserved */
#define GREY_TUPLE_MAIL		64	/* MAIL argument */
#define GREY_TUPLE_RCPT		128	/* RCPT argument */


#ifdef FUTURE
#define GREY_TUPLE_IP		1	/* complete IP address */
#define GREY_TUPLE_IP0		2	/* ** IPv4: first 3 octets; IPv6: first 7 words */
#define GREY_TUPLE_PTR		4	/* IP or truncated PTR */
#define GREY_TUPLE_PTR0		8	/* IP or numerics in PTR compressed to # */
#define GREY_TUPLE_PTR1		16	/* ** If numerics in first label, use PTR0, else PTR */
#define GREY_TUPLE_P0F		32	/* reserved */
#define GREY_TUPLE_HELO		64	/* HELO/EHLO argument */
#define GREY_TUPLE_MAIL		128	/* MAIL argument */
#define GREY_TUPLE_RCPT		256	/* RCPT argument */

#endif

extern Option optGreyKey;
extern Option optGreyPolicy;
extern Option optGreyTempFailPeriod;
extern Option optGreyTempFailTTL;
extern Option optGreyContent;
extern Option optGreyContentSave;
extern Option optGreyReportHeader;

extern void greyInitOptions(void);

extern Stats stat_grey_upgrade;
extern Stats stat_grey_downgrade;
extern Stats stat_grey_accept;
extern Stats stat_grey_tempfail;
extern Stats stat_grey_reject;

extern Stats stat_grey_content;
extern Stats stat_grey_hash_mismatch;

extern Verbose verb_grey;

extern mcc_hooks grey_cache_hooks;

extern int greyRegister(Session *sess, va_list ignore);
extern int greyInit(Session *null, va_list ignore);
extern int greyFini(Session *null, va_list ignore);
extern int greyOptn(Session *null, va_list ignore);
extern int greyGc(Session *null, va_list args);
extern int greyRset(Session *sess, va_list ignore);
extern int greyData(Session *sess, va_list ignore);
extern int greyHeaders(Session *sess, va_list args);
extern int greyContent(Session *sess, va_list args);
extern int greyDot(Session *sess, va_list ignore);
extern int greyClose(Session *sess, va_list ignore);

extern int greyExpireRows(time_t *when);
extern long greyPtrSuffix(Session *sess, char *buffer, long size); /* deprecated */
extern long greyDomainSuffix(const char *name, char *buffer, long size);
extern long greyMakeKey(Session *sess, long grey_key, ParsePath *rcpt, char *buffer, size_t size);

extern void greySqlite3KeyToHost(sqlite3_context *context, int argc, sqlite3_value **argv);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __grey_h__ */
