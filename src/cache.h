/*
 * cache.h
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __cache_h__
#define __cache_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#include <com/snert/lib/type/mcc.h>

extern Option optCachePath;
extern Option optCacheMulticastIp;
extern Option optCacheMulticastPort;
extern Option optCacheSecret;
extern Option optCacheUnicastDomain;
extern Option optCacheUnicastHosts;
extern Option optCacheUnicastPort;
#ifdef NO_LONGER_USED
extern Option optCacheOnCorrupt;
#endif
extern Option optCacheSyncMode;

extern void cacheInit(void);
extern void cacheFini(void);
extern int cacheIsGcRunning(void);
extern long cacheGetTTL(SmtpfCode code);
extern int cacheRegister(Session *null, va_list ignore);
extern int cacheGc(Session *null, va_list args);
extern int cacheCommand(Session *sess);
extern void cacheGcStart(void);

/***********************************************************************
 *** Description of cache tags.
 ***********************************************************************/

/*
 * Cache tags related to SMTP command states.
 */
#define CACHE_CONN_TAG		"conn:"
#define CACHE_RSET_TAG		"rset:"
#define CACHE_VRFY_TAG		"vrfy:"
#define CACHE_EXPN_TAG		"expn:"
#define CACHE_NOOP_TAG		"noop:"
#define CACHE_AUTH_TAG		"auth:"
#define CACHE_EHLO_TAG		"ehlo:"
#define CACHE_HELO_TAG		"helo:"
#define CACHE_MAIL_TAG		"mail:"
#define CACHE_RCPT_TAG		"rcpt:"
#define CACHE_DATA_TAG		"data:"
#define CACHE_DOT_TAG		"dot:"

#define CACHE_CONN_KEY		CACHE_CONN_TAG	""
#define CACHE_RSET_KEY		CACHE_RSET_TAG	""
#define CACHE_VRFY_KEY		CACHE_VRFY_TAG	""
#define CACHE_EXPN_KEY		CACHE_EXPN_TAG	""
#define CACHE_NOOP_KEY		CACHE_NOOP_TAG	""
#define CACHE_AUTH_KEY		CACHE_AUTH_TAG	""
#define CACHE_EHLO_KEY		CACHE_EHLO_TAG	""
#define CACHE_HELO_KEY		CACHE_HELO_TAG	"%s"	/* IP */
#define CACHE_MAIL_KEY		CACHE_MAIL_TAG	""
#define CACHE_RCPT_KEY		CACHE_RCPT_TAG	"%s"	/* RCPT address */
#define CACHE_DATA_KEY		CACHE_DATA_TAG	""
#define CACHE_DOT_KEY		CACHE_DOT_TAG	""

#define CACHE_CONN_VALUE	""
#define CACHE_RSET_VALUE	""
#define CACHE_VRFY_VALUE	""
#define CACHE_EXPN_VALUE	""
#define CACHE_NOOP_VALUE	""
#define CACHE_AUTH_VALUE	""
#define CACHE_EHLO_VALUE	""
#define CACHE_HELO_VALUE	"%s"			/* HELO | EHLO arg */
#define CACHE_MAIL_VALUE	""
#define CACHE_RCPT_VALUE	"%1d"			/* ASCII 2 = accept, 5 = reject */
#define CACHE_DATA_VALUE	""
#define CACHE_DOT_VALUE		""

#define CACHE_CLIK_TAG		"clik:"
#define CACHE_CLIK_KEY		CACHE_CLIK_KEY	"%s,%s"	/* IP | PTR, MAIL address */
#define CACHE_CLIK_VALUE	"%1d"			/* ASCII 2 = accept. */

#define CACHE_DUMB_TAG		"dumb:"
#define CACHE_DUMB_KEY		CACHE_DUMB_TAG	"%s,%s"
#define CACHE_DUMB_VALUE	"%1d"			/* ASCII 2 = accept, 5 = reject */

#define CACHE_DUP_TAG		"dupmsg:"
#define CACHE_DUP_KEY		CACHE_DUMB_TAG	"%s%s"	/* original msg-id, first RCPT address */
#define CACHE_DUP_VALUE		"%1d %s"		/* ASCII SMTPF code, previous session ID */

#define CACHE_GREY_TAG		"grey:"
#define CACHE_GREY_KEY		CACHE_GREY_TAG	"%s"	/* variable based on grey-key */
#define CACHE_GREY_VALUE_0	"%1d"			/* ASCII 0 = continue, 4 = temp. fail, 5 = reject. */
#define CACHE_GREY_VALUE_1	"%1d %32s %32s"		/* ASCII 0 = continue, 4 = temp. fail, 5 = reject;
							 * optionally followed by a space and two hexdecimal
							 * MD5 hashes when using +grey-content. The key field
							 * order remains constant, fields present according
							 * to grey-key; be sure to review how the ip and ptr
							 * fields are used.
							 */
#define CACHE_SAV_TAG		"sav:"
#define CACHE_SAV_KEY		CACHE_SAV_TAG	"%s"	/* MAIL address | domain */
#define CACHE_SAV_VALUE		"%1d"			/* ASCII 2 = accept, 4 = temp.fail, 5 = reject */

#define CACHE_SIQ_TAG		"siq:"
#define CACHE_SIQ_KEY		CACHE_SIQ_TAG	"%s,%s"	/* IP, MAIL domain */
#define CACHE_SIQ_VALUE		"%s"			/* mixed binary and ASCII */

#define CACHE_MSGL_TAG		"msg-limit:"
#define CACHE_MSGL_KEY		CACHE_MSGL_TAG	"%s"	/* IP | MAIL address | RCPT address */
#define CACHE_MSGL_VALUE	"%u"			/* ASCII integer counter of messages sent */

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __cache_h__ */
