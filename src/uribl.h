/*
 * uribl.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __uribl_h__
#define __uribl_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#define FILTER_URIBL_CONTENT_SHORTCUT

extern Option optHttpTimeout;
extern Option optUriBL;
extern Option optUriDnsBL;
extern Option optUriBlPolicy;
extern Option optUriLinksPolicy;
extern Option optUriSubDomains;
extern Option optUriMaxLimit;
extern Option optUriMaxTest;
extern Option optUriBlHelo;
extern Option optUriBlMail;
extern Option optUriBlPtr;
extern Option optUriBlHeaders;
extern Option optUriBlNs;
extern Option optUriRequireDomain;
extern Option optUriRequirePtr;
extern Option optUriIpInName;
extern Option optUriIpInNs;
extern Option optUriIpInPtr;
extern Option optUriNsNxDomain;
extern Option optUriRejectUnknown;
extern Option optUriRejectOnTimeout;

extern Verbose verb_uri;

extern Stats stat_uri_bl;
extern Stats stat_uri_dns_bl;
extern Stats stat_uri_bl_helo;
extern Stats stat_uri_bl_ptr;
extern Stats stat_uri_bl_ptr_ns;
extern Stats stat_uri_bl_mail;
extern Stats stat_uri_bl_mail_ns;
extern Stats stat_uri_bl_headers;
extern Stats stat_uri_ip_in_name;
extern Stats stat_uri_ip_in_ns;
extern Stats stat_uri_ip_in_ptr;
extern Stats stat_uri_links_policy;
extern Stats stat_uri_max_limit;
extern Stats stat_uri_max_test;
extern Stats stat_uri_ns_nxdomain;
extern Stats stat_uri_reject_on_timeout;
extern Stats stat_uri_reject_unknown;
extern Stats stat_uri_require_domain;
extern Stats stat_uri_require_ptr;

extern int uriRegister(Session *sess, va_list ignore);
extern int uriblInit(Session *null, va_list ignore);
extern int uriblFini(Session *null, va_list ignore);
extern int uriblOptn(Session *null, va_list ignore);
extern int uriblConnect(Session *sess, va_list ignore);
extern int uriblData(Session *sess, va_list ignore);
extern int uriblHeaders(Session *sess, va_list args);
extern int uriblContent(Session *sess, va_list args);
extern int uriblDot(Session *sess, va_list ignore);
extern int uriblRset(Session *sess, va_list ignore);
extern int uriblClose(Session *sess, va_list ignore);

extern int uriblPtrConnect(Session *sess, va_list ignore);
extern int uriblPtrMail(Session *sess, va_list args);

extern int uriblHeloHelo(Session *sess, va_list ignore);
extern int uriblHeloMail(Session *sess, va_list args);

extern int uriblMailMail(Session *sess, va_list args);

extern int uriblTestURI(Session *sess, URI *uri, int post_data);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __uribl_h__ */
