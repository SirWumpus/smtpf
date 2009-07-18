/*
 * access.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __access_h__
#define __access_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern smdb *access_map;
extern int accessPattern(Session *sess, const char *hay, char *pins, char **actionp);
extern int accessClient(Session *sess, const char *tag, const char *client_name, const char *client_addr, char **lhs, char **rhs, int include_default);
extern int accessEmail(Session *sess, const char *tag, const char *mail, char **lhs, char **rhs);
extern char *accessDefault(Session *sess, const char *tag);
extern int accessMapOpen(Session *);
extern void accessMapClose(Session *);

extern Option optAccessMap;
extern Option optAccessTagWords;
extern Option optAccessWordTags;

extern Stats stat_connect_bl;
extern Stats stat_connect_wl;
extern Stats stat_connect_mail_bl;
extern Stats stat_connect_mail_wl;
extern Stats stat_mail_bl;
extern Stats stat_mail_wl;
extern Stats stat_connect_rcpt_bl;
extern Stats stat_connect_rcpt_wl;
extern Stats stat_mail_rcpt_bl;
extern Stats stat_mail_rcpt_wl;
extern Stats stat_rcpt_bl;
extern Stats stat_rcpt_wl;
extern Stats stat_tagged;

extern int accessRegister(Session *null, va_list ignore);
extern int accessInit(Session *null, va_list ignore);
extern int accessFini(Session *null, va_list ignore);
extern int accessIdle(Session *sess, va_list ignore);
extern int accessConnect(Session *sess, va_list ignore);
extern int accessHelo(Session *sess, va_list ignore);
extern int accessMail(Session *sess, va_list args);
extern int accessRcpt(Session *sess, va_list args);
extern int accessData(Session *sess, va_list ignore);
extern int accessHeaders(Session *sess, va_list args);
extern int accessContent(Session *sess, va_list args);
extern int accessDot(Session *sess, va_list ignore);
extern int accessClose(Session *sess, va_list ignore);

/***********************************************************************
 *** Description of access-map tags and words.
 ***********************************************************************/

/*
 * Key Tags
 */
#define ACCESS_BODY_TAG		"body:"
#define ACCESS_CONN_TAG		"connect:"
#define ACCESS_CONCURRENT_TAG	"concurrent-connect:"
#define ACCESS_HELO_TAG		"helo:"
#define ACCESS_MAIL_TAG		"from:"
#define ACCESS_RCPT_TAG		"to:"
#define ACCESS_EMEW_TAG		"emew:"
#define ACCESS_GREY_CONN_TAG	"grey-connect:"
#define ACCESS_GREY_RCPT_TAG	"grey-to:"
#define ACCESS_SIZE_CONN_TAG	"length-connect:"
#define ACCESS_SIZE_MAIL_TAG	"length-from:"
#define ACCESS_SIZE_RCPT_TAG	"length-to:"
#define ACCESS_MSGS_CONN_TAG	"msg-limit-connect:"
#define ACCESS_MSGS_MAIL_TAG	"msg-limit-from:"
#define ACCESS_MSGS_RCPT_TAG	"msg-limit-to:"
#define ACCESS_NULL_TAG		"null-rate-to:"
#define ACCESS_RATE_TAG		"rate-connect:"
#define ACCESS_SPAM_TAG		"spamd:"

#define ACCESS_CONN_MAIL_TAG	ACCESS_CONN_TAG ACCESS_MAIL_TAG
#define ACCESS_CONN_RCPT_TAG	ACCESS_CONN_TAG ACCESS_RCPT_TAG
#define ACCESS_MAIL_RCPT_TAG	ACCESS_MAIL_TAG ACCESS_RCPT_TAG

/*
 * Key Regex
 */
#define ACCESS_BODY_RE		ACCESS_BODY_TAG	".*"
#define ACCESS_CONN_RE		ACCESS_CONN_TAG	".*"
#define ACCESS_CONN_MAIL_RE	ACCESS_CONN_TAG ".+:" ACCESS_MAIL_TAG ".+"
#define ACCESS_CONN_RCPT_RE	ACCESS_CONN_TAG ".+:" ACCESS_RCPT_TAG ".+"
#define ACCESS_CONCURRENT_RE	ACCESS_CONCURRENT_TAG ".*"
#define ACCESS_MAIL_RE		ACCESS_MAIL_TAG	".*"
#define ACCESS_MAIL_RCPT_RE	ACCESS_MAIL_TAG ".+:" ACCESS_RCPT_TAG ".+"
#define ACCESS_RCPT_RE		ACCESS_RCPT_TAG	".*"
#define ACCESS_EMEW_RE		ACCESS_EMEW_TAG	".*"
#define ACCESS_GREY_CONN_RE	ACCESS_GREY_CONN_TAG ".*"
#define ACCESS_GREY_RCPT_RE	ACCESS_GREY_RCPT_TAG ".*"
#define ACCESS_SIZE_CONN_RE	ACCESS_SIZE_CONN_TAG ".*"
#define ACCESS_SIZE_MAIL_RE	ACCESS_SIZE_MAIL_TAG ".*"
#define ACCESS_SIZE_RCPT_RE	ACCESS_SIZE_RCPT_TAG ".*"
#define ACCESS_MSGS_CONN_RE	ACCESS_MSGS_CONN_TAG ".*"
#define ACCESS_MSGS_MAIL_RE	ACCESS_MSGS_MAIL_TAG ".*"
#define ACCESS_MSGS_RCPT_RE	ACCESS_MSGS_RCPT_TAG ".*"
#define ACCESS_NULL_RE		ACCESS_NULL_TAG	".*"
#define ACCESS_RATE_RE		ACCESS_RATE_TAG	".*"
#define ACCESS_SPAM_RE		ACCESS_SPAM_TAG	".*"

/*
 * Key printf formats
 */
#define ACCESS_BODY_KEY		ACCESS_BODY_TAG	"%s"		/* IP | domain | mail */
#define ACCESS_CONN_KEY		ACCESS_CONN_TAG	"%s"		/* IP | domain */
#define ACCESS_CONN_MAIL_KEY	ACCESS_CONN_TAG "%s:" ACCESS_MAIL_TAG "%s"	/* IP | domain, mail */
#define ACCESS_CONN_RCPT_KEY	ACCESS_CONN_TAG "%s:" ACCESS_RCPT_TAG "%s"	/* IP | domain, mail */
#define ACCESS_CONCURRENT_KEY	ACCESS_CONCURRENT_TAG "%s"			/* IP | domain */
#define ACCESS_HELO_KEY		ACCESS_HELO_TAG	"%s"		/* IP | domain */
#define ACCESS_MAIL_KEY		ACCESS_MAIL_TAG	"%s"		/* mail */
#define ACCESS_MAIL_RCPT_KEY	ACCESS_MAIL_TAG "%s:" ACCESS_RCPT_TAG "%s"	/* mail, mail */
#define ACCESS_RCPT_KEY		ACCESS_RCPT_TAG	"%s"		/* mail */
#define ACCESS_EMEW_KEY		ACCESS_EMEW_TAG	"%s"		/* mail */
#define ACCESS_GREY_CONN_KEY	ACCESS_GREY_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_GREY_RCPT_KEY	ACCESS_GREY_RCPT_TAG "%s"		/* mail */
#define ACCESS_SIZE_CONN_KEY	ACCESS_SIZE_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_SIZE_MAIL_KEY	ACCESS_SIZE_MAIL_TAG "%s"	/* mail */
#define ACCESS_SIZE_RCPT_KEY	ACCESS_SIZE_RCPT_TAG "%s"		/* mail */
#define ACCESS_MSGS_CONN_KEY	ACCESS_MSGS_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_MSGS_MAIL_KEY	ACCESS_MSGS_MAIL_TAG "%s"	/* mail */
#define ACCESS_MSGS_RCPT_KEY	ACCESS_MSGS_RCPT_TAG "%s"		/* mail */
#define ACCESS_NULL_KEY		ACCESS_NULL_TAG	"%s"		/* mail */
#define ACCESS_RATE_KEY		ACCESS_RATE_TAG	"%s"		/* IP | domain */
#define ACCESS_SPAM_KEY		ACCESS_SPAM_TAG	"%s"		/* domain | mail */

/*
 * Action Values
 */
#define ACCESS_OK_WORD		"OK"				/* all */
#define ACCESS_CONTENT_WORD	"CONTENT"			/* Connect */
#define ACCESS_DISCARD_WORD	"DISCARD"			/* all */
#define ACCESS_IREJECT_WORD	"IREJECT"			/* Connect, Connect:From, From */
#define ACCESS_NEXT_WORD	"NEXT"				/* all */
#define ACCESS_REJECT_WORD	"REJECT"			/* all */
#define ACCESS_SAVE_WORD	"SAVE"				/* Connect, From, To */
#define ACCESS_SKIP_WORD	"SKIP"				/* all */
#define ACCESS_SPF_PASS_WORD	"SPF-PASS"			/* Connect:From, From */
#define ACCESS_TAG_WORD		"TAG"				/* all */
#define ACCESS_TEMPFAIL_WORD	"TEMPFAIL"			/* all */
#define ACCESS_TRAP_WORD	"TRAP"				/* Connect, From, To */

#define ACCESS_OK_RE		ACCESS_OK_WORD "(:\"[^\"]*\")?"
#define ACCESS_CONTENT_RE	ACCESS_CONTENT_WORD
#define ACCESS_DISCARD_RE	ACCESS_DISCARD_WORD
#define ACCESS_IREJECT_RE	ACCESS_IREJECT_WORD "(:\"[^\"]*\")?"
#define ACCESS_NEXT_RE		ACCESS_NEXT_WORD
#define ACCESS_REJECT_RE	ACCESS_REJECT_WORD "(:\"[^\"]*\")?"
#define ACCESS_SAVE_RE		ACCESS_SAVE_WORD
#define ACCESS_SKIP_RE		ACCESS_SKIP_WORD
#define ACCESS_SPF_PASS_RE	ACCESS_SPF_PASS_WORD
#define ACCESS_TAG_RE		ACCESS_TAG_WORD
#define ACCESS_TEMPFAIL_RE	ACCESS_TEMPFAIL_WORD "(:\"[^\"]*\")?"
#define ACCESS_TRAP_RE		ACCESS_TRAP_WORD

#define ACCESS_PATTERN_LIST_RE	"(([/![].+[]!/])?[A-Z-]+(:\".*\")?([ \t]+)?)+([ \t]+[A-Z-]+)?"

typedef struct {
	const char *token;
	const char *valid;
} AccessMapping;

extern AccessMapping accessTagWordsMap[];
extern AccessMapping accessWordTagsMap[];
extern void accessPrintMapping(AccessMapping *table);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __access_h__ */
