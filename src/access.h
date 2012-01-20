/*
 * access.h
 *
 * Copyright 2006, 2010 by Anthony Howe. All rights reserved.
 */

#ifndef __access_h__
#define __access_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 *** Access Actions
 ***********************************************************************/

typedef enum {
	ACCESS_OK,
	ACCESS_REJECT,
	ACCESS_IREJECT,
	ACCESS_CONTENT,
	ACCESS_PROTOCOL,
	ACCESS_DISCARD,
	ACCESS_NEXT,
	ACCESS_OK_AV,
	ACCESS_POLICY_OK,
	ACCESS_POLICY_PASS,
	ACCESS_SAVE,
	ACCESS_SKIP,
	ACCESS_SPF_PASS,		/* replaced by policy-pass */
	ACCESS_TAG,
	ACCESS_TEMPFAIL,
	ACCESS_TRAP,
	ACCESS_REQUIRE,
	ACCESS_VERIFY,
	ACCESS_UNKNOWN,
	ACCESS_NOT_FOUND = SMDB_ACCESS_NOT_FOUND,
} AccessCode;

typedef struct {
	const int code;
	const char *name;
} EnumStringMapping;

extern AccessCode access_word_to_code(const char *word);

/***********************************************************************
 ***
 ***********************************************************************/

extern smdb *access_map;
extern AccessCode accessPattern(Session *sess, const char *hay, char *pins, char **actionp);
extern AccessCode accessClient(Session *sess, const char *tag, const char *client_name, const char *client_addr, char **lhs, char **rhs, int include_default);
extern AccessCode accessEmail(Session *sess, const char *tag, const char *mail, char **lhs, char **rhs);
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

extern SmtpfCode accessRegister(Session *null, va_list ignore);
extern SmtpfCode accessInit(Session *null, va_list ignore);
extern SmtpfCode accessFini(Session *null, va_list ignore);
extern SmtpfCode accessIdle(Session *sess, va_list ignore);
extern SmtpfCode accessConnect(Session *sess, va_list ignore);
extern SmtpfCode accessHelo(Session *sess, va_list ignore);
extern SmtpfCode accessMail(Session *sess, va_list args);
extern SmtpfCode accessRcpt(Session *sess, va_list args);
extern SmtpfCode accessData(Session *sess, va_list ignore);
extern SmtpfCode accessHeaders(Session *sess, va_list args);
extern SmtpfCode accessContent(Session *sess, va_list args);
extern SmtpfCode accessDot(Session *sess, va_list ignore);
extern SmtpfCode accessClose(Session *sess, va_list ignore);

/***********************************************************************
 *** Description of access-map tags and words.
 ***********************************************************************/

/*
 * Key Tags
 */
#define ACCESS_BODY_TAG			"body:"
#define ACCESS_CONN_TAG			"connect:"
#define ACCESS_CONCURRENT_TAG		"concurrent-connect:"
#define ACCESS_HELO_TAG			"helo:"
#define ACCESS_MAIL_TAG			"from:"
#define ACCESS_RCPT_TAG			"to:"
#define ACCESS_EMEW_TAG			"emew:"
#define ACCESS_GREY_CONN_TAG		"grey-connect:"
#define ACCESS_GREY_RCPT_TAG		"grey-to:"
#define ACCESS_SIZE_CONN_TAG		"length-connect:"
#define ACCESS_SIZE_MAIL_TAG		"length-from:"
#define ACCESS_SIZE_RCPT_TAG		"length-to:"
#define ACCESS_MSGS_CONN_TAG		"msg-limit-connect:"
#define ACCESS_MSGS_MAIL_TAG		"msg-limit-from:"
#define ACCESS_MSGS_RCPT_TAG		"msg-limit-to:"
#define ACCESS_NULL_TAG			"null-rate-to:"
#define ACCESS_RATE_TAG			"rate-connect:"
#define ACCESS_SPAM_TAG			"spamd:"

#define ACCESS_CONN_MAIL_TAG		ACCESS_CONN_TAG ACCESS_MAIL_TAG
#define ACCESS_CONN_RCPT_TAG		ACCESS_CONN_TAG ACCESS_RCPT_TAG
#define ACCESS_MAIL_RCPT_TAG		ACCESS_MAIL_TAG ACCESS_RCPT_TAG

#define ACCESS_FILENAME_CONN_TAG	"filename-connect:"
#define ACCESS_FILENAME_MAIL_TAG	"filename-from:"
#define ACCESS_FILENAME_RCPT_TAG	"filename-to:"
#define ACCESS_MIMETYPE_CONN_TAG	"mimetype-connect:"
#define ACCESS_MIMETYPE_MAIL_TAG	"mimetype-from:"
#define ACCESS_MIMETYPE_RCPT_TAG	"mimetype-to:"
#define ACCESS_ARCHNAME_CONN_TAG	"archname-connect:"
#define ACCESS_ARCHNAME_MAIL_TAG	"archname-from:"
#define ACCESS_ARCHNAME_RCPT_TAG	"archname-to:"
#define ACCESS_TOPMIMETYPE_CONN_TAG	"top-mimetype-connect:"
#define ACCESS_TOPMIMETYPE_MAIL_TAG	"top-mimetype-from:"
#define ACCESS_TOPMIMETYPE_RCPT_TAG	"top-mimetype-to:"

#define ACCESS_TLS_CONN_TAG		"tls-connect:"
#define ACCESS_TLS_MAIL_TAG		"tls-from:"
#define ACCESS_TLS_RCPT_TAG		"tls-to:"

/*
 * Key Regex
 */
#define ACCESS_BODY_RE			ACCESS_BODY_TAG	".*"
#define ACCESS_CONN_RE			ACCESS_CONN_TAG	".*"
#define ACCESS_CONN_MAIL_RE		ACCESS_CONN_TAG ".+:" ACCESS_MAIL_TAG ".+"
#define ACCESS_CONN_RCPT_RE		ACCESS_CONN_TAG ".+:" ACCESS_RCPT_TAG ".+"
#define ACCESS_CONCURRENT_RE		ACCESS_CONCURRENT_TAG ".*"
#define ACCESS_MAIL_RE			ACCESS_MAIL_TAG	".*"
#define ACCESS_MAIL_RCPT_RE		ACCESS_MAIL_TAG ".+:" ACCESS_RCPT_TAG ".+"
#define ACCESS_RCPT_RE			ACCESS_RCPT_TAG	".*"
#define ACCESS_EMEW_RE			ACCESS_EMEW_TAG	".*"
#define ACCESS_GREY_CONN_RE		ACCESS_GREY_CONN_TAG ".*"
#define ACCESS_GREY_RCPT_RE		ACCESS_GREY_RCPT_TAG ".*"
#define ACCESS_SIZE_CONN_RE		ACCESS_SIZE_CONN_TAG ".*"
#define ACCESS_SIZE_MAIL_RE		ACCESS_SIZE_MAIL_TAG ".*"
#define ACCESS_SIZE_RCPT_RE		ACCESS_SIZE_RCPT_TAG ".*"
#define ACCESS_MSGS_CONN_RE		ACCESS_MSGS_CONN_TAG ".*"
#define ACCESS_MSGS_MAIL_RE		ACCESS_MSGS_MAIL_TAG ".*"
#define ACCESS_MSGS_RCPT_RE		ACCESS_MSGS_RCPT_TAG ".*"
#define ACCESS_NULL_RE			ACCESS_NULL_TAG	".*"
#define ACCESS_RATE_RE			ACCESS_RATE_TAG	".*"
#define ACCESS_SPAM_RE			ACCESS_SPAM_TAG	".*"

#define ACCESS_FILENAME_CONN_RE		ACCESS_FILENAME_CONN_TAG ".*"
#define ACCESS_FILENAME_MAIL_RE		ACCESS_FILENAME_MAIL_TAG ".*"
#define ACCESS_FILENAME_RCPT_RE		ACCESS_FILENAME_RCPT_TAG ".*"
#define ACCESS_MIMETYPE_CONN_RE		ACCESS_MIMETYPE_CONN_TAG ".*"
#define ACCESS_MIMETYPE_MAIL_RE		ACCESS_MIMETYPE_MAIL_TAG ".*"
#define ACCESS_MIMETYPE_RCPT_RE		ACCESS_MIMETYPE_RCPT_TAG ".*"
#define ACCESS_ARCHNAME_CONN_RE		ACCESS_ARCHNAME_CONN_TAG ".*"
#define ACCESS_ARCHNAME_MAIL_RE		ACCESS_ARCHNAME_MAIL_TAG ".*"
#define ACCESS_ARCHNAME_RCPT_RE		ACCESS_ARCHNAME_RCPT_TAG ".*"
#define ACCESS_TOPMIMETYPE_CONN_RE	ACCESS_TOPMIMETYPE_CONN_TAG ".*"
#define ACCESS_TOPMIMETYPE_MAIL_RE	ACCESS_TOPMIMETYPE_MAIL_TAG ".*"
#define ACCESS_TOPMIMETYPE_RCPT_RE	ACCESS_TOPMIMETYPE_RCPT_TAG ".*"

#define ACCESS_TLS_CONN_RE		ACCESS_TLS_CONN_TAG ".*"
#define ACCESS_TLS_MAIL_RE		ACCESS_TLS_MAIL_TAG ".*"
#define ACCESS_TLS_RCPT_RE		ACCESS_TLS_RCPT_TAG ".*"

/*
 * Key printf formats
 */
#define ACCESS_BODY_KEY			ACCESS_BODY_TAG	"%s"		/* IP | domain | mail */
#define ACCESS_CONN_KEY			ACCESS_CONN_TAG	"%s"		/* IP | domain */
#define ACCESS_CONN_MAIL_KEY		ACCESS_CONN_TAG "%s:" ACCESS_MAIL_TAG "%s"	/* IP | domain, mail */
#define ACCESS_CONN_RCPT_KEY		ACCESS_CONN_TAG "%s:" ACCESS_RCPT_TAG "%s"	/* IP | domain, mail */
#define ACCESS_CONCURRENT_KEY		ACCESS_CONCURRENT_TAG "%s"			/* IP | domain */
#define ACCESS_HELO_KEY			ACCESS_HELO_TAG	"%s"		/* IP | domain */
#define ACCESS_MAIL_KEY			ACCESS_MAIL_TAG	"%s"		/* mail */
#define ACCESS_MAIL_RCPT_KEY		ACCESS_MAIL_TAG "%s:" ACCESS_RCPT_TAG "%s"	/* mail, mail */
#define ACCESS_RCPT_KEY			ACCESS_RCPT_TAG	"%s"		/* mail */
#define ACCESS_EMEW_KEY			ACCESS_EMEW_TAG	"%s"		/* mail */
#define ACCESS_GREY_CONN_KEY		ACCESS_GREY_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_GREY_RCPT_KEY		ACCESS_GREY_RCPT_TAG "%s"	/* mail */
#define ACCESS_SIZE_CONN_KEY		ACCESS_SIZE_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_SIZE_MAIL_KEY		ACCESS_SIZE_MAIL_TAG "%s"	/* mail */
#define ACCESS_SIZE_RCPT_KEY		ACCESS_SIZE_RCPT_TAG "%s"	/* mail */
#define ACCESS_MSGS_CONN_KEY		ACCESS_MSGS_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_MSGS_MAIL_KEY		ACCESS_MSGS_MAIL_TAG "%s"	/* mail */
#define ACCESS_MSGS_RCPT_KEY		ACCESS_MSGS_RCPT_TAG "%s"	/* mail */
#define ACCESS_NULL_KEY			ACCESS_NULL_TAG	"%s"		/* mail */
#define ACCESS_RATE_KEY			ACCESS_RATE_TAG	"%s"		/* IP | domain */
#define ACCESS_SPAM_KEY			ACCESS_SPAM_TAG	"%s"		/* domain | mail */

#define ACCESS_FILENAME_CONN_KEY	ACCESS_FILENAME_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_FILENAME_MAIL_KEY	ACCESS_FILENAME_MAIL_TAG "%s"	/* mail */
#define ACCESS_FILENAME_RCPT_KEY	ACCESS_FILENAME_RCPT_TAG "%s"	/* mail */
#define ACCESS_MIMETYPE_CONN_KEY	ACCESS_MIMETYPE_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_MIMETYPE_MAIL_KEY	ACCESS_MIMETYPE_MAIL_TAG "%s"	/* mail */
#define ACCESS_MIMETYPE_RCPT_KEY	ACCESS_MIMETYPE_RCPT_TAG "%s"	/* mail */
#define ACCESS_ARCHNAME_CONN_KEY	ACCESS_ARCHNAME_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_ARCHNAME_MAIL_KEY	ACCESS_ARCHNAME_MAIL_TAG "%s"	/* mail */
#define ACCESS_ARCHNAME_RCPT_KEY	ACCESS_ARCHNAME_RCPT_TAG "%s"	/* mail */
#define ACCESS_TOPMIMETYPE_CONN_KEY	ACCESS_TOPMIMETYPE_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_TOPMIMETYPE_MAIL_KEY	ACCESS_TOPMIMETYPE_MAIL_TAG "%s"	/* mail */
#define ACCESS_TOPMIMETYPE_RCPT_KEY	ACCESS_TOPMIMETYPE_RCPT_TAG "%s"	/* mail */

#define ACCESS_TLS_CONN_KEY		ACCESS_TLS_CONN_TAG "%s"	/* IP | domain */
#define ACCESS_TLS_MAIL_KEY		ACCESS_TLS_MAIL_TAG "%s"	/* mail */
#define ACCESS_TLS_RCPT_KEY		ACCESS_TLS_RCPT_TAG "%s"		/* mail */

/*
 * Action Values
 */
#define ACCESS_OK_WORD			"OK"				/* all */
#define ACCESS_OK_AV_WORD		"OK+AV"				/* Connect: Helo: From: To: and combos */
#define ACCESS_CONTENT_WORD		"CONTENT"			/* Connect: Helo: */
#define ACCESS_PROTOCOL_WORD		"PROTOCOL"			/* To */
#define ACCESS_DISCARD_WORD		"DISCARD"			/* all */
#define ACCESS_IREJECT_WORD		"IREJECT"			/* Connect, Connect:From, From */
#define ACCESS_NEXT_WORD		"NEXT"				/* all */
#define ACCESS_POLICY_PASS_WORD		"POLICY-PASS"			/* Connect:From, From */
#define ACCESS_POLICY_OK_WORD		"POLICY-OK"			/* Connect:From, From */
#define ACCESS_REJECT_WORD		"REJECT"			/* all */
#define ACCESS_SAVE_WORD		"SAVE"				/* Connect, From, To */
#define ACCESS_SKIP_WORD		"SKIP"				/* all */
#define ACCESS_SPF_PASS_WORD		"SPF-PASS"			/* Connect:From, From */
#define ACCESS_TAG_WORD			"TAG"				/* all */
#define ACCESS_TEMPFAIL_WORD		"TEMPFAIL"			/* all */
#define ACCESS_TRAP_WORD		"TRAP"				/* Connect, From, To */

#define ACCESS_REQUIRE_WORD		"REQUIRE"			/* tls-* */
#define ACCESS_VERIFY_WORD		"VERIFY"			/* tls-* */

#define ACCESS_OK_RE			ACCESS_OK_WORD "(:\"[^\"]*\")?"
#define ACCESS_OK_AV_RE			"OK\+AV(:\"[^\"]*\")?"
#define ACCESS_CONTENT_RE		ACCESS_CONTENT_WORD
#define ACCESS_PROTOCOL_RE		ACCESS_PROTOCOL_WORD
#define ACCESS_DISCARD_RE		ACCESS_DISCARD_WORD
#define ACCESS_IREJECT_RE		ACCESS_IREJECT_WORD "(:\"[^\"]*\")?"
#define ACCESS_NEXT_RE			ACCESS_NEXT_WORD
#define ACCESS_REJECT_RE		ACCESS_REJECT_WORD "(:\"[^\"]*\")?"
#define ACCESS_SAVE_RE			ACCESS_SAVE_WORD
#define ACCESS_SKIP_RE			ACCESS_SKIP_WORD
#define ACCESS_SPF_PASS_RE		ACCESS_SPF_PASS_WORD
#define ACCESS_TAG_RE			ACCESS_TAG_WORD
#define ACCESS_TEMPFAIL_RE		ACCESS_TEMPFAIL_WORD "(:\"[^\"]*\")?"
#define ACCESS_TRAP_RE			ACCESS_TRAP_WORD

#define ACCESS_REQUIRE_RE		ACCESS_REQUIRE_WORD
#define ACCESS_VERIFY_RE		ACCESS_VERIFY_WORD "(:[A-Z]+=([^,]+,)*([^,;]+))?"


#define ACCESS_PATTERN_LIST_RE	"(([/![].+[]!/])?[+A-Z-]+(:\".*\")?([ \t]+)?)+([ \t]+[+A-Z-]+)?"

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
