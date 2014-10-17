/*
 * spf.c
 *
 * Copyright 2006 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_SPF

#include "smtpf.h"

#include <com/snert/lib/io/Dns.h>
#include <com/snert/lib/mail/spf.h>
#include <com/snert/lib/util/setBitWord.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_spf_helo_policy[] =
  "Check HELO argument and act according to a comma separated list:\n"
"# softfail-reject, softfail-tag, fail-reject, fail-tag\n"
"#\n"
"# Example: spf-helo-policy=fail-reject\n"
"#"
;

static const char usage_spf_mail_policy[] =
  "Check MAIL FROM: domain and act according to a comma separated list:\n"
"# softfail-reject, softfail-tag, fail-reject, fail-tag\n"
"#\n"
"# Example: spf-mail-policy=softfail-reject,fail-reject\n"
"#"
;

#define USAGE_SPF_BEST_GUESS_TXT					\
  "If the initial SPF test does not yield a Pass for any reason, then\n"\
"# we check this \"best guess\" TXT record (eg. v=spf1 a/24 mx/24 ptr)\n"\
"# to see if it yields a Pass result. Otherwise use the original SPF\n"	\
"# result.\n"								\
"#"

Option optSpfHeloPolicy		= { "spf-helo-policy",		"",		usage_spf_helo_policy };
Option optSpfMailPolicy		= { "spf-mail-policy",		"fail-reject",	usage_spf_mail_policy };
Option optSpfReceivedSpfHeaders	= { "spf-received-spf-headers",	"+",		"Add Received-SPF: headers with results of HELO and MAIL FROM: checks." };
Option optSpfBestGuessTxt	= { "spf-best-guess-txt",	"",		USAGE_SPF_BEST_GUESS_TXT };

#define RECEIVED_SPF			"Received-SPF"

#define SPIFF_FAIL_MASK			0x00FF
#define SPIFF_FAIL_TAG			0x0001
#define SPIFF_FAIL_REJECT		0x0002

#define SPIFF_SOFTFAIL_MASK		0xFF00
#define SPIFF_SOFTFAIL_TAG		0x0100
#define SPIFF_SOFTFAIL_REJECT		0x0200

static struct bitword result_action_words[] = {
	{ SPIFF_FAIL_TAG, 		"fail-tag" },
	{ SPIFF_FAIL_REJECT, 		"fail-reject" },
	{ SPIFF_SOFTFAIL_TAG,		"softfail-tag" },
	{ SPIFF_SOFTFAIL_REJECT,	"softfail-reject" },
	{ 0, 				NULL }
};

Verbose verb_spf = { { "spf", "-", "" } };

Stats stat_spf_pass			= { STATS_TABLE_MAIL, "spf-pass" };
Stats stat_spf_fail			= { STATS_TABLE_MAIL, "spf-fail" };
Stats stat_spf_softfail			= { STATS_TABLE_MAIL, "spf-softfail" };

/***********************************************************************
 ***
 ***********************************************************************/

int
spfRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_spf);

	optionsRegister(&optSpfBestGuessTxt, 		0);
	optionsRegister(&optSpfHeloPolicy, 		0);
	optionsRegister(&optSpfMailPolicy, 		0);
	optionsRegister(&optSpfReceivedSpfHeaders, 	0);
	optionsRegister(&spfTempErrorDns,		0);

	(void) statsRegister(&stat_spf_pass);
	(void) statsRegister(&stat_spf_fail);
	(void) statsRegister(&stat_spf_softfail);

	return SMTPF_CONTINUE;
}

int
spfInit(Session *null, va_list ignore)
{
	optSpfHeloPolicy.value = setBitWord(result_action_words, optSpfHeloPolicy.string);
	optSpfMailPolicy.value = setBitWord(result_action_words, optSpfMailPolicy.string);

	return SMTPF_CONTINUE;
}

static int
spfFailAction(long option)
{
	int rc = SMTPF_CONTINUE;

	if (option & SPIFF_FAIL_TAG)
		rc = SMTPF_TAG;

	else if (option & SPIFF_FAIL_REJECT)
		rc = SMTPF_REJECT;

	if (verb_spf.option.value)
		syslog(LOG_DEBUG, LOG_NUM(695) "spfFailAction(%lx) rc=%d", option, rc);

	return rc;
}

static int
spfSoftFailAction(long option)
{
	int rc = SMTPF_CONTINUE;

	if (option & SPIFF_SOFTFAIL_TAG)
		rc = SMTPF_TAG;

	else if (option & SPIFF_SOFTFAIL_REJECT)
		rc = SMTPF_REJECT;

	if (verb_spf.option.value)
		syslog(LOG_DEBUG, LOG_NUM(696) "spfSoftFailAction(%lx) rc=%d", option, rc);

	return rc;
}

static int
spfAction(Session *sess, long option, int spf)
{
	int rc = SMTPF_CONTINUE;

	switch (spf) {
	case SPF_PASS:
		statsCount(&stat_spf_pass);
		rc = SMTPF_ACCEPT;
		break;

	case SPF_FAIL:
		statsCount(&stat_spf_fail);
		rc = spfFailAction(option);
		break;

	case SPF_SOFTFAIL:
		statsCount(&stat_spf_softfail);
		rc = spfSoftFailAction(option);
		break;

	/* TempError, PermError, None, Neutral are all counted
	 * but ignored, which allows us to continue with other
	 * tests.
	 */
	}

	if (verb_spf.option.value)
		syslog(LOG_DEBUG, LOG_NUM(697) "spfAction(%lx, %d=%s) rc=%d", option, spf, spfResultString[spf], rc);

	/* Tag a fail/softfail only if there is be previously
	 * delayed reply.
	 */
	if (!replyIsNegative(sess, 1) && rc == SMTPF_TAG) {
		MSG_SET(sess, MSG_TAG);
		rc = SMTPF_REJECT;
	}

	return rc;
}

int
spfRset(Session *sess, va_list ignore)
{
	LOG_TRACE(sess, 698, spfRset);

	sess->client.spf_helo = SPF_NONE;
	sess->client.spf_helo_error = "";
	sess->msg.spf_mail = SPF_NONE;
	sess->msg.spf_mail_error = "";

	return SMTPF_CONTINUE;
}

int
spfMail(Session *sess, va_list args)
{
	int spf_guess;

	LOG_TRACE(sess, 699, spfMail);

	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS))
		return SMTPF_CONTINUE;

	if (*optSpfHeloPolicy.string != '\0') {
		sess->client.spf_helo_error = spfCheckDomain(
			sess->client.addr, sess->client.helo, &sess->client.spf_helo
		);
		if (*optSpfBestGuessTxt.string != '\0' && sess->client.spf_helo != SPF_PASS) {
			(void) spfCheckHeloMailTxt(
				sess->client.addr, NULL, sess->client.helo,
				optSpfBestGuessTxt.string, &spf_guess
			);
			if (spf_guess == SPF_PASS)
				sess->client.spf_helo = SPF_PASS;
		}
	}

	if (*optSpfMailPolicy.string != '\0') {
		/* Defer any rejction until RCPT or DATA command so
		 * that we can first check for any white listed RCPT.
		 */
		sess->msg.spf_mail_error = spfCheckHeloMail(
			sess->client.addr, sess->client.helo,
			sess->msg.mail->address.string, &sess->msg.spf_mail
		);
		if (*optSpfBestGuessTxt.string != '\0' && sess->msg.spf_mail != SPF_PASS) {
			(void) spfCheckHeloMailTxt(
				sess->client.addr, sess->client.helo,
				sess->msg.mail->address.string,
				optSpfBestGuessTxt.string, &spf_guess
			);
			if (spf_guess == SPF_PASS)
				sess->msg.spf_mail = SPF_PASS;
		}
	}

	return SMTPF_CONTINUE;
}

int
spfRcpt(Session *sess, va_list args)
{
	int rc;

	LOG_TRACE(sess, 700, spfRcpt);

	if (CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_HAS_AUTH|CLIENT_IS_2ND_MX))
		return SMTPF_CONTINUE;

	switch (rc = spfAction(sess, optSpfHeloPolicy.value, sess->client.spf_helo)) {
	case SMTPF_TEMPFAIL:
		/* An invalid HELO, which is a not FQDN, will probably generate
		 * a "DNS name not found" error and so return SPF_TEMP_ERROR.
		 * This can happen while many mail clients continue to submit
		 * email via port 25, instead of the MSA port 587. Consider
		 * a Windows machine where the mail client uses the machine's
		 * workgroup name with no Internet domain suffix.
		 *
		 * So when the HELO argument generates an SPF_TEMP_ERROR and
		 * the DNS error corresponds to not found or undefined result,
		 * then treat the test result as SPF_NONE.
		 */
#ifdef ENABLE_PDQ
		if (sess->client.spf_helo_error == pdqRcodeName(PDQ_RCODE_UNDEFINED) || sess->client.spf_helo_error == pdqRcodeName(PDQ_RCODE_ERRNO))
#else
		if (sess->client.spf_helo_error == DnsErrorNotFound || sess->client.spf_helo_error == DnsErrorUndefined)
#endif
			break;
		/*@fallthrough@*/

	case SMTPF_REJECT:
		rc = replyPushFmt(sess, SMTPF_DELAY |  rc, "%s HELO %s from " CLIENT_FORMAT " SPF result %s; %s" ID_MSG(701) "\r\n",
			rc == SMTPF_TEMPFAIL ? "451 4.4.3" : "550 5.7.1",
			sess->client.helo, CLIENT_INFO(sess),
			spfResultString[sess->client.spf_helo],
			TextEmpty(sess->client.spf_helo_error),
			ID_ARG(sess)
		);
/*{REPLY
See <a href="summary.html#opt_spf_helo_policy">spf-helo-policy</a> option.
}*/
		return  rc;

	case SMTPF_ACCEPT:
		/* HELO can be used to override MAIL FROM, in particualar for
		 * the DSN address, as outlined in Meng Weng Wong's Dec 2004
		 * white paper.
		 */
		if (sess->msg.mail->address.length == 0)
			return SMTPF_CONTINUE;
		/*@fallthrough@*/
	}

	switch (rc = spfAction(sess, optSpfMailPolicy.value, sess->msg.spf_mail)) {
	case SMTPF_TEMPFAIL:
	case SMTPF_REJECT:
		rc = replyPushFmt(sess, SMTPF_DELAY |  rc, "%s sender <%s> via %s (" CLIENT_FORMAT ") SPF result %s; %s" ID_MSG(702) "\r\n",
			rc == SMTPF_TEMPFAIL ? "451 4.4.3" : "550 5.7.1",
			sess->msg.mail->address.string,
			sess->client.helo, CLIENT_INFO(sess),
			spfResultString[sess->msg.spf_mail],
			TextEmpty(sess->msg.spf_mail_error),
			ID_ARG(sess)
		);
/*{REPLY
See <a href="summary.html#opt_spf_mail_policy">spf-mail-policy</a> option.
}*/
		return  rc;
	}

	return SMTPF_CONTINUE;
}

int
spfHeaders(Session *sess, va_list args)
{
	char *hdr;
	int length;

	LOG_TRACE(sess, 703, spfHeaders);

	if (!optSpfReceivedSpfHeaders.value)
		return SMTPF_CONTINUE;

	if ((hdr = malloc(SMTP_TEXT_LINE_LENGTH)) == NULL)
		return SMTPF_CONTINUE;

	length = snprintf(hdr, SMTP_TEXT_LINE_LENGTH, "Received-SPF: %s", spfResultString[sess->client.spf_helo]);
	if (sess->client.spf_helo_error != NULL && *sess->client.spf_helo_error != '\0')
		length += snprintf(hdr+length, SMTP_TEXT_LINE_LENGTH-length, "; problem=%s", sess->client.spf_helo_error);
	length += snprintf(hdr+length, SMTP_TEXT_LINE_LENGTH-length, "; identity=helo; helo=%s; client-ip=%s; receiver=%s\r\n", sess->client.helo, sess->client.addr, sess->iface->name);

	if (VectorAdd(sess->msg.headers, hdr))
		free(hdr);

	if ((hdr = malloc(SMTP_TEXT_LINE_LENGTH)) == NULL)
		return SMTPF_CONTINUE;

	length = snprintf(hdr, SMTP_TEXT_LINE_LENGTH, "Received-SPF: %s", spfResultString[sess->msg.spf_mail]);
	if (sess->msg.spf_mail_error != NULL && *sess->msg.spf_mail_error != '\0')
		length += snprintf(hdr+length, SMTP_TEXT_LINE_LENGTH-length, "; problem=%s", sess->msg.spf_mail_error);
	length += snprintf(hdr+length, SMTP_TEXT_LINE_LENGTH-length, "; identity=mailfrom; envelope-from=<%s>; helo=%s; client-ip=%s; receiver=%s\r\n", sess->msg.mail->address.string, sess->client.helo, sess->client.addr, sess->iface->name);

	if (VectorAdd(sess->msg.headers, hdr))
		free(hdr);

	return SMTPF_CONTINUE;
}

#endif /* FILTER_SPF */
