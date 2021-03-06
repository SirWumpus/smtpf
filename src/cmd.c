/*
 * cmd.c
 *
 * Copyright 2006, 2012 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifndef AUTH_MECHANISMS
/*
 *	LOGIN		Only method supported by Outlook & Outlook Express 6.
 *
 *	PLAIN		Old Netscape 4 mail clients; Thunderbird 1.x, Opera 7
 *
 *	DIGEST-MD5	Thunderbird 1.x, Opera 7
 */
#define AUTH_MECHANISMS	"PLAIN LOGIN"
#endif

#include "smtpf.h"
#include <assert.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <ctype.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/spf.h>
#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/util/b64.h>

#define ENABLE_ETRN

/***********************************************************************
 *** SMTP commands
 ***********************************************************************/

/* The message-id is composed of
 *
 *	ymd HMS ppppp sssss cc
 */
void
getMsgId(Session *sess, char buffer[20])
{
	time62Encode(time(NULL), buffer);

	(void) snprintf(buffer+TIME62_BUFFER_SIZE, 20-TIME62_BUFFER_SIZE, "%05u%05u", getpid(), sess->session->id);

	if (62 * 62 <= ++sess->msg.count)
		sess->msg.count = 1;

	buffer[16] = base62[sess->msg.count / 62];
	buffer[17] = base62[sess->msg.count % 62];
	buffer[18] = '\0';
}

void
resetHelo(Session *sess)
{
/*	sessionReset(sess);		*/
	sess->client.auth[0] = '\0';
/*	sess->client.helo[0] = '\0'; 	*/
}

int
cmdNoop(Session *sess)
{
	int rc;

	rc = filterRun(sess, filter_idle_table);
	if (rc != SMTPF_CONTINUE && replyDefined(sess))
		return rc;

	return replySetFmt(sess, SMTPF_CONTINUE, msg_ok, ID_ARG(sess));
}

int
cmdRset(Session *sess)
{
/*	sessionReset(sess); */
	if (sess->client.fwd_to_queue != NULL) {
#ifdef NOT_SURE
		if (mxCommand(sess, sess->client.fwd_to_queue, "RSET\r\n", 250)) {
			(void) mxCommand(sess, sess->client.fwd_to_queue, "QUIT\r\n", 221);
			connectionFree(sess->client.fwd_to_queue);
			sess->client.fwd_to_queue = NULL;
		}
#else
		(void) mxCommand(sess, sess->client.fwd_to_queue, "RSET\r\n", 250);
#endif
	}

	if (sess->state != state0)
		sess->state = sess->helo_state;

	return replySetFmt(sess, SMTPF_CONTINUE, msg_ok, ID_ARG(sess));
}

int
cmdQuit(Session *sess)
{
	if (sess->state == stateRcpt)
		statsCount(&stat_quit_after_rcpt);
	else if (sess->state == stateEhlo)
		statsCount(&stat_quit_after_ehlo);
	else if (sess->state == stateHelo)
		statsCount(&stat_quit_after_helo);

	replyDelayFree(sess);
	sess->state = stateQuit;
	statsCount(&stat_clean_quit);
	CLIENT_SET(sess, CLIENT_HAS_QUIT);
	/* Client sent QUIT, so we can do a normal socket close. */
	(void) socketSetLinger(sess->client.socket, LINGER_ON_CLOSE);

	return replySetFmt(sess, SMTPF_CONTINUE, "221 2.0.0 %s closing connection" ID_MSG(247) "\r\n", sess->iface->name, ID_ARG(sess));
/*{REPLY
The connected client sent an SMTP QUIT command. The server will now close the connection.
}*/
}

int
cmdUnknown(Session *sess)
{
	int rc;

	if (optSmtpDropUnknown.value
	/* Stupid Cisco PIX obfuscates ESMTP EHLO ie. XXXX and some other
	 * extensions. Also ignore extended SMTP commands like Postfix's
	 * XCLIENT
	 */
 	&& (sess->input[0] != 'X' || sess->helo_state == stateHelo)
	&& CLIENT_NOT_SET(sess, CLIENT_TRUSTED)) {
		statsCount(&stat_smtp_drop_unknown);
		rc = SMTPF_DROP;
		goto error0;
	}

	rc = filterRun(sess, filter_idle_table);
	if (rc != SMTPF_CONTINUE && replyDefined(sess))
		return rc;

	rc = SMTPF_REJECT;
error0:
	MSG_SET(sess, MSG_POLICY);
	sess->input[strcspn(sess->input, " ")] = '\0';
	return replySetFmt(sess, rc, "500 5.5.1 %s command unknown" ID_MSG(248) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
An unknown command was sent.
}*/
}

int
cmdMissingArg(Session *sess, int cmd_length)
{
	int rc;

	if (cmd_length < sess->input_length)
		return SMTPF_CONTINUE;

	rc = filterRun(sess, filter_idle_table);
	if (rc != SMTPF_CONTINUE && replyDefined(sess))
		return rc;

	MSG_SET(sess, MSG_POLICY);
	return replySetFmt(sess, SMTPF_REJECT, "501 5.5.2 %s missing argument" ID_MSG(249) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The specified command requires one or more arguments.
}*/
}

int
cmdUnavailable(Session *sess)
{
	MSG_SET(sess, MSG_POLICY);
	return replyPushFmt(sess, SMTPF_TEMPFAIL, msg_421_unavailable, ID_ARG(sess));
}

int
cmdNotImplemented(Session *sess)
{
	MSG_SET(sess, MSG_POLICY);
	sess->input[strcspn(sess->input, " ")] = '\0';
	return replySetFmt(sess, SMTPF_REJECT, "502 5.5.1 %s not implemented" ID_MSG(250) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The given command is specified in a known RFC, but not supported.
}*/
}

int
cmdOutOfSequence(Session *sess)
{
	MSG_SET(sess, MSG_POLICY);
	sess->input[strcspn(sess->input, " ")] = '\0';
	return replySetFmt(sess, SMTPF_REJECT, "503 5.5.1 %s out of sequence" ID_MSG(251) "\r\n", sess->input, ID_ARG(sess));
/*{REPLY
The specified command was sent out of order with respect to other commands expected before this command.
For example HELO or EHLO must be issued and accepted before the first MAIL FROM:; a successful MAIL FROM:
must be sent before any RCPT TO: commands; and there must be at least one successful RCPT TO: before
the DATA command will be accepted. See RFC 5321 for details. Other SMTP command extensions may impose
similar sequence restrictions, such as AUTH (RFC 2554) after EHLO and before MAIL FROM:,
STARTTLS (RFC 3207) after EHLO and not after a previous STARTTLS.
}*/
}

#ifdef ENABLE_TEST_ON_COMMAND
int
cmdTryAgainLater(Session *sess)
{
	return replyPush(sess, &reply_try_again);
}

int
cmdReject(Session *sess)
{
	return replyPush(sess, &reply_notprocessed);
}

int
cmdDrop(Session *sess)
{
	return replyPush(sess, &reply_notprocessed);
}
#endif

int
cmdEhlo(Session *sess)
{
	int rc;
	Reply *reply;

	if ((rc = cmdMissingArg(sess, sizeof ("EHLO ")-1)) != SMTPF_CONTINUE) {
		return rc;
	}

	if (optSmtpHeloSchizo.value
	&& *sess->client.helo != '\0'
	&& TextInsensitiveCompare(sess->client.helo, sess->input + sizeof ("EHLO ")-1) != 0) {
		statsCount(&stat_helo_schizophrenic);
		CLIENT_SET(sess, CLIENT_IS_SCHIZO);
		return replySetFmt(sess, 1 < optSmtpHeloSchizo.value ? SMTPF_DROP : SMTPF_REJECT, "550 5.7.1 client " CLIENT_FORMAT " is schizophrenic" ID_MSG(252) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
The client has sent HELO or EHLO more than once with different arguments each time.
}*/
	}

	(void) TextCopy(sess->client.helo, sizeof (sess->client.helo), sess->input + sizeof ("EHLO ")-1);

	if (!optSmtpEnableEsmtp.value
#ifdef HAVE_OPENSSL_SSL_H
	&&  !(tls_get_flags(sess) & TLS_FLAG_ENABLE_EHLO)
#endif
	&& CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_IS_GREY|CLIENT_PASSED_GREY)) {
		/* Offset the positive count in smtpReplyLog(). When
		 * ESMTP is disabled there will more often than not
		 * be an EHLO attempted, which should not be counted
		 * against smtp-drop-after. A HELO schzio rejection
		 * would be the real reject to count. [SF]
		 */
		sess->client.reject_count--;

		CLIENT_SET(sess, CLIENT_IS_EHLO_NO_HELO);
		return replySetFmt(sess, SMTPF_REJECT, "502 5.5.1 EHLO not supported" ID_MSG(253) "\r\n", ID_ARG(sess));
/*{REPLY
When the <a href="summary.html#opt_smtp_enable_esmtp">smtp-enable-esmtp</a> option is off,
we force the client to down grade to the older HELO command per RFC 2821.
}*/
	}

	resetHelo(sess);

	rc = filterRun(sess, filter_helo_table, sess->client.helo);
	switch (rc & SMTPF_FLAGS) {
	case SMTPF_DROP:
	case SMTPF_REJECT:
	case SMTPF_TEMPFAIL:
		return rc;
	}

	sess->state = sess->helo_state = stateEhlo;

	/* We have to feed a reasonable EHLO response, because some mail
	 * clients will abort if STARTTLS and AUTH are not supported.
	 */
	reply = replyFmt(SMTPF_CONTINUE, "250-%s Hello " CLIENT_FORMAT "" ID_MSG(254) "\r\n", sess->iface->name, CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
}*/
#ifdef HAVE_OPENSSL_SSL_H
	if (*opt_server_key.string != '\0'
	&&  *opt_server_cert.string != '\0'
	&&  !(tls_get_flags(sess) & (TLS_FLAG_SKIP|TLS_FLAG_STARTED)))
		reply = REPLY_APPEND_CONST(reply, "250-STARTTLS\r\n");
#endif
	if (optSmtpAuthEnable.value) {
#ifdef HAVE_OPENSSL_SSL_H
		if ((tls_get_flags(sess) & TLS_FLAG_STARTED) || !optSmtpAuthTls.value)
#endif
			reply = REPLY_APPEND_CONST(reply, "250-AUTH " AUTH_MECHANISMS "\r\n");
	}

	reply = REPLY_APPEND_CONST(reply, "250-ENHANCEDSTATUSCODES\r\n");
	if (optRFC2920Pipelining.value)
		reply = REPLY_APPEND_CONST(reply, "250-PIPELINING\r\n");
	if (optRFC16528bitmime.value)
		reply = REPLY_APPEND_CONST(reply, "250-8BITMIME\r\n");
	if (optSmtpXclientEnable.value && CLIENT_ANY_SET(sess, CLIENT_USUAL_SUSPECTS))
		reply = REPLY_APPEND_CONST(reply, "250-XCLIENT ADDR HELO NAME PROTO\r\n");
#ifdef ENABLE_ETRN
	reply = REPLY_APPEND_CONST(reply, "250-ETRN\r\n");
#endif
#ifdef FILTER_SIZE
	reply = REPLY_APPEND_CONST(reply, "250-SIZE 0\r\n");
#endif
	reply = REPLY_APPEND_CONST(reply, "250 HELP\r\n");

	return replyPush(sess, reply);
}

int
cmdHelo(Session *sess)
{
	int rc;

	if ((rc = cmdMissingArg(sess, sizeof ("HELO ")-1)) != SMTPF_CONTINUE) {
		return rc;
	}

	CLIENT_CLEAR(sess, CLIENT_IS_EHLO_NO_HELO);

	if (optSmtpHeloSchizo.value
	&& *sess->client.helo != '\0'
	&& TextInsensitiveCompare(sess->client.helo, sess->input + sizeof ("HELO ")-1) != 0) {
		statsCount(&stat_helo_schizophrenic);
		CLIENT_SET(sess, CLIENT_IS_SCHIZO);
		return replySetFmt(sess, 1 < optSmtpHeloSchizo.value ? SMTPF_DROP : SMTPF_REJECT, "550 5.7.1 client " CLIENT_FORMAT " is schizophrenic" ID_MSG(255) "\r\n", CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
The client has sent HELO or EHLO more than once with different arguments each time.
}*/
	}

	(void) TextCopy(sess->client.helo, sizeof (sess->client.helo), sess->input + sizeof ("HELO ")-1);
	resetHelo(sess);

	rc = filterRun(sess, filter_helo_table, sess->client.helo);
	switch (rc & SMTPF_FLAGS) {
	case SMTPF_DROP:
	case SMTPF_REJECT:
	case SMTPF_TEMPFAIL:
		return rc;
	}

	sess->state = sess->helo_state = stateHelo;

	return replySetFmt(sess, SMTPF_CONTINUE, "250 %s Hello " CLIENT_FORMAT "" ID_MSG(256) "\r\n", sess->iface->name, CLIENT_INFO(sess), ID_ARG(sess));
/*{REPLY
}*/
}

int
cmdReadLine(Session *sess, const char *prompt, char *buffer, size_t size)
{
	long length;

	SENDCLIENT(sess, prompt);
	if (!socketHasInput(sess->client.socket, optSmtpCommandTimeout.value))
		return -1;
	if ((length = socketReadLine(sess->client.socket, buffer, size)) < 0)
		return -1;
	if (1 < verb_smtp.option.value)
		syslog(LOG_DEBUG, LOG_MSG(258) "> %ld:%s", LOG_ARGS(sess), length, buffer);
	return 0;
}

/* Perform man-in-the-middle AUTH LOGIN dialogue with the client
 * and convert the AUTH LOGIN into an AUTH PLAIN (see RFC 2595).
 *
 *	>>> AUTH LOGIN
 *	334 VXNlcm5hbWU6
 *	>>> dGVzdA==
 *	334 UGFzc3dvcmQ6
 * 	>>> dEVzdDQy
 *	235 2.0.0 OK Authenticated
 *
 * PLAIN authentication details, RFC 2595:
 *
 *	[authorize-id] \0 authenticate-id \0 password
 */
int
cmdAuthLogin(Session *sess)
{
	B64 b64;
	size_t auth_length;
	long buffer_length;
	char buffer[SMTP_COMMAND_LINE_LENGTH], *pass;

	auth_length = 0;

	/* Read the login name from the client. */
	if (sess->input_length == STRLEN("AUTH LOGIN")) {
		if (cmdReadLine(sess, "334 VXNlcm5hbWU6\r\n", buffer, sizeof (buffer))) {
			syslog(LOG_ERR, LOG_MSG(257) "client " CLIENT_FORMAT " I/O error: %s (%d)", LOG_ARGS(sess), CLIENT_INFO(sess), strerror(errno), errno);
/*{LOG
During AUTH LOGIN, there was a client read error while waiting for login name.
}*/
			goto error0;
		}
		if (*buffer == '*')
			goto error0;
	} else {
		buffer_length = TextCopy(buffer, sizeof (buffer), sess->input+STRLEN("AUTH LOGIN "));
		if (sizeof (buffer) <= buffer_length) {
			syslog(LOG_ERR, LOG_MSG(260) "AUTH LOGIN buffer overflow", LOG_ARGS(sess));
/*{LOG
AUTH LOGIN user name given exceeds the size of the decoding buffer.
}*/
			goto error0;
		}
	}

	b64Init();
	b64Reset(&b64);
	*sess->input = '\0';
	sess->input_length = 1;

	if (b64DecodeBuffer(&b64, buffer, buffer_length, (unsigned char *) sess->input, sizeof (sess->input), (size_t *) &sess->input_length)) {
		syslog(LOG_ERR, LOG_MSG(261) "login base64 decode error", LOG_ARGS(sess));
/*{LOG
The AUTH LOGIN user name could not be Base64 decoded.
}*/
		goto error0;
	}

	/* Count the null byte. */
	sess->input_length++;

	pass = sess->input + sess->input_length;

	if (cmdReadLine(sess, "334 UGFzc3dvcmQ6\r\n", buffer, sizeof (buffer))) {
		syslog(LOG_ERR, LOG_MSG(262) "client " CLIENT_FORMAT " I/O error: %s (%d)", LOG_ARGS(sess), CLIENT_INFO(sess), strerror(errno), errno);
/*{LOG
During AUTH LOGIN, there was a client read error while waiting for password.
}*/
		goto error0;
	}
	if (*buffer == '*')
		goto error0;

	b64Reset(&b64);

	if (b64DecodeBuffer(&b64, buffer, buffer_length, (unsigned char *) sess->input, sizeof (sess->input), (size_t *) &sess->input_length)) {
		syslog(LOG_ERR, LOG_MSG(265) "password base64 decode error", LOG_ARGS(sess));
/*{LOG
AUTH LOGIN password could not be Base64 decoded.
}*/
		goto error0;
	}

	/*@never-truncates@*/
	auth_length = TextCopy(sess->client.auth, sizeof (sess->client.auth), "AUTH PLAIN ");

	b64Reset(&b64);
	b64EncodeBuffer(&b64, (unsigned char *) sess->input, sess->input_length, sess->client.auth, sizeof (sess->client.auth), &auth_length);
	b64EncodeFinish(&b64, sess->client.auth, sizeof (sess->client.auth), &auth_length, 0);

	if (verb_auth.option.value)
		syslog(LOG_DEBUG, LOG_MSG(266) "login=%s pass=%s plain=\"%s\"", LOG_ARGS(sess), sess->input+1, pass, sess->client.auth);
error0:
	/* Erase the clear text credentials from memory. */
	memset(sess->input, 0, sizeof (sess->input));
	memset(buffer, 0, sizeof (buffer));

	return auth_length;
}

/*
 * RFC 2554
 */
int
cmdAuth(Session *sess)
{
	B64 b64;
	int can_queue;
	Connection *fwd;
	size_t auth_length;
	char *user, *pass, *auth_domain;

	if (!optSmtpAuthEnable.value) {
		return replySetFmt(sess, SMTPF_REJECT, "502 5.5.1 AUTH not supported" ID_MSG(827) "\r\n", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_smtp_auth_enable">smtp-auth-enable</a> documentation.
}*/
	}

#ifdef HAVE_OPENSSL_SSL_H
	if (optSmtpAuthTls.value && !(tls_get_flags(sess) & TLS_FLAG_STARTED)) {
		return replySetFmt(sess, SMTPF_REJECT, "538 5.7.11 Encryption required for requested authentication mechanism" ID_MSG(1020) "\r\n", ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_smtp_auth_tls">smtp-auth-tls</a> documentation.
}*/
	}
#endif
	if (CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH)) {
		(void) replySetFmt(sess, SMTPF_REJECT, "503 5.5.1 already authenticated" ID_MSG(267) "\r\n", ID_ARG(sess));
/*{REPLY
RFC 2554 states that once a client successfully authenticates,
additional AUTH commands are rejected.
}*/
		goto error0;
	}

	if (3 <= sess->client.auth_count)
		goto error1;

	if (TextMatch(sess->input, "AUTH LOGIN*",  sess->input_length, 1)) {
		/* Convert an AUTH LOGIN into an AUTH PLAIN.
		 * Makes it easier to handle below.
		 */
		if ((auth_length = cmdAuthLogin(sess)) == 0)
			goto error2;
	} else if (TextMatch(sess->input, "AUTH PLAIN*",  sess->input_length, 1)) {
		/* Save this for possible use in cmdRcpt(). */
		auth_length = TextCopy(sess->client.auth, sizeof (sess->client.auth), sess->input);
		if (sizeof (sess->client.auth) <= auth_length) {
			syslog(LOG_ERR, LOG_MSG(268) "AUTH PLAIN buffer overflow caught", LOG_ARGS(sess));
/*{LOG
During AUTH PLAIN, the Base64 argument given exceeds the size of the decoding buffer.
}*/
			goto error2;
		}
	} else if (TextMatch(sess->input, "AUTH *",  sess->input_length, 1)) {
		(void) replySetFmt(sess, SMTPF_REJECT, "504 5.5.4 unknown AUTH mechanism" ID_MSG(269) "\r\n", ID_ARG(sess));
/*{REPLY
@PACKAGE_NAME@ only supports AUTH PLAIN and AUTH LOGIN mechanisms.
}*/
		goto error0;
	} else {
		return cmdMissingArg(sess, sess->input_length);
	}

	b64Init();
	b64Reset(&b64);
	sess->input_length = 0;
	auth_length -= sizeof ("AUTH PLAIN ")-1;

	if (b64DecodeBuffer(&b64, sess->client.auth+sizeof ("AUTH PLAIN ")-1, auth_length, (unsigned char *) sess->input, sizeof (sess->input), (size_t *) &sess->input_length)) {
		syslog(LOG_ERR, LOG_MSG(270) "AUTH base64 decode error", LOG_ARGS(sess));
/*{LOG
The AUTH PLAIN argument could not be decoded according to Base64 rules.
}*/
		goto error2;
	}

	/* RFC 2595 section 6
	 *
	 *   message         = [authorize-id] NUL authenticate-id NUL password
	 *   authenticate-id = 1*UTF8-SAFE      ; MUST accept up to 255 octets
	 *   authorize-id    = 1*UTF8-SAFE      ; MUST accept up to 255 octets
	 *   password        = 1*UTF8-SAFE      ; MUST accept up to 255 octets
	 */
	user = &sess->input[strlen(sess->input)+1];
	pass = &user[strlen(user)+1];

	if (verb_auth.option.value)
		syslog(LOG_DEBUG, LOG_MSG(271) "user=%s pass=%s", LOG_ARGS(sess), user, pass);

	/* Check for a qualified authentication id, ie. user@domain. */
	auth_domain = user + strcspn(user, "@");
	if (*auth_domain == '@')
		auth_domain++;

	/* Open a connection for the authentication domain. */
	if ((fwd = routeKnownAuth(sess, user, &can_queue)) == NULL) {
		if (CLIENT_ANY_SET(sess, CLIENT_IS_RELAY))
			goto relay_auth;
		goto error2;
	}

#ifdef MOVED_TO_ROUTE_KNOWN_AUTH
	/* Get SMTP welcome message. */
	if (mxCommand(sess, fwd, NULL, 220))
		goto error3;
#endif
	/* Send EHLO. */
	snprintf(sess->reply, sizeof (sess->reply), "EHLO %s\r\n", sess->iface->name);
	if (mxCommand(sess, fwd, sess->reply, 250))
		goto error3;

	/* Forward AUTH PLAIN to server. */
	TextCat(sess->client.auth, sizeof (sess->client.auth), "\r\n");
	if (mxCommand(sess, fwd, sess->client.auth, 235)) {
		if (*auth_domain == '\0')
			goto error3;

		/* Try forwarding the unqualified auth-id to the server. */
		sess->input_length = strlen(pass);
		memmove(auth_domain-1, pass-1, sess->input_length+1);
		sess->input_length += (auth_domain - user) + 1;

		/*@never-truncates@*/
		auth_length = TextCopy(sess->reply, sizeof (sess->reply), "AUTH PLAIN ");

		b64Reset(&b64);
		b64EncodeBuffer(&b64, (unsigned char *) sess->input, sess->input_length , sess->reply, sizeof (sess->reply), &auth_length);
		b64EncodeFinish(&b64, sess->reply, sizeof (sess->reply), &auth_length, 0);

		/* If the attempt fails and we are a relay, then accept the
		 * AUTH PLAIN command since its possible that its the client
		 * AUTH is intended for the destination MX, rather than a
		 * request to allow relaying.
		 */
		(void) TextCopy(sess->reply+auth_length, sizeof (sess->reply)-auth_length, "\r\n");
		if (mxCommand(sess, fwd, sess->reply, 235) && CLIENT_NOT_SET(sess, CLIENT_IS_RELAY))
			goto error3;
	}

	/* Client successfully authenticated and is allowed to relay. */
	if (can_queue) {
		if (verb_info.option.value) {
			syslog(LOG_INFO, LOG_MSG(272) "queuing all messages on %s [%s]", LOG_ARGS(sess), fwd->mx_host, fwd->mx_ip);
/*{LOG
All messages from successfully authenticated clients are queued on the local route.
See <a href="route-map.html#route_local_route_queue">route-map</a> documentation.
}*/
		}

		sess->client.fwd_to_queue = fwd;

		/* Add the forward queue to the list of forwards. This simplifies
		 * cmdData() processing. We have to avoid closing this connection
		 * between mail transactions though, see sessionReset().
		 */
		fwd->next = sess->msg.fwds;
		sess->msg.fwds = fwd;
	} else {
		connectionFree(fwd);
	}

relay_auth:
	if (verb_info.option.value) {
		syslog(
			LOG_INFO, LOG_MSG(273) "auth-id=<%s> relay=%d", LOG_ARGS(sess), user,
			CLIENT_ANY_SET(sess, CLIENT_IS_RELAY)
		);
/*{LOG
}*/
	}

	/* Erase all copies of the AUTH credentials. */
	if (CLIENT_NOT_SET(sess, CLIENT_IS_RELAY))
		memset(sess->client.auth, 0, sizeof (sess->client.auth));
	memset(sess->input, 0, sizeof (sess->input));
	memset(sess->reply, 0, sizeof (sess->reply));

	statsCount(&stat_auth_pass);
	CLIENT_SET(sess, CLIENT_IS_RELAY|CLIENT_HAS_AUTH);

	return replySetFmt(sess, SMTPF_CONTINUE, "235 2.0.0 authenticated" ID_MSG(274) "\r\n", ID_ARG(sess));
/*{REPLY
The client has successfully authenticated and their messages will be queued by the local route.
See <a href="route-map.html#route_local_route_queue">route-map</a> documentation.
}*/
error3:
	connectionFree(fwd);
error2:
	/* Erase all copies of the AUTH credentials. */
	memset(sess->client.auth, 0, sizeof (sess->client.auth));
	memset(sess->input, 0, sizeof (sess->input));
	memset(sess->reply, 0, sizeof (sess->reply));
error1:
	(void) replySetFmt(sess, SMTPF_REJECT, "535 5.7.0 authentication failed" ID_MSG(275) "\r\n", ID_ARG(sess));
/*{REPLY
}*/
error0:
	sess->client.auth_count++;
	statsCount(&stat_auth_fail);
	CLIENT_CLEAR(sess, CLIENT_HAS_AUTH);

	return SMTPF_REJECT;
}

#ifdef ENABLE_ETRN
/*
 * RFC 1985 ETRN
 *
 * Simply proxy the ETRN command to the local queue route.
 *
 * *** NOTE that if the local route specifies more than one forward host,
 * *** then the ETRN is sent to the first that answers, not to all of them.
 */
int
cmdEtrn(Session *sess)
{
	int rc, span;
	Connection *local;

	if ((rc = cmdMissingArg(sess, sizeof ("ETRN ")-1)) != SMTPF_CONTINUE)
		return rc;

	span  = strcspn(sess->input, " \t");
	span += strspn(sess->input+span, " \t");

	if ((local = connectionAlloc()) == NULL)
		replyResourcesError(sess, FILE_LINENO);

	if (routeQueue(sess, NULL, local)) {
		rc = replySetFmt(sess, SMTPF_REJECT, "458 4.4.0 unable to queue messages for %s" ID_MSG(276) "\r\n", sess->input+span, ID_ARG(sess));
/*{REPLY
SMTP ETRN commands are sent to the local route, which is responsible for queuing.
See <a href="route-map.html#route_local_route_queue">route-map</a> documentation.
}*/
	} else {
		(void) TextCopy(sess->input+sess->input_length, sizeof (sess->input)-sess->input_length, "\r\n");
		(void) mxCommand(sess, local, sess->input, 250);

		rc = SMTP_IS_OK(local->smtp_code) ? SMTPF_CONTINUE
			: SMTP_IS_PERM(local->smtp_code) ? SMTPF_REJECT
			: SMTPF_TEMPFAIL;

		rc = replySetFmt(sess, rc, "%s" ID_MSG(277) "\r\n", sess->reply, ID_ARG(sess));
/*{REPLY
After an SMTP ETRN command, this is the response relayed from the one of local route servers.
}*/
	}

	connectionFree(local);

	return rc;
}
#endif

int
cmdMail(Session *sess)
{
	int rc, span, args;
	Vector params_list;
	const char *error, *params, **table;

	sessionReset(sess);

	rc = filterRun(sess, filter_idle_table);
	if (rc != SMTPF_CONTINUE && replyDefined(sess))
		return rc;

	sess->client.mail_count++;
	statsCount(&stat_mail_count);

	/* Find the end of the "MAIL FROM:" string. */
	span  = strcspn(sess->input, ":");
	span += (sess->input[span] == ':');
	span += strspn(sess->input+span, " \t");

	if ((rc = cmdMissingArg(sess, span)) != SMTPF_CONTINUE)
		goto error0;

	/* Split the MAIL FROM: address from any trailing options, in
	 * particular: "MAIL FROM:<user@example.com> AUTH=<>" which
	 * causes parsePath() to find the right most set of angle
	 * brackets.
	 */
	args = span + strcspn(sess->input+span, ">");
	if (sess->input[args] == '\0')
		args = span + strcspn(sess->input+span, " \t");
	else
		args++;
	params = &sess->input[args + strspn(sess->input+args, " \t")];
	sess->input[args] = '\0';

#ifdef CONVERT_WRONG_NULL_SENDER
	if (TextMatch(sess->input+span, "<NULL>", -1, 1)) {
		syslog(LOG_DEBUG, LOG_MSG(278) "converting \"%s\" to \"MAIL FROM:<>\"", LOG_ARGS(sess), sess->input);
		TextCopy(sess->input+span, sizeof (sess->input)-span, "<>");
	}
#endif

	if ((error = parsePath(sess->input+span, parse_path_flags, 1, &sess->msg.mail)) != NULL) {
		rc = replySetFmt(
			sess, SMTP_ISS_TEMP(error) ? SMTPF_TEMPFAIL : SMTPF_REJECT,
			"%d %s, sender %s" ID_MSG(279) "\r\n",
			SMTP_ISS_TEMP(error) ? 451 : 553, error,
			sess->input+span, ID_ARG(sess)
		);
/*{REPLY
The SMTP MAIL FROM: address could not be correctly parsed according to the
strict application of one or more RFC 2821 grammar rules.
See
<a href="summary.html#opt_rfc2821_line_length">rfc2821-line-length</a>,
<a href="summary.html#opt_rfc2821_local_length">rfc2821-local-length</a>,
<a href="summary.html#opt_rfc2821_domain_length">rfc2821-domain-length</a>,
<a href="summary.html#opt_rfc2821_literal_plus">rfc2821-literal-plus</a>,
<a href="summary.html#opt_rfc2821_strict_dot">rfc2821-strict-dot</a>.
}*/
		statsCount(&stat_mail_parse);
		goto error1;
	}

	if (*sess->client.sender_domain == '\0') {
		(void) TextCopy(sess->client.sender_domain, sizeof (sess->client.sender_domain), sess->msg.mail->domain.string);
	} else if (optOneDomainPerSession.value && strcmp(sess->client.sender_domain, sess->msg.mail->domain.string) != 0) {
		rc = replySetFmt(sess, SMTPF_REJECT, "450 4.7.1 more than one sender <%s> domain per session; domain=%s" ID_MSG(944) CRLF, sess->msg.mail->address.string, sess->client.sender_domain, ID_ARG(sess));
		statsCount(&stat_one_domain_per_session);
		goto error1;
	}

	getMsgId(sess, sess->msg.id);

	if (span != sizeof ("MAIL FROM:")-1) {
		MAIL_SET(sess, MAIL_HAS_EXTRA_SPACES);

		if (optRFC2821ExtraSpaces.value
		&& CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_HAS_AUTH)) {
			rc = replySetFmt(sess, SMTPF_REJECT, "501 5.5.2 syntax error" ID_MSG(280) "\r\n", LOG_ARGS(sess), sess->input, ID_ARG(sess));
/*{REPLY
The RFC 2821 grammar for the <code>MAIL FROM:</code> command does not allow for white space between
the <code>FROM:</code> and the &lt;address&gt; argument. When they appear it is typically a virus or
spamware sign.
See <a href="summary.html#opt_rfc2821_extra_spaces">rfc2821-extra-spaces</a>.
}*/
			statsCount(&stat_mail_parse);
			goto error1;
		}
	}

	if (sess->msg.mail->address.length == 0)
		statsCount(&stat_null_sender);

	params_list = TextSplit(params, " \t", 0);
	for (table = (const char **) VectorBase(params_list); *table != NULL; table++) {
		if (TextInsensitiveCompare(*table, "BODY=7BIT") == 0)
			MAIL_CLEAR(sess, MAIL_IS_8BITMIME|MAIL_IS_BINARYMIME);
		else if (TextInsensitiveCompare(*table, "BODY=8BITMIME") == 0)
			MAIL_SET(sess, MAIL_IS_8BITMIME);
		else if (TextInsensitiveCompare(*table, "BODY=BINARYMIME") == 0)
			MAIL_SET(sess, MAIL_IS_BINARYMIME);
	}
	rc = filterRun(sess, filter_mail_table, sess->msg.mail, params_list);
	VectorDestroy(params_list);

	switch (rc) {
	case SMTPF_CONTINUE:
	case SMTPF_DISCARD:
	case SMTPF_ACCEPT:
	case SMTPF_GREY:
		break;

	case SMTPF_DROP:
		statsCount(&stat_mail_drop);
		goto error1;

	case SMTPF_REJECT:
		statsCount(&stat_mail_reject);
		goto error1;

	case SMTPF_TEMPFAIL:
		statsCount(&stat_mail_tempfail);
		goto error1;

	default:
		syslog(LOG_WARN, LOG_MSG(281) "filter_mail_table unexpected rc=%d", LOG_ARGS(sess), rc);
/*{LOG
This is an internal error.
}*/
		goto error1;
	}

	/* Do we forward all mail transactions to this queue?
	 * This only happens for authenticated connections.
	 */
	if (sess->client.fwd_to_queue != NULL) {
		sess->input_length = snprintf(sess->input, sizeof (sess->input), "MAIL FROM:<%s>\r\n", sess->msg.mail->address.string);
		if (mxCommand(sess, sess->client.fwd_to_queue, sess->input, 250)) {
			rc = SMTP_IS_PERM(sess->client.fwd_to_queue->smtp_code) ? SMTPF_REJECT : SMTPF_TEMPFAIL;
			rc = replySetFmt(sess, rc, "%d %d.1.0 sender <%s> denied" ID_MSG(282) "\r\n", sess->client.fwd_to_queue->smtp_code, rc, sess->msg.mail->address.string, ID_ARG(sess));
/*{REPLY
The forward host rejected or temporarily failed the sender.
}*/
			if (rc == SMTPF_TEMPFAIL)
				statsCount(&stat_mail_tempfail);
			else
				statsCount(&stat_mail_reject);
			goto error1;
		}
	}

	sess->msg.reject[0] = '\0';
	sess->state = stateMail;

	rc = replySetFmt(sess, SMTPF_CONTINUE, "250 2.1.0 sender <%s> accepted" ID_MSG(283) "\r\n", sess->msg.mail->address.string, ID_ARG(sess));
/*{REPLY
}*/
error1:
	summarySender(sess, sess->input+span);
error0:
	return rc;
}

int
cmdRcpt(Session *sess)
{
	ParsePath *rcpt;
	Connection *fwd;
	Vector params_list;
	const char *error, *params;
	int i, rc, span, args, apply_smtpf_delay;

	fwd = NULL;
	*sess->reply = '\0';
	statsCount(&stat_rcpt_count);
	apply_smtpf_delay = SMTPF_DELAY;

	/* Find the end of the "MAIL FROM:" string. */
	span  = strcspn(sess->input, ":");
	span += (sess->input[span] == ':');
	span += strspn(sess->input+span, " \t");

	if ((rc = cmdMissingArg(sess, span)) != SMTPF_CONTINUE)
		return rc;

	/* Split the RCPT TO: address from any trailing options. */
	args = span + strcspn(sess->input+span, ">");
	if (sess->input[args] == '\0')
		args = span + strcspn(sess->input+span, " \t");
	else
		args++;
	params = &sess->input[args + strspn(sess->input+args, " \t")];
	sess->input[args] = '\0';

	if ((error = parsePath(sess->input+span, parse_path_flags, 0, &rcpt)) != NULL) {
		rc = replySetFmt(
			sess, SMTP_ISS_TEMP(error) ? SMTPF_TEMPFAIL : SMTPF_REJECT,
			"%d %s, recipient %s" ID_MSG(284) "\r\n",
			SMTP_ISS_TEMP(error) ? 451 : 553, error,
			sess->input+span, ID_ARG(sess)
		);
/*{REPLY
The SMTP <code>RCPT TO:</code> address could not be correctly parsed according to the
strict application of one or more RFC 2821 grammar rules.
See
<a href="summary.html#opt_rfc2821_line_length">rfc2821-line-length</a>,
<a href="summary.html#opt_rfc2821_local_length">rfc2821-local-length</a>,
<a href="summary.html#opt_rfc2821_domain_length">rfc2821-domain-length</a>,
<a href="summary.html#opt_rfc2821_literal_plus">rfc2821-literal-plus</a>,
<a href="summary.html#opt_rfc2821_strict_dot">rfc2821-strict-dot</a>.
}*/
		statsCount(&stat_rcpt_parse);
		RCPT_SET(sess, RCPT_FAILED);
		goto error1;
	}

	if (span != sizeof ("RCPT TO:")-1) {
		RCPT_SET(sess, RCPT_HAS_EXTRA_SPACES);

		if (optRFC2821ExtraSpaces.value
		&& CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS|CLIENT_HAS_AUTH)) {
			rc = replySetFmt(sess, SMTPF_REJECT, "501 5.5.2 syntax error" ID_MSG(285) "\r\n", LOG_ARGS(sess), sess->input, ID_ARG(sess));
/*{REPLY
The RFC 2821 grammar for the <code>RCPT TO:</code> command does not allow for white space between
the <code>TO:</code> and the &lt;address&gt; argument. When they appear it is typically a virus or
spamware sign.
See <a href="summary.html#opt_rfc2821_extra_spaces">rfc2821-extra-spaces</a>.
}*/
			statsCount(&stat_rcpt_parse);
			RCPT_SET(sess, RCPT_FAILED);
			goto error1;
		}
	}

	if (rcpt->address.length == 0) {
		rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 null recipient invalid" ID_MSG(286) "\r\n", ID_ARG(sess));
/*{REPLY
The SMTP client specified <code>RCPT TO:&lt;&gt;</code>
}*/
		goto error2;
	}

	/* Add this recipient's route to the forward list if we can route it.
	 * We keep track of the recipient route until final dot, RSET, or QUIT
	 * when we can then count the number of messages accepted or rejected
	 * for a route.
	 */
	switch (routeAdd(sess, rcpt, &fwd)) {
	case ROUTE_OK:
	case ROUTE_FORWARD:
		break;

	case ROUTE_BAD:
		rc = replySetFmt(sess, SMTPF_DROP, msg_resources, ID_ARG(sess));
		statsCount(&stat_rcpt_tempfail);
		goto error1;

	case ROUTE_NO_ROUTE:
		rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> relaying denied" ID_MSG(288) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
The SMTP client is attempting to relay mail for an unknown recipient domain.
Domains that @PACKAGE_NAME@ is responsible for is specified in the
<a href="route-map.html">route-map</a>. Either the domain has not yet been
added, was removed, or the SMTP client is hoping that the server is an
open relay.
}*/
		statsCount(&stat_rcpt_relay_denied);
		goto error2;
	}

	params_list = TextSplit(params, " \t", 0);
	rc = filterRun(sess, filter_rcpt_table, rcpt, params_list);
	VectorDestroy(params_list);

	switch (rc) {
	case SMTPF_CONTINUE:
		/* No black or white listing. Any previously recorded
		 * policy rejections _may_ be reported in place of a
		 * 250 OK, if we get that far.
		 */

		/* If the RCPT is not white listed and there is delayed
		 * reply to report to the client, then we can avoid
		 * doing an expensive call-ahead, since we already have
		 * a negative result to report.
		 */
		if (replyIsNegative(sess, 1)) {
			if (verb_rcpt.option.value)
				syslog(LOG_DEBUG, LOG_MSG(289) "reject reply already queued, skipping call-ahead", LOG_ARGS(sess));
			/* Force this state in order to report the delayed
			 * response for this recipient. If there is only one,
			 * the previous state will be restored; otherwise
			 * we were already in this state and shall remain so.
			 */
			sess->state = stateRcpt;
			sess->msg.rcpt_count++;

			rc = SMTPF_REJECT;
			goto error2;
		}

		break;

	case SMTPF_ACCEPT:
	case SMTPF_GREY:
		/* A white listed RCPT wants this mail regardless of
		 * any previously recorded policy rejections. Disable
		 * SMTPF_DELAY flag in order to return 250 OK, if we
		 * get that far.
		 */
		apply_smtpf_delay = 0;
		break;

	case SMTPF_DISCARD:
		/* When a DISCARD is applied to the recipient, we simply
		 * choose not to forward the recipient. However, we have
		 * to appear to have accepted the recipient to the client.
		 */
		rc = replySetFmt(sess, SMTPF_CONTINUE, "250 2.1.5 recipient <%s> accepted" ID_MSG(290) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
}*/
		/* Force this state in order to report any delayed
		 * response for this recipient. If there is only one,
		 * the previous state will be restored; otherwise
		 * we were already in this state and shall remain so.
		 */
		sess->state = stateRcpt;
		sess->msg.rcpt_count++;

		/* Count a rejection, should have a separate state really.
		 * Then free up the recipient.
		 */
		goto error2;

	case SMTPF_DROP:
		statsCount(&stat_rcpt_drop);
		goto error1;

	case SMTPF_REJECT:
		goto error2;

	case SMTPF_TEMPFAIL:
		statsCount(&stat_rcpt_tempfail);
		RCPT_SET(sess, RCPT_FAILED);
		goto error1;

	default:
		/* Black listed or rejected RCPT. */
		syslog(LOG_WARN, LOG_MSG(291) "filter_rcpt_table unexpected rc=%d", LOG_ARGS(sess), rc);
/*{LOG
This is an internal error.
}*/
		goto error1;
	}

	/* Do a call-ahead if necessary. */
	switch (routeRcpt(sess, rcpt)) {
	case ROUTE_BAD:
		rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> unknown" ID_MSG(292) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
A call-ahead to a down stream host rejected the recipient.
See <a href="route-map.html#route_call_ahead">route-map</a> about RCPT: attribute.
}*/
		statsCount(&stat_rcpt_unknown);
		RCPT_SET(sess, RCPT_FAILED);
		goto error2;

	case ROUTE_NO_ROUTE:
		rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> relaying denied" ID_MSG(293) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
The SMTP client is attempting to relay mail for an unknown recipient domain.
Domains that @PACKAGE_NAME@ is responsible for is specified in the
<a href="route-map.html">route-map</a>. Either the domain has not yet been
added, was removed, or the SMTP client is hoping that the server is an
open relay.
}*/
		statsCount(&stat_rcpt_relay_denied);
		goto error2;
	default:
		break;
	}

	if (!connectionIsOpen(fwd) && fwd->rcpt_count == 0) {
		/* Forward to the recipient's MX or queue. */
		switch (routeForward(sess, rcpt, fwd)) {
		case ROUTE_OK:
			break;

		case ROUTE_QUEUE:
			/* Queue for a client relay, authenticated sender,
			 * or unqualified recipient.
			 */
			if (routeQueue(sess, rcpt, fwd)) {
				if (verb_info.option.value) {
					syslog(LOG_INFO, LOG_MSG(294) "queuing message on %s [%s] for <%s>", LOG_ARGS(sess), TextEmpty(fwd->mx_host), fwd->mx_ip, rcpt->address.string);
/*{LOG
The message is being sent to the local route.
See <a href="route-map.html">route-map</a> about the
<a href="route-map.html#route_local_route_queue">local route</a>
and <a href="route-map.html#route_auth_support">AUTH support</a>.
}*/
				}
				statsCount(&stat_msg_queue);
				MSG_SET(sess, MSG_QUEUE);
				break;
			}
			/*@fallthrough@*/

		case ROUTE_FORWARD:
			/* We're responsible for this domain, but had a
			 * connection error.
			 */
			rc = replySetFmt(sess, SMTPF_TEMPFAIL, "451 4.0.0 cannot forward mail for <%s> at this time" ID_MSG(295) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
We are responsible for this domain, but had a connection error with the forward host.
}*/
			statsCount(&stat_rcpt_tempfail);
			RCPT_SET(sess, RCPT_FAILED);
			goto error1;

		default:
			rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 recipient <%s> relaying denied" ID_MSG(296) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
The SMTP client is attempting to relay mail for an unknown recipient domain.
Domains that @PACKAGE_NAME@ is responsible for is specified in the
<a href="route-map.html">route-map</a>. Either the domain has not yet been
added, was removed, or the SMTP client is hoping that the server is an
open relay.
}*/
			statsCount(&stat_rcpt_relay_denied);
			goto error2;
		}

		/* Send HELO or EHLO to MX. */
		sess->msg.chunk0_length = snprintf((char *)sess->msg.chunk0, sizeof (sess->msg.chunk0), "EHLO %s\r\n", sess->iface->name);
		if (mxCommand(sess, fwd, (char *)sess->msg.chunk0, 250)) {
			sess->msg.chunk0_length = snprintf((char *)sess->msg.chunk0, sizeof (sess->msg.chunk0), "HELO %s\r\n", sess->iface->name);
			if (mxCommand(sess, fwd, (char *)sess->msg.chunk0, 250)) {
				statsCount(SMTP_IS_TEMP(fwd->smtp_code) ? &stat_forward_helo_tempfail : &stat_forward_helo_reject);
				RCPT_SET(sess, RCPT_FAILED);
				goto error4;
			}
		}

		/* Send MAIL FROM: to MX. */
		sess->msg.chunk0_length = snprintf(
			(char *)sess->msg.chunk0, sizeof (sess->msg.chunk0),
			"MAIL FROM:<%s>%s\r\n", sess->msg.mail->address.string,
			optRFC16528bitmime.value && MAIL_ANY_SET(sess, MAIL_IS_8BITMIME) ? " BODY=8BITMIME" : ""
		);
		if (mxCommand(sess, fwd, (char *)sess->msg.chunk0, 250)) {
			statsCount(SMTP_IS_TEMP(fwd->smtp_code) ? &stat_forward_mail_tempfail : &stat_forward_mail_reject);
			RCPT_SET(sess, RCPT_FAILED);
			goto error4;
		}
	}

	/* Send RCPT TO: to MX. */
	sess->msg.chunk0_length = snprintf((char *)sess->msg.chunk0, sizeof (sess->msg.chunk0), "RCPT TO:<%s>\r\n", rcpt->address.string);
	if (mxCommand(sess, fwd, (char *)sess->msg.chunk0, 250)) {
		if (*rcpt->localRight.string != '\0') {
			sess->msg.chunk0_length = snprintf((char *)sess->msg.chunk0, sizeof (sess->msg.chunk0), "RCPT TO:<%s@%s>\r\n", rcpt->localLeft.string, rcpt->domain.string);
			if (!mxCommand(sess, fwd, (char *)sess->msg.chunk0, 250))
				goto unplussed_rcpt;
		}

		statsCount(SMTP_IS_TEMP(fwd->smtp_code) ? &stat_forward_rcpt_tempfail : &stat_forward_rcpt_reject);
		RCPT_SET(sess, RCPT_FAILED);
		goto error3;
	}

unplussed_rcpt:
	if (routeAddRcpt(fwd, rcpt)) {
		rc = replySetFmt(sess, SMTPF_DROP, msg_resources, ID_ARG(sess));
		statsCount(&stat_rcpt_tempfail);
		goto error1;
	}

	/* Enter the RCPT state so that replySend() will
	 * send delayed replies when necessary.
	 */
	sess->state = stateRcpt;

	/* SMTPF_DELAY|SMTPF_CONTINUE is intended to signal that this
	 * reply should be reported only if there is no delayed message
	 * waiting. See replySend()
	 */
	rc = replySetFmt(sess, apply_smtpf_delay | SMTPF_CONTINUE, "250 2.1.5 recipient <%s> accepted" ID_MSG(297) "\r\n", rcpt->address.string, ID_ARG(sess));
/*{REPLY
}*/
	summaryRecipient(sess, rcpt->address.string);
	sess->msg.rcpt_count++;

	return rc;
error4:
	if (fwd->smtp_code != SMTP_ERROR_IO) {
		(void) TextCopy((char *) sess->msg.chunk0, sizeof (sess->msg.chunk0), sess->reply);
		(void) mxCommand(sess, fwd, "QUIT\r\n", 221);
		(void) TextCopy(sess->reply, sizeof (sess->reply), (char *) sess->msg.chunk0);
	}
	connectionClose(fwd);
error3:
	if (verb_rcpt.option.value)
		syslog(LOG_DEBUG, LOG_MSG(298) "domain=%s SMTP forward error: %s", LOG_ARGS(sess), rcpt->domain.string, sess->reply);

	rc = SMTP_IS_PERM(sess->smtp_code) ? SMTPF_REJECT : SMTPF_TEMPFAIL;

	if (optRelayReply.value) {
		rc = replySetFmt(sess, rc, "%s" ID_MSG(299) "\r\n", sess->reply, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_relay_reply">relay-reply</a> option.
The whole reply from the forward host is relayed to the client.
}*/
	} else {
		i = smtpGetReplyCodes(sess->reply, NULL, 0);
		sess->reply[i] = '\0';
		rc = replySetFmt(sess, rc, "%srecipient <%s> denied" ID_MSG(300) "\r\n", sess->reply, rcpt->address.string, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_relay_reply">relay-reply</a> option.
Only the reply codes from the forward host are relayed to the client with a standardise reason.
}*/
	}
error2:
	statsCount(&stat_rcpt_reject);
error1:
	/* Discard the recipent route if there are no valid recipients.
	 * A forward host should only contain an open connection with
	 * valid recipients.
	 */
	if (fwd != NULL && fwd->rcpt_count == 0
	&& fwd != sess->client.fwd_to_queue && !connectionIsOpen(fwd)) {
		sess->msg.fwds = fwd->next;
		connectionFree(fwd);
	}

	sess->msg.bad_rcpt_count++;
	summaryRecipient(sess, sess->input+span);
	free(rcpt);

	return rc;
}

#ifdef __WIN32__
/*
 * Windows is so fucked. Thay can't follow a simple standard like ANSI C.
 */
static int
getTimeZone(char *buffer, size_t size)
{
	int bias, hh, mm;
	TIME_ZONE_INFORMATION info;

	(void) GetTimeZoneInformation(&info);

	bias = -(info.Bias + info.DaylightBias);
	hh = bias / 60;
	mm = bias - hh * 60;
	if (mm < 0)
		mm = -mm;

	return snprintf(buffer, size, "%+.2d%.2d", hh, mm);
}
#endif

int
getRFC2821DateTime(struct tm *local, char *buffer, size_t size)
{
	int length;

	if (local == NULL)
		return 0;
#ifdef __WIN32__
	length = strftime(buffer, size, "%a, %d %b %Y %H:%M:%S ", local);
	length += getTimeZone(buffer+length, size-length);
#else
	length = strftime(buffer, size, "%a, %d %b %Y %H:%M:%S %z", local);
#endif
	return length;
}

int
getReceivedHeader(Session *sess, char *buffer, size_t size)
{
	int length;
	struct tm local;
	char stamp[40], *with;
	time_t now = time(NULL);
#ifdef HAVE_OPENSSL_SSL_H
	char cipher_info[SOCKET_INFO_STRING_SIZE];
#endif
#ifdef FILTER_EMEW
	EMEW *emew = filterGetContext(sess, emew_context);
#endif
	(void) localtime_r(&now, &local);
	(void) getRFC2821DateTime(&local, stamp, sizeof (stamp));

	/* Specify a Received header with clause. */
	if (sess->helo_state == stateHelo) {
		with = "SMTP";
#ifdef HAVE_OPENSSL_SSL_H
	} else if (tls_get_flags(sess) & TLS_FLAG_STARTED) {
		if (CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH))
			with = "ESMTPSA";
		else
			with = "ESMTPS";
#endif
	} else if (CLIENT_ANY_SET(sess, CLIENT_HAS_AUTH)) {
		/* RFC 3848 ESMTP and LMTP Transmission Types Registration */
		with = "ESMTPA";
	} else {
		with = "ESMTP";
	}

#ifdef HAVE_OPENSSL_SSL_H
	(void) socket3_get_cipher_tls(socketGetFd(sess->client.socket), cipher_info, sizeof (cipher_info));
#endif
	length = snprintf(
		buffer, size,
		"Received: from %s (" CLIENT_FORMAT ")\r\n\tby %s (%s [%s]) envelope-from <%s>\r\n\twith %s (%s) id %s"
#ifdef FILTER_EMEW
		" ret-id %s"
#endif
		"; %s\r\n",
		sess->client.helo, CLIENT_INFO(sess),
		sess->iface->name, sess->iface->name,
		sess->session->if_addr, sess->msg.mail->address.string,
		with, cipher_info, sess->msg.id,
#ifdef FILTER_EMEW
		emew_code_strings[emew->result],
#endif
		stamp
	);

	return length;
}

/*
 * Prefix the message with our Received: header. Some applications,
 * like MailScanner or SpamAssassin, need this information (for the
 * client IP address) and RFC 2821 states we must add one when the
 * message transits our application.
 */
static void
headerReceived(Session *sess)
{
	char *hdr;
	long length;

	length = getReceivedHeader(sess, sess->input, sizeof (sess->input));

	if ((hdr = TextDupN(sess->input, length)) != NULL) {
		if (VectorInsert(sess->msg.headers, 0, hdr))
			free(hdr);
	}
}

static size_t
chunkBufferForward(Socket2 *daemon, unsigned char *buffer, size_t size)
{
	int ch;
	unsigned char *line;
	size_t chunk_length, line_length;

	assert(size < SMTP_MINIMUM_MESSAGE_LENGTH);

	/* For a NULL connection assume successful forwarding. */
	if (daemon == NULL)
		return size;

	/* Set a sentinel. */
	ch = buffer[size];
	buffer[size] = '\n';

	line = buffer;
	for (chunk_length = 0; chunk_length < size; chunk_length += line_length) {
		/* Apply SMTP dot transparency. RFC 5321 section 4.5.2. */
		if (*line == '.' && socketWrite(daemon, (unsigned char *) ".", 1) != 1)
			break;

		/* Find the end of line (or sentinel). */
		for (line_length = 0; line[line_length] != '\n'; line_length++)
			;

		/* Don't count sentinel newline. */
		line_length += (chunk_length + line_length < size);

		/* Forward the line. */
		if (socketWrite(daemon, line, line_length) != line_length)
			break;

		line += line_length;
	}

	buffer[size] = ch;

	return chunk_length;
}

/*
 * Forward data chunk to each connected SMTP server.
 */
static void
forwardChunk(Session *sess, unsigned char *chunk, long size)
{
	size_t written;
	int sent, count;
	Connection *fwd;

	sent = count = 0;

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next, count++) {
		if (fwd->smtp_code == SMTP_ERROR_IO)
			continue;

		if ((written = chunkBufferForward(fwd->mx, chunk, size)) < size) {

			syslog(LOG_ERR, LOG_MSG(301) "chunk write error size=%ld written=%lu: %s (%d)", LOG_ARGS(sess), size, (unsigned long) written, strerror(errno), errno);
/*{LOG
There was an I/O write error while trying to relay a DATA chunk to a forward host.
}*/
			fwd->smtp_code = SMTP_ERROR_IO;
		} else {
			sent++;
			fwd->length += written;
		}
	}

	if (2 < verb_smtp.option.value)
		syslog(LOG_DEBUG, LOG_MSG(302) "chunk size=%lu relays=%d sent=%d fail=%d", LOG_ARGS(sess), size, count, sent, count - sent);
}

/*
 * @return
 *	SMTPF_TEMPFAIL, SMTPF_REJECT, or SMTPF_CONTINUE.
 */
static int
forwardCommand(Session *sess, const char *cmd, int expect, long timeout, int *count, int *sent)
{
	long time_taken;
	Connection *fwd;
	time_t start, now;

	time_taken = 0;
	start = time(NULL);
	*sent = *count = 0;

	if (MSG_ANY_SET(sess, MSG_DISCARD))
		return SMTPF_CONTINUE;

	for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next, (*count)++) {
		if (fwd->rcpt_count == 0)
			continue;

		if (fwd->smtp_code != SMTP_ERROR_IO) {
			(void) mxPrint(sess, fwd, cmd, strlen(cmd));
			if (SMTP_IS_OK(fwd->smtp_code)) {
				fwd->time_of_last_command = start;
			} else {
				connectionClose(fwd);
			}
		}

		if (fwd->smtp_code != SMTP_ERROR_IO) {
			if (1 < verb_smtp.option.value)
				syslog(LOG_DEBUG, LOG_MSG(303) "%s time-taken=%ld time-left=%ld", LOG_ARGS(sess), fwd->route.key, time_taken, timeout - time_taken);
			socketSetTimeout(fwd->mx, timeout - time_taken);
			(void) mxResponse(sess, fwd);
			socketSetTimeout(fwd->mx, optSmtpCommandTimeout.value);

			if (0 < verb_smtp.option.value && *cmd == '.' && fwd->reply != NULL)
				syslog(LOG_DEBUG, LOG_MSG(304) "%s << %s", LOG_ARGS(sess), fwd->route.key, *fwd->reply);

			if (fwd->smtp_code == expect)
				(*sent)++;

			/* can_quit should be set if DATA sent and not
			 * 354, or DOT sent and any result returned.
   			 */
			fwd->can_quit = (*cmd == 'D' && fwd->smtp_code != expect)
				|| (*cmd == '.' && fwd->smtp_code != SMTP_ERROR_IO);

			/* Be sure to handle system clock updates that
			 * might alter the time drastically.
			 */
			now = time(NULL);
			if (start <= now)
				time_taken += now - start;
		}
	}

	if (1 < verb_smtp.option.value)
		syslog(LOG_DEBUG, LOG_MSG(305) "overall time-taken=%ld time-left=%ld", LOG_ARGS(sess), time_taken, timeout - time_taken);

	/* Things to test for at final dot.
	 *
	 * No foward host:
	 *  a)  message discarded, generates 250 reply to client.
	 *
	 * Single forward host:
	 *  a)	message accepted generates 250 reply to client.
	 *  b)	message temp.failed generates 4xy reply to client.
	 *  c)	message rejected generates 5xy reply to client.
	 *
	 * Multiple foward hosts:
	 *  a)	all forwards accept the message, 250 reply to client.
	 *  b)	all forwards reject the message, 5xy reply to client.
	 *  c)	some forwards accept the message and at least one
	 *	rejects it, 250 reply to client and one or more DSN
	 *  d)	some forwards accept the message and at least one I/O
	 *	error, 250 reply to client and one or more DSN
	 *  e)	some forwards accept the message and at least one
	 *	times out, 250 reply to client and one or more DSN
	 */
	if (sess->msg.fwds == NULL) {
		*sent = *count = sess->msg.rcpt_count;
	} else if (sess->msg.fwds->next == NULL) {
		/* Only one forward connection. We can
		 * return a reply instead of a DSN.
		 */
		fwd = sess->msg.fwds;

		if (SMTP_IS_PERM(fwd->smtp_code))
			return replySetFmt(sess, SMTPF_REJECT, "554 5.7.0 transaction failed" ID_MSG(306) "\r\n", ID_ARG(sess));
/*{REPLY
While forwarding a message for a single recipient, the forward host
rejected the message.
}*/
		else if (SMTP_IS_TEMP(fwd->smtp_code) || fwd->smtp_code == SMTP_ERROR_IO)
			return replySetFmt(sess, SMTPF_TEMPFAIL, "451 4.4.0 transaction aborted" ID_MSG(307) "\r\n", ID_ARG(sess));
/*{REPLY
While forwarding a message for a single recipient, the forward host
returned a temporary failure of the message.
}*/
	} else if (*sent < *count) {
		/* Multple forward connections, some that failed.
		 * Send DSN for those that failed.
		 */
		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			if (!SMTP_IS_OK(fwd->smtp_code) || (*cmd == '.' && fwd->smtp_code != expect)) {
				sendDSN(sess, fwd);
			}
		}
	}

	return SMTPF_CONTINUE;
}

#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
int
forwardDataAtDot(Session *sess, va_list ignore)
{
	FILE *fp;
	const char *name;
	unsigned char *hdr;
	int i, rc, sent, count;

	LOG_TRACE(sess, 308, forwardDataAtDot);

	rc = SMTPF_CONTINUE;

	/* Get the temporary message file name. */
	if ((name = saveGetName(sess)) == NULL) {
		syslog(LOG_ERR, LOG_MSG(309) "missing temp. file name", LOG_ARGS(sess));
/*{NEXT}*/
		rc = replySetFmt(sess, SMTPF_TEMPFAIL, msg_451_internal, ID_ARG(sess));
		goto error0;
	}

	/* Reopen the saved message file. */
	if ((fp = fopen(name, "rb")) == NULL) {
		syslog(LOG_ERR, LOG_MSG(310) "open error \"%s\": %s (%d)", LOG_ARGS(sess), name, strerror(errno), errno);
/*{NEXT}*/
		rc = replySetFmt(sess, SMTPF_TEMPFAIL, msg_451_internal, ID_ARG(sess));
		goto error0;
	}

	cliFdCloseOnExec(fileno(fp), 1);

	/* Skip headers, but not the CRLF separator. */
	if (fseek(fp, saveGetEOH(sess) - CRLF_LENGTH, SEEK_SET)) {
		syslog(LOG_ERR, LOG_MSG(311) "seek error \"%s\": %s (%d)", LOG_ARGS(sess), name, strerror(errno), errno);
/*{LOG
An error trying to find and open a temporary message file
which is to be relayed onto the forward hosts.
See <a href="summary.html#opt_save_dir">save-dir</a> option.
}*/
		rc = replySetFmt(sess, SMTPF_TEMPFAIL, msg_451_internal, ID_ARG(sess));
		goto error1;
	}

	/* Send DATA command to relays. */
	if ((rc = forwardCommand(sess, "DATA\r\n", 354, optSmtpCommandTimeout.value, &count, &sent)) != SMTPF_CONTINUE)
		goto error1;

	/* Did all the relays rejected the DATA command? */
	if (sent == 0) {
		syslog(LOG_ERR, LOG_MSG(312) "DATA failed by all forward hosts", LOG_ARGS(sess));
/*{LOG
All of the forward hosts for this message rejected the DATA command.
This message almost never appears. If it does, check if the forward
hosts have implemented any filtering that rejects at DATA, like
@PACKAGE_NAME@ does for grey-listing and call-back failures.
}*/
		rc = replySetFmt(sess, SMTPF_REJECT, msg_421_unavailable, sess->msg.id, ID_ARG(sess));
		goto error1;
	}

	for (i = 0; i < VectorLength(sess->msg.headers); i++) {
		if ((hdr = VectorGet(sess->msg.headers, i)) != NULL)
			forwardChunk(sess, hdr, strlen((char *) hdr));
	}

	while (!feof(fp)) {
		/* Leave room to add a CRLF to the last chunk if necessary.
		 * See cmdData().
		 */
		sess->msg.chunk1_length = (unsigned long) fread(sess->msg.chunk1, 1, sizeof (sess->msg.chunk1)-2, fp);
		if (ferror(fp)) {
			syslog(LOG_ERR, LOG_MSG(313) "read error \"%s\": %s (%d)", LOG_ARGS(sess), name, strerror(errno), errno);
/*{LOG
An error while reading from a temporary message file,
which is to be relayed onto the forward hosts.
See <a href="summary.html#opt_save_dir">save-dir</a> option.
}*/
			rc = replySetFmt(sess, SMTPF_TEMPFAIL, msg_451_internal, ID_ARG(sess));
			goto error1;
		}
		forwardChunk(sess, sess->msg.chunk1, sess->msg.chunk1_length);
	}
error1:
	fclose(fp);
error0:
	return rc;
}
#endif

static int
readClientData(Session *sess, unsigned char *chunk, unsigned long *size)
{
	long length, offset;
	int rc, last_line_was_dot_lf, leading_dot_removed;

	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(317) "enter readClientData()", LOG_ARGS(sess));

	/* Becasue we delay the forwarding of the DATA command, we have
	 * to keep the forward connection alive until they pass into the
	 * DATA state after the first chunk is received.
	 */
	keepAlive(sess);

	last_line_was_dot_lf = 0;

	/* Read a chunk of data lines. Make sure there is always
	 * enough room left for the largest possible line.
	 */
	for (offset = 0; offset+SMTP_TEXT_LINE_LENGTH < sizeof (sess->msg.chunk1)-1; offset += length) {
		if (!socketHasInput(sess->client.socket, optSmtpDataLineTimeout.value)) {
			if (verb_data.option.value)
				syslog(LOG_ERR, LOG_MSG(977) "%s(%lu)", LOG_ARGS(sess), FILE_LINENO);
/*{LOG
Read error for verb +data.
See the section <a href="runtime.html#runtime_config">Runtime Configuration</a>
and <a href="summary.html#opt_verbose">verbose</a> option.
}*/
			goto read_error;
		}

		pthread_testcancel();

		/* Check for dot transparency at start of new line. */
		leading_dot_removed = 0;
		if ((length = socketPeek(sess->client.socket, chunk+offset, 2)) < 0) {
			if (verb_data.option.value)
				syslog(LOG_ERR, LOG_MSG(978) "%s(%lu)", LOG_ARGS(sess), FILE_LINENO);
/*{NEXT}*/
			goto read_error;
		}

		if (length == 2 && chunk[offset] == '.' && chunk[offset+1] != '\r' && chunk[offset+1] != '\n') {
			/* Strip SMTP dot transparency. RFC 5321 section 4.5.2. */
			if (verb_data.option.value)
				syslog(LOG_DEBUG, LOG_MSG(979) "dot transparency, next=%c", LOG_ARGS(sess), chunk[offset+1]);
/*{NEXT}*/
			if (socketRead(sess->client.socket, chunk+offset, 1) != 1) {
				if (verb_data.option.value)
					syslog(LOG_ERR, LOG_MSG(980) "%s(%lu)", LOG_ARGS(sess), FILE_LINENO);
/*{LOG
Read error and debug output for verb +data during the stripping of SMTP dot transparency;
<a href="http://tools.ietf.org/html/rfc5321#section-4.5.2">RFC 5321 section 4.5.2</a>.
See the section <a href="runtime.html#runtime_config">Runtime Configuration</a>
and <a href="summary.html#opt_verbose">verbose</a> option.
}*/
				goto read_error;
			}
			leading_dot_removed = 1;
			sess->client.octets++;
			sess->msg.length++;
		}

		/* Get remainder of line. */
		length = socketReadLine2(sess->client.socket, (char *) chunk+offset, sizeof (sess->msg.chunk1)-1-offset, 1);

		if (length < 0) {
read_error:
			if (errno != 0)
				statsCount((errno == ETIMEDOUT) ? &stat_client_timeout : &stat_client_io_error);

			if (errno == ETIMEDOUT && last_line_was_dot_lf) {
				syslog(LOG_ERR, LOG_MSG(319) "client " CLIENT_FORMAT " timeout after DOT-LF; message must end with CRLF-DOT-CRLF", LOG_ARGS(sess), CLIENT_INFO(sess));
/*{LOG
See <a href="summary.html#opt_rfc2821_strict_dot">rfc2821-strict-dot</a>.
}*/
				statsCount(&stat_strict_dot);
			} else {
				syslog(LOG_ERR, LOG_MSG(320) "client " CLIENT_FORMAT " I/O error: %s (%d)", LOG_ARGS(sess), CLIENT_INFO(sess), strerror(errno), errno);
/*{LOG
The client appears to have disconnected. A read error occured in the DATA collection loop.
}*/
			}

			CLIENT_SET(sess, CLIENT_IO_ERROR);
			sess->smtp_code = SMTP_ERROR_IO;

			VALGRIND_PRINTF("readClientData longjmp: %s (%d)\n", strerror(errno), errno);
			VALGRIND_DO_LEAK_CHECK;
			SIGLONGJMP(sess->on_error, SMTPF_DROP);
		}

		if (2 < verb_smtp.option.value) {
			if (leading_dot_removed)
				syslog(LOG_DEBUG, LOG_MSG(981) "line %ld:.%.100s", LOG_ARGS(sess), length+1, chunk+offset);
/*{NEXT}*/
			else
				syslog(LOG_DEBUG, LOG_MSG(318) "line %ld:%.100s", LOG_ARGS(sess), length, chunk+offset);
/*{LOG
Debug output for verb +smtp-data. Note that the logged data lines are truncated at 75 characters.
See the section <a href="runtime.html#runtime_config">Runtime Configuration</a>
and <a href="summary.html#opt_verbose">verbose</a> option.
}*/
		}

		sess->client.octets += length;
		sess->msg.length += length;

		if (optRFC2821LineLength.value && SMTP_TEXT_LINE_LENGTH < length) {
			rc = replySetFmt(sess, 1 < optRFC2821LineLength.value ? SMTPF_DROP : SMTPF_REJECT, "554 5.5.2 content line too long (%ld); RFC 2821 section 4.5.3.1" ID_MSG(321) "\r\n", length, ID_ARG(sess));
/*{REPLY
See <a href="summary.html#opt_rfc2821_line_length">rfc2821-line-length</a>.
}*/
			statsCount(&stat_line_length);
			goto error0;
		}

		last_line_was_dot_lf = 0;

		/* Look for RFC 2821 compliant CRLF-DOT-CRLF sequence. */
		if (!leading_dot_removed && chunk[offset] == '.') {
			/* RFC 2821 section 4.1.1.4 DATA paragraph 2 & 3 states
			 * that only CRLF-DOT-CRLF can terminate the message and
			 * that LF-DOT-LF, LF-DOT-CRLF, and CRLF-DOT-LF are NOT
			 * acceptable.
			 */
			if (length == 3 && chunk[offset+1] == '\r' && chunk[offset+2] == '\n'
			&& (sess->msg.seen_crlf_before_dot || !optRFC2821StrictDot.value)) {
				sess->msg.seen_final_dot = 1;
				/* Do not count DOT-CRLF towards msg.length. */
				sess->msg.length -= length;
				break;
			}

			/* Check for non-conformant LF-DOT-LF (or CRLF-DOT-LF).
			 */
			if (length == 2 && (chunk[offset+1] == '\r' || chunk[offset+1] == '\n')) {
				last_line_was_dot_lf = 1;
				sess->msg.length -= length;

				if (!optRFC2821StrictDot.value) {
					sess->msg.seen_final_dot = 1;
					break;
				}
			}
		}

		sess->msg.seen_crlf_before_dot = (2 <= length && chunk[offset+length-2] == '\r' && chunk[offset+length-1] == '\n');

		/* For the first chunk, save a copy of the message headers as
		 * a Vector. This allows for easier modification, insertion,
		 * and/or addition of headers, such as Date, From, Message-Id.
		 */
		if (chunk == sess->msg.chunk0 && sess->msg.eoh == 0) {
			size_t n;
			char *hdr, *bigger;

			/* Detect the start of a header line or a blank header/body separator. */
			if ((!isspace(chunk[offset]) && strchr((char *) chunk+offset+1, ':') == NULL)
			||  (length == 2 && chunk[offset] == '\r' && chunk[offset+1] == '\n')) {
				sess->msg.eoh = offset+length;
				continue;
			}

			if (isspace(chunk[offset])) {
				if ((hdr = VectorGet(sess->msg.headers, -1)) == NULL)
					continue;

				n = strlen(hdr);

				if ((bigger = realloc(hdr, n + length + 1)) != NULL) {
					/* Append the header continuation to the
					 * most recent header received.
					 */
					(void) TextCopy(bigger+n, length+1, (char *) chunk+offset);
					VectorReplace(sess->msg.headers, -1, bigger);
				}
			} else if ((hdr = TextDupN((char *) chunk+offset, length)) != NULL) {
				if (VectorAdd(sess->msg.headers, hdr))
					free(hdr);
			}
		}

		pthread_testcancel();
	}

	(void) time(&sess->last_mark);
	chunk[offset] = '\0';
	*size = offset;

	if (chunk == sess->msg.chunk0) {
		/* Was the end-of-headers found before the end of the first chunk? */
		if (sess->msg.eoh == 0) {
			if (optRFC2822MissingEOH.value) {
				rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.1 missing of end-of-header line" ID_MSG(927), ID_ARG(sess));
/*{REPLY
See the section on <a href="smtpf-cf.html#smtpf_rfc">RFC conformance</a> and
<a href="summary.html#opt_rfc2822_missing_eoh">rfc2822-missing-eoh</a> option.
}*/
				statsCount(&stat_rfc2822_missing_eoh);
			} else {
				sess->msg.eoh = offset;
			}
		}

		/* This used to happen in filterContent() after the retContent()
		 * check. However, when something is white listed so that it
		 * by-passes much of filterContent(), have to be sure to generate
		 * the header afterwards.
		 */
		headerReceived(sess);

		rc = filterRun(sess, filter_headers_table, sess->msg.headers);
		if (verb_data.option.value)
			syslog(LOG_DEBUG, LOG_MSG(863) "filter-table=%s rc=%d", LOG_ARGS(sess), filter_headers_table[0].name, rc);

		switch (rc) {
		case SMTPF_CONTINUE:
		case SMTPF_DISCARD:
		case SMTPF_ACCEPT:
			rc = filterRun(sess, filter_content_table, chunk+sess->msg.eoh, offset-sess->msg.eoh);
		}
	} else {
		rc = filterRun(sess, filter_content_table, chunk, offset);
	}

	if (verb_data.option.value)
		syslog(LOG_DEBUG, LOG_MSG(864) "filter-table=%s rc=%d", LOG_ARGS(sess), filter_content_table[0].name, rc);

	keepAlive(sess);
error0:
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(322) "exit  readClientData() rc=%d", LOG_ARGS(sess), rc);

	return rc;
}

int
cmdData(Session *sess)
{
	char *hdr;
	unsigned char *chunk;
	unsigned long chunk_length;
	int sent, count, rc, i;

	/* How many DATA commands. */
	statsCount(&stat_data_count);

	if (sess->msg.rcpt_count < 1)
		return replySetFmt(sess, SMTPF_REJECT, "554 5.5.0 no recipients" ID_MSG(982) "\r\n", ID_ARG(sess));
/*{REPLY
The SMTP transaction attempted to send a DATA command without any valid recipients.
Either there were no recipients specified or all the RCPT commands were rejected.
The latter can occur with scripted mail transactions, a typical sign of spam.
}*/

	rc = filterRun(sess, filter_data_table);
	if (verb_data.option.value)
		syslog(LOG_DEBUG, LOG_MSG(865) "filter-table=%s rc=%d", LOG_ARGS(sess), filter_data_table[0].name, rc);

	switch (rc) {
	case SMTPF_ACCEPT:
		statsCount(&stat_data_accept);
		/*@fallthrough@*/

	case SMTPF_CONTINUE:
		/* For SMTPF_ACCEPT and SMTPF_CONTINUE, initialise manditory
		 * filters, such as anti-virus scanning.
		 */
		(void) filterRun(sess, filter_data_init_table);
		/*@fallthrough@*/

	case SMTPF_DISCARD:
		/* Proceed to reading the message from the client. */
		break;

	case SMTPF_DROP:
		summaryData(sess);
		statsCount(&stat_data_drop);
		return SMTPF_DROP;

	case SMTPF_REJECT:
		/* For any sort of rejection of DATA return the SMTPF_ code
		 * and do NOT count towards the processed message stats.
		 */
		summaryData(sess);
		statsCount(&stat_data_reject);
		return SMTPF_REJECT;

	default:
		summaryData(sess);
		statsCount(&stat_data_tempfail);
		return SMTPF_TEMPFAIL;
	}

	/* Tell the client we're ready for content. */
	sess->state = stateData;
	statsCount(&stat_data_354);
	statsCount(&stat_msg_count);
	SENDCLIENT(sess, "354 enter mail, end with \".\" on a line by itself\r\n");

	sess->msg.length = 0;
	sess->msg.seen_final_dot = 0;
	socketSetTimeout(sess->client.socket, optSmtpDataLineTimeout.value);

	/* Read headers and first chunk into chunk0 which can be used
	 * then for a DSN if requried.
	 */
	sess->msg.chunk0[0] = '\0';
	sess->msg.seen_crlf_before_dot = 1;

	rc = readClientData(sess, sess->msg.chunk0, &sess->msg.chunk0_length);
	chunk_length = sess->msg.chunk0_length;
	chunk = sess->msg.chunk0;

	switch (rc) {
	case SMTPF_DROP:
		goto reject0;

	case SMTPF_ACCEPT:
	case SMTPF_CONTINUE:
#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
if (MSG_NOT_SET(sess, MSG_TAG) && !(optSaveData.value & 2)) {
#endif
		/* Send DATA command to relays. */
		if ((rc = forwardCommand(sess, "DATA\r\n", 354, optSmtpCommandTimeout.value, &count, &sent)) != SMTPF_CONTINUE)
			goto reject0;

		/* Did all the relays rejected the DATA command? */
		if (sent == 0) {
			goto reject1;
		}

		/* Forward our updated message headers. */
		for (i = 0; i < VectorLength(sess->msg.headers); i++) {
			if ((hdr = VectorGet(sess->msg.headers, i)) != NULL)
				forwardChunk(sess, (unsigned char *) hdr, strlen(hdr));
		}

		/* Forward end of headers and start of message. */
		forwardChunk(sess, sess->msg.chunk0 + sess->msg.eoh-CRLF_LENGTH, sess->msg.chunk0_length - sess->msg.eoh+CRLF_LENGTH);
#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
}
#endif
	}

	/* Forward remainder of message. */
	while (!sess->msg.seen_final_dot) {
		rc = readClientData(sess, sess->msg.chunk1, &sess->msg.chunk1_length);
		chunk_length = sess->msg.chunk1_length;
		chunk = sess->msg.chunk1;

		switch (rc) {
		case SMTPF_DROP:
			goto reject0;

		case SMTPF_ACCEPT:
		case SMTPF_CONTINUE:
#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
if (MSG_NOT_SET(sess, MSG_TAG) && !(optSaveData.value & 2))
#endif
			forwardChunk(sess, sess->msg.chunk1, sess->msg.chunk1_length);
		}
	}

	/* Check final state of message filters BEFORE sending final dot. */
	rc = filterRun(sess, filter_dot_table);
	if (MSG_ANY_SET(sess, MSG_TRAP)) {
		rc = replySetFmt(sess, SMTPF_REJECT, "550 5.7.0 this message was blocked" ID_MSG(945) CRLF, ID_ARG(sess));
		statsCount(&stat_msg_trap);
	}

	if (verb_data.option.value)
		syslog(LOG_DEBUG, LOG_MSG(866) "filter-table=%s rc=%d", LOG_ARGS(sess), filter_dot_table[0].name, rc);

	switch (rc) {
#if !defined(FILTER_SPAMD) && defined(FILTER_SPAMD2)
	default:
		if (MSG_ANY_SET(sess, MSG_TAG) || (optSaveData.value & 2)) {
			if ((rc = forwardDataAtDot(sess, NULL)) != SMTPF_CONTINUE)
				goto reject0;

			/* forwardDataAtDot() will have the last part of the
			 * message data in chunk1.
			 */
			chunk_length = sess->msg.chunk1_length;
			chunk = sess->msg.chunk1;
		}
		break;
#endif
	case SMTPF_DISCARD:
		/* Tell the client we accepted the message, but skip
		 * sending the final dot to the forward host(s).
		 * Muhahaha!
		 */
		(void) replySetFmt(sess, rc, msg_250_accepted, sess->msg.id, ID_ARG(sess));
		/*@fallthrough@*/

	case SMTPF_REJECT:
	case SMTPF_TEMPFAIL:
		/* Don't send the final dot to the relays. We close the
		 * relays between messages to prevent them from accepting
		 * the message otherwise.
		 *
		 * The reply has already been queued by a filter and could
		 * be either SMTPF_TEMPFAIL or SMTPF_REJECT.
		 */
		goto reject0;
	}

	/* Some MUA and/or MLM (ecartis) fail to maintain CRLF newlines
	 * in the message body. So some remote MTAs (qmail) will reject
	 * a message that is not terminated by CRLF-DOT-CRLF; LF-DOT-LF
	 * or LF-DOT-CRLF is not sufficient for them.
	 *
	 * Here we assert that the last message body chunk ended with
	 * CRLF before we send DOT-CRLF.
	 *
	 * NOTE that this will probably break digital signatures that
	 * sign the whole message body; mind you if CRLF were altered
	 * to LF by a MUA or MLM, then things are already broken before
	 * we deal with them.
	 */
	if (!(2 < chunk_length && chunk[chunk_length-2] == '\r' && chunk[chunk_length-1] == '\n')) {
		/* Send CRLF as a dynamic string in the chunk buffer. */
		chunk[0] = '\r'; chunk[1] = '\n'; chunk[2] = '\0';
		forwardChunk(sess, chunk, 2);
	}

	/* Send final dot, read the relays' responses. */
	if ((rc = forwardCommand(sess, ".\r\n", 250, optSmtpDotTimeout.value, &count, &sent)) != SMTPF_CONTINUE)
		goto reject0;

	if (0 < optTestPauseAfterDot.value)
		pthreadSleep(optTestPauseAfterDot.value, 0);

	/* Between here and the client receiving the SMTP reply,
	 * the client could disconnect. Assuming the forward host
	 * accepts the message, then this means the client will
	 * retry sending the message, which it think failed to
	 * get through the first time, thus sending duplicate
	 * messages.
	 */

	/* Did all the relays accept the final dot? */
	rc = (sent == 0 ? SMTPF_REJECT : SMTPF_CONTINUE);

	/* If at least one relay accepts the message, report success
	 * and rely on DSN notification in case of some errors. If
	 * none were sent, then we can report failure.
	 */
reject1:
	sess->state = sess->helo_state;
	(void) replySetFmt(sess, rc, sent == 0 ? msg_550_rejected : msg_250_accepted, sess->msg.id, ID_ARG(sess));
reject0:
	socketSetTimeout(
		sess->client.socket,
		CLIENT_ANY_SET(sess, CLIENT_IS_BLACK)
			? optSmtpCommandTimeoutBlack.value
			: optSmtpCommandTimeout.value
	);
	summaryMessage(sess);

	switch (rc) {
	case SMTPF_ACCEPT:
	case SMTPF_CONTINUE:
		sess->client.forward_count++;
		statsCount(&stat_msg_accept);
		break;
	case SMTPF_DROP:
		statsCount(&stat_msg_drop);
		break;
	case SMTPF_REJECT:
		statsCount(&stat_msg_reject);
		if (optSmtpDropDot.value)
			rc = SMTPF_DROP;
		break;
	case SMTPF_TEMPFAIL:
		statsCount(&stat_msg_tempfail);
		break;
	case SMTPF_DISCARD:
		statsCount(&stat_msg_discard);
		break;
	}

	sess->state = sess->helo_state;
	sess->msg.smtpf_code = rc;

	return rc;
}

int
cmdHelp(Session *sess)
{
	int rc;

	rc = filterRun(sess, filter_idle_table);
	if (rc != SMTPF_CONTINUE && replyDefined(sess))
		return rc;

	return REPLY_PUSH_CONST(
		sess, SMTPF_CONTINUE,
		"214-2.0.0 ESMTP RFC 1985, 3207, 4954, 5321 supported commands:\r\n"
		"214-2.0.0     AUTH    DATA    EHLO    ETRN    HELO    HELP\r\n"
		"214-2.0.0     NOOP    MAIL    RCPT    RSET    QUIT    STARTTLS\r\n"
		"214-2.0.0\r\n"
		"214-2.0.0 ESMTP RFC 2821, 5321 not implemented:\r\n"
		"214-2.0.0     EXPN    TURN    VRFY\r\n"
		"214-2.0.0\r\n"
		"214-2.0.0 Administration commands:\r\n"
		"214-2.0.0     CONN    CACHE   INFO    KILL    LKEY    OPTN\r\n"
		"214-2.0.0     STAT    VERB    XCLIENT\r\n"
		"214-2.0.0 \r\n"
		"214 2.0.0 End\r\n"
	);
}


int
cmdOption(Session *sess)
{
	char *args;
	Option **opt, *o;
	Reply *reply = NULL;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
		return cmdOutOfSequence(sess);

	statsCount(&stat_admin_commands);

	/* Argument after OPTN? */
	if (sizeof ("OPTN ")-1 < sess->input_length) {
		args = sess->input + sizeof ("OPTN")-1;
		args += strspn(args, " \t-+");

		for (opt = optTableRestart; *opt != NULL; opt++) {
			o = *opt;

			if (o->usage == NULL)
				continue;

			if (TextInsensitiveCompare(args, o->name) == 0)
				return replySetFmt(sess, SMTPF_REJECT, "501 5.5.4 %s requires restart" ID_MSG(323) "\r\n", o->name, ID_ARG(sess));
/*{REPLY
Some options cannot be changed during runtime. Modify the /etc/@PACKAGE_NAME@/@PACKAGE_NAME@.cf options file,
then restart the @PACKAGE_NAME@ process.
}*/
		}

		(void) optionString(sess->input + sizeof ("OPTN ")-1, optTable, NULL);
		(void) filterRun(sess, filter_optn_table, NULL);
	} else {
		/* Dump option settings. */
		for (opt = optTable; *opt != NULL; opt++) {
			o = *opt;

			if (*o->name != '\0') {
				if (o->initial == NULL) {
					/* Action like -help/+help */
				} else if ((*o->initial == '+' || *o->initial == '-') && o->initial[1] == '\0') {
					/* Boolean +option or -option */
#ifdef OPTN_SHOW_DEFAULTS
					if (strcmp(o->initial, o->string) != 0)
						reply = replyAppendFmt(reply, "214-2.0.0 #%s%s\r\n", o->initial, o->name);
#endif
					reply = replyAppendFmt(reply, "214-2.0.0 %s%s\r\n", o->value ? "+" : "-", o->name);
				} else {
					/* Assignment option=value */
#ifdef OPTN_SHOW_DEFAULTS
					if (strcmp(o->initial, o->string) != 0)
						reply = replyAppendFmt(reply, "#%s=\"%s\"\r\n", o->name, o->initial);
#endif
					reply = replyAppendFmt(reply, "214-2.0.0 %s=\"%s\"\r\n", o->name, o->string);
				}
			}
		}
	}

	reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));

	return replyPush(sess, reply);
}

int
cmdLickey(Session *sess)
{
	Reply *reply = NULL;
#ifdef ENABLE_LICKEY
	Option **opt, *o;
	extern Option *lickeyTable[];

	statsCount(&stat_admin_commands);

	if (CLIENT_ANY_SET(sess, CLIENT_IS_LOCALHOST)) {
		for (opt = lickeyTable; *opt != NULL; opt++) {
			o = *opt;

			if (o->usage == NULL)
				continue;

			reply = replyAppendFmt(reply, "214-2.0.0 %s=\"%s\"\r\n", o->name, o->string);
		}
	}

	/* Force a license key check, which may exit the program. */
	lickeyInit(server.interfaces);

#endif
	reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));

	return replyPush(sess, reply);
}

static int
cmdConnReport(List *list, ListItem *node, void *data)
{
	time_t now;
	Session *conn;
	Command *state;
	Reply *reply = data;
	ServerWorker *worker;

	worker = node->data;
	if (worker->session == NULL)
		return 0;

	conn = worker->session->data;
	state = conn->state;

	(void) time(&now);
	reply = replyAppendFmt(
		reply, "214-2.0.0 %s %s " CLIENT_FORMAT " %lu %lu %lu\r\n",
		conn->long_id, state == NULL ? "null" : state[0].command, CLIENT_INFO(conn),
		(long) difftime(now, conn->start),
		(long) difftime(now, conn->last_mark),
		conn->client.octets
	);

	return 0;
}

int
cmdConnections(Session *sess)
{
	Reply *reply;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
		return cmdOutOfSequence(sess);

	statsCount(&stat_admin_commands);

	/* NOTE that the server.connections value and the number of active
	 * connections displayed may NOT correspond as connections will
	 * start or finish while the list is being displayed and so alter
	 * the count.
	 */
{
	unsigned numbers[2];
	serverNumbers(sess->session->server, numbers);
	reply = replyFmt(SMTPF_CONTINUE, "214-2.0.0 th=%lu cn=%lu cs=%lu\r\n", numbers[0], numbers[1], connections_per_second);
}
	if (reply == NULL)
		replyInternalError(sess, FILE_LINENO);

	(void) queueWalk(&server.workers, cmdConnReport, reply);
	reply = replyAppendFmt(reply, msg_end, ID_ARG(sess));

	return replyPush(sess, reply);
}

static int
cmdKillFind(List *list, ListItem *node, void *data)
{
	ServerWorker *worker;
	char *sess_id = data;

	worker = node->data;
	if (worker->session != NULL && strcmp(worker->session->id_log, sess_id) == 0)
		return -1;

	return 0;
}

int
cmdKill(Session *sess)
{
	int rc;
	char *arg;
	ListItem *node;

	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
		return cmdOutOfSequence(sess);

	statsCount(&stat_admin_commands);

	if ((rc = cmdMissingArg(sess, sizeof ("KILL ")-1)) != SMTPF_CONTINUE) {
		return rc;
	}

	arg = sess->input+sizeof ("KILL ")-1;

	/* Lock the list from alteration while we display it. */
	rc = SMTPF_UNKNOWN;

	if ((node = queueWalk(&server.workers, cmdKillFind, arg)) != NULL) {
		ServerWorker *worker = node->data;
		rc = replySetFmt(sess, SMTPF_CONTINUE, "214 2.0.0 killing session %s" ID_MSG(324) "\r\n", arg, ID_ARG(sess));
/*{REPLY
}*/
		(void) replySetFmt(worker->session->data, SMTPF_DROP, "550 5.0.0 session %s killed" ID_MSG(325) "\r\n", arg, ID_ARG(sess));
/*{REPLY
}*/
		(void) socketSetLinger(worker->session->client, 0);
		(void) shutdown(socketGetFd(worker->session->client), SHUT_RDWR);
		closesocket(socketGetFd(worker->session->client));

		/* Don't try to send this to ourself. */
		if (strcmp(worker->session->id_log, sess->session->id_log) != 0) {
#ifdef USE_PTHREAD_CANCEL
		pthread_cancel(worker->thread);
#elif defined(HAVE_PTHREAD_KILL)
		pthread_kill(worker->thread, SIGUSR1);
#else
		SetEvent(worker->kill_event);
#endif
		}
	}

	if (rc == SMTPF_UNKNOWN)
		rc = replySetFmt(sess, SMTPF_REJECT, "504 5.5.4 session %s not found" ID_MSG(326) "\r\n", arg, ID_ARG(sess));
/*{REPLY
The session given to KILL was not found. It probably terminated before this command was entered
or there is a typo in the session ID given.
}*/

	return rc;
}

int
cmdXclient(Session *sess)
{
	int rc;
	long length;
	Vector args;
	const char **list, *value;
	extern void checkClientIP(Session *);

	if (!optSmtpXclientEnable.value || CLIENT_NOT_SET(sess, CLIENT_USUAL_SUSPECTS))
		return cmdOutOfSequence(sess);

	statsCount(&stat_admin_commands);

	if ((rc = cmdMissingArg(sess, sizeof ("XCLIENT ")-1)) != SMTPF_CONTINUE)
		return rc;

	sess->state = state0;
	CLIENT_CLEAR_ALL(sess);
	CLIENT_SET(sess, CLIENT_NO_PTR);
	sess->client.name[0] = '\0';
	sess->client.helo[0] = '\0';

	args = TextSplit(sess->input+sizeof ("XCLIENT ")-1, " ", 0);
	for (list = (const char **) VectorBase(args);  *list != NULL; list++) {
		if (0 <= TextInsensitiveStartsWith(*list, "NAME=")) {
			value = *list + sizeof ("NAME=")-1;
			if (TextInsensitiveCompare(value, "[UNAVAILABLE]") == 0) {
				CLIENT_SET(sess, CLIENT_NO_PTR);
				statsCount(&stat_client_ptr_required);
			} else if (TextInsensitiveCompare(value, "[TEMPUNAVAIL]") == 0) {
				CLIENT_SET(sess, CLIENT_NO_PTR|CLIENT_NO_PTR_ERROR);
				statsCount(&stat_client_ptr_required_error);
				statsCount(&stat_client_ptr_required);
			} else {
				length = TextCopy(sess->client.name, sizeof (sess->client.name), value);
				if (0 < length && sess->client.name[length-1] == '.')
					sess->client.name[length-1] = '\0';
				TextLower(sess->client.name, length);
				CLIENT_CLEAR(sess, CLIENT_IS_RELAY);
			}
			continue;
		}
		if (0 <= TextInsensitiveStartsWith(*list, "ADDR=")) {
			value = *list + sizeof ("ADDR=")-1;
			if (0 < parseIPv6(value, sess->client.ipv6)) {
				length = TextCopy(sess->client.addr, sizeof (sess->client.addr), value);
			}
			if (isReservedIPv6(sess->client.ipv6, IS_IP_LOCAL)) {
				CLIENT_SET(sess, CLIENT_IS_LOCALHOST);
			}
			if (routeKnownClientAddr(sess)) {
				CLIENT_SET(sess, CLIENT_IS_RELAY);
			}
			checkClientIP(sess);
			continue;
		}
		if (0 <= TextInsensitiveStartsWith(*list, "HELO=")) {
			value = *list + sizeof ("HELO=")-1;
			length = TextCopy(sess->client.helo, sizeof (sess->client.helo), value);
			continue;
		}
		if (0 <= TextInsensitiveStartsWith(*list, "PROTO=")) {
			value = *list + sizeof ("PROTO=")-1;
			if (TextInsensitiveCompare(value, "SMTP") == 0) {
				sess->state = sess->helo_state = stateHelo;
			} else if (TextInsensitiveCompare(value, "ESMTP") == 0) {
				sess->state = sess->helo_state = stateEhlo;
			}
			continue;
		}

		return replySetFmt(sess, SMTPF_REJECT, "501 5.5.4 invalid argument %s" ID_MSG(928) CRLF, *list, ID_ARG(sess));
	}

	if (routeKnownClientName(sess)) {
		CLIENT_SET(sess, CLIENT_IS_RELAY);
	}

	(void) filterRun(sess, filter_connect_table);

	if (CLIENT_ANY_SET(sess, CLIENT_IS_BLACK))
		socketSetTimeout(sess->client.socket, optSmtpCommandTimeoutBlack.value);

	syslog(LOG_INFO, LOG_MSG(929) "xclient " CLIENT_FORMAT " f=\"%s\" h=\"%s\"", LOG_ARGS(sess), CLIENT_INFO(sess), clientFlags(sess), sess->client.helo);
/*{LOG
STMP XCLIENT command summary.
}*/
	VectorDestroy(args);

	return welcome(sess);
}

struct command state0[] = {
	{ "CONN", cmdUnknown },		/* First entry is state name. */
#ifdef ENABLE_TEST_ON_COMMAND
	{ "FAIL", cmdUnknown },
#endif
	{ "AUTH", cmdOutOfSequence },
	{ "DATA", cmdOutOfSequence },
	{ "EHLO", cmdEhlo },
	{ "HELO", cmdHelo },
	{ "HELP", cmdHelp },
	{ "MAIL", cmdOutOfSequence },
	{ "NOOP", cmdNoop },
	{ "QUIT", cmdQuit },
	{ "RCPT", cmdOutOfSequence },
	{ "RSET", cmdOutOfSequence },
	{ "VRFY", cmdOutOfSequence },
	{ "EXPN", cmdOutOfSequence },
	{ "TURN", cmdOutOfSequence },
	{ "ETRN", cmdOutOfSequence },
	{ "CONN", cmdConnections },
	{ "STAT", statsCommand },
	{ "VERB", verboseCommand },
	{ "OPTN", cmdOption },
	{ "LKEY", cmdLickey },
	{ "KILL", cmdKill },
	{ "CACHE", cacheCommand },
	{ "INFO", infoCommand },
	{ "XCLIENT", cmdXclient },
	{ "STARTTLS", cmdOutOfSequence },
	{ NULL, cmdUnknown }
};

struct command stateHelo[] = {
	{ "HELO", cmdUnknown },		/* First entry is state name. */
#ifdef ENABLE_TEST_ON_COMMAND
	{ "FAIL", cmdUnknown },
#endif
	{ "AUTH", cmdOutOfSequence },
	{ "DATA", cmdOutOfSequence },
	{ "EHLO", cmdEhlo },
	{ "HELO", cmdHelo },
	{ "HELP", cmdHelp },
	{ "MAIL", cmdMail },
	{ "NOOP", cmdNoop },
	{ "QUIT", cmdQuit },
	{ "RCPT", cmdOutOfSequence },
	{ "RSET", cmdRset },
	{ "VRFY", cmdNotImplemented },
	{ "EXPN", cmdNotImplemented },
	{ "TURN", cmdNotImplemented },
	{ "ETRN", cmdNotImplemented },
	{ "CONN", cmdConnections },
	{ "STAT", statsCommand },
	{ "VERB", verboseCommand },
	{ "OPTN", cmdOption },
	{ "LKEY", cmdLickey },
	{ "KILL", cmdKill },
	{ "CACHE", cacheCommand },
	{ "INFO", infoCommand },
	{ "XCLIENT", cmdXclient },
	{ "STARTTLS", cmdOutOfSequence },
	{ NULL, cmdUnknown }
};

struct command stateEhlo[] = {
	{ "EHLO", cmdUnknown },		/* First entry is state name. */
#ifdef ENABLE_TEST_ON_COMMAND
	{ "FAIL", cmdUnknown },
#endif
	{ "AUTH", cmdAuth },
	{ "DATA", cmdOutOfSequence },
	{ "EHLO", cmdEhlo },
	{ "HELO", cmdHelo },
	{ "HELP", cmdHelp },
	{ "MAIL", cmdMail },
	{ "NOOP", cmdNoop },
	{ "QUIT", cmdQuit },
	{ "RCPT", cmdOutOfSequence },
	{ "RSET", cmdRset },
	{ "VRFY", cmdNotImplemented },
	{ "EXPN", cmdNotImplemented },
	{ "TURN", cmdNotImplemented },
#ifdef ENABLE_ETRN
	{ "ETRN", cmdEtrn },
#else
	{ "ETRN", cmdNotImplemented },
#endif
	{ "CONN", cmdConnections },
	{ "STAT", statsCommand },
	{ "VERB", verboseCommand },
	{ "OPTN", cmdOption },
	{ "LKEY", cmdLickey },
	{ "KILL", cmdKill },
	{ "CACHE", cacheCommand },
	{ "INFO", infoCommand },
	{ "XCLIENT", cmdXclient },
#ifdef HAVE_OPENSSL_SSL_H
	{ "STARTTLS", cmdStartTLS },
#else
	{ "STARTTLS", cmdNotImplemented },
#endif
	{ NULL, cmdUnknown }
};

struct command stateMail[] = {
	{ "MAIL", cmdUnknown },		/* First entry is state name. */
#ifdef ENABLE_TEST_ON_COMMAND
	{ "FAIL", cmdUnknown },
#endif
	{ "AUTH", cmdOutOfSequence },
	{ "DATA", cmdOutOfSequence },
	{ "EHLO", cmdEhlo },
	{ "HELO", cmdHelo },
	{ "HELP", cmdHelp },
	{ "MAIL", cmdOutOfSequence },
	{ "NOOP", cmdNoop },
	{ "QUIT", cmdQuit },
	{ "RCPT", cmdRcpt },
	{ "RSET", cmdRset },
	{ "VRFY", cmdNotImplemented },
	{ "EXPN", cmdNotImplemented },
	{ "TURN", cmdNotImplemented },
	{ "ETRN", cmdOutOfSequence },
	{ "CONN", cmdOutOfSequence },
	{ "STAT", cmdOutOfSequence },
	{ "VERB", cmdOutOfSequence },
	{ "OPTN", cmdOutOfSequence },
	{ "LKEY", cmdOutOfSequence },
	{ "KILL", cmdOutOfSequence },
	{ "CACHE", cmdOutOfSequence },
	{ "INFO", cmdOutOfSequence },
	{ "XCLIENT", cmdOutOfSequence },
	{ "STARTTLS", cmdOutOfSequence },
	{ NULL, cmdUnknown }
};

struct command stateRcpt[] = {
	{ "RCPT", cmdUnknown },		/* First entry is state name. */
#ifdef ENABLE_TEST_ON_COMMAND
	{ "FAIL", cmdUnknown },
#endif
	{ "AUTH", cmdOutOfSequence },
	{ "DATA", cmdData },
	{ "EHLO", cmdEhlo },
	{ "HELO", cmdHelo },
	{ "HELP", cmdHelp },
	{ "MAIL", cmdOutOfSequence },
	{ "NOOP", cmdNoop },
	{ "QUIT", cmdQuit },
	{ "RCPT", cmdRcpt },
	{ "RSET", cmdRset },
	{ "VRFY", cmdNotImplemented },
	{ "EXPN", cmdNotImplemented },
	{ "TURN", cmdNotImplemented },
	{ "ETRN", cmdOutOfSequence },
	{ "CONN", cmdOutOfSequence },
	{ "STAT", cmdOutOfSequence },
	{ "VERB", cmdOutOfSequence },
	{ "OPTN", cmdOutOfSequence },
	{ "LKEY", cmdOutOfSequence },
	{ "KILL", cmdOutOfSequence },
	{ "CACHE", cmdOutOfSequence },
	{ "INFO", cmdOutOfSequence },
	{ "XCLIENT", cmdOutOfSequence },
	{ "STARTTLS", cmdOutOfSequence },
	{ NULL, cmdUnknown }
};

struct command stateData[] = {
	{ "DATA", cmdUnknown },		/* First entry is state name. */
	{ NULL, cmdUnknown }
};

struct command stateSink[] = {
	{ "SINK", cmdUnknown },		/* First entry is state name. */
	{ "QUIT", cmdQuit },
	{ NULL, cmdUnavailable }
};

struct command stateQuit[] = {
	{ "QUIT", cmdUnknown },		/* First entry is state name. */
	{ NULL, cmdUnknown }
};


