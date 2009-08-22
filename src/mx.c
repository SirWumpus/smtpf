/*
 * mx.c
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

#include "smtpf.h"

#include <com/snert/lib/io/Dns.h>

/***********************************************************************
 ***
 ***********************************************************************/

int
mxPrint(Session *sess, Connection *relay, const char *line, size_t length)
{
	if (verb_smtp.option.value
#ifdef FILTER_SAV
	|| verb_sav.option.value
#endif
	)
		syslog(LOG_DEBUG, LOG_MSG(479) "%s >> %s", LOG_ARGS(sess), relay->route.key, line);

#ifdef OLD_SMTP_ERROR_CODES
	/* Replaced use of smtpWrite() with our own inline socketWrite()
	 * that avoid the socketCanSend().
	 */
	if (socketWrite(relay->mx, (unsigned char *) line, length) == SOCKET_ERROR) {
		syslog(LOG_ERR, LOG_MSG(480) "%s write error: %s (%d)", LOG_ARGS(sess), relay->route.key, strerror(errno), errno);
/*{NEXT}*/
		(void) snprintf(sess->reply, sizeof (sess->reply), "451 4.4.2 internal network error for %s" ID_MSG(481), relay->route.key, ID_ARG(sess));
/*{REPLY
An error occurred while sending an SMTP command to a forward host.
}*/
		relay->smtp_error = SMTP_ERROR_WRITE;
		relay->smtp_code = 451;

	} else {
		relay->smtp_error = SMTP_ERROR_OK;
	}

	sess->smtp_error = relay->smtp_error;

	return relay->smtp_error;
#else
	relay->smtp_code = SMTP_OK;
	if (socketWrite(relay->mx, (unsigned char *) line, length) == SOCKET_ERROR) {
		syslog(LOG_ERR, LOG_MSG(482) "%s write error: %s (%d)", LOG_ARGS(sess), relay->route.key, strerror(errno), errno);
/*{LOG
An error occurred while sending an SMTP command to a forward host.
}*/
		relay->smtp_code = SMTP_ERROR_IO;
	}

	return relay->smtp_code;
#endif
}

int
mxResponse(Session *sess, Connection *relay)
{
	char **ln;

	free(relay->reply);
	relay->reply = NULL;

#ifdef OLD_SMTP_ERROR_CODES
	if ((relay->smtp_error = smtpRead(relay->mx, &relay->reply, &relay->smtp_code)) == SMTP_ERROR_OK) {
		for (ln = relay->reply; *ln != NULL; ln++) {
			if (verb_smtp.option.value
#ifdef FILTER_SAV
			|| verb_sav.option.value
#endif
#ifdef REPORT_NEGATIVES
			|| !SMTP_IS_OK(relay->smtp_code)
#endif
			)
				syslog(LOG_DEBUG, LOG_MSG(483) "%s << %s", LOG_ARGS(sess), relay->route.key, *ln);
		}

		(void) TextCopy(sess->reply, sizeof (sess->reply), ln[-1]);
	} else {
		syslog(LOG_ERR, LOG_MSG(484) "%s read error: %s (%d)", LOG_ARGS(sess), relay->route.key, strerror(errno), errno);
/*{NEXT}*/
		(void) snprintf(sess->reply, sizeof (sess->reply), "451 4.4.2 internal network error for %s" ID_MSG(485), relay->route.key, ID_ARG(sess));
/*{REPLY
An error occurred while reading an SMTP reply from a forward host.
}*/
	}

	sess->smtp_error = relay->smtp_error;
	sess->smtp_code = relay->smtp_code;

	return relay->smtp_error;
#else
	relay->smtp_code = smtp2Read(relay->mx, &relay->reply);

	if (SMTP_IS_ERROR(relay->smtp_code)) {
		syslog(LOG_ERR, LOG_MSG(486) "%s read error: %s (%d)", LOG_ARGS(sess), relay->route.key, strerror(errno), errno);
/*{LOG
An error occurred while reading an SMTP reply from a forward host.
}*/
	} else {
		for (ln = relay->reply; *ln != NULL; ln++) {
			if (verb_smtp.option.value
#ifdef FILTER_SAV
			|| verb_sav.option.value
#endif
#ifdef REPORT_NEGATIVES
			|| !SMTP_IS_OK(relay->smtp_code)
#endif
			)
				syslog(LOG_DEBUG, LOG_MSG(487) "%s << %s", LOG_ARGS(sess), relay->route.key, *ln);
		}

		(void) TextCopy(sess->reply, sizeof (sess->reply), ln[-1]);
	}

	sess->smtp_code = relay->smtp_code;

	return relay->smtp_code;
#endif
}

int
mxCommand(Session *sess, Connection *relay, const char *line, int expect)
{
#ifdef OLD_SMTP_ERROR_CODES
	if (relay->mx == NULL)
		return SMTP_ERROR_NULL;

	sess->smtp_code = relay->smtp_code = 451;
	sess->smtp_error = relay->smtp_error = SMTP_ERROR_TEMPORARY;

	if (line != NULL && mxPrint(sess, relay, line, strlen(line)))
		goto error0;

	*sess->reply = '\0';

	if (mxResponse(sess, relay))
		goto error0;

	if (expect != relay->smtp_code) {
		relay->smtp_error = SMTP_IS_PERM(relay->smtp_code) ? SMTP_ERROR_REJECT : SMTP_ERROR_TEMPORARY;
	}

error0:
	return relay->smtp_error;
#else
	if (relay->mx == NULL)
		return -1;

	if (line != NULL) {
		(void) mxPrint(sess, relay, line, strlen(line));
		if (SMTP_IS_ERROR(relay->smtp_code))
			return -1;
	}

	*sess->reply = '\0';
	return -(mxResponse(sess, relay) != expect);
#endif
}

Socket2 *
mxConnect(Session *sess, const char *domain)
{
	Socket2 *socket;
	unsigned preference;
	PDQ_rr *list, *rr, *mx;

	/* Default response when no MX answers. */
#ifdef OLD_SMTP_ERROR_CODES
	sess->smtp_code = 451;
	sess->smtp_error = SMTP_ERROR_TEMPORARY;
#else
	sess->smtp_code = SMTP_TRY_AGAIN_LATER;
#endif
	snprintf(sess->reply, sizeof (sess->reply), "451 4.4.4 no answer from %s MX" ID_MSG(488), domain, ID_ARG(sess));
/*{REPLY
While attempting to perfom a call-back, there was
no answer from any of the MX servers tried.
See <a href="summary.html#opt_call_back">call-back</a> option.
}*/
	list = pdqGet(sess->pdq, PDQ_CLASS_IN, PDQ_TYPE_MX, domain, NULL);

	/* Resource error? */
	if (list == NULL && (errno == EMFILE || errno == ENFILE))
		replyResourcesError(sess, FILE_LINENO);

	/* Did we get a result we can use and is it a valid domain? */
	if (list != NULL && list->rcode == PDQ_RCODE_UNDEFINED) {
		snprintf(sess->reply, sizeof (sess->reply), "553 5.4.4 %s does not exist" ID_MSG(489) CRLF, domain, ID_ARG(sess));
/*{NEXT}*/
#ifdef OLD_SMTP_ERROR_CODES
		sess->smtp_error = SMTP_ERROR_REJECT;
		sess->smtp_code = 553;
#else
		sess->smtp_code = SMTP_BAD_ADDRESS;
#endif
		return NULL;
	}

	/* Was there some sort of error? */
	if (list == NULL || list->rcode != PDQ_RCODE_OK) {
		int rcode = list == NULL ? PDQ_RCODE_ERRNO : list->rcode;
		syslog(LOG_ERR, LOG_MSG(490) "MX %s error %s", LOG_ARGS(sess), domain, pdqRcodeName(rcode));
/*{LOG
While attempting to perfom a call-back, there was an error
looking up the MX records of the sender's domain.
See <a href="summary.html#opt_call_back">call-back</a> option.
}*/
		snprintf(sess->reply, sizeof (sess->reply), "451 4.4.3 %s MX lookup error" ID_MSG(491) CRLF, domain, ID_ARG(sess));
/*{REPLY
While attempting to perfom a call-back, there was an error
looking up the MX records of the sender's domain.
See <a href="summary.html#opt_call_back">call-back</a> option.
}*/
#ifdef OLD_SMTP_ERROR_CODES
		sess->smtp_error = SMTP_ERROR_TEMPORARY;
		sess->smtp_code = 451;
#else
		sess->smtp_code = SMTP_TRY_AGAIN_LATER;
#endif
		return NULL;
	}

	/* Remove impossible to reach MX and A/AAAA records. */
	list = pdqListPrune(list, IS_IP_RESTRICTED|IS_IP_LAN);

	/* Is the MX/A/AAAA list empty?  */
	if (list == NULL) {
		if (verb_smtp.option.value
#ifdef FILTER_SAV
		|| verb_sav.option.value
#endif
		)
			syslog(LOG_DEBUG, LOG_MSG(492) "%s has no acceptable MX", LOG_ARGS(sess), domain);

		snprintf(sess->reply, sizeof (sess->reply), "550 5.4.4 no acceptable MX for %s" ID_MSG(493) CRLF, domain, ID_ARG(sess));
/*{REPLY
While attempting to perfom a call-back,
the MX list gathered from DNS was pruned to remove hosts that resolve to localhost,
RFC 3330 reserved IP addresses that cannot be reached from the Internet, or
have no A/AAAA record. This message is reported if the MX list is empty after pruning.
See <a href="summary.html#opt_call_back">call-back</a> option.
}*/
#ifdef OLD_SMTP_ERROR_CODES
		sess->smtp_error = SMTP_ERROR_REJECT;
		sess->smtp_code = 550;
#else
		sess->smtp_code = SMTP_REJECT;
#endif
	}

	/* Find preference weight of connected client. */
	preference = 65535;
	if ((rr = pdqListFindAddress(list, PDQ_CLASS_IN, PDQ_TYPE_ANY, sess->client.addr)) != NULL
	&&  (mx = pdqListFindHost(list, PDQ_CLASS_IN, PDQ_TYPE_MX, rr->name.string.value)) != NULL)
		preference = ((PDQ_MX *) mx)->preference;

	/* Do not ignore the implicit MX record. */
	if (preference == 0)
		preference = 65535;

	/* Try all MX of a lower preference until one answers. */
	socket = NULL;
	for (rr = list; rr != NULL; rr = rr->next) {
		if (rr->type != PDQ_TYPE_MX || preference <= ((PDQ_MX *) rr)->preference) {
#ifdef FILTER_SAV
			if (verb_sav.option.value) {
				syslog(LOG_DEBUG, LOG_MSG(828) "%s ignoring DNS RR...", LOG_ARGS(sess), domain);
				pdqLog(rr);
			}
#endif
			continue;
		}

		if (verb_smtp.option.value
#ifdef FILTER_SAV
		|| verb_sav.option.value
#endif
		)
			syslog(LOG_DEBUG, LOG_MSG(494) "%s trying MX %d %s ...", LOG_ARGS(sess), domain, ((PDQ_MX *) rr)->preference, ((PDQ_MX *) rr)->host.string.value);

		if (socketOpenClient(((PDQ_MX *) rr)->host.string.value, SMTP_PORT, optSmtpConnectTimeout.value, NULL, &socket) == 0) {
			if (verb_smtp.option.value
#ifdef FILTER_SAV
			|| verb_sav.option.value
#endif
			)
				syslog(LOG_DEBUG, LOG_MSG(495) "%s connected to MX %d %s", LOG_ARGS(sess), domain, ((PDQ_MX *) rr)->preference, ((PDQ_MX *) rr)->host.string.value);

			socketSetTimeout(socket, optSmtpCommandTimeout.value);
			(void) socketSetNonBlocking(socket, 1);
			(void) socketSetKeepAlive(socket, 1);
#ifdef DISABLE_NAGLE
			(void) socketSetNagle(socket, 0);
#endif
			*sess->reply = '\0';
			break;
		}
	}

	pdqFree(list);

	return socket;
}
