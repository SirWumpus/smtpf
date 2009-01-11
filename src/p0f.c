/*
 * p0f.c
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H)

#include "smtpf.h"

#include <p0f-query.h>

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
# include <stdint.h>
# endif
#endif

#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/util/Text.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_p0f_socket[] =
 " When set to the unix domain socket path of the p0f (passive OS finger-\n"
"# printing) server, typically /var/run/p0f.socket, then an X-p0f-Report:\n"
"# header is added to each message containing details about the SMTP\n"
"# client connection. Specify the empty string to disable.\n"
"#"
;

Option optP0fSocket	= { "p0f-socket",	"",	usage_p0f_socket };
Option optP0fTimeout	= { "p0f-timeout",	"60",	"The p0f I/O timeout in seconds." };

static const char usage_p0f_mutex[] =
  "The p0f daemon is a single threaded process, but supposedly\n"
"# fast enough not to require threading or mutex locking. When\n"
"# enabled, a mutex is used to control access to the p0f daemon.\n"
"# (Experimental)\n"
"#"
;

Option optP0fMutex	= { "p0f-mutex",	"-",	usage_p0f_mutex };

Option optP0fReportHeader = { "p0f-report-header",	"X-p0f-Report",	"The name of the p0f report header. Empty string to disable." };

FilterContext p0f_context;
static pthread_mutex_t p0f_mutex;

Verbose verb_p0f		= { { "p0f", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
p0fAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&p0f_mutex);
}

void
p0fAtForkParent(void)
{
	(void) pthread_mutex_unlock(&p0f_mutex);
}

void
p0fAtForkChild(void)
{
	(void) pthread_mutex_unlock(&p0f_mutex);
	(void) pthread_mutex_destroy(&p0f_mutex);
}
#endif

int
p0fOptn(Session *null, va_list ignore)
{
	optP0fTimeout.value = strtol(optP0fTimeout.string, NULL, 10) * 1000;

	return SMTPF_CONTINUE;
}

int
p0fRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_p0f);

	optionsRegister(&optP0fMutex,			0);
	optionsRegister(&optP0fSocket,			0);
	optionsRegister(&optP0fTimeout,			0);
	optionsRegister(&optP0fReportHeader,		0);

	p0f_context = filterRegisterContext(sizeof (P0F));

	return SMTPF_CONTINUE;
}

int
p0fInit(Session *null, va_list ignore)
{
	(void) p0fOptn(null, ignore);

	(void) pthread_mutex_init(&p0f_mutex, NULL);
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(p0fAtForkPrepare, p0fAtForkParent, p0fAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif

	return SMTPF_CONTINUE;
}

int
p0fFini(Session *null, va_list ignore)
{
	(void) pthread_mutex_destroy(&p0f_mutex);
	return SMTPF_CONTINUE;
}

static int
p0fGenerateReport(Session *sess, P0F *data)
{
	int length;

        length = snprintf(sess->input, sizeof (sess->input), "%s: " CLIENT_FORMAT " %s", optP0fReportHeader.string, CLIENT_INFO(sess), CLIENT_ANY_SET(sess, CLIENT_IS_FORGED) ? "(forged) " : "");
	if (*data->p_response.genre == '\0')
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "(unknown) ");
	else
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "%s %s ", data->p_response.genre, data->p_response.detail);
	if (data->p_response.dist != -1)
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "hops %d ", data->p_response.dist);
	if (*data->p_response.link != '\0')
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "link %s ", data->p_response.link);
	if (*data->p_response.tos != '\0')
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "service %s ", data->p_response.tos);
	if (data->p_response.uptime != -1L)
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "up %ld ", (long) data->p_response.uptime);
	if (data->p_response.score != NO_SCORE)
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "score %d flags 0x%x ", data->p_response.score, data->p_response.mflags);
	if (data->p_response.nat)
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "NAT ");
	if (data->p_response.fw)
		length += snprintf(sess->input+length, sizeof (sess->input)-length, "FW ");

	return length;
}

int
p0fConnect(Session *sess, va_list ignore)
{
	Socket2 *p0f;
	socklen_t slen;
	uint32_t *dst_ip;
	SocketAddress *caddr, saddr;
	P0F *data = filterGetContext(sess, p0f_context);

	if (*optP0fSocket.string == '\0' || !isReservedIPv6(sess->client.ipv6, IS_IP_V4))
		return SMTPF_CONTINUE;

	data->p_query.magic = QUERY_MAGIC;
	data->p_query.type = QTYPE_FINGERPRINT;
	data->p_query.id = sess->id;
	data->p_query.dst_port = socketAddressGetPort(&sess->iface->socket->address);
	data->p_query.src_port = socketAddressGetPort(&sess->client.socket->address);

	slen = sizeof (saddr);
	if (getsockname(sess->client.socket->fd, &saddr.sa, &slen))
		return SMTPF_CONTINUE;

	dst_ip = saddr.sa.sa_family == AF_INET
		? (uint32_t *) &saddr.in.sin_addr
		: (uint32_t *) ((char *) &saddr.in6.sin6_addr + IPV6_OFFSET_IPV4)
	;

#ifdef OLD
	memcpy(&data->p_query.dst_ad, dst_ip, IPV4_BYTE_LENGTH);
	memcpy(&data->p_query.src_ad, &sess->client.ipv6+IPV6_OFFSET_IPV4, IPV4_BYTE_LENGTH);
#else
	data->p_query.dst_ad = *dst_ip;
	data->p_query.src_ad = *(uint32_t *) (sess->client.ipv6+IPV6_OFFSET_IPV4);
#endif

	data->p_response.magic = 0;
	data->p_response.type = RESP_BADQUERY;

	if ((caddr = socketAddressCreate(optP0fSocket.string, 0)) == NULL) {
		syslog(LOG_ERR, LOG_MSG(506) "p0f address error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error0;
	}

	if ((p0f = socketOpen(caddr, 1)) == NULL) {
		syslog(LOG_ERR, LOG_MSG(507) "p0f open error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error1;
	}

	cliFdCloseOnExec(socketGetFd(p0f), 1);

	/***
	 *** p0f 2.0.6 -d option is single thread with a listen() queue of 10.
	 ***/
	if (optP0fMutex.value)
		(void) mutex_lock(SESS_ID, FILE_LINENO, &p0f_mutex);

	if (socketClient(p0f, optP0fTimeout.value)) {
		syslog(LOG_ERR, LOG_MSG(508) "p0f connection error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error2;
	}

	if (verb_p0f.option.value) {
		syslog(
			LOG_DEBUG, LOG_MSG(509) "> src %s port %d dst %s port %d", LOG_ARGS(sess),
			sess->client.addr, data->p_query.src_port, sess->if_addr, data->p_query.dst_port
		);
	}

	if (socketWrite(p0f, (void *) &data->p_query, sizeof (data->p_query)) != sizeof (data->p_query)) {
		syslog(LOG_ERR, LOG_MSG(510) "p0f write error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error2;
	}

	if (!socketHasInput(p0f, optP0fTimeout.value)) {
		syslog(LOG_ERR, LOG_MSG(511) "p0f timeout error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error2;
	}

	if (socketRead(p0f, (void *) &data->p_response, sizeof (data->p_response)) != sizeof (data->p_response)) {
		syslog(LOG_ERR, LOG_MSG(512) "p0f read error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error2;
	}

	if (optP0fMutex.value && mutex_unlock(SESS_ID, FILE_LINENO, &p0f_mutex)) {
		syslog(LOG_ERR, LOG_MSG(513) "p0f mutex unlock failed: %s (%d) ", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
	}

	socketClose(p0f);
	free(caddr);

	if (verb_p0f.option.value)
		syslog(LOG_DEBUG, LOG_MSG(514) "< %lu bytes", LOG_ARGS(sess), (unsigned long) sizeof (data->p_response));

	if (data->p_response.magic != QUERY_MAGIC) {
		syslog(LOG_ERR, LOG_MSG(515) "p0f magic number error", LOG_ARGS(sess));
/*{NEXT}*/
		goto error0;
	}

	if (data->p_response.type != RESP_OK && data->p_response.type != RESP_NOMATCH) {
		syslog(LOG_ERR, LOG_MSG(516) "p0f query error (%d)", LOG_ARGS(sess), data->p_response.type);
/*{NEXT}*/
		goto error0;
	}

	if (*optP0fReportHeader.string != '\0')
		(void) p0fGenerateReport(sess, data);

	if (verb_p0f.option.value) {
		syslog(LOG_INFO, LOG_MSG(517) "p0f %s", LOG_ARGS(sess), sess->input);
/*{LOG
See <a href="summary.html#opt_p0f_socket">p0f-socket</a>
and <a href="summary.html#opt_p0f_timeout">p0f-timeout</a>options.
}*/
	}

	return SMTPF_CONTINUE;
error2:
	if (optP0fMutex.value)
		(void) (void) mutex_unlock(SESS_ID, FILE_LINENO, &p0f_mutex);
	socketClose(p0f);
error1:
	free(caddr);
error0:
	return SMTPF_CONTINUE;
}

int
p0fHeaders(Session *sess, va_list args)
{
	char *hdr;
	int length;
	time_t now;
	char timestamp[40];
	P0F *data = filterGetContext(sess, p0f_context);

	if (*optP0fSocket.string != '\0' && CLIENT_NOT_SET(sess, CLIENT_HOLY_TRINITY)) {
		length = p0fGenerateReport(sess, data);

		(void) time(&now);
		(void) TimeStamp((time_t *) &now, timestamp, sizeof (timestamp));
		(void) snprintf(sess->input+length, sizeof (sess->input)-length, "\r\n    by [%s]; %s\r\n", sess->if_addr, timestamp);

		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	return SMTPF_CONTINUE;
}

#endif /* defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H) */
