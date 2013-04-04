/*
 * p0f.c
 *
 * Copyright 2007, 2012 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#if defined(FILTER_P0F)

#include "smtpf.h"

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
Option optP0fTimeout	= { "p0f-timeout",	"5",	"The p0f I/O timeout in seconds." };

Option optP0fReportHeader = { "p0f-report-header",	"X-p0f-Report",	"The name of the p0f report header. Empty string to disable." };

FilterContext p0f_context;
#ifdef ENABLE_P0F_MUTEX
static pthread_mutex_t p0f_mutex;
#endif

Verbose verb_p0f		= { { "p0f", "-", "" } };

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef ENABLE_P0F_MUTEX
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

#ifdef ENABLE_P0F_MUTEX
	(void) pthread_mutex_init(&p0f_mutex, NULL);
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(p0fAtForkPrepare, p0fAtForkParent, p0fAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
#endif
#endif
	return SMTPF_CONTINUE;
}

int
p0fFini(Session *null, va_list ignore)
{
#ifdef ENABLE_P0F_MUTEX
	(void) pthread_mutex_destroy(&p0f_mutex);
#endif
	return SMTPF_CONTINUE;
}

int
p0fGenerateReport(Session *sess, P0F *data, char *buf, size_t size, int is_hdr)
{
	int length = 0;

	if (is_hdr)
	        length = snprintf(buf, size, "%s: " CLIENT_FORMAT " %s", optP0fReportHeader.string, CLIENT_INFO(sess), CLIENT_ANY_SET(sess, CLIENT_IS_FORGED) ? "(forged) " : "");

#if defined P0F_QUERY_MAGIC
{
	struct tm when;

	if (*data->p_response.os_name == '\0') {
		length += snprintf(buf+length, size-length, "? ?");
	} else {
		length += snprintf(
			buf+length, size-length,
			"%s %s", data->p_response.os_name,
			data->p_response.os_flavor
		);
	}
	length += snprintf(
		buf+length, size-length,
		" conn %d", data->p_response.total_conn
	);

	/* Response fields not reported: first_seen, last_seen, language  */

	if (data->p_response.distance != -1)
		length += snprintf(
			buf+length, size-length,
			" hops %d", data->p_response.distance
		);
	{
		static char *quality[] = { "ok", "fuzzy", "generic", "fuzzy-generic" };
		length += snprintf(
			buf+length, size-length,
			" quality %s", quality[data->p_response.os_match_q]
		);
	}
	/* Pretty boring. Typically always says "Ethernet or modem" or "generic". */
	if (*data->p_response.link_type != '\0')
		length += snprintf(
			buf+length, size-length,
			" link %s", data->p_response.link_type
		);
	if (*data->p_response.http_name != '\0')
		length += snprintf(
			buf+length, size-length,
			" agent %s/%s", data->p_response.http_name,
			data->p_response.http_flavor
		);
	if (data->p_response.bad_sw > 0) {
		static char *suspect[] = { "ok", "proxy", "bad" };
		length += snprintf(
			buf+length, size-length,
			" suspect %s", suspect[data->p_response.bad_sw]
		);
	}
	if (data->p_response.uptime_min > 0) {
		unsigned long s;
		unsigned d, h, m;

		s = data->p_response.uptime_min;
	        d = s / 86400;
	        s -= d * 86400;
	        h = s / 3600;
	        s -= h * 3600;
	        m = s / 60;
	        s -= m * 60;

		length += snprintf(
			buf+length, size-length,
			" up %ud%uh%um%lus cycle %lud", d, h, m, s,
			(unsigned long) data->p_response.up_mod_days
		);
	}
	if (data->p_response.last_nat > 0) {
		(void) gmtime_r(&data->p_response.last_nat, &when);
		(void) strftime(timestamp, sizeof (timestamp), "%FT%T", &when);
		length += snprintf(buf+length, size-length, " ip-shared %s", timestamp);
	}
	if (data->p_response.last_chg > 0) {
		(void) gmtime_r(&data->p_response.last_chg, &when);
		(void) strftime(timestamp, sizeof (timestamp), "%FT`%T", &when);
		length += snprintf(buf+length, size-length, " os-changed %s", timestamp);
	}
}
#elif defined HAVE_P0F_QUERY_H
	if (*data->p_response.genre == '\0')
		length += snprintf(buf+length, size-length, " ? ?");
	else
		length += snprintf(buf+length, size-length, " %s %s", data->p_response.genre, data->p_response.detail);
	if (data->p_response.dist != -1)
		length += snprintf(buf+length, size-length, " hops %d", data->p_response.dist);
	if (*data->p_response.link != '\0')
		length += snprintf(buf+length, size-length, " link %s", data->p_response.link);
	if (*data->p_response.tos != '\0')
		length += snprintf(buf+length, size-length, " service %s", data->p_response.tos);
	if (data->p_response.uptime != -1L)
		length += snprintf(buf+length, size-length, " up %ld", (long) data->p_response.uptime);
	if (data->p_response.score != NO_SCORE)
		length += snprintf(buf+length, size-length, " score %d flags 0x%x", data->p_response.score, data->p_response.mflags);
	if (data->p_response.nat)
		length += snprintf(buf+length, size-length, " NAT");
	if (data->p_response.fw)
		length += snprintf(buf+length, size-length, " FW");
#endif /* HAVE_P0F_QUERY_H */
	if (is_hdr)
		length += snprintf(buf+length, size-length, CRLF);
	return length;
}

int
p0fConnect(Session *sess, va_list ignore)
{
	Socket2 *p0f;
	SocketAddress *caddr;
	P0F *data = filterGetContext(sess, p0f_context);

	if (*optP0fSocket.string == '\0' || !isReservedIPv6(sess->client.ipv6, IS_IP_V4))
		return SMTPF_CONTINUE;

#if defined P0F_QUERY_MAGIC
	data->p_query.magic = P0F_QUERY_MAGIC;
	if (sess->client.socket->address.sa.sa_family == AF_INET) {
		data->p_query.addr_type = P0F_ADDR_IPV4;
		memcpy(data->p_query.addr, &sess->client.socket->address.in.sin_addr, IPV4_BYTE_LENGTH);
	} else {
		data->p_query.addr_type = P0F_ADDR_IPV6;
		memcpy(data->p_query.addr, &sess->client.socket->address.in6.sin6_addr, IPV6_BYTE_LENGTH);
	}
#elif defined HAVE_P0F_QUERY_H
{
	socklen_t slen;
	uint32_t *dst_ip;
	SocketAddress saddr;

	data->p_query.magic = QUERY_MAGIC;
	data->p_query.type = QTYPE_FINGERPRINT;
	data->p_query.id = sess->session->id;
	data->p_query.dst_port = socketAddressGetPort(&sess->iface->socket->address);
	data->p_query.src_port = socketAddressGetPort(&sess->client.socket->address);

	slen = sizeof (saddr);
	if (getsockname(sess->client.socket->fd, &saddr.sa, &slen))
		return SMTPF_CONTINUE;

	dst_ip = saddr.sa.sa_family == AF_INET
		? (uint32_t *) &saddr.in.sin_addr
		: (uint32_t *) ((char *) &saddr.in6.sin6_addr + IPV6_OFFSET_IPV4)
	;

	data->p_query.dst_ad = *dst_ip;
	data->p_query.src_ad = *(uint32_t *) (sess->client.ipv6+IPV6_OFFSET_IPV4);

	data->p_response.magic = 0;
	data->p_response.type = RESP_BADQUERY;
}
#endif /* HAVE_P0F_QUERY_H */

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

#ifdef ENABLE_P0F_MUTEX
	/*** p0f 2.0.6 -d option is single thread with a listen() queue of 10. ***/
	PTHREAD_MUTEX_LOCK(&p0f_mutex);
#endif
	if (socketClient(p0f, optP0fTimeout.value)) {
		syslog(LOG_ERR, LOG_MSG(508) "p0f connection error: %s (%d)", LOG_ARGS(sess), strerror(errno), errno);
/*{NEXT}*/
		goto error2;
	}

	if (verb_p0f.option.value) {
#if defined P0F_QUERY_MAGIC
		syslog(
			LOG_DEBUG, LOG_MSG(509) "> p0f query [%s]",
			LOG_ARGS(sess), sess->client.addr
		);
#elif defined HAVE_P0F_QUERY_H
		syslog(
			LOG_DEBUG, LOG_MSG(509) "> src %s port %d dst %s port %d", LOG_ARGS(sess),
			sess->client.addr, data->p_query.src_port, sess->session->if_addr, data->p_query.dst_port
		);
#endif /* HAVE_P0F_QUERY_H */
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

#ifdef ENABLE_P0F_MUTEX
	PTHREAD_MUTEX_UNLOCK(&p0f_mutex);
#endif
	socketClose(p0f);
	free(caddr);

	if (verb_p0f.option.value)
		syslog(LOG_DEBUG, LOG_MSG(514) "< p0f %lu bytes", LOG_ARGS(sess), (unsigned long) sizeof (data->p_response));

#if defined P0F_RESP_MAGIC
	if (data->p_response.magic != P0F_RESP_MAGIC) {
		syslog(LOG_ERR, LOG_MSG(515) "p0f magic number error", LOG_ARGS(sess));
/*{NEXT}*/
		goto error0;
	}
	if (data->p_response.status != P0F_STATUS_OK) {
		syslog(LOG_ERR, LOG_MSG(516) "p0f query error (%d)", LOG_ARGS(sess), data->p_response.status);
/*{NEXT}*/
		goto error0;
	}
#elif defined HAVE_P0F_QUERY_H
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
#endif /* HAVE_P0F_QUERY_H */

	if (verb_p0f.option.value) {
		(void) p0fGenerateReport(sess, data, sess->input, sizeof (sess->input), 0);
		syslog(LOG_INFO, LOG_MSG(517) "%s", LOG_ARGS(sess), sess->input);
/*{LOG
See <a href="summary.html#opt_p0f_socket">p0f-socket</a>
and <a href="summary.html#opt_p0f_timeout">p0f-timeout</a>options.
}*/
	}

	return SMTPF_CONTINUE;
error2:
#ifdef ENABLE_P0F_MUTEX
	PTHREAD_MUTEX_UNLOCK(&p0f_mutex);
#endif
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
	P0F *data = filterGetContext(sess, p0f_context);

	if (*optP0fSocket.string != '\0' && CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST)) {
		(void) p0fGenerateReport(sess, data, sess->input, sizeof (sess->input), 1);
		if ((hdr = strdup(sess->input)) != NULL && VectorAdd(sess->msg.headers, hdr))
			free(hdr);
	}

	return SMTPF_CONTINUE;
}

#endif /* defined(FILTER_P0F) && defined(HAVE_P0F_QUERY_H) */
