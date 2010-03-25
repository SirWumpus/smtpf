/*
 * route.c
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

#define ENABLE_FALSE_RCPT_TEST
#define ENABLE_CACHE_UPDATE_MUTEX

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include "smtpf.h"

#include <ctype.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <com/snert/lib/crc/Luhn.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Text.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_route_map[] =
  "route-map=\n"
"#\n"
"# The type & location of the route key-value map used for forwarding,\n"
"# authentication, and recipient validation. The following methods are\n"
"# supported:\n"
"#\n"
"#   text!/path/map.txt\t\t\tr/o text file, memory hash\n"
#if defined(BREAK_LICKEY) && defined(HAVE_DB_H)
"#   db!/path/map.db\t\t\tBerkeley DB hash format\n"
"#   db!btree!/path/map.db\t\tBerkeley DB btree format\n"
#endif
#ifdef HAVE_SQLITE3_H
"#   sql!/path/database\t\t\tan SQLite database\n"
#endif
"#   socketmap!host:port\t\t\tSendmail style socket-map\n"
"#   socketmap!/path/local/socket\tSendmail style socket-map\n"
"#   socketmap!123.45.67.89:port\t\tSendmail style socket-map\n"
"#   socketmap![2001:0DB8::1234]:port\tSendmail style socket-map\n"
"#\n"
"# If port is omitted, the default is 7953.\n"
"#\n"
"# The route-map contains key-value pairs. Lookups are performed\n"
"# from most to least specific, stopping on the first entry found.\n"
"# Keys are case-insensitive. Lookups are the same as for access-map\n"
"# using a route: tag and can include recipient mail address lookups.\n"
"#\n"
"# If a key is found, then the value is a semicolon separated list of\n"
"# one or more parameters. The three types of parameters are:\n"
"#\n"
"#   RELAY\t\t\t\tconnecting clients can relay\n"
"#   RCPT: host:port ...\t\t\trecipient verification list\n"
"#   FORWARD: host:port ...\t\taccept & forward mail list\n"
"#\n"
"# If the :port is omitted from a host name or IP address, then the\n"
"# default is SMTP port 25. The hosts are tried in the order they\n"
"# were specified. Some examples:\n"
"#\n"
"#   route:127.0.0.1      FORWARD: 127.0.0.1:26; RELAY\n"
"#\n"
"# Relay mail inbound and outbound for the local host. Unqualified\n"
"# recipients will be directed to here as well.\n"
"#\n"
"#   route:192.0.2        RELAY\n"
"#\n"
"# Relay mail outbound for the LAN.\n"
"#\n"
"#   route:example.com    FORWARD: mx.filter.net; RCPT: in.our.net\n"
"#\n"
"# Forward mail to another mail appliance, but call-ahead to validate\n"
"# recipients deeper inside our network.\n"
"#\n"
"#   route:other.example  RELAY; FORWARD: mx.other.example:8025\n"
"#\n"
"# Relay mail outbound from client connections that resolve to\n"
"# other.example and forward mail destined for other.example to\n"
"# to an MX listening on a different port.\n"
"#\n"
"#   route:john@some.tld  FORWARD: mx1.baka.tld mx2.baka.tld\n"
"#\n"
"# Forward mail for this recipient address to one of these two hosts.\n"
"#"
;

Option optRouteMap		= {
	"route-map",
#if defined(HAVE_SQLITE3_H)
	"sql!" CF_DIR "/route.sq3"
#elif defined(BREAK_LICKEY) && defined(HAVE_DB_H)
	"db!" CF_DIR "/route.db"
#else
	"text!" CF_DIR "/route.cf"
#endif
	, usage_route_map
};

static const char usage_route_forward_selection[] =
  "The FORWARD host selection policy used when there is more than one\n"
"# FORWARD host. Specify ordered or random. Ordered selection connects\n"
"# to each host in turn until one answers or the list is exhausted. \n"
"# Random selection will randomly connect to hosts from the list until\n"
"# one answers or the list is exhausted.\n"
"#"
;

Option optRouteForwardSelection	= { "route-forward-selection", "ordered", usage_route_forward_selection };

static const char usage_call_ahead_as_sender[] =
  "When set, perform the call-ahead using the original MAIL FROM:<sender>\n"
"# instead of the MAIL FROM:<> (null sender). Some down stream mail stores\n"
"# reject MAIL FROM:<> or reject a sender at RCPT TO:\n"
"#"
;

Option optCallAheadAsSender = { "call-ahead-as-sender", "-", usage_call_ahead_as_sender };

#define RCPT_TAG		"rcpt:"
#define DUMB_TAG		"dumb:"

#ifdef ENABLE_CACHE_UPDATE_MUTEX
static pthread_mutex_t route_mutex;
#endif
char *route_map_path;

/***********************************************************************
 *** Route Database Lookups
 ***********************************************************************/

Connection *
connectionAlloc(void)
{
	Connection *fwd;

	if ((fwd = calloc(1, sizeof (*fwd))) != NULL) {
		fwd->time_of_last_command = time(NULL);
	}

	return fwd;
}

void
connectionFree(Connection *fwd)
{
	Rcpt *rcpt, *rcpt_next;

	if (fwd != NULL) {
		for (rcpt = fwd->rcpts; rcpt != NULL; rcpt = rcpt_next) {
			rcpt_next = rcpt->next;
			free(rcpt->rcpt);
			free(rcpt);
		}


		free(fwd->route.value);
		free(fwd->route.key);
		socketClose(fwd->mx);
		free(fwd->mx_host);
		free(fwd->reply);
		free(fwd);
	}
}

void
connectionClose(Connection *conn)
{
	socketClose(conn->mx);
	conn->mx = NULL;
}

int
connectionIsOpen(Connection *conn)
{
	return conn->mx != NULL;
}

void
connectionOptions(Connection *fwd)
{
	fileSetCloseOnExec(socketGetFd(fwd->mx), 1);
	socketFdSetKeepAlive(socketGetFd(fwd->mx), 1, SMTP_COMMAND_TO, 60, 3);
	socketAddressGetString(&fwd->mx->address, 0, fwd->mx_ip, sizeof (fwd->mx_ip));
	socketSetTimeout(fwd->mx, optSmtpCommandTimeout.value);
	(void) socketSetNonBlocking(fwd->mx, 1);
#ifdef DISABLE_NAGLE
	(void) socketSetNagle(fwd->mx, 0);
#endif
	fwd->can_quit = 1;
}

/***********************************************************************
 ***
 ***********************************************************************/

static int
route_compare_domain(const void *_a, const void *_b)
{
	const char *a = *(const char **) _a;
	const char *b = *(const char **) _b;

	/* NULL pointers sort towards the end of a list. This may seem
	 * odd, but consider a NULL terminated array of pointers to char,
	 * like argv. You can iterate over the array stopping at the
	 * NULL. Sorting NULL to the end allows us to continue using
	 * that iteration technique.
	 */
	if (a == NULL && b != NULL)
		return 1;
	if (a != NULL && b == NULL)
		return -1;
	if (a == b)
		return 0;

	return strnatcasecmp(a, b);
}

static int
route_walk_count(kvm_data *key, kvm_data *value, void *data)
{
	char *at_sign, *domain;
	RouteCount *rcp = data;

	if (0 <= TextInsensitiveStartsWith(key->data, ROUTE_TAG) && strstr(value->data, ROUTE_ATTR_FORWARD) != NULL) {
		if ((at_sign = strchr(key->data, '@')) == NULL) {
			rcp->domains++;

			if (VectorAdd(rcp->domain_list, (domain = strdup(key->data + sizeof (ROUTE_TAG)-1))))
				free(domain);
		} else if (at_sign[1] != '\0') {
			rcp->addresses++;

			if (VectorAdd(rcp->domain_list, (domain = strdup(at_sign + 1))))
				free(domain);
		} else {
			rcp->accounts++;
		}
	}

	return 1;
}

int
routeGetRouteCount(RouteCount *rcp)
{
	int rc;
	char *value;
	smdb *route_map;

	if (rcp == NULL) {
		errno = EFAULT;
		return -1;
	}

	memset(rcp, 0, sizeof (*rcp));
	rcp->domain_list = VectorCreate(10);
	VectorSetDestroyEntry(rcp->domain_list, free);

	rc = KVM_ERROR;
	if ((route_map = smdbOpen(route_map_path, 1)) == NULL) {
		syslog(LOG_ERR, LOG_NUM(000) "route-map=%s open error: %s (%d)", optRouteMap.string, strerror(errno), errno);
		goto error1;
	}

	if (TextMatch(route_map_path, "*socketmap!*", -1 , 1)) {
		value = smdbGetValue(route_map, ROUTE_TAG "__counts__");
		if (verb_kvm.option.value)
			syslog(LOG_DEBUG, ROUTE_TAG "__counts__=\"%s\"", TextNull(value));
		if (value != NULL
		&& sscanf(value, "%lu %lu %lu %lu", &rcp->domains, &rcp->accounts, &rcp->addresses, &rcp->unique_domains) == 4) {
			if (verb_kvm.option.value)
				syslog(LOG_DEBUG, ROUTE_TAG "__counts__ parsed ok");
			free(value);
			rc = KVM_OK;
		}
	} else {
		rc = route_map->walk(route_map, route_walk_count, rcp);

		if (rcp->domain_list != NULL) {
			char **table;

			VectorSort(rcp->domain_list, (int (*)(const void *, const void *)) route_compare_domain);
			VectorUniq(rcp->domain_list, (int (*)(const void *, const void *)) route_compare_domain);

			if (verb_debug.option.value) {
				for (table = (char **) VectorBase(rcp->domain_list); *table != NULL; table++)
					syslog(LOG_DEBUG, LOG_NUM(913) "route uniq domain=%s", *table);
			}

			rcp->unique_domains = VectorLength(rcp->domain_list);
			rc = KVM_OK;
		}
	}
error1:
	VectorDestroy(rcp->domain_list);
	rcp->domain_list = NULL;
	smdbClose(route_map);

	if (verb_info.option.value) {
		syslog(LOG_INFO, LOG_NUM(557) "route domains=%lu addresses=%lu accounts=%lu unique-domains=%lu", rcp->domains, rcp->addresses, rcp->accounts, rcp->unique_domains);
/*{LOG
A summary of route types found in the route-map, used for
<em>max-domains</em> license control.
The domain, addresses, and accounts refer to records in the
<a href="route-map.html">route-map</a> of the form
<span class="key"><span class="tag">route:</span>some.domain</span>,
<span class="key"><span class="tag">route:</span>user@some.domain</span>,
and
<span class="key"><span class="tag">route:</span>user@</span> respectively.

<p>
The license key field <em>max-domains</em> is a bit of a misnomer.
It should have been called <em>max-routes</em>, but it is
easier for people to think in terms of domains and in the
majority of cases routing is by-domain only.
</p>
<p>
However, our logic counts all <span class="tag">route:</span> records,
regardless of type, towards the license's <em>max-domains</em>, since
the same amount of work is necessary to route by-domain as by-address or
by-account.
}*/

	}

	return -(rc == KVM_ERROR);
}

/***********************************************************************
 *** Individual Recipients Addresses
 ***********************************************************************/

Rcpt *
rcptCreate(ParsePath *rcpt)
{
	Rcpt *r;

	if (rcpt == NULL)
		return NULL;

	if ((r = calloc(1, sizeof (*r))) != NULL)
		r->rcpt = rcpt;

	return r;
}

void
rcptFree(Rcpt *r)
{
	if (r != NULL) {
		free(r->rcpt);
		free(r);
	}
}

Rcpt *
rcptListFind(Rcpt *list, ParsePath *rcpt)
{
	if (list != NULL && rcpt != NULL) {
		for ( ; list != NULL; list = list->next) {
			if (strcmp(list->rcpt->address.string, rcpt->address.string) == 0)
				return list;
		}
	}

	return NULL;
}

Rcpt *
rcptListAdd(Rcpt **list, ParsePath *rcpt)
{
	Rcpt *r;

	if (list == NULL)
		return NULL;

	if ((r = rcptListFind(*list, rcpt)) == NULL) {
		if ((r = rcptCreate(rcpt)) != NULL) {
			r->next = *list;
			*list = r;
		}
	}

	return r;
}

void
rcptListFree(Rcpt *list)
{
	Rcpt *next;

	for ( ; list != NULL; list = next) {
		next = list->next;
		rcptFree(list);
	}
}

/***********************************************************************
 ***
 ***********************************************************************/

static int
routeCacheGetRcpt(Session *sess, char *key)
{
	int rc;
	mcc_row row;

	rc = SMTPF_CONTINUE;

#ifdef ENABLE_CACHE_UPDATE_MUTEX
	/* While the mcc_handle structure has its own mutex, we use this
	 * mutex to avoid a race condition between getting the record
	 * and updating the record.
	 */
	if (mutex_lock(SESS_ID, FILE_LINENO, &route_mutex))
		goto error0;
#endif
	MEMSET(&row, 0, sizeof (row));
	row.key_size = snprintf(row.key_data, sizeof (row.key_data), RCPT_TAG "%s", key);
	TextLower(row.key_data, -1);

	if (mccGetRow(mcc, &row) == MCC_OK) {
		row.value_data[row.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);

		rc = (int) strtol(row.value_data, NULL, 10);

		/* Touch the record. */
		if (rc == SMTPF_ACCEPT)
			row.expires = time(NULL) + optCacheAcceptTTL.value;

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
		if (mccPutRow(mcc, &row) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
	}

#ifdef ENABLE_CACHE_UPDATE_MUTEX
	(void) mutex_unlock(SESS_ID, FILE_LINENO, &route_mutex);
#endif
error0:
	return rc;
}

static void
routeCacheAddRcpt(Session *sess, char *key, int smtpf_code)
{
	mcc_row row;

	MEMSET(&row, 0, sizeof (row));
	row.hits = 0;
	row.created = time(NULL);
	row.expires = row.created + cacheGetTTL(smtpf_code);
	row.key_size = snprintf(row.key_data, sizeof (row.key_data), RCPT_TAG "%s", key);
	row.value_size = (unsigned char) snprintf(row.value_data, sizeof (row.value_data), "%d", smtpf_code);
	TextLower(row.key_data, -1);

	if (verb_cache.option.value)
		syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
	if (mccPutRow(mcc, &row) == MCC_ERROR)
		syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), row.key_data, row.value_data, FILE_LINENO);
}

#ifdef ENABLE_CACHE_UPDATE_MUTEX
#if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
void
routeAtForkPrepare(void)
{
	(void) pthread_mutex_lock(&route_mutex);
}

void
routeAtForkParent(void)
{
	(void) pthread_mutex_unlock(&route_mutex);
}

void
routeAtForkChild(void)
{
	(void) pthread_mutex_unlock(&route_mutex);
	(void) pthread_mutex_destroy(&route_mutex);
}
#endif
#endif

int
routeKnownClientAddr(Session *sess)
{
	int found;
	char *value;

	if (smdbAccessIp(sess->route_map, ROUTE_TAG, sess->client.addr, NULL, &value) == SMDB_ACCESS_NOT_FOUND)
		return 0;

	found = (strstr(value, ROUTE_ATTR_RELAY) != NULL);
	free(value);

	return found;
}

int
routeKnownClientName(Session *sess)
{
	int found;
	char *value;

	if (CLIENT_ANY_SET(sess, CLIENT_IS_RELAY))
		return 1;

	if (CLIENT_ANY_SET(sess, CLIENT_IS_FORGED) || smdbAccessDomain(sess->route_map, ROUTE_TAG, sess->client.name, NULL, &value) == SMDB_ACCESS_NOT_FOUND)
		return 0;

	found = (strstr(value, ROUTE_ATTR_RELAY) != NULL);
	free(value);

	return found;
}

int
routeKnownDomain(Session *sess, const char *domain)
{
        int found;
        char *value;

        if (smdbAccessDomain(sess->route_map, ROUTE_TAG, domain, NULL, &value) == SMDB_ACCESS_NOT_FOUND) {
        	errno = EINVAL;
                return 0;
	}

        found = (strstr(value, ROUTE_ATTR_FORWARD) != NULL);
        free(value);

        return found;
}

static int
routeIsMember(const char *value, const char *tag, const char *name, const char *ip)
{
	char *list;
	long span;

	if (value == NULL || (name == NULL && ip == NULL) || (list = strstr(value, tag)) == NULL)
		return 0;

	/* Scan over the list of host names and IP addresses:
	 *
	 *	tag: host:port 123.45.67.89:port [2001:0db8::1234:5678]:25 ... ;
	 */
	for (list += strlen(tag); *list != '\0'; list += strcspn(list, " ,")) {
		list += strspn(list, " ,");
		if (*list == ';')
			break;

		/* Remember IPv6 addresses with port numbers are of
		 * the form [2001:0db8::1234:5678]:25
		 */
		if (*list == '[') {
			list++;
			span = strcspn(list, "]");
		} else {
			/* Find end of host name or IP address. */
			span = strcspn(list, " ,:;");
		}

		if ((name != NULL && name[span] == '\0' && TextInsensitiveCompareN(list, name, span) == 0)
		||  (ip != NULL && ip[span] == '\0' && TextInsensitiveCompareN(list, ip, span) == 0))
			return 1;

		list += span;
	}

	return 0;
}

char *
routeGetNextMember(const char *next, const char **stop)
{
	const char *member;

	if (stop != NULL)
		*stop = NULL;

	if (next == NULL)
		return NULL;

	/* Skip leading white space. */
	member = next + strspn(next, " \t,");

	/* End of list? */
	if (*member == ';' || *member == '\0')
		return NULL;

	/* Find end of list member. */
	next = member + strcspn(member, " \t,;");
	if (stop != NULL)
		*stop = next;

	member = TextDupN(member, next - member);

	return (char *) member;
}

/*
 *	route:local
 *	route:127.0.0.1
 *	route:127.0.0
 *	route:127.0
 *	route:127
 *	route:::1
 */
static char *
routeGetLocal(smdb *map)
{
	char *value;

	if ((value = smdbGetValue(map, ROUTE_LOCAL)) != NULL)
		return value;

	if (smdbAccessIp(map, ROUTE_TAG, "127.0.0.1", NULL, &value) != SMDB_ACCESS_NOT_FOUND)
		return value;

	return smdbGetValue(map, ROUTE_TAG "::1");
}

char *
routeGetLocalRoute(void)
{
	smdb *route_map;
	char *value = NULL;

	if ((route_map = smdbOpen(route_map_path, 1)) != NULL) {
		value = routeGetLocal(route_map);
		smdbClose(route_map);
	}

	return value;
}

Vector
routeGetLocalHosts(void)
{
	Vector hosts = NULL;
	char *local_route, *host;

	if ((local_route = routeGetLocalRoute()) == NULL)
		goto error0;

	if ((host = strstr(local_route, ROUTE_ATTR_FORWARD)) == NULL)
		goto error1;

	host += sizeof (ROUTE_ATTR_FORWARD)-1;
	host[strcspn(host, ";")] = '\0';
	hosts = TextSplit(host, " \t,", 0);
error1:
	free(local_route);
error0:
	return hosts;
}

/* When the connecting client is a local service, like the MTA or MSP,
 * that is sending internal mail, eg. from root to root@this.host.name,
 * then we have to take care NOT to loop back to ourselves in an attempt
 * to deliver the message. Consider a common route:
 *
 *	route:127		FORWARD: 127.0.0.1:26; RELAY
 *
 * Here localhost is allowed to receive mail from itself and send mail
 * out to the Internet.
 *
 * Normally there should be host specific route entries like:
 *
 *	route:this.host.name	FORWARD: 127.0.0.1:26
 *
 * But if they're missing then we can end up in a mail loop. To avoid
 * this easy to forget situation we check to see if we're localhost,
 * delivering to an unqualified recipient or to a recipient addressed
 * to this host, in which case we want to FORWARD the mail and not
 * RELAY it.
 *
 * We'll assume that at least one of the routes for 127.0.0.1 or ::1 is
 * specified and use it to forward. The lookup order is:
 *
 *	route:127.0.0.1
 *	route:127.0.0
 *	route:127.0
 *	route:127
 *	route:::1
 */
static int
routeLocal(Session *sess, const char *domain, char **keyp, char **valuep)
{
	if (*domain != '\0') {
		if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST))
			return 0;

		if (TextInsensitiveCompare(domain, sess->iface->name) != 0)
			return 0;
	}

	/* Unqualified recipients or recipients destined to our host name
	 * are forwarded to the local route.
	 */
	if ((*valuep = routeGetLocal(sess->route_map)) != NULL)
		*keyp = strdup(ROUTE_LOCAL);

	return *valuep != NULL;
}

/*
 * @return
 *	Return one of SMTPF_CONTINUE, SMTPF_ACCEPT, SMTPF_REJECT,
 *	or SMTPF_TEMPFAIL.
 */
int
routeCallAhead(Session *sess, const char *host, ParsePath *rcpt)
{
	int rc;
	Connection *conn;
#ifdef ENABLE_FALSE_RCPT_TEST
	long length;
	mcc_row dumb_host;
	int dumb_host_cached;
	char false_rcpt[SMTP_LOCAL_PART_LENGTH];

#endif
	*sess->reply = '\0';

#ifdef ENABLE_FALSE_RCPT_TEST
	/* Does the recipient's route blindly accept all recipients? */
	MEMSET(&dumb_host, 0, sizeof (dumb_host));
	dumb_host.key_size = (unsigned short) snprintf(dumb_host.key_data, sizeof (dumb_host.key_data), DUMB_TAG "%s,%s", host, rcpt->domain.string);

	if ((dumb_host_cached = mccGetRow(mcc, &dumb_host)) == MCC_OK) {
		dumb_host.value_data[dumb_host.value_size] = '\0';
		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_get, LOG_ARGS(sess), dumb_host.key_data, dumb_host.value_data, FILE_LINENO);

		if (verb_cache.option.value)
			syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), dumb_host.key_data, dumb_host.value_data, FILE_LINENO);
		if (mccPutRow(mcc, &dumb_host) == MCC_ERROR)
			syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), dumb_host.key_data, dumb_host.value_data, FILE_LINENO);

		dumb_host.value_data[dumb_host.value_size] = '\0';

		if (SMTP_ISS_OK(dumb_host.value_data)) {
			(void) TextCopy(sess->reply, sizeof (sess->reply), "dumb mail host, skipping");
			rc = SMTPF_CONTINUE;
			goto error0;
		}
	}
#endif
	if ((conn = connectionAlloc()) == NULL) {
		(void) TextCopy(sess->reply, sizeof (sess->reply), "out of memory");
		rc = SMTPF_TEMPFAIL;
		goto error0;
	}

	if (socketOpenClient(host, SMTP_PORT, optSmtpConnectTimeout.value, NULL, &conn->mx)) {
		(void) TextCopy(sess->reply, sizeof (sess->reply), "connection error");
		rc = SMTPF_TEMPFAIL;
		goto error1;
	}

	conn->route.key = strdup(host);
	connectionOptions(conn);

	/* Get welcome message from MX. */
	if (mxCommand(sess, conn, NULL, 220)) {
		/* Avoid caching a failure result regardless of the
		 * response from the downstream host.
		 */
		rc = SMTPF_TEMPFAIL;
		goto error2;
	}

	(void) snprintf(sess->input, sizeof (sess->input), "HELO %s\r\n", sess->iface->name);
	if (mxCommand(sess, conn, sess->input, 250)) {
		/* Avoid caching a failure result regardless of the
		 * response from the downstream host.
		 */
		rc = SMTPF_TEMPFAIL;
		goto error2;
	}

	(void) snprintf(
		sess->input, sizeof (sess->input), "MAIL FROM:<%s>\r\n",
		optCallAheadAsSender.value ? sess->msg.mail->address.string : ""
	);
	if (mxCommand(sess, conn, sess->input, 250)) {
		/* Avoid caching a failure result regardless of the
		 * response from the downstream host.
		 */
		rc = SMTPF_TEMPFAIL;
		goto error2;
	}

	(void) snprintf(sess->input, sizeof (sess->input), "RCPT TO:<%s>\r\n", rcpt->address.string);
	if (mxCommand(sess, conn, sess->input, 250)) {
		if (*rcpt->localRight.string != '\0') {
			(void) snprintf(sess->input, sizeof (sess->input), "RCPT TO:<%s>\r\n", rcpt->address.string);
			if (!mxCommand(sess, conn, sess->input, 250))
				goto unplussed_rcpt;
		}

		rc = SMTP_IS_PERM(conn->smtp_code) ? SMTPF_REJECT : SMTPF_TEMPFAIL;
		goto error2;
	}
unplussed_rcpt:
#ifdef ENABLE_FALSE_RCPT_TEST
	/* If the recipient's call-ahead host status hasn't been
	 * cached, then perform the false address test.
	 */
	if (dumb_host_cached == MCC_NOT_FOUND) {
		/* Generate a false address, which is the local-part
		 * reversed plus a LUHN check digit appended.
		 */
		length = TextCopy(false_rcpt, sizeof (false_rcpt), rcpt->localLeft.string);
		TextReverse(false_rcpt, length);
		if (sizeof (false_rcpt) <= length)
			length = sizeof (false_rcpt)-2;
		false_rcpt[length++] = LuhnGenerate(false_rcpt) + '0';
		false_rcpt[length] = '\0';

		(void) snprintf(
			sess->input, sizeof (sess->input), "RCPT TO:<%s@%s>\r\n",
			false_rcpt, rcpt->domain.string
		);

		(void) mxCommand(sess, conn, sess->input, 250);

		/* Assume for an I/O error that the call-ahead host dropped
		 * the connection and that the sender test result is still
		 * good.
		 *
		 * ovh.net drop the connection following a RSET after a bad
		 * RCPT TO: command.
		 *
		 * sappi.com (mxlogic.net) drop the connection following the
		 * second MAIL FROM: command after a bad RCPT TO: command.
		 */
#ifdef OLD_SMTP_ERROR_CODES
		if (conn->smtp_error & SMTP_ERROR_IO_MASK) {
#else
		if (SMTP_IS_ERROR(conn->smtp_code)) {
#endif
			dumb_host.value_data[0] = SMTPF_REJECT + '0';
		} else {
			dumb_host.value_data[0] = conn->smtp_code / 100 + '0';
		}

		if (SMTP_IS_TEMP(conn->smtp_code)) {
			/* Assume 4xx for false recipient is a grey-list
			 * response.
			 */
			(void) TextCopy(sess->reply, sizeof (sess->reply), "dumb mail host inconclusive");
			rc = SMTPF_TEMPFAIL;
			goto error2;
		} else {
			dumb_host.hits = 0;
			dumb_host.value_size = 1;
			dumb_host.value_data[1] = '\0';
			dumb_host.created = time(NULL);
			dumb_host.expires = dumb_host.created + cacheGetTTL(dumb_host.value_data[0] - '0');

			dumb_host.key_size = (unsigned short) snprintf(dumb_host.key_data, sizeof (dumb_host.key_data), DUMB_TAG "%s,%s", host, rcpt->domain.string);

			if (verb_cache.option.value)
				syslog(LOG_DEBUG, log_cache_put, LOG_ARGS(sess), dumb_host.key_data, dumb_host.value_data, FILE_LINENO);
			if (mccPutRow(mcc, &dumb_host) == MCC_ERROR)
				syslog(LOG_ERR, log_cache_put_error, LOG_ARGS(sess), dumb_host.key_data, dumb_host.value_data, FILE_LINENO);

			if (SMTP_IS_OK(conn->smtp_code)) {
				(void) TextCopy(sess->reply, sizeof (sess->reply), "dumb mail host found");
				rc = SMTPF_CONTINUE;
				goto error2;
			}

			sess->reply[0] = '\0';
		}
	}
#endif
	rc = SMTPF_ACCEPT;
error2:
	/* Preserve the call-ahead reply that will be overwritten by QUIT.
	 * If +relay-reply, then we'll want report negative replies.
	 */
	(void) TextCopy(sess->input, sizeof (sess->input), sess->reply);
#ifdef OLD_SMTP_ERROR_CODES
	if (!(conn->smtp_error & SMTP_ERROR_IO_MASK))
#else
	if (conn->smtp_code != SMTP_ERROR_IO)
#endif
		(void) mxCommand(sess, conn, "QUIT\r\n", 221);
	(void) TextCopy(sess->reply, sizeof (sess->reply), sess->input);
error1:
	connectionFree(conn);
error0:
	syslog(LOG_INFO, LOG_MSG(558) "call-ahead host=%s rcpt=<%s> rc=%d reply=\"%s\"", LOG_ARGS(sess), host, rcpt->address.string, rc, sess->reply);
/*{LOG
A summary of call-ahead results.
}*/
	return rc;
}

/*
 * Lookup the recipient's domain for a RCPT list and perform
 * call-ahead recipient validation.
 *
 * @return
 *	ROUTE_OK	call-ahead reports valid recipient
 *	ROUTE_BAD	call-ahead reports invalid recipient
 *	ROUTE_QUEUE	skip call-ahead and send to queue
 *	ROUTE_FORWARD	skip call-ahead and just forward
 *	ROUTE_NO_ROUTE	relaying denied, not our domain
 */
int
routeRcpt(Session *sess, ParsePath *rcpt)
{
	int rc, ret;
	const char *next;
	char *value, *host;

	rc = ROUTE_FORWARD;

	/* Is this recipient destined for the local queue? */
	if (CLIENT_ANY_SET(sess, CLIENT_IS_RELAY|CLIENT_HAS_AUTH) || rcpt->domain.length == 0) {
		rc = ROUTE_QUEUE;
		goto error0;
	}

	/* Do we route for this domain? */
	if (smdbAccessMail(sess->route_map, ROUTE_TAG, rcpt->address.string, NULL, &value) == SMDB_ACCESS_NOT_FOUND) {
		rc = ROUTE_NO_ROUTE;
		goto error0;
	}

	/* Find start of RCPT host list. */
	if ((host = strstr(value, ROUTE_ATTR_RCPT)) == NULL) {
		rc = ROUTE_FORWARD;
		goto error1;
	}

	/*** TODO check if RCPT: list is equivalent to FORWARD: list
	 *** and if so then skip the call-ahead as it is pointless
	 *** to call-ahead to the same host we forward to.
	 ***/

	/* Check for a previously cached result. Only definitive accept
	 * or reject result is cached; never temporary failure since
	 * that state might change before the cache entry expires.
	 */
	switch (ret = routeCacheGetRcpt(sess, rcpt->address.string)) {
	case SMTPF_REJECT:
		rc = ROUTE_BAD;
		goto error1;

	case SMTPF_ACCEPT:
		rc = ROUTE_OK;
		goto error1;
	}

	/* Check each RCPT host in turn. */
	for (next = host + sizeof (ROUTE_ATTR_RCPT)-1; (host = routeGetNextMember(next, &next)) != NULL; free(host)) {
		if ((ret = routeCallAhead(sess, host, rcpt)) == SMTPF_ACCEPT) {
			rc = ROUTE_OK;
			break;
		}

		/* Try the next host for a reject or temp. fail to so
		 * if another machine will acknowledge the recipient.
		 */
	}
	free(host);

	/* Cache only definitive results: accept or reject. */
	switch (ret) {
	case SMTPF_REJECT:
		rc = ROUTE_BAD;
		/*@fallthrough@*/
	case SMTPF_ACCEPT:
		routeCacheAddRcpt(sess, rcpt->address.string, ret);
		break;
	default:
		/* Temporary failure or other inconclusive state,
		 * accept the recipient and let the next hop deal
		 * with it. Similar to backup-mx support.
		 */
		rc = ROUTE_FORWARD;
		break;
	}
error1:
	free(value);
error0:
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(559) "routeRcpt(%lx, %s) rc=%d", LOG_ARGS(sess), (long) sess, rcpt->address.string, rc);
	return rc;
}

/*
 * Lookup the recipient's domain for a FORWARD list as to where this
 * message should go.
 *
 * @return
 *	ROUTE_OK	forward route established
 *	ROUTE_QUEUE	send to queue
 *	ROUTE_FORWARD	forward exists, but failed to connect
 *	ROUTE_NO_ROUTE	relaying denied
 */
int
routeForward(Session *sess, ParsePath *rcpt, Connection *fwd)
{
	long length;
	Vector fwd_list;
	int rc, i, ordered;
	char *value, *host;

	rc = ROUTE_NO_ROUTE;

	if (CLIENT_ANY_SET(sess, CLIENT_IS_RELAY|CLIENT_HAS_AUTH) || rcpt->domain.length == 0) {
		rc = ROUTE_QUEUE;
		goto error0;
	}

	if ((fwd_list = VectorCreate(10)) == NULL) {
		rc = ROUTE_FORWARD;
		goto error0;
	}

	VectorSetDestroyEntry(fwd_list, FreeStub);

	if (smdbAccessMail(sess->route_map, ROUTE_TAG, rcpt->address.string, NULL, &value) == SMDB_ACCESS_NOT_FOUND) {
		rc = ROUTE_NO_ROUTE;
		goto error1;
	}

	/* Find start of FORWARD host list. */
	if ((host = strstr(value, ROUTE_ATTR_FORWARD)) == NULL) {
		rc = ROUTE_NO_ROUTE;
		goto error2;
	}

	/* Split the list into host strings. */
	for (host += sizeof (ROUTE_ATTR_FORWARD)-1; *host != '\0'; ) {
		host += strspn(host, " \t,;");
		if (*host == ';' || *host == '\0')
			break;

		/* Save the pointer to the host string. */
		(void) VectorAdd(fwd_list, host);

		/* Find end of host string and null terminate. */
		host += strcspn(host, " \t,;");
		i = *host;
		*host = '\0';

		if (isspace(i) || i == ',')
			host++;
	}

	/* Check for an empty list. */
	if (VectorLength(fwd_list) == 0) {
		rc = ROUTE_NO_ROUTE;
		goto error2;
	}

	/* We forward mail for this recipient. */
	rc = ROUTE_FORWARD;
	ordered = (tolower(*optRouteForwardSelection.string) == 'o');

	for (i = 0, length = VectorLength(fwd_list); 0 < length; length--, i++) {
		/* Pick the next host string to try at random. */
		if (!ordered)
			i = RANDOM_NUMBER(length);
		if ((host = VectorGet(fwd_list, i)) == NULL)
			continue;
		if (!ordered)
			VectorRemove(fwd_list, i);

		if (verb_smtp.option.value)
			syslog(LOG_DEBUG, LOG_MSG(560) "rcpt=%s connecting forward=%s index=%d ...", LOG_ARGS(sess), rcpt->address.string, host, i);

		if ((fwd->mx = mxConnect(sess, host, IS_IP_RESERVED)) != NULL) {
			/* Get welcome message from forward host. */
			if (mxCommand(sess, fwd, NULL, 220)) {
				connectionClose(fwd);
				continue;
			}

			if (verb_smtp.option.value)
				syslog(LOG_DEBUG, LOG_MSG(561) "rcpt=%s forward=%s ready", LOG_ARGS(sess), rcpt->address.string, host);
			fwd->mx_host = strdup(host);
			rc = ROUTE_OK;
			break;
		}
	}
error2:
	free(value);
error1:
	VectorDestroy(fwd_list);
error0:
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(562) "routeForward(%lx, %s, %lx) rc=%d", LOG_ARGS(sess), (long) sess, rcpt->address.string, (long) fwd, rc);
	return rc;
}

Connection *
routeKnownAuth(Session *sess, const char *auth, int *can_queue)
{
	char *host;
	Socket2 *mx;
	Connection *fwd;
	const char *next;

	*can_queue = 0;

	if (verb_auth.option.value)
		syslog(LOG_DEBUG, LOG_MSG(563) "enter routeKnownAuth(%lx, %s, %lx)", LOG_ARGS(sess), (long) sess, auth, (long) can_queue);

	if ((fwd = connectionAlloc()) == NULL)
		goto error0;

	if (smdbAccessMail(sess->route_map, ROUTE_TAG, auth, &fwd->route.key, &fwd->route.value) == SMDB_ACCESS_NOT_FOUND) {
	 	host = (char *) &auth[strcspn(auth, "@")];
	 	if (*host == '@')
	 		host++;

		if (!routeLocal(sess, host, &fwd->route.key, &fwd->route.value))
			goto error1;

		/* We have a local route at this point. Flag this as a
		 * connection we can keep open for the whole SMTP session.
		 * The local route is used for queuing and if we are going
		 * to open it for authentication, then  we want to keep it
		 * open to avoid the overhead of closing and reopening the
		 * connection later.
		 */
		*can_queue = 1;
	}

	/* Find start of RCPT or FORWARD host lists. The RCPT: list takes
	 * priority since its assumed to point to a more authorative source,
	 * such as the local mail store, while FORWARD: will point to the
	 * next hop, which could be something like an intermediate appliance
	 * machine with no local knowledge.
	 */
	if ((host = strstr(fwd->route.value, ROUTE_ATTR_RCPT)) != NULL) {
		host += sizeof (ROUTE_ATTR_RCPT)-1;

		/* A RCPT: list is only ever used for doing recipient
		 * call-ahead or authenticating a sender. It should not
		 * be used for forwarding since this will jump over any
		 * intermediate filters specified by FORWARD:
		 */
		*can_queue = 0;
	} else if ((host = strstr(fwd->route.value, ROUTE_ATTR_FORWARD)) != NULL) {
		host += sizeof (ROUTE_ATTR_FORWARD)-1;
	} else {
		goto error1;
	}

	for (next = host; (host = routeGetNextMember(next, &next)) != NULL; free(host)) {
		if (!socketOpenClient(host, SMTP_PORT, optSmtpConnectTimeout.value, NULL, &mx)) {
			fwd->mx = mx;
			connectionOptions(fwd);

			/* Get welcome message from forward host. */
			if (mxCommand(sess, fwd, NULL, 220)) {
				connectionClose(fwd);
				continue;
			}

			if (verb_smtp.option.value)
				syslog(LOG_DEBUG, LOG_MSG(564) "auth=%s forward=%s ready", LOG_ARGS(sess), auth, host);
			fwd->mx_host = host;
			return fwd;
		}
	}

	free(host);
error1:
	connectionFree(fwd);
error0:
	if (verb_auth.option.value)
		syslog(LOG_DEBUG, LOG_MSG(565) "exit routeKnownAuth(%lx, %s, %lx) fwd=%lx", LOG_ARGS(sess), (long) sess, auth, (long) can_queue, (long) fwd);

	return NULL;
}

/*
 * @return
 *	Return true if a forward connection was created.
 */
int
routeQueue(Session *sess, ParsePath *rcpt, Connection *fwd)
{
	const char *next;
	char *value, *host;

	/* Allow only designated clients or authenticated connections to
	 * relay through us to the MTA. Typically an MTA is configured to
	 * always relay connections from 127.0.0.1, so we cannot rely on
	 * the MTA to tell us "relaying denied".
	 *
	 * Also unqualified recipients, ie. no @domain given, are sent to
	 * the "smart host" queue.
	 */
	if (CLIENT_NOT_SET(sess, CLIENT_IS_RELAY|CLIENT_HAS_AUTH) && rcpt != NULL && 0 < rcpt->domain.length)
		goto error0;

	/* Find route to a "smart host" that can handle our queuing. */
	if (smdbAccessIp(sess->route_map, ROUTE_TAG, "127.0.0.1", NULL, &value) == SMDB_ACCESS_NOT_FOUND)
		value = smdbGetValue(sess->route_map, ROUTE_TAG "::1");

	if (value == NULL) {
		syslog(LOG_ERR, LOG_MSG(566) "localhost route required", LOG_ARGS(sess));
/*{NEXT}*/
		goto error0;
	}

	/* Make sure the FOWARD: list is defined. */
	if ((host = strstr(value, ROUTE_ATTR_FORWARD)) == NULL) {
		syslog(LOG_ERR, LOG_MSG(567) "localhost route requires FORWARD definition", LOG_ARGS(sess));
/*{LOG
The <a href="route-map.html#route_local_route_queue">local route</a> is not defined
and is required for correct operation.
See <a href="route-map.html">route-map</a> documentation.
}*/
		goto error1;
	}

	/* When the mail is coming from one of our smart hosts then we
	 * would like to relay outbound, not forward inbound, otherwise
	 * we end up in a loop.
	 *
	 * The localhost is a relay by definition and typically the
	 * FORWARD route is to an MTA on localhost listening on another
	 * port. So we have to account for a local MUA connecting to us
	 * to send mail and we want to be sure to queue it. If the MTA
	 * connects back to us then we can end up in a _nasty_ mail loop.
	 */
	if (CLIENT_NOT_SET(sess, CLIENT_IS_LOCALHOST)
	&& routeIsMember(value, ROUTE_ATTR_FORWARD, sess->client.name, sess->client.addr)) {
		syslog(LOG_ERR, LOG_MSG(568) "mail loop from " CLIENT_FORMAT " in localhost route", LOG_ARGS(sess), CLIENT_INFO(sess));
/*{LOG
When the mail is coming from one of our smart hosts then we
would like to relay outbound, not forward inbound, otherwise
we end up in a loop.
}*/
		goto error1;
	}

	for (next = host + sizeof (ROUTE_ATTR_FORWARD)-1; (host = routeGetNextMember(next, &next)) != NULL; free(host)) {
		if (!socketOpenClient(host, SMTP_PORT, optSmtpConnectTimeout.value, NULL, &fwd->mx)) {
			connectionOptions(fwd);

			/* Get welcome message from forward host. */
			if (mxCommand(sess, fwd, NULL, 220)) {
				connectionClose(fwd);
				continue;
			}

			if (verb_smtp.option.value && rcpt != NULL)
				syslog(LOG_DEBUG, LOG_MSG(569) "rcpt=%s forward=%s ready", LOG_ARGS(sess), rcpt->address.string, host);
			fwd->mx_host = host;
			host = NULL;
			break;
		}
	}

	free(host);
error1:
	free(value);
error0:
	return connectionIsOpen(fwd);
}

static Connection *
routeFind(Session *sess, const char *key, const char *value)
{
	Connection *fwd = NULL;

	/* Queue all mail during this session on the server that
	 * handled our authentication.
	 */
	if (sess->client.fwd_to_queue != NULL)
		return sess->client.fwd_to_queue;

	/* Queue only this mail transaction? */
	if (sess->msg.fwd_to_queue != NULL)
		return sess->msg.fwd_to_queue;

	/* Do we already have a connection for this route? */
	if (key != NULL) {
		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			if (TextInsensitiveCompare(fwd->route.key+sizeof (ROUTE_TAG)-1, key+sizeof (ROUTE_TAG)-1) == 0)
				break;
		}
	}

	if (fwd == NULL) {
		/* Do we already have a connection for one of the forward hosts? */
		for (fwd = sess->msg.fwds; fwd != NULL; fwd = fwd->next) {
			if (routeIsMember(value, ROUTE_ATTR_FORWARD, fwd->mx_host, fwd->mx_ip))
				break;
		}
	}

	return fwd;
}

/*
 * Lookup the recipient's domain for a FORWARD list as to where this
 * message should go.
 *
 * @return
 *	ROUTE_OK	forward route found
 *	ROUTE_BAD	check errno
 *	ROUTE_FORWARD	forward exists, but not connected
 *	ROUTE_NO_ROUTE	relaying denied
 */
int
routeAdd(Session *sess, ParsePath *rcpt, Connection **out)
{
	Connection *fwd;
	char *key, *value;

	if (smdbAccessMail(sess->route_map, ROUTE_TAG, rcpt->address.string, &key, &value) == SMDB_ACCESS_NOT_FOUND) {
		if (CLIENT_NOT_SET(sess, CLIENT_IS_RELAY|CLIENT_HAS_AUTH) && 0 < rcpt->domain.length)
			return ROUTE_NO_ROUTE;

		if (optSmtpStrictRelay.value
		&& CLIENT_ANY_SET(sess, CLIENT_IS_RELAY)
		&& sess->msg.mail != NULL && 0 < sess->msg.mail->address.length
		&& !routeKnownDomain(sess, sess->msg.mail->domain.string)) {
			syslog(
				LOG_INFO, LOG_MSG(570) "smtp-strict-relay client " CLIENT_FORMAT " sender <%s> denied",
				LOG_ARGS(sess), CLIENT_INFO(sess), sess->msg.mail->address.string
			);
/*{LOG
See <a href="summary.html#opt_smtp_strict_relay">smtp-strict-relay</a> options.
}*/
			return ROUTE_NO_ROUTE;
		}

		/* Allow only designated clients or authenticated connections to
		 * relay through us to the MTA. Typically an MTA is configured to
		 * always relay connections from 127.0.0.1, so we cannot rely on
		 * the MTA to tell us "relaying denied".
		 *
		 * Also unqualified recipients, ie. no @domain given, are sent to
		 * the "smart host" queue.
		 */
		if (smdbAccessIp(sess->route_map, ROUTE_TAG, "127.0.0.1", &key, &value) == SMDB_ACCESS_NOT_FOUND) {
			value = smdbGetValue(sess->route_map, ROUTE_TAG "::1");
			if (value != NULL)
				key = strdup(ROUTE_TAG "::1");
		}
	}

	if ((*out = routeFind(sess, key, value)) != NULL) {
		free(key);
		free(value);
		return connectionIsOpen(*out) ? ROUTE_OK : ROUTE_FORWARD;
	}

	if ((fwd = connectionAlloc()) == NULL) {
		free(key);
		free(value);
		return ROUTE_BAD;
	}

	fwd->route.value = value;
	fwd->route.key = key;

	fwd->next = sess->msg.fwds;
	sess->msg.fwds = fwd;
	*out = fwd;

	return ROUTE_OK;
}

int
routeAddRcpt(Connection *fwd, ParsePath *rcpt)
{
	Rcpt *r;

	if ((r = rcptListAdd(&fwd->rcpts, rcpt)) != NULL) {
		fwd->rcpt_count++;
		return 0;
	}

	return -1;
}

smdb *
routeGetMap(Session *sess)
{
	return sess->route_map;
}

/***********************************************************************
 ***
 ***********************************************************************/

int
routeInit(Session *null, va_list ignore)
{
	size_t length;

#ifdef ENABLE_CACHE_UPDATE_MUTEX
	(void) pthread_mutex_init(&route_mutex, NULL);
# if defined(FILTER_CLI) && defined(HAVE_PTHREAD_ATFORK)
	if (pthread_atfork(routeAtForkPrepare, routeAtForkParent, routeAtForkChild)) {
		syslog(LOG_ERR, log_init, FILE_LINENO, "", strerror(errno), errno);
		exit(1);
	}
# endif
#endif
	smdbSetDebug(verb_db.option.value);

	if (*optRouteMap.string == '\0') {
		/* We cannot operate without the route-map. */
		syslog(LOG_ERR, log_init, FILE_LINENO, "route-map undefined", strerror(EINVAL), EINVAL);
		exit(1);
	}

	length = sizeof ("route" KVM_DELIM_S) + strlen(optRouteMap.string);

	if ((route_map_path = malloc(length)) == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}

	(void) snprintf(route_map_path, length, "route" KVM_DELIM_S "%s", optRouteMap.string);

	return SMTPF_CONTINUE;
}

int
routeFini(Session *null, va_list ignore)
{
	free(route_map_path);
	return SMTPF_CONTINUE;
}

int
routeMapOpen(Session *sess)
{
	sess->route_map = smdbOpen(route_map_path, 1);
	return -(sess->route_map == NULL);
}

void
routeMapClose(Session *sess)
{
	smdbClose(sess->route_map);
}
