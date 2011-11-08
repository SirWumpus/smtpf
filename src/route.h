/*
 * route.h
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __route_h__
#define __route_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

typedef enum {
	ROUTE_OK,
	ROUTE_BAD,
	ROUTE_QUEUE,
	ROUTE_FORWARD,
	ROUTE_NO_ROUTE
} RouteCode;

#define ROUTE_TAG			"route:"
#define ROUTE_ATTR_FORWARD		"FORWARD:"
#define ROUTE_ATTR_RCPT			"RCPT:"
#define ROUTE_ATTR_RELAY		"RELAY"
#define ROUTE_LOCAL			ROUTE_TAG "local"

typedef struct {
	unsigned long domains;		/* route:some.domain.tld */
	unsigned long accounts;		/* route:account@ */
	unsigned long addresses;	/* route:account@some.domain.tld */
	unsigned long unique_domains;
	Vector domain_list;		/* maintained during counting, NULL once computed. */
} RouteCount;

extern int routeGetRouteCount(RouteCount *rcp);
extern smdb *routeGetMap(Session *sess);
extern char *routeGetLocalRoute(void);
extern Vector routeGetLocalHosts(void);
extern int routeMapOpen(Session *);
extern void routeMapClose(Session *);

extern Option optRouteMap;
extern Option optRouteForwardSelection;
extern Option optCallAheadAsSender;
extern Option optCallAheadCommandTimeout;

extern int routeRegister(Session *null, va_list ignore);
extern int routeInit(Session *null, va_list ignore);
extern int routeFini(Session *null, va_list ignore);
extern int routeConnect(Session *sess, va_list ignore);
extern int routeClose(Session *sess, va_list ignore);

extern Connection *connectionAlloc(void);
extern void connectionFree(Connection *conn);
extern void connectionClose(Connection *conn);
extern int connectionIsOpen(Connection *conn);
extern void connectionOptions(Connection *conn);

extern int routeKnownClientAddr(Session *);
extern int routeKnownClientName(Session *);
extern Connection *routeKnownAuth(Session *sess, const char *auth, int *can_queue);
extern int routeKnownDomain(Session *sess, const char *domain);
extern int routeExpire(kvm_data *key, kvm_data *value, void *data);
extern int routeCheckRcpt(Session *sess, ParsePath *rcpt);
extern RouteCode routeRcpt(Session *sess, ParsePath *rcpt);
extern int routeQueue(Session *sess, ParsePath *rcpt, Connection *fwd);
extern RouteCode routeForward(Session *sess, ParsePath *rcpt, Connection *fwd);
extern int routeAdd(Session *sess, ParsePath *rcpt, Connection **out);
extern int routeAddRcpt(Connection *fwd, ParsePath *rcpt);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __route_h__ */
