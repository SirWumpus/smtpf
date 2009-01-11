#ifdef OFF
/*** TODO look into defining separate state flags vs. local policy flags
 *** such as session tests vs access-map, route-map defintions .
 ***/

/*
 * What we know or have found out about the client session.
 */
#define CLIENT_IS_LAN			0x00000001	/* RFC 3330 private IP address. */
#define CLIENT_IS_RELAY			0x00000002	/* Route map RELAY host. */
#define CLIENT_IS_LOCALHOST		0x00000004	/* 127.0.0.0/8 or ::1 */
#define CLIENT_IS_MX			0x00000008
#define CLIENT_IS_2ND_MX		0x00000010	/* Client is our secondary MX. */
#define CLIENT_IS_IPV6			0x00000020	/* IPv6 socket family */
#define CLIENT_NO_PTR			0x00000040	/* Has no PTR record. */
#define CLIENT_NO_PTR_ERROR		0x00000080	/* Has no PTR record due to an error. */
#define CLIENT_IS_PTR_MULTIDOMAIN	0x00000100	/* True if the PTR is multihomed for multiple domains. */
#define CLIENT_IS_IP_IN_PTR		0x00000200
#define CLIENT_IS_FORGED		0x00000400	/* IP -> PTR name != A name -> IP */
#define CLIENT_IS_HELO_IP		0x00000800	/* HELO is an IP address string */
#define CLIENT_IS_HELO_HOSTNAME		0x00001000	/* HELO has A / AAAA record matching client IP. */
#define CLIENT_IS_EHLO_NO_HELO		0x00002000	/* Has sent EHLO and no HELO. */
#define CLIENT_IS_SCHIZO		0x00004000	/* Different HELO/EHLO arguments used. */
#define CLIENT_PIPELINING		0x00008000	/* Client sent next command before end of reply. */
#define CLIENT_PIPELINING_OK		0x00010000	/* Client allowed to pipeline. */
#define CLIENT_IO_ERROR			0x00020000
#define CLIENT_RATE_LIMIT		0x00040000
#define CLIENT_CONCURRENCY_LIMIT	0x00080000
#define CLIENT_NO_CRLF			0x00100000	/* SMTP command was not terminated by CRLF. */
#define CLIENT_HAS_QUIT			0x00200000

/*
 * Access map, DNS black/grey/white, SMTP AUTH.
 */
#define CLIENT_ACL_BLACK		0x00000001	/* Black listed, reject earliest possible. */
#define CLIENT_ACL_GREY			0x00000002	/* Grey listed, by-pass pre-DATA tests only. */
#define CLIENT_ACL_SAVE			0x00000004	/* Save message to save-dir if content sent. */
#define CLIENT_ACL_TAG			0x00000008	/* TAG subject if any policy test fails. */
#define CLIENT_ACL_WHITE		0x00000010	/* White listed, by-pass remaining tests. */
#define CLIENT_ACL_DISCARD		0x00000020	/* Accept and discard the message. */
#define CLIENT_ACL_TEMPFAIL		0x00000040
#define CLIENT_ACL_GREY_EXEMPT		0x00000080	/* Client exempt from grey-listing. */
#define CLIENT_ACL_PASSED_GREY		0x00000100	/* Client has previously passed grey-listing. */
#define CLIENT_ACL_AUTH			0x00000200	/* Has sucessfully authenticated. */

#define CLIENT_ACL_SET(s, m)		FLAG_SET((s)->client.acl_flags, m)
#define CLIENT_ACL_CLEAR(s, m)		FLAG_CLEAR((s)->client.acl_flags, m)
#define CLIENT_ACL_CLEAR_ALL(s)		FLAG_CLEAR_ALL((s)->client.acl_flags)
#define CLIENT_ACL_IS_SET(s, m, n)	FLAG_IS_SET((s)->client.acl_flags, m, n)
#define CLIENT_ACL_NOT_SET(s, m)	FLAG_NOT_SET((s)->client.acl_flags, m)
#define CLIENT_ACL_ANY_SET(s, m)	FLAG_ANY_SET((s)->client.acl_flags, m)
#define CLIENT_ACL_ALL_SET(s, m)	CLIENT_ACL_IS_SET(s, m, m)
#endif

