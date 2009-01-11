/*
 * nxdomain.c
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#include <ctype.h>
#include <limits.h>
#include <com/snert/lib/io/Dns.h>
#include <com/snert/lib/net/network.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/util/Text.h>


/***********************************************************************
 ***
 ***********************************************************************/

/*
 * @param sess
 *	A session pointer.
 *
 * @param host
 *	A pointer to a C string containing a host / domain name.
 *
 * @return
 *	SMTPF_REJECT if the host and none of its parent domains
 *	upto, but not including, the TLD have an SOA. SMTPF_TEMPFAIL
 *	if there was a DNS lookup error. Otherwise SMTPF_CONTINUE if
 *	the host name or any of its parent domains have an SOA before
 *	the TLD is reached.
 *
 *	Consider:
 *
 *	puff# dig +short ns vocus.com
 *	name.phx.gblx.net.
 *	name.roc.gblx.net.
 *	name.snv.gblx.net.
 *	name.jfk.gblx.net.
 *	name.lon.gblx.net.
 *
 *	puff# dig +short soa vocus.com
 *	gblx.net. dns.gblx.net. 22048 7200 1800 604800 3600
 *
 *	puff# dig +short @gblx.net ns vocus.com
 *	dig: couldn't get address for 'gblx.net': not found
 *
 *	puff# dig +short @gblx.net a gblx.net.
 *	dig: couldn't get address for 'gblx.net': not found
 *
 * ***	[SF] Apperently this is allowed though really weird.
 * ***	From dnsstuff.com
 *
 *	WARN	SOA MNAME Check	WARNING: Your SOA (Start of Authority)
 *	record states that your master (primary) name server is: gblx.net..
 *	However, that server is not listed at the parent servers as one
 *	of your NS records! This is legal, but you should be sure that
 *	you know what you are doing.
 */
int
isNxDomain(const char *host)
{
	int i, length, offset;
	Vector answers;
	DnsEntry *entry;
	const char *error, *domain, *tld;

	/* Find start of TLD. */
	offset = indexValidTLD(host);

	/* Is it an unknown TLD domain or a TLD without a second level? */
	if (offset <= 0) {
		printf("\tdomain %s does not exist\n", TextNull(host));
		return 5;
	}

	domain = host;
	tld = &host[offset];
	do {
		printf("\tlookup %s\n", domain);

		switch (DnsGet2(DNS_TYPE_SOA, 0, domain, &answers, &error)) {
		case DNS_RCODE_UNDEFINED:
			printf("\tdomain %s does not exist\n", domain);
			return 5;

		case DNS_RCODE_OK:
			length = VectorLength(answers);
			for (i = 0; i < length; i++) {
				if ((entry = VectorGet(answers, i)) == NULL)
					continue;

				if (entry->type == DNS_TYPE_SOA) {
					printf("\t%s SOA %s\n", entry->name, ((DnsSOA *) entry->value)->mname);
					break;
				}
			}
			VectorDestroy(answers);
			if (length == 0)
				break;
			return 0;

		default:
			printf("\tSOA for %s lookup error: %s\n", domain, error);
			return 4;
		}

		if ((domain = strchr(domain, '.')) == NULL)
			break;

		domain++;
	} while (domain < tld);

	printf("\tSOA for %s does not exist\n", host);

	return 5;
}

#include <stdio.h>

void
isNsNxDomain(const char *domain)
{
	int i;
	Vector answers;
	DnsEntry *entry;

	if (DnsGet2(DNS_TYPE_NS, 1, domain, &answers, NULL) == DNS_RCODE_OK) {
		for (i = 0; i < VectorLength(answers); i++) {
			if ((entry = VectorGet(answers, i)) == NULL)
				continue;

			if (entry->type == DNS_TYPE_CNAME) {
				(void) printf("%s CNAME %s\n", domain, (char *) entry->value);
			}

			else if (entry->type == DNS_TYPE_NS) {
				(void) printf("%s NS %s\n", domain, (char *) entry->value);

				if (entry->address != NULL && isIPv4InClientName(entry->value, entry->address+IPV6_OFFSET_IPV4)) {
					 (void) printf("\tcontains IP %s in name\n", entry->address_string);
				}

				(void) isNxDomain(entry->value);
			}
		}

		VectorDestroy(answers);
	}
}

char buffer[512];

int
main(int argc, char **argv)
{
	int argi;

	if (1 < argc) {
		for (argi = 1; argi < argc; argi++)
			isNsNxDomain(argv[argi]);
	} else {
		while (fgets(buffer, sizeof (buffer), stdin) != NULL)
			isNsNxDomain(buffer);
	}

	return 0;
}

