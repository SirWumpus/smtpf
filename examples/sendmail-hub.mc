divert(-1)
#
# Copyright (c) 1998 Sendmail, Inc.  All rights reserved.
# Copyright (c) 1983 Eric P. Allman.  All rights reserved.
# Copyright (c) 1988, 1993
# The Regents of the University of California.  All rights reserved.
#
# By using this file, you agree to the terms and conditions set
# forth in the LICENSE file which can be found at the top level of
# the sendmail distribution.
#

divert(0)dnl
OSTYPE(openbsd)dnl

dnl
dnl Outgoing mail from a workstation will appear to be from this mail hub.
dnl

MASQUERADE_AS(`snert.example')dnl
FEATURE(local_no_masquerade)dnl
FEATURE(`masquerade_envelope')dnl
FEATURE(always_add_domain)dnl

dnl define(`confAUTH_OPTIONS',      `A p y')
dnl define(`confAUTH_MECHANISMS',   `PLAIN LOGIN')
dnl TRUST_AUTH_MECH(`PLAIN LOGIN')    
dnl FEATURE(`authinfo', `hash /etc/mail/authinfo')dnl

dnl define(`CERT_DIR',              `/etc/openssl')
dnl define(`confCACERT_PATH',       `CERT_DIR')
dnl define(`confCACERT',            `CERT_DIR/cert.pem')
dnl define(`confSERVER_CERT',       `CERT_DIR/certs/host.snert.example.crt')
dnl define(`confSERVER_KEY',        `CERT_DIR/private/host.snert.example.key')
dnl define(`confCLIENT_CERT',       `CERT_DIR/certs/host.snert.example.crt')
dnl define(`confCLIENT_KEY',        `CERT_DIR/private/host.snert.example.key')

dnl
dnl Disable the Mail Submission Agent (MSA) and just use the
dnl historical setup using the Mail Transfer Agent (MTA) on
dnl port 25.
dnl

FEATURE(`no_default_msa')dnl

dnl
dnl A web server only need to listen for local mail connections
dnl in order to process sending of forms and web-based mail.
dnl A web server never needs to receive mail.
dnl

DAEMON_OPTIONS(`Family=inet, Name=mta, Port=smtp, Address=127.0.0.1')dnl
dnl DAEMON_OPTIONS(`Family=inet, Name=msp, Port=submission, Addr=127.0.0.1')dnl    

dnl Choice 1.
dnl
dnl Enable this line to forward all local mail to a central hub.
dnl Sets $H macro.  See Bat Book 3e section 4.5.7.
dnl 

dnl define(MAIL_HUB, `relay:hub.snert.example.')dnl

dnl Choice 2.
dnl
dnl Enable this line to forward mail via a gateway.
dnl Sets $S macro. See Bat Book 3e section 4.3.3.6.
dnl

define(`SMART_HOST', `relay:gw.snert.example.')dnl

dnl Have the smart host relay mailer connect on a different port.
dnl

dnl define(`RELAY_MAILER_ARGS', `TCP $h 587')dnl
dnl define(`ESMTP_MAILER_ARGS', `TCP $h 587')dnl

dnl If you relay via the Mail Submission port 587, you'll need a host 
dnl certificate and an account credentials on the smart host. Enable    
dnl this to separate AuthInfo records into a more secure file than
dnl access.db. See Bat Book 3e section 10.9.3.2.
dnl 

dnl FEATURE(`authinfo')dnl

dnl Choice 3.
dnl
dnl Enable this line to forward all mail to a central hub or gateway.
dnl Be sure to disable/remove MAILER(`smtp') and MAILER(`local') lines.
dnl Sets both $H and $S macros. See Bat Book 3e section 4.8.33.
dnl

dnl FEATURE(`nullclient', `mx.snert.example')dnl

dnl Choice 4.
dnl
dnl Intended for testing. Using nullclient or msp preferred for mail
dnl delivery. See Bat Book 3e section 24.9.22.
dnl

dnl define(`confCONNECT_ONLY_TO', `192.0.2.1')

dnl
dnl For an internal central hub/gateway you want to specify your
dnl network that you are willing to relay mail for. Doing this 
dnl here removes the need for FEATURE(`access') and an access.db
dnl entry.
dnl

RELAY_DOMAIN(`127.0.0.1')dnl
RELAY_DOMAIN(`192.168')dnl
RELAY_DOMAIN(`10')dnl

LOCAL_DOMAIN(`host.snert.example')dnl
LOCAL_USER(`root')dnl

dnl
dnl Disable these mailers for FEATURE(`nullclient').
dnl

MAILER(smtp)dnl
MAILER(local)dnl

dnl Choice 5.
dnl 
dnl Similar to using SMART_HOST and FEATURE(`mailertable'), but as
dnl a set of specific rules. See Bat Book 3e section 4.3.3.7 and
dnl 4.8.24.
dnl

dnl LOCAL_NET_CONFIG
dnl R $* <@ $+.> $*		$#relay $@ some.host.example $: $1 <@ $2 > $3

