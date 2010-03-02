/*
 * options.c
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

#include <ctype.h>
#include <com/snert/lib/mail/tlds.h>

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_intro[] =
  "\n"
"# " _NAME " " _VERSION_STRING ", " LIBSNERT_STRING "\n"
"# \n"
"# " _COPYRIGHT "\n"
;

static const char usage_syntax[] =
  "Option Syntax\n"
"# \n"
"# Options can be expressed in four different ways. Boolean options\n"
"# are expressed as +option or -option to turn the option on or off\n"
"# respectively. Numeric, string, and list options are expressed as\n"
"# option=value to set the option or option+=value to append to a\n"
"# list. Note that the +option and -option syntax are equivalent to\n"
"# option=1 and option=0 respectively. String values containing white\n"
"# space must be quoted using single (') or double quotes (\"). Option\n"
"# names are case insensitive.\n"
"# \n"
"# Some options, like +help or -help, are treated as immediate\n"
"# actions or commands. Unknown options are ignored and not reported.\n"
"# The first command-line argument is that which does not adhere to\n"
"# the above option syntax. The special command-line argument -- can\n"
"# be used to explicitly signal an end to the list of options.\n"
"# \n"
"# The default options, as shown below, can be altered by specifying\n"
"# them on the command-line or within an option file, which simply\n"
"# contains command-line options one or more per line and/or on\n"
"# multiple lines. Comments are allowed and are denoted by a line\n"
"# starting with a hash (#) character. If the file option is defined\n"
"# and not empty, then it is parsed first, followed by the command\n"
"# line options.\n"
;

static const char usage_option_names[] =
  "Option Names\n"
"# \n"
"# Options that begin with a leading underscore (_) are considered\n"
"# experimental, are undocumented, and may change or be removed in\n"
"# future builds. Use at your own risk.\n"
;

static const char usage_help[] =
  "Write the option summary to standard output and exit. The output\n"
"# is suitable for use as an option file. For Windows this option\n"
"# can be assigned a file path string to save the output to a file,\n"
"# eg. help=./" _NAME ".cf.txt\n"
"#"
;

static const char usage_info[] =
  "Write the configuration and compile time options to standard output\n"
"# and exit.\n"
"#"
;

#define USAGE_INTERFACE_IP						\
  "The IP address and optional port to listen on. When undefined,\n"	\
"# then the IP address will be determined at start-up. If the port\n"	\
"# is not specified, then SMTP port 25 is assumed.\n"		\
"#"

#define USAGE_INTERFACE_NAME						\
  "One of the FQDN for this host. If empty, then the host name will\n"	\
"# be automatically determined at start-up. If interface-ip is \n"	\
"# undefined, then the name specified here or determined at start-up\n"	\
"# will select the IP address used.\n"					\
"#"

#define USAGE_RELAY_REPLY						\
  "Relay downstream MTA error responses during RCPT TO: processing to\n"\
"# connected clients. Enabling this option might disclose information\n"\
"# about internal network structure, present incomplete or out of\n"	\
"# context errors, have inconsistent message styles from multiple MTAs,\n"\
"# and generally appear more confusing than helpful to the connecting\n"\
"# client.\n"								\
"#"


#define USAGE_SMTP_DROP_AFTER						\
  "Drop the connection after N temporary and permanently rejected\n"	\
"# commands, ie. count any 4xy or 5xy responses and eventually drop.\n"	\
"# Zero to disable.\n"							\
"#"

static const char usage_smtp_data_line_timeout[] =
  "SMTP data line timeout in seconds after DATA while collecting\n"
"# message content.\n"
"#"
;

static const char usage_smtp_dot_timeout[] =
  "Timeout in seconds to wait for a reply to the SMTP final dot sent\n"
"# to the forward hosts.\n"
"#"
;

static const char usage_test_lickey[] =
  "Test the license key file and exit. An exit code of zero (0) for\n"
"# a valid license key, 1 for an error not related to the license key,\n"
"# 2 for usage summary, 3 the license is invalid (details in the mail\n"
"# log).\n"
"#"
;

static const char usage_test_mode[] =
  "Used for testing. Run the server in single thread mode and accept\n"
"# client connections sequentionally ie. no concurrency possible.\n"
"#"
;

#define USAGE_TEST_ON_COMMAND						\
  "Used for testing. The specified action, one of temp-fail, reject,\n"	\
"# or drop, will be applied whenever the given SMTP command is seen\n"	\
"# eg \"temp-fail,data\". Specify an empty string to disable.\n"	\
"#"

static const char usage_auth_delay_checks[] =
  "Delay some client connection and HELO tests until MAIL FROM: to\n"
"# allow the sender to authenticate using the AUTH command.\n"
"#"
;

#define USAGE_WELCOME_BANNER_FILE					\
  "The file path to a text file containing one or more lines used\n"	\
"# for the SMTP welcome message banner. The 220 status code will be\n"	\
"# automatically prepended to each line. It is recommended that this\n"	\
"# message be two or more lines as this has been found to foil some\n"	\
"# spamware. If an empty string is given, a hard coded default will\n"	\
"# be used.\n"								\
"#"

static const char usage_smtp_reject_file[] =
  "The file path of a text file containing a site specific message\n"
"# that will be appended to all SMTP reject responses. This text\n"
"# should contain brief instructions for the sender about who to\n"
"# contact for help. The text can be more than one line. Specify\n"
"# the empty string to disable this message.\n"
"#"
;

static const char usage_smtp_dsn_reply_to[] =
  "When set this is the mail address of the site's postmaster or\n"
"# help desk used for the Reply-To header in DSN error messages.\n"
"# Specify the empty string to disable.\n"
"#"
;

static const char usage_rfc2606_special_domains[] =
  "When set, use of RFC 2606 reserved domains from the Internet or\n"
"# in mail addresses is rejected. They are the TLDs .test, .example,\n"
"# .invalid, .localhost, and the second level domain .example using\n"
"# any TLD. While not part of RFC 2606, .localdomain and .local are\n"
"# also included. Clients within the LAN and relays are excluded.\n"
"#"
;

static const char usage_smtp_enable_esmtp[] =
  "Enable enhanced SMTP (ESMTP) for all clients. When disabled any\n"
"# hosts marked as RELAY in the route-map or from RFC 3330 private\n"
"# IP addresses will be exempted and always allowed to use ESMTP\n"
"# regardless.\n"
"#"
;

static const char usage_smtp_drop_unknown[] =
  "Drop the connection if client sends an unknown command.\n"
"# To work around Cisco PIX firewalls broken fix-up protocol,\n"
"# this option ignores any command that starts with 'XXX'.\n"
"#"
;

static const char usage_smtp_server_queue[] =
  "SMTP server connection queue size. This setting is OS specific and\n"
"# tells the kernel how many unanswered connections on the socket it\n"
"# should allow.\n"
"#"
;

static const char usage_smtp_slow_reply[] =
  "Impose an throttling delay for all SMTP server replies. This option\n"
"# will most likely result in increased concurrency, which is normal.\n"
"#"
;

static const char usage_smtp_auth_enable[] =
  "When set enable SMTP AUTH support when EHLO command is given.\n"
"#"
;

static const char usage_smtp_auth_white[] =
  "When set, successful SMTP authenticated sessions are white listed\n"
"# through content filters. Otherwise, content filtering is applied.\n"
"# Regardless of this setting, successful SMTP AUTH sessions are\n"
"# always allowed to relay.\n"
"#"
;

static const char usage_smtp_strict_relay[] =
  "Only allow outbound messages from our specified relays and where\n"
"# the sender is from one of our routed domains (see route-map).\n"
"#"
;

/*
 * First pass option table.
 */
Option optFile0			= { "file", 			CF_FILE, 	"" };
Option *optTable0[]		= {
	&optFile0,
	NULL
};

/*
 * Second pass option table.
 */
Option optFile			= { "file", 			CF_FILE, 	"Read option file before command line options." };
Option optLicenseKeyFile	= { "lickey-file", 		LICKEY_FILE, 	"License key file." };

Option optIntro			= { "\001A",			NULL,		usage_intro };
Option optSyntax		= { "\001B",			NULL,		usage_syntax };
Option optNames 		= { "\001C", 			NULL, 		usage_option_names };

Option optDaemon		= { "daemon",			"+",		"Start as a background daemon or foreground application." };
Option optHelp			= { "help", 			NULL,		usage_help };
Option optInfo			= { "info", 			NULL,		usage_info };

#ifdef ENABLE_LINT
static const char usage_lint[] =
  "Lint SMTP sessions and messages for as many issues as possible. A\n"
"# report of the results is sent to postmaster. This option requires\n"
"# a special license key.\n"
"#"
;

Option optLint			= { "lint",			"-",		usage_lint };
#endif

/* Keep these for lickey. */
Option optInterfaceIp		= { "interface-ip",		"0.0.0.0:" QUOTE(SMTP_PORT),	USAGE_INTERFACE_IP };
Option optInterfaceName 	= { "interface-name", 		"", 		USAGE_INTERFACE_NAME };

static const char usage_interfaces[] =
  "A semi-colon separared list of interface host names or IP addresses\n"
"# on which to bind and listen for new connections. They can be IPv4\n"
"# and/or IPv6.\n"
"#"
;
Option optInterfaces 		= { "interfaces", 		"[::0]:"QUOTE(SMTP_PORT)";0.0.0.0:"QUOTE(SMTP_PORT),		usage_interfaces };

Option optQuit			= { "quit", 			NULL,		"Quit an already running instance and exit." };

#ifdef ENABLE_SLOW_QUIT
static const char usage_slow_quit[] =
  "Quit an already running instance, waiting for all the connections to\n"
"# terminate, then exit.\n"
"#"
;
Option optSlowQuit		= { "slow-quit",		NULL,		usage_slow_quit };
#endif

Option optRestart		= { "restart", 			NULL,		"Terminate an already running instance before starting." };
Option optRestartIf		= { "restart-if", 		NULL,		"Only restart when there is a previous instance running." };
Option optRelayReply		= { "relay-reply",		"-",		USAGE_RELAY_REPLY };
Option optService		= { "service",			NULL,		"Remove or add Windows service." };
Option optVersion		= { "version",			NULL,		"Show version and copyright." };

Option optRunGroup		= { "run-group",		RUN_AS_GROUP,	"Run as this Unix group." };
Option optRunJailed		= { "run-jailed",		"-",		"Run in a chroot jail; run-work-dir used as the new root directory." };
Option optRunOpenFileLimit	= { "run-open-file-limit",	QUOTE(RUN_FILE_LIMIT),	"The maximum open file limit for the process." };
Option optRunPidFile 		= { "run-pid-file", 		PID_FILE,	"The file path of where to save the process-id." };
Option optRunUser		= { "run-user",			RUN_AS_USER,	"Run as this Unix user." };
Option optRunWorkDir 		= { "run-work-dir", 		WORK_DIR, 	"The working directory of the process." };
Option opt_run_save_core	= { "run-save-core",		"-",		"When true, the process can save core if necessary." };

Option optSmtpAuthEnable	= { "smtp-auth-enable",		"-",		usage_smtp_auth_enable };
Option optSmtpAuthWhite		= { "smtp-auth-white",		"-",		usage_smtp_auth_white };
Option optSmtpCommandTimeoutBlack	= { "smtp-command-timeout-black",	"30",		"SMTP command timeout in seconds for black-listed clients." };
Option optSmtpCommandTimeout	= { "smtp-command-timeout",	QUOTE(SMTP_COMMAND_TO),		"SMTP command timeout in seconds." };
Option optSmtpConnectTimeout	= { "smtp-connect-timeout",	"60",		"SMTP client connection timeout in seconds." };
Option optSmtpDataLineTimeout	= { "smtp-data-line-timeout",	QUOTE(SMTP_DATA_BLOCK_TO), usage_smtp_data_line_timeout };
Option optSmtpDotTimeout	= { "smtp-dot-timeout",		QUOTE(SMTP_DOT_TO), usage_smtp_dot_timeout };

static const char usage_smtp_keep_alive_timeout[] =
  "In some cases, the forwarding of the DATA command is delayed and so\n"
"# we have to keep the forward connection(s) alive until they pass into\n"
"# the DATA state. The timeout is specified in seconds; specify 0 to\n"
"# disable the timeout.\n"
"#"
;
Option optSmtpKeepAliveTimeout	= { "smtp-keep-alive-timeout",	"60",		usage_smtp_keep_alive_timeout };

Option optSmtpEnableEsmtp	= { "smtp-enable-esmtp",	"+",		usage_smtp_enable_esmtp };
Option optSmtpRejectFile	= { "smtp-reject-file",		"",		usage_smtp_reject_file };
Option optSmtpServerQueue	= { "smtp-server-queue",	"20",		usage_smtp_server_queue };
Option optSmtpSlowReply		= { "smtp-slow-reply",		"-",		usage_smtp_slow_reply };
Option optSmtpDropUnknown	= { "smtp-drop-unknown",	"-",		usage_smtp_drop_unknown };
Option optSmtpDropAfter		= { "smtp-drop-after",		"5",		USAGE_SMTP_DROP_AFTER };
Option optSmtpDsnReplyTo	= { "smtp-dsn-reply-to",	"",		usage_smtp_dsn_reply_to };
Option optSmtpWelcomeFile	= { "smtp-welcome-file",	"",		USAGE_WELCOME_BANNER_FILE };
Option optSmtpStrictRelay	= { "smtp-strict-relay",	"-",		usage_smtp_strict_relay };

static const char usage_smtp_xclient_enable[] =
  "When set enable SMTP XCLIENT support when EHLO command is given.\n"
"#"
;
Option optSmtpXclientEnable	= { "smtp-xclient-enable",	"+",		usage_smtp_xclient_enable };

Option optTestLickey		= { "test-lickey",		"-",		usage_test_lickey };
Option optTestMode		= { "test-mode",		"-",		usage_test_mode };
#ifdef ENABLE_TEST_ON_COMMAND
Option optTestOnCommand		= { "test-on-command",		"",		USAGE_TEST_ON_COMMAND };
#endif
Option optTestPauseAfterDot	= { "test-pause-after-dot", 	"0",		"Delay in seconds to pause after dot. Zero to disable." };


static const char usage_smtp_drop_dot[] =
  "Drop the connection at dot after any 5xy response.\n"	\
"#"
;
Option optSmtpDropDot		= { "smtp-drop-dot",		"-",		usage_smtp_drop_dot };

static const char usage_rfc1652_8bitmime[] =
  "Enables support for RFC 1652 8BITMIME transfers when the client sends\n"
"# EHLO. Note that the support for this is weak, pass through only. If\n"
"# enabled, then all forward hosts must also advertise 8BITMIME, otherwise\n"
"# the behaviour is undefined. See also smtp-enable-esmtp.\n"
"#"
;
Option optRFC16528bitmime	= { "rfc1652-8bitmime",		"-",		usage_rfc1652_8bitmime };

static const char usage_rfc2920_pipelining[] =
  "Enables support for RFC 2920 SMTP command pipelining when the client\n"
"# sends EHLO. When there is early input before HELO/EHLO, HELO is used,\n"
"# or EHLO PIPELINING has been disabled by this option, earlier talkers\n"
"# are detected and rejected. See also smtp-enable-esmtp.\n"
"#"
;
Option optRFC2920Pipelining	= { "rfc2920-pipelining",	"+",		usage_rfc2920_pipelining };

static const char usage_rfc2821_angle_brackets[] =
  "Strict RFC 2821 grammar requirement for mail addresses be surrounded\n"
"# by angle brackets in MAIL FROM: and RCPT TO: commands.\n"
"#"
;
Option optRFC2821AngleBrackets	= { "rfc2821-angle-brackets",	"+", 		usage_rfc2821_angle_brackets };

static const char usage_rfc2821_extra_spaces[] =
  "Strict RFC 2821 grammar requirement that SMTP commands not contain any\n"
"# supurious white spaces.\n"
"#"
;
Option optRFC2821ExtraSpaces	= { "rfc2821-extra-spaces",	"-", 		usage_rfc2821_extra_spaces };

Option optRFC2821CommandLength	= { "rfc2821-command-length", 	"-", 		"Strict RFC 2821 command line length limit." };
Option optRFC2821LineLength	= { "rfc2821-line-length", 	"-", 		"Strict RFC 2821 data line length limit." };
Option optRFC2821LocalLength	= { "rfc2821-local-length", 	"-", 		"Strict RFC 2821 local-part length limit." };
Option optRFC2821DomainLength	= { "rfc2821-domain-length", 	"-", 		"Strict RFC 2821 domain name length limit." };
Option optRFC2821LiteralPlus	= { "rfc2821-literal-plus", 	"-", 		"Treat plus-sign as itself; not a sendmail plussed address." };
Option optRFC2821StrictDot	= { "rfc2821-strict-dot", 	"-", 		"Strict RFC 2821 section 4.1.1.4 DATA handling of CRLF-DOT-CRLF sequence." };

Option optRFC2606SpecialDomains	= { "rfc2606-special-domains", 	"+", 		usage_rfc2606_special_domains };
Option optRejectUnknownTLD 	= { "reject-unknown-tld", 	"+", 		"Reject top-level-domains not listed by IANA." };

Option optAuthDelayChecks	= { "auth-delay-checks",	"-",		usage_auth_delay_checks };

Option optSmtpReportHeader	= { "smtp-report-header",	"X-" _NAME "-Report", "The name of the smtpf report header. Empty string to disable." };

Vector optionTable;
Vector optionTableRestart;

static int
optionsSort(const void *_a, const void *_b)
{
	const char *a, *b;

	a = (*(Option **) _a)->name;
	if (*a == '_')
		a++;

	b = (*(Option **) _b)->name;
	if (*b == '_')
		b++;

	/* Make sure our special options for version, intro, etc.
	 * appear first ahead of special "description only" options.
	 */
	if (iscntrl(*a) && *b == '\0')
		return -1;
	if (*a == '\0' && iscntrl(*b))
		return 1;

	if (*a == '\0')
		a = (*(Option **) _a)->usage;
	if (*b == '\0')
		b = (*(Option **) _b)->usage;

	return TextInsensitiveCompare(a, b);
}

static void
optionsDestroy(void *ignore)
{
	/* Do nothing. Members of this vector should be
	 * pointers to constant structures.
	 */
}

void
optionsRegister(Option *option, int requires_restart)
{
	if (VectorAdd(optionTable, option)) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}

	if (requires_restart && VectorAdd(optionTableRestart, option)) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}
}

int
optionsRegister0(Session *sess, va_list ignore)
{
	VectorDestroy(optionTable);
	if ((optionTable = VectorCreate(150)) == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}

	VectorSetDestroyEntry(optionTable, optionsDestroy);

	if ((optionTableRestart = VectorCreate(40)) == NULL) {
		syslog(LOG_ERR, log_oom, FILE_LINENO);
		exit(1);
	}

	VectorSetDestroyEntry(optionTableRestart, optionsDestroy);

	optionsRegister(&optIntro, 			0);
	optionsRegister(&optSyntax, 			0);
	optionsRegister(&optNames, 			0);

	optionsRegister(&optDaemon, 			1);
	optionsRegister(&optFile, 			1);
	optionsRegister(&optHelp, 			1);
	optionsRegister(&optInfo, 			1);
	optionsRegister(&optQuit, 			1);
#ifdef ENABLE_SLOW_QUIT
	optionsRegister(&optSlowQuit, 			1);
#endif
	optionsRegister(&optRestart, 			1);
	optionsRegister(&optRestartIf, 			1);
	optionsRegister(&optService, 			1);
	optionsRegister(&optTestLickey,			1);
	optionsRegister(&optTestMode, 			1);
	optionsRegister(&optTestPauseAfterDot, 		0);
	optionsRegister(&optVersion, 			1);

	optionsRegister(&optAuthDelayChecks, 		0);

	optionsRegister(&optDnsMaxTimeout, 		0);
	optionsRegister(&optDnsRoundRobin, 		0);
	optionsRegister(&optDnsSpamHausDbl, 		0);

#ifdef OLD
	optionsRegister(&optInterfaceIp, 		1);
	optionsRegister(&optInterfaceName, 		1);
#endif
	optionsRegister(&optInterfaces, 		1);

	optionsRegister(&optLicenseKeyFile, 		1);
#ifdef ENABLE_LINT
	optionsRegister(&optLint,			0);
#endif
	optionsRegister(&optRejectPercentRelay, 	0);
	optionsRegister(&optRejectQuotedAtSign, 	0);
	optionsRegister(&optRejectUnknownTLD, 		0);
	optionsRegister(&optRejectUucpRoute, 		0);
	optionsRegister(&optRelayReply, 		0);
	optionsRegister(&optRFC2606SpecialDomains, 	0);
	optionsRegister(&optRFC2821AngleBrackets,	0);
	optionsRegister(&optRFC2821CommandLength,	0);
	optionsRegister(&optRFC2821DomainLength, 	0);
	optionsRegister(&optRFC2821ExtraSpaces,		0);
	optionsRegister(&optRFC2821LineLength, 		0);
	optionsRegister(&optRFC2821LiteralPlus, 	0);
	optionsRegister(&optRFC2821LocalLength, 	0);
	optionsRegister(&optRFC2821StrictDot, 		0);
	optionsRegister(&optRFC2821StrictHelo, 		0);
	optionsRegister(&optCallAheadAsSender,		0);
	optionsRegister(&optRouteForwardSelection,	0);
	optionsRegister(&optRouteMap, 			1);
	optionsRegister(&optRunGroup, 			1);
	optionsRegister(&optRunJailed, 			1);
	optionsRegister(&optRunOpenFileLimit, 		1);
	optionsRegister(&optRunPidFile, 		1);
	optionsRegister(&opt_run_save_core,		1);
	optionsRegister(&optRunUser, 			1);
	optionsRegister(&optRunWorkDir, 		1);
	optionsRegister(&optServerMaxThreads, 		0);
	optionsRegister(&optServerMinThreads, 		0);
	optionsRegister(&optServerNewThreads, 		0);
	optionsRegister(&optSmtpAcceptTimeout, 		0);
	optionsRegister(&optSmtpAuthEnable,		0);
	optionsRegister(&optSmtpAuthWhite, 		0);
	optionsRegister(&optSmtpCommandTimeout, 	0);
	optionsRegister(&optSmtpCommandTimeoutBlack, 	0);
	optionsRegister(&optSmtpConnectTimeout, 	0);
	optionsRegister(&optSmtpDataLineTimeout, 	0);
	optionsRegister(&optSmtpDelayChecks,		0);
	optionsRegister(&optSmtpDotTimeout, 		0);
	optionsRegister(&optSmtpDropAfter, 		0);
	optionsRegister(&optSmtpDropDot,		0);
	optionsRegister(&optSmtpDropUnknown, 		0);
	optionsRegister(&optSmtpDsnReplyTo, 		0);
	optionsRegister(&optSmtpEnableEsmtp,		0);
	optionsRegister(&optSmtpKeepAliveTimeout,	0);
	optionsRegister(&optRFC16528bitmime,		0);
	optionsRegister(&optRFC2920Pipelining,		0);
	optionsRegister(&optSmtpRejectFile, 		1);
	optionsRegister(&optSmtpReportHeader,		0);
	optionsRegister(&optSmtpServerQueue, 		1);
	optionsRegister(&optSmtpStrictRelay,		0);
	optionsRegister(&optSmtpSlowReply,		0);
	optionsRegister(&optSmtpWelcomeFile, 		1);
	optionsRegister(&optSmtpXclientEnable,		0);
	optionsRegister(&tldOptLevelOne,		1);
	optionsRegister(&tldOptLevelTwo,		1);

	return SMTPF_CONTINUE;
}

int
optionsRegister1(Session *sess, va_list ignore)
{
	VectorSort(optionTable, optionsSort);

	return SMTPF_CONTINUE;
}

