/*
 * options.h
 *
 * Copyright 2006, 2008 by Anthony Howe. All rights reserved.
 */

#ifndef __options_h__
#define __options_h__			1

#ifdef __cplusplus
extern "C" {
#endif

#include <com/snert/lib/util/option.h>

/***********************************************************************
 ***
 ***********************************************************************/

#define optTable		(Option **) VectorBase(optionTable)
#define optTableRestart		(Option **) VectorBase(optionTableRestart)

Vector optionTable;
Vector optionTableRestart;

extern void optionsRegister(Option *option, int requires_restart);
extern int optionsRegister0(Session *sess, va_list ignore);
extern int optionsRegister1(Session *sess, va_list ignore);

extern Option optFile0;
extern Option *optTable0[];

extern Option optAuthDelayChecks;
extern Option optCacheAcceptTTL;
extern Option optCacheGcInterval;
extern Option optCacheRejectTTL;
extern Option optCacheTempFailTTL;
extern Option optDaemon;
extern Option optFile;
extern Option optHelp;
extern Option optInfo;
extern Option optHttpTimeout;
#ifdef REPLACED
extern Option optInterfaceIp;
extern Option optInterfaceName;
#endif
extern Option optInterfaces;
extern Option optIntro;
extern Option optNames;
extern Option optLint;
extern Option optQuit;
extern Option optSlowQuit;
extern Option optRejectPercentRelay;
extern Option optRejectQuotedAtSign;
extern Option optRejectUnknownTLD;
extern Option optRejectUucpRoute;
extern Option optRelayReply;
extern Option optRestart;
extern Option optRestartIf;
extern Option optRFC16528bitmime;
extern Option optRFC2606SpecialDomains;
extern Option optRFC2821AngleBrackets;
extern Option optRFC2821CommandLength;
extern Option optRFC2821DomainLength;
extern Option optRFC2821ExtraSpaces;
extern Option optRFC2821LineLength;
extern Option optRFC2821LiteralPlus;
extern Option optRFC2821LocalLength;
extern Option optRFC2821StrictDot;
extern Option optRouteForwardSelection;
extern Option optRouteMap;
extern Option optRunGroup;
extern Option optRunJailed;
extern Option optRunOpenFileLimit;
extern Option optRunPidFile;
extern Option optRunUser;
extern Option optRunWorkDir;
extern Option optService;
extern Option optServerMaxThreads;
extern Option optServerMinThreads;
extern Option optServerNewThreads;
extern Option optSmtpAcceptTimeout;
extern Option optSmtpAuthEnable;
extern Option optSmtpAuthWhite;
extern Option optSmtpCommandTimeout;
extern Option optSmtpCommandTimeoutBlack;
extern Option optSmtpConnectTimeout;
extern Option optSmtpKeepAliveTimeout;
extern Option optSmtpDataLineTimeout;
extern Option optSmtpDotTimeout;
extern Option optSmtpDelayChecks;
extern Option optSmtpDropAfter;
extern Option optSmtpDropDot;
extern Option optSmtpDropUnknown;
extern Option optSmtpDsnReplyTo;
extern Option optSmtpEnableEsmtp;
extern Option optRFC2920Pipelining;
extern Option optSmtpRejectFile;
extern Option optSmtpReportHeader;
extern Option optSmtpServerQueue;
extern Option optSmtpSlowReply;
extern Option optSmtpStrictRelay;
extern Option optSmtpWelcomeFile;
extern Option optSyntax;
extern Option optTestCase;
extern Option optTestLickey;
extern Option optTestMode;
extern Option optTestOnCommand;
extern Option optTestPauseAfterDot;
extern Option optVersion;

#define optServerQueueSize		optSmtpServerQueue
#define optServerAcceptTimeout		optSmtpAcceptTimeout

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __options_h__ */
