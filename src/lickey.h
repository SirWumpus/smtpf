/*
 * lickey.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __lickey_h__
#define __lickey_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern Option optLicenseKeyFile;

extern Option lickeyClientName;
extern Option lickeyClientMail;
extern Option lickeyComments;
extern Option lickeyCorePerIpList;
extern Option lickeyDateIssued;
extern Option lickeyDateExpires;
extern Option lickeyHwMachine;
extern Option lickeyHwModel;
extern Option lickeyHwProduct;
extern Option lickeyHwVendor;
extern Option lickeyHwVersion;
extern Option lickeyHwSerialNo;
extern Option lickeyProcessName;
extern Option lickeyProcessVersion;
extern Option lickeyGeneratedBy;
extern Option lickeyKeycode;
extern Option lickeyHash;
extern Option lickeyMaxDomains;
extern Option lickeyResellerName;
extern Option lickeyResellerMail;
extern Option lickeySupportMail;
extern Option lickeyPlatform;
extern Option lickeyLint;
extern Option lickeyHttpRealm;
extern Option lickeyHttpUser;
extern Option lickeyHttpPass;

extern Option *lickeyOptTable[];

extern Stats stat_route_accounts;
extern Stats stat_route_addresses;
extern Stats stat_route_domains;
extern Stats stat_route_unique_domains;

extern void lickeyInit(Vector interfaces);
extern void lickeyHasExpired(void);
extern void lickeyRouteCount(void);
extern void lickeySendWarning(void);
extern int lickeyFileIsValid(const char *file, const char *ip);
extern int lickeyStringIsValid(const char *string, const char *ip);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __lickey_h__ */
