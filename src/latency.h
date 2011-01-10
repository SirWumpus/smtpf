/*
 * latency.h
 *
 * Copyright 2009 by Anthony Howe. All rights reserved.
 */

#ifndef __latency_h__
#define __latency_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

extern void latencyInit(void);
extern void latencySend(mcc_context *mcc);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __latency_h__ */
