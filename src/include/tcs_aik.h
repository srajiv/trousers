
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */

#ifndef _TCS_AIK_H_
#define _TCS_AIK_H_

#define TR_ENDORSEMENT_CREDENTIAL	1
#define TR_CONFORMANCE_CREDENTIAL	2
#define TR_PLATFORM_CREDENTIAL		3

void get_credential(int, UINT32 *, BYTE **);

#endif
