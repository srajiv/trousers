
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _CAPABILITIES_H_
#define _CAPABILITIES_H_

/**********************************************
	This header has all of the software capabilities
		that are returned either via
		Tspi_Context_GetCapability or
		TCS_GetCapability.
***********************************************/

/* TSP */
#define INTERNAL_CAP_TSP_VERSION		{ 0x01, 0x00, 0x00, 0x01 }

#define INTERNAL_CAP_TSP_ALG_RSA		TRUE
#define INTERNAL_CAP_TSP_ALG_SHA		TRUE
#define INTERNAL_CAP_TSP_ALG_3DES		FALSE
#define INTERNAL_CAP_TSP_ALG_DES		FALSE
#define INTERNAL_CAP_TSP_ALG_HMAC		FALSE
#define INTERNAL_CAP_TSP_ALG_AES		FALSE

#define INTERNAL_CAP_TSP_PERSSTORAGE		TRUE

/* TCS */
#define INTERNAL_CAP_TCS_VERSION		{ 0x01, 0x00, 0x00, 0x01 }

#define INTERNAL_CAP_TCS_ALG_RSA		FALSE
#define INTERNAL_CAP_TCS_ALG_AES		FALSE
#define INTERNAL_CAP_TCS_ALG_3DES		FALSE
#define INTERNAL_CAP_TCS_ALG_DES		FALSE
#define INTERNAL_CAP_TCS_ALG_SHA		FALSE
#define INTERNAL_CAP_TCS_ALG_HMAC		FALSE

#define INTERNAL_CAP_TCS_PERSSTORAGE		TRUE

#define INTERNAL_CAP_TCS_CACHING_KEYCACHE	TRUE
#define INTERNAL_CAP_TCS_CACHING_AUTHCACHE	FALSE

#define INTERNAL_CAP_TCS_MANUFACTURER	{ 'I', 'B', 'M', ' ' };

#endif
