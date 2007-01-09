
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_tsp.h"
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"


TSS_RESULT
internal_TCSGetCap(TCS_CONTEXT_HANDLE hContext,
		   TCPA_CAPABILITY_AREA capArea,
		   UINT32 subCapSize, BYTE * subCap,
		   UINT32 * respSize, BYTE ** resp)
{
	UINT32 tcsSubCapContainer;
	UINT64 offset;
	TSS_RESULT result;
	TCPA_VERSION tcsVersion = INTERNAL_CAP_TCS_VERSION;

	if ((result = ctx_verify_context(hContext)))
		return result;

	LogDebug("Checking Software Cap of TCS");
	switch (capArea) {
	case TSS_TCSCAP_ALG:
		LogDebug("TSS_TCSCAP_ALG");
		tcsSubCapContainer = Decode_UINT32(subCap);
		*respSize = 1;
		*resp = malloc(1);
		if (*resp == NULL) {
			LogError("malloc of %d bytes failed.", 1);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		switch (tcsSubCapContainer) {
		case TSS_ALG_RSA:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_RSA;
			break;
		case TSS_ALG_DES:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_DES;
			break;
		case TSS_ALG_3DES:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_3DES;
			break;
		case TSS_ALG_SHA:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_SHA;
			break;
		case TSS_ALG_AES:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_AES;
			break;
		case TSS_ALG_HMAC:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_HMAC;
			break;
		default:
			free(*resp);
			return TCSERR(TSS_E_FAIL);
		}
		break;
	case TSS_TCSCAP_VERSION:
		LogDebug("TSS_TCSCAP_VERSION");
		*resp = calloc(1, 4);
		if (*resp == NULL) {
			LogError("malloc of %d bytes failed.", 4);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		LoadBlob_VERSION(&offset, *resp, &tcsVersion);
		*respSize = offset;
		break;
	case TSS_TCSCAP_PERSSTORAGE:
		LogDebug("TSS_TCSCAP_PERSSTORAGE");
		*respSize = 1;
		*resp = malloc(1);
		if (*resp == NULL) {
			LogError("malloc of %d byte failed.", 1);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*resp)[0] = INTERNAL_CAP_TCS_PERSSTORAGE;
		break;

	case TSS_TCSCAP_CACHING:
		LogDebug("TSS_TCSCAP_CACHING");
		tcsSubCapContainer = Decode_UINT32(subCap);
		if (tcsSubCapContainer == TSS_TCSCAP_PROP_KEYCACHE) {
			*respSize = 1;
			*resp = malloc(1);
			if (*resp == NULL) {
				LogError("malloc of %d byte failed.", 1);
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			(*resp)[0] = INTERNAL_CAP_TCS_CACHING_KEYCACHE;
		} else if (tcsSubCapContainer == TSS_TCSCAP_PROP_AUTHCACHE) {
			*respSize = 1;
			*resp = malloc(1);
			if (*resp == NULL) {
			LogError("malloc of %d byte failed.", 1);
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			(*resp)[0] = INTERNAL_CAP_TCS_CACHING_AUTHCACHE;
		} else {
			LogDebugFn("Bad subcap");
			return TCSERR(TSS_E_FAIL);
		}
		break;
	case TSS_TCSCAP_MANUFACTURER:
		tcsSubCapContainer = Decode_UINT32(subCap);
		if (tcsSubCapContainer == TSS_TCSCAP_PROP_MANUFACTURER_ID) {
			*respSize = sizeof(UINT32);
			*resp = malloc(sizeof(UINT32));
			if (*resp == NULL) {
				LogError("malloc of %zd byte failed.", sizeof(UINT32));
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			*(UINT32 *)(*resp) = INTERNAL_CAP_TCS_MANUFACTURER_ID;
		} else if (tcsSubCapContainer == TSS_TCSCAP_PROP_MANUFACTURER_STR) {
			BYTE str[] = INTERNAL_CAP_TCS_MANUFACTURER_STR;

			*respSize = INTERNAL_CAP_TCS_MANUFACTURER_STR_LEN;
			*resp = malloc(INTERNAL_CAP_TCS_MANUFACTURER_STR_LEN);
			if (*resp == NULL) {
				LogError("malloc of %d byte failed.", 1);
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			memcpy(*resp, str, INTERNAL_CAP_TCS_MANUFACTURER_STR_LEN);
		} else {
			LogDebugFn("Bad subcap");
			return TCSERR(TSS_E_FAIL);
		}
		break;
	default:
		return TCSERR(TSS_E_FAIL);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
TCS_GetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_CAPABILITY_AREA capArea,	/* in */
			   UINT32 subCapSize,	/* in */
			   BYTE * subCap,	/* in */
			   UINT32 * respSize,	/* out */
			   BYTE ** resp	/* out */
    )
{
	TSS_RESULT result;

	if ((result = ctx_verify_context(hContext)))
		return result;

	return internal_TCSGetCap(hContext, capArea, subCapSize, subCap,
				  respSize, resp);
}

