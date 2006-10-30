
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <netdb.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcs_utils.h"
#include "rpc_tcstp_tcs.h"


TSS_RESULT
tcs_wrap_EvictKey(struct tcsd_thread_data *data,
		  struct tsp_packet *tsp_data,
		  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = key_mgr_evict(hContext, hKey);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetPubkey(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	TPM_AUTH auth;
	TPM_AUTH *pAuth;
	UINT32 pubKeySize;
	BYTE *pubKey;
	TSS_RESULT result;
	int i;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = getData(TCSD_PACKET_TYPE_AUTH, 2, &auth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
		pAuth = NULL;
	else if (result)
		return result;
	else
		pAuth = &auth;

	result = TCSP_GetPubKey_Internal(hContext, hKey, pAuth, &pubKeySize, &pubKey);
	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + pubKeySize);
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) +
					sizeof(UINT32) + pubKeySize);
			free(pubKey);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pAuth != NULL)
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pAuth, 0, *hdr)) {
				free(*hdr);
				free(pubKey);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pubKeySize, 0, *hdr)) {
			free(*hdr);
			free(pubKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, pubKey, pubKeySize, *hdr)) {
			free(*hdr);
			free(pubKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(pubKey);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_TerminateHandle(struct tcsd_thread_data *data,
			 struct tsp_packet *tsp_data,
			 struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_AUTHHANDLE authHandle;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &authHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_TerminateHandle_Internal(hContext, authHandle);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_LoadKeyByBlob(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hUnwrappingKey;
	UINT32 cWrappedKeyBlob;
	BYTE *rgbWrappedKeyBlob;

	TPM_AUTH auth;

	TCS_KEY_HANDLE phKeyTCSI;
	TCS_KEY_HANDLE phKeyHMAC;

	TPM_AUTH *pAuth;
	TSS_RESULT result;
	int i;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hUnwrappingKey, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &cWrappedKeyBlob, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	rgbWrappedKeyBlob = calloc(1, cWrappedKeyBlob);
	if (rgbWrappedKeyBlob == NULL) {
		LogError("malloc of %d bytes failed.", cWrappedKeyBlob);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, rgbWrappedKeyBlob, cWrappedKeyBlob, tsp_data)) {
		free(rgbWrappedKeyBlob);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	result = getData(TCSD_PACKET_TYPE_AUTH, 4, &auth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
		pAuth = NULL;
	else if (result) {
		free(rgbWrappedKeyBlob);
		return result;
	} else
		pAuth = &auth;

	result = key_mgr_load_by_blob(hContext, hUnwrappingKey, cWrappedKeyBlob, rgbWrappedKeyBlob,
				      pAuth, &phKeyTCSI, &phKeyHMAC);

	if (!result)
		result = ctx_mark_key_loaded(hContext, phKeyTCSI);

	free(rgbWrappedKeyBlob);

	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + (2 * sizeof(UINT32)));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) +
					(2 * sizeof(UINT32)));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pAuth, 0, *hdr)) {
				free(*hdr);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &phKeyTCSI, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &phKeyHMAC, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_CreateWrapKey(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hWrappingKey;
	TCPA_ENCAUTH KeyUsageAuth;
	TCPA_ENCAUTH KeyMigrationAuth;
	UINT32 keyInfoSize;
	BYTE *keyInfo;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TPM_AUTH pAuth;

	UINT32 keyDataSize;
	BYTE *keyData;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hWrappingKey, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 2, &KeyUsageAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 3, &KeyMigrationAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 4, &keyInfoSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	keyInfo = calloc(1, keyInfoSize);
	if (keyInfo == NULL) {
		LogError("malloc of %d bytes failed.", keyInfoSize);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 5, keyInfo, keyInfoSize, tsp_data)) {
		free(keyInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 6, &pAuth, 0, tsp_data)) {
		free(keyInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = TCSP_CreateWrapKey_Internal(hContext, hWrappingKey, KeyUsageAuth,
					KeyMigrationAuth, keyInfoSize, keyInfo,
					&keyDataSize, &keyData, &pAuth);

	free(keyInfo);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + keyDataSize + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			free(keyData);
			LogError("malloc of %zd bytes failed.", size + sizeof(UINT32) +
				 keyDataSize + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &keyDataSize, 0, *hdr)) {
			free(*hdr);
			free(keyData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, keyData, keyDataSize, *hdr)) {
			free(*hdr);
			free(keyData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(keyData);
		if (setData(TCSD_PACKET_TYPE_AUTH, 2, &pAuth, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TSS_SUCCESS;
}
