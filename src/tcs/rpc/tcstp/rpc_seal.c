
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
tcs_wrap_Seal(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE keyHandle;
	TCPA_ENCAUTH KeyUsageAuth;
	UINT32 PCRInfoSize, inDataSize;
	BYTE *PCRInfo = NULL, *inData = NULL;
	TPM_AUTH emptyAuth, pubAuth, *pAuth;
	UINT32 outDataSize;
	BYTE *outData;

	int i = 0;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	memset(&emptyAuth, 0, sizeof(TPM_AUTH));
	memset(&pubAuth, 0, sizeof(TPM_AUTH));

	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &keyHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, i++, &KeyUsageAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &PCRInfoSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (PCRInfoSize > 0) {
		PCRInfo = calloc(1, PCRInfoSize);
		if (PCRInfo == NULL) {
			LogError("malloc of %u bytes failed.", PCRInfoSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, PCRInfo, PCRInfoSize, tsp_data)) {
			free(PCRInfo);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &inDataSize, 0, tsp_data)) {
		free(PCRInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if (inDataSize > 0) {
		inData = calloc(1, inDataSize);
		if (inData == NULL) {
			LogError("malloc of %u bytes failed.", inDataSize);
			free(PCRInfo);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, inData, inDataSize, tsp_data)) {
			free(inData);
			free(PCRInfo);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	result = getData(TCSD_PACKET_TYPE_AUTH, i++, &pubAuth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
		pAuth = NULL;
	else if (result) {
		free(inData);
		free(PCRInfo);
		return result;
	} else
		pAuth = &pubAuth;

	result = TCSP_Seal_Internal(hContext, keyHandle, KeyUsageAuth, PCRInfoSize, PCRInfo,
			inDataSize, inData, pAuth, &outDataSize, &outData);
	free(inData);
	free(PCRInfo);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) +
					sizeof(UINT32) + outDataSize);
			free(outData);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, pAuth, 0, *hdr)) {
				free(*hdr);
				free(outData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &outDataSize, 0, *hdr)) {
			free(*hdr);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, outData, outDataSize, *hdr)) {
			free(*hdr);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(outData);
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
tcs_wrap_UnSeal(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE parentHandle;
	UINT32 inDataSize;
	BYTE *inData;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TPM_AUTH parentAuth, dataAuth, emptyAuth;
	TPM_AUTH *pParentAuth, *pDataAuth;

	UINT32 outDataSize;
	BYTE *outData;
	TSS_RESULT result;

	memset(&emptyAuth, 0, sizeof(TPM_AUTH));

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &inDataSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	inData = calloc(1, inDataSize);
	if (inData == NULL) {
		LogError("malloc of %d bytes failed.", inDataSize);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, inData, inDataSize, tsp_data)) {
		free(inData);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = getData(TCSD_PACKET_TYPE_AUTH, 4, &parentAuth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
		pParentAuth = NULL;
	else if (result) {
		free(inData);
		return result;
	} else
		pParentAuth = &parentAuth;

	result = getData(TCSD_PACKET_TYPE_AUTH, 5, &dataAuth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE) {
		pDataAuth = pParentAuth;
		pParentAuth = NULL;
	} else if (result) {
		free(inData);
		return result;
	} else
		pDataAuth = &dataAuth;

	result = TCSP_Unseal_Internal(hContext, parentHandle, inDataSize, inData,
				 pParentAuth, pDataAuth, &outDataSize, &outData);
	free(inData);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + (2 * sizeof(TPM_AUTH)) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + (2 * sizeof(TPM_AUTH)) +
					sizeof(UINT32) + outDataSize);
			free(outData);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pParentAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, pParentAuth, 0, *hdr)) {
				free(*hdr);
				free(outData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		} else {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, &emptyAuth, 0, *hdr)) {
				free(*hdr);
				free(outData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 1, &dataAuth, 0, *hdr)) {
			free(*hdr);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 2, &outDataSize, 0, *hdr)) {
			free(*hdr);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 3, outData, outDataSize, *hdr)) {
			free(*hdr);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(outData);
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
