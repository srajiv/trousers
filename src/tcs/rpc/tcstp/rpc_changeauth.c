
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
tcs_wrap_ChangeAuth(struct tcsd_thread_data *data,
		    struct tsp_packet *tsp_data,
		    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE parentHandle;
	TCPA_PROTOCOL_ID protocolID;
	TCPA_ENCAUTH newAuth;
	TCPA_ENTITY_TYPE entityType;
	UINT32 encDataSize;
	BYTE *encData;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TPM_AUTH ownerAuth;
	TPM_AUTH entityAuth;

	UINT32 outDataSize;
	BYTE *outData;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT16, 2, &protocolID, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 3, &newAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT16, 4, &entityType, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 5, &encDataSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	encData = calloc(1, encDataSize);
	if (encData == NULL) {
		LogError("malloc of %d bytes failed.", encDataSize);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 6, encData, encDataSize, tsp_data)) {
		free(encData);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 7, &ownerAuth, 0, tsp_data)) {
		free(encData);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 8, &entityAuth, 0, tsp_data)) {
		free(encData);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = TCSP_ChangeAuth_Internal(hContext, parentHandle, protocolID,
				     newAuth, entityType, encDataSize, encData,
				     &ownerAuth, &entityAuth, &outDataSize,
				     &outData);
	free(encData);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + (2 * sizeof(TPM_AUTH)) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			free(outData);
			LogError("malloc of %zd bytes failed.", size + (2 * sizeof(TPM_AUTH)) +
					sizeof(UINT32) + outDataSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(outData);
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 1, &entityAuth, 0, *hdr)) {
			free(outData);
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 2, &outDataSize, 0, *hdr)) {
			free(outData);
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 3, outData, outDataSize, *hdr)) {
			free(outData);
			free(*hdr);
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
tcs_wrap_ChangeAuthOwner(struct tcsd_thread_data *data,
			 struct tsp_packet *tsp_data,
			 struct tcsd_packet_hdr **hdr)
{

	TCS_CONTEXT_HANDLE hContext;
	TCPA_PROTOCOL_ID protocolID;
	TCPA_ENCAUTH newAuth;
	TCPA_ENTITY_TYPE entityType;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TPM_AUTH ownerAuth;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 2, &newAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT16, 3, &entityType, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &ownerAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_ChangeAuthOwner_Internal(hContext, protocolID, newAuth,
					  entityType, &ownerAuth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
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
