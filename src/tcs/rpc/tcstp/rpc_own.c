
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
tcs_wrap_TakeOwnership(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT16 protocolID;
	UINT32 encOwnerAuthSize;
	BYTE *encOwnerAuth;
	UINT32 encSrkAuthSize;
	BYTE *encSrkAuth;
	UINT32 srkInfoSize;
	BYTE *srkInfo;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TPM_AUTH ownerAuth;

	UINT32 srkKeySize;
	BYTE *srkKey;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &encOwnerAuthSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	encOwnerAuth = calloc(1, encOwnerAuthSize);
	if (encOwnerAuth == NULL) {
		LogError("malloc of %d bytes failed.", encOwnerAuthSize);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, encOwnerAuth, encOwnerAuthSize, tsp_data)) {
		free(encOwnerAuth);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_UINT32, 4, &encSrkAuthSize, 0, tsp_data)) {
		free(encOwnerAuth);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	encSrkAuth = calloc(1, encSrkAuthSize);
	if (encSrkAuth == NULL) {
		LogError("malloc of %d bytes failed.", encSrkAuthSize);
		free(encOwnerAuth);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 5, encSrkAuth, encSrkAuthSize, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_UINT32, 6, &srkInfoSize, 0, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	srkInfo = calloc(1, srkInfoSize);
	if (srkInfo == NULL) {
		LogError("malloc of %d bytes failed.", srkInfoSize);
		free(encOwnerAuth);
		free(encSrkAuth);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 7, srkInfo, srkInfoSize, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		free(srkInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 8, &ownerAuth, 0, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		free(srkInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = TCSP_TakeOwnership_Internal(hContext, protocolID, encOwnerAuthSize,
					encOwnerAuth, encSrkAuthSize,
					encSrkAuth, srkInfoSize, srkInfo,
					&ownerAuth, &srkKeySize, &srkKey);
	free(encOwnerAuth);
	free(encSrkAuth);
	free(srkInfo);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + srkKeySize);
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) +
					sizeof(UINT32) + srkKeySize);
			free(srkKey);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			free(srkKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &srkKeySize, 0, *hdr)) {
			free(*hdr);
			free(srkKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, srkKey, srkKeySize, *hdr)) {
			free(*hdr);
			free(srkKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(srkKey);
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
tcs_wrap_OwnerClear(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TPM_AUTH auth;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &auth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_OwnerClear_Internal(hContext, &auth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &auth, 0, *hdr)) {
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
