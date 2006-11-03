
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
tcs_wrap_GetCapability(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_CAPABILITY_AREA capArea;
	UINT32 subCapSize;
	BYTE *subCap;
	UINT32 respSize;
	BYTE *resp;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (subCapSize == 0)
		subCap = NULL;
	else {
		subCap = calloc(1, subCapSize);
		if (subCap == NULL) {
			LogError("malloc of %u bytes failed.", subCapSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, tsp_data)) {
			free(subCap);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	result = TCSP_GetCapability_Internal(hContext, capArea, subCapSize, subCap, &respSize,
					     &resp);
	free(subCap);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + respSize);
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(UINT32) + respSize);
			free(resp);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &respSize, 0, *hdr)) {
			free(*hdr);
			free(resp);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, resp, respSize, *hdr)) {
			free(*hdr);
			free(resp);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(resp);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %u bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetCapabilityOwner(struct tcsd_thread_data *data,
			    struct tsp_packet *tsp_data,
			    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TPM_AUTH ownerAuth;
	TCPA_VERSION version;
	UINT32 nonVol;
	UINT32 vol;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &ownerAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_GetCapabilityOwner_Internal(hContext, &ownerAuth, &version,
					     &nonVol, &vol);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_VERSION) + (2 * sizeof(UINT32)) +
				sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TCPA_VERSION) +
					(2 * sizeof(UINT32)) + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_VERSION, 0, &version, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &nonVol, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 2, &vol, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 3, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %u bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_SetCapability(struct tcsd_thread_data *data,
		       struct tsp_packet *tsp_data,
		       struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_CAPABILITY_AREA capArea;
	UINT32 subCapSize;
	BYTE *subCap;
	UINT32 valueSize;
	BYTE *value;
	TSS_RESULT result;
	TPM_AUTH ownerAuth, *pOwnerAuth;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (subCapSize == 0)
		subCap = NULL;
	else {
		subCap = calloc(1, subCapSize);
		if (subCap == NULL) {
			LogError("malloc of %u bytes failed.", subCapSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, tsp_data)) {
			free(subCap);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	if (getData(TCSD_PACKET_TYPE_UINT32, 4, &valueSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (valueSize == 0)
		value = NULL;
	else {
		value = calloc(1, valueSize);
		if (value == NULL) {
			free(subCap);
			LogError("malloc of %u bytes failed.", valueSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 5, value, valueSize, tsp_data)) {
			free(subCap);
			free(value);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	if (getData(TCSD_PACKET_TYPE_AUTH, 6, &ownerAuth, 0, tsp_data))
		pOwnerAuth = NULL;
	else
		pOwnerAuth = &ownerAuth;


	result = TCSP_SetCapability_Internal(hContext, capArea, subCapSize, subCap, valueSize,
					     value, pOwnerAuth);
	free(subCap);
	free(value);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pOwnerAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, pOwnerAuth, 0, *hdr)) {
				free(*hdr);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %u bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TSS_SUCCESS;
}
