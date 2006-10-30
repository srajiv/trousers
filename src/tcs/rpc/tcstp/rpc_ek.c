
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
tcs_wrap_CreateEndorsementKeyPair(struct tcsd_thread_data *data,
				struct tsp_packet *tsp_data,
				struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_NONCE antiReplay;
	UINT32 eKPtrSize;
	BYTE *eKPtr;
	UINT32 eKSize;
	BYTE* eK;
	TCPA_DIGEST checksum;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &eKPtrSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (eKPtrSize == 0)
		eKPtr = NULL;
	else {
		eKPtr = calloc(1, eKPtrSize);
		if (eKPtr == NULL) {
			LogError("malloc of %d bytes failed.", eKPtrSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, eKPtr, eKPtrSize, tsp_data)) {
			free(eKPtr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	result = TCSP_CreateEndorsementKeyPair_Internal(hContext, antiReplay, eKPtrSize, eKPtr, &eKSize, &eK, &checksum);

	free(eKPtr);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + eKSize + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(UINT32) + eKSize + sizeof(TCPA_DIGEST));
			free(eK);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &eKSize, 0, *hdr)) {
			free(*hdr);
			free(eK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, eK, eKSize, *hdr)) {
			free(*hdr);
			free(eK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(eK);
		if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &checksum, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}
	else {
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
tcs_wrap_ReadPubek(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_NONCE antiReplay;
	UINT32 pubEKSize;
	BYTE *pubEK;
	TCPA_DIGEST checksum;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_ReadPubek_Internal(hContext, antiReplay, &pubEKSize, &pubEK,
				    &checksum);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + pubEKSize + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(UINT32) + pubEKSize);
			free(pubEK);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &pubEKSize, 0, *hdr)) {
			free(*hdr);
			free(pubEK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, pubEK, pubEKSize, *hdr)) {
			free(*hdr);
			free(pubEK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(pubEK);
		if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &checksum, 0, *hdr)) {
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
tcs_wrap_OwnerReadPubek(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 pubEKSize;
	BYTE *pubEK;
	TSS_RESULT result;
	TPM_AUTH auth;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &auth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_OwnerReadPubek_Internal(hContext, &auth, &pubEKSize, &pubEK);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + pubEKSize);
		if (*hdr == NULL) {
			free(pubEK);
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) +
					sizeof(UINT32) + pubEKSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &auth, 0, *hdr)) {
			free(*hdr);
			free(pubEK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &pubEKSize, 0, *hdr)) {
			free(*hdr);
			free(pubEK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, pubEK, pubEKSize, *hdr)) {
			free(*hdr);
			free(pubEK);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(pubEK);
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
tcs_wrap_DisablePubekRead(struct tcsd_thread_data *data,
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

	result = TCSP_DisablePubekRead_Internal(hContext, &auth);

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
