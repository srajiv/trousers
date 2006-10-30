
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
tcs_wrap_KillMaintenanceFeature(struct tcsd_thread_data *data,
			        struct tsp_packet *tsp_data,
			        struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TPM_AUTH ownerAuth;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %x context %x", (UINT32)pthread_self(), hContext);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &ownerAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_KillMaintenanceFeature_Internal(hContext, &ownerAuth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zu bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
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
tcs_wrap_CreateMaintenanceArchive(struct tcsd_thread_data *data,
				  struct tsp_packet *tsp_data,
				  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TPM_AUTH ownerAuth;
	TSS_BOOL generateRandom;
	UINT32 randomSize, archiveSize;
	BYTE *random, *archive;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %x context %x", (UINT32)pthread_self(), hContext);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &generateRandom, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_AUTH, 2, &ownerAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_CreateMaintenanceArchive_Internal(hContext, generateRandom, &ownerAuth,
							&randomSize, &random, &archiveSize,
							&archive);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + (2 * sizeof(UINT32)) +
			      randomSize + archiveSize);
		if (*hdr == NULL) {
			free(random);
			free(archive);
			LogError("malloc of %zu bytes failed.", size + sizeof(TPM_AUTH) +
				 (2 * sizeof(UINT32)) + randomSize + archiveSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			free(random);
			free(archive);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &randomSize, 0, *hdr)) {
			free(*hdr);
			free(random);
			free(archive);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, random, randomSize, *hdr)) {
			free(*hdr);
			free(random);
			free(archive);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 3, &archiveSize, 0, *hdr)) {
			free(*hdr);
			free(random);
			free(archive);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 4, archive, archiveSize, *hdr)) {
			free(*hdr);
			free(random);
			free(archive);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		free(random);
		free(archive);
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
tcs_wrap_LoadMaintenanceArchive(struct tcsd_thread_data *data,
				struct tsp_packet *tsp_data,
				struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TPM_AUTH ownerAuth;
	UINT32 dataInSize, dataOutSize;
	BYTE *dataIn, *dataOut;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %x context %x", (UINT32)pthread_self(), hContext);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &dataInSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	dataIn = (BYTE *)malloc(dataInSize);
	if (dataIn == NULL) {
		LogError("malloc of %d bytes failed.", dataInSize);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 2, dataIn, dataInSize, tsp_data)) {
		free(dataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if (getData(TCSD_PACKET_TYPE_AUTH, 3, &ownerAuth, 0, tsp_data)) {
		free(dataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = TCSP_LoadMaintenanceArchive_Internal(hContext, dataInSize, dataIn, &ownerAuth,
							&dataOutSize, &dataOut);
	free(dataIn);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + dataOutSize);
		if (*hdr == NULL) {
			free(dataOut);
			LogError("malloc of %zu bytes failed.", size + sizeof(TPM_AUTH) +
				 sizeof(UINT32) + dataOutSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			free(dataOut);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &dataOutSize, 0, *hdr)) {
			free(*hdr);
			free(dataOut);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, dataOut, dataOutSize, *hdr)) {
			free(*hdr);
			free(dataOut);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		free(dataOut);
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
tcs_wrap_LoadManuMaintPub(struct tcsd_thread_data *data,
			  struct tsp_packet *tsp_data,
			  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 pubKeySize;
	BYTE *pubKey;
	TCPA_NONCE antiReplay;
	TCPA_DIGEST checksum;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %x context %x", (UINT32)pthread_self(), hContext);

	if (getData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &pubKeySize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	pubKey = (BYTE *)malloc(pubKeySize);
	if (pubKey == NULL) {
		LogError("malloc of %d bytes failed.", pubKeySize);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, pubKey, pubKeySize, tsp_data)) {
		free(pubKey);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = TCSP_LoadManuMaintPub_Internal(hContext, antiReplay, pubKeySize, pubKey,
						&checksum);
	free(pubKey);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zu bytes failed.", size + sizeof(TCPA_DIGEST));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &checksum, 0, *hdr)) {
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
tcs_wrap_ReadManuMaintPub(struct tcsd_thread_data *data,
			  struct tsp_packet *tsp_data,
			  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TCPA_NONCE antiReplay;
	TCPA_DIGEST checksum;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebugFn("thread %x context %x", (UINT32)pthread_self(), hContext);

	if (getData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_ReadManuMaintPub_Internal(hContext, antiReplay, &checksum);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zu bytes failed.", size + sizeof(TCPA_DIGEST));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &checksum, 0, *hdr)) {
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
