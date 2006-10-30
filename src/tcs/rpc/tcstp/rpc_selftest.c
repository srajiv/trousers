
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
tcs_wrap_SelfTestFull(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x servicing a %s request", (UINT32)pthread_self(), __FUNCTION__);

	result = TCSP_SelfTestFull_Internal(hContext);
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
tcs_wrap_CertifySelfTest(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;
	UINT32 sigSize;
	BYTE *sigData = NULL;
	TCS_KEY_HANDLE hKey;
	TCPA_NONCE antiReplay;
	TPM_AUTH privAuth;
	TPM_AUTH *pPrivAuth;
	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x servicing a %s request", (UINT32)pthread_self(), __FUNCTION__);
        if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
                return TCSERR(TSS_E_INTERNAL_ERROR);
        if (getData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, tsp_data))
                return TCSERR(TSS_E_INTERNAL_ERROR);

        result = getData(TCSD_PACKET_TYPE_AUTH, 3, &privAuth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
                pPrivAuth = NULL;
	else if (result)
		return result;
        else
                pPrivAuth = &privAuth;

	result = TCSP_CertifySelfTest_Internal(hContext, hKey, antiReplay, pPrivAuth, &sigSize, &sigData);
	i = 0;
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + sigSize);
		if (*hdr == NULL) {
			free(sigData);
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) + sizeof(UINT32) + sigSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
                if (pPrivAuth != NULL) {
                        if (setData(TCSD_PACKET_TYPE_AUTH, i++, pPrivAuth, 0, *hdr)) {
                                free(*hdr);
                                free(sigData);
                                return TCSERR(TSS_E_INTERNAL_ERROR);
                        }
                }

		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &sigSize, 0, *hdr)) {
			free(*hdr);
			free(sigData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, sigData, sigSize, *hdr)) {
			free(*hdr);
			free(sigData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(sigData);
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
tcs_wrap_GetTestResult(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;
	UINT32 resultDataSize;
	BYTE *resultData = NULL;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x servicing a %s request", (UINT32)pthread_self(), __FUNCTION__);

	result = TCSP_GetTestResult_Internal(hContext, &resultDataSize, &resultData);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + resultDataSize);
		if (*hdr == NULL) {
			free(resultData);
			LogError("malloc of %zd bytes failed.", size + sizeof(UINT32) + resultDataSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &resultDataSize, 0, *hdr)) {
			free(*hdr);
			free(resultData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, resultData, resultDataSize, *hdr)) {
			free(*hdr);
			free(resultData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(resultData);
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
