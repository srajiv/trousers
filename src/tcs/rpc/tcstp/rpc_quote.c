
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
tcs_wrap_Quote(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	TCPA_NONCE antiReplay;
	UINT32 pcrDataSizeIn;
	BYTE *pcrDataIn;

	TPM_AUTH privAuth;
	TPM_AUTH *pPrivAuth;

	UINT32 pcrDataSizeOut;
	BYTE *pcrDataOut;
	UINT32 sigSize;
	BYTE *sig;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &pcrDataSizeIn, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	pcrDataIn = (BYTE *)calloc(1, pcrDataSizeIn);
	if (pcrDataIn == NULL) {
		LogError("malloc of %d bytes failed.", pcrDataSizeIn);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, pcrDataIn, pcrDataSizeIn, tsp_data)) {
		free(pcrDataIn);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = getData(TCSD_PACKET_TYPE_AUTH, 5, &privAuth, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
		pPrivAuth = NULL;
	else if (result) {
		free(pcrDataIn);
		return result;
	} else
		pPrivAuth = &privAuth;

	result = TCSP_Quote_Internal(hContext, hKey, antiReplay, pcrDataSizeIn,
				pcrDataIn, pPrivAuth, &pcrDataSizeOut,
				&pcrDataOut, &sigSize, &sig);
	free(pcrDataIn);
	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + (2 * sizeof(UINT32)) +
				pcrDataSizeOut + sigSize);
		if (*hdr == NULL) {
			free(pcrDataOut);
			free(sig);
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH) +
					(2 * sizeof(UINT32)) + pcrDataSizeOut + sigSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pPrivAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pPrivAuth, 0, *hdr)) {
				free(*hdr);
				free(pcrDataOut);
				free(sig);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcrDataSizeOut, 0, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, pcrDataOut, pcrDataSizeOut, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &sigSize, 0, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, sig, sigSize, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		free(pcrDataOut);
		free(sig);
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
