
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
tcs_wrap_CertifyKey(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE certHandle, keyHandle;
	TPM_AUTH *pCertAuth = NULL, *pKeyAuth = NULL, certAuth, keyAuth, nullAuth;
	UINT32 CertifyInfoSize, outDataSize;
	BYTE *CertifyInfo, *outData;
	TCPA_NONCE antiReplay;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr), i;

	memset(&nullAuth, 0, sizeof(TPM_AUTH));
	memset(&certAuth, 0, sizeof(TPM_AUTH));
	memset(&keyAuth, 0, sizeof(TPM_AUTH));

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &certHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &keyHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_NONCE, 3, &antiReplay, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &certAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_AUTH, 5, &keyAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (memcmp(&nullAuth, &certAuth, sizeof(TPM_AUTH)))
		pCertAuth = &certAuth;

	if (memcmp(&nullAuth, &keyAuth, sizeof(TPM_AUTH)))
		pKeyAuth = &keyAuth;

	result = TCSP_CertifyKey_Internal(hContext, certHandle, keyHandle,
			antiReplay, pCertAuth, pKeyAuth, &CertifyInfoSize,
			&CertifyInfo, &outDataSize, &outData);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + (2 * sizeof(TPM_AUTH)) + (2 * sizeof(UINT32))
					+ CertifyInfoSize + outDataSize);
		if (*hdr == NULL) {
			free(CertifyInfo);
			free(outData);
			LogError("malloc of %zd bytes failed.", size +
						(2 * sizeof(TPM_AUTH)) +
						(2 * sizeof(UINT32)) +
						+ CertifyInfoSize + outDataSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		i = 0;
		if (pCertAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pCertAuth, 0, *hdr)) {
				free(*hdr);
				free(CertifyInfo);
				free(outData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (pKeyAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pKeyAuth, 0, *hdr)) {
				free(*hdr);
				free(CertifyInfo);
				free(outData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &CertifyInfoSize, 0, *hdr)) {
			free(*hdr);
			free(CertifyInfo);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, CertifyInfo, CertifyInfoSize, *hdr)) {
			free(*hdr);
			free(CertifyInfo);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(CertifyInfo);
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &outDataSize, 0, *hdr)) {
			free(*hdr);
			free(outData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, outData, outDataSize, *hdr)) {
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
