
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
tcs_wrap_MakeIdentity(struct tcsd_thread_data *data,
		      struct tsp_packet *tsp_data,
		      struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_ENCAUTH identityAuth;
	TCPA_CHOSENID_HASH privCAHash;
	UINT32 idKeyInfoSize;
	BYTE *idKeyInfo = NULL;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TPM_AUTH auth1, auth2;
	TPM_AUTH *pSRKAuth, *pOwnerAuth;

	UINT32 idKeySize;
	BYTE *idKey = NULL;
	UINT32 pcIDBindSize;
	BYTE *prgbIDBind = NULL;
	UINT32 pcECSize;
	BYTE *prgbEC = NULL;
	UINT32 pcPlatCredSize;
	BYTE *prgbPlatCred = NULL;
	UINT32 pcConfCredSize;
	BYTE *prgbConfCred = NULL;
	TSS_RESULT result;

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 1, &identityAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &privCAHash, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &idKeyInfoSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	idKeyInfo = (BYTE *) calloc(1, idKeyInfoSize);
	if (idKeyInfo == NULL) {
		LogError("malloc of %d bytes failed.", idKeyInfoSize);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, idKeyInfo, idKeyInfoSize, tsp_data)) {
		free(idKeyInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 5, &auth1, 0, tsp_data)) {
		free(idKeyInfo);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = getData(TCSD_PACKET_TYPE_AUTH, 6, &auth2, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE) {
		pOwnerAuth = &auth1;
		pSRKAuth = NULL;
	} else if (result) {
		free(idKeyInfo);
		return result;
	} else {
		pOwnerAuth = &auth2;
		pSRKAuth = &auth1;
	}

	result = TCSP_MakeIdentity_Internal(hContext, identityAuth, privCAHash,
				       idKeyInfoSize, idKeyInfo, pSRKAuth,
				       pOwnerAuth, &idKeySize, &idKey,
				       &pcIDBindSize, &prgbIDBind, &pcECSize,
				       &prgbEC, &pcPlatCredSize, &prgbPlatCred,
				       &pcConfCredSize, &prgbConfCred);
	free(idKeyInfo);

	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size +
				2 * sizeof(TPM_AUTH) +
				5 * sizeof(UINT32) +
			        idKeySize + pcIDBindSize +
				pcECSize + pcPlatCredSize +
				pcConfCredSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (pSRKAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pSRKAuth, 0, *hdr))
				goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &idKeySize, 0, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, idKey, idKeySize, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcIDBindSize, 0, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbIDBind, pcIDBindSize, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcECSize, 0, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbEC, pcECSize, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcPlatCredSize, 0, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbPlatCred, pcPlatCredSize, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcConfCredSize, 0, *hdr))
			goto internal_error;
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbConfCred, pcConfCredSize, *hdr))
			goto internal_error;

		free(idKey);
		free(prgbIDBind);
		free(prgbEC);
		free(prgbPlatCred);
		free(prgbConfCred);
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

internal_error:
	free(*hdr);
	free(idKey);
	free(prgbIDBind);
	free(prgbEC);
	free(prgbPlatCred);
	free(prgbConfCred);
	return TCSERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT
tcs_wrap_ActivateIdentity(struct tcsd_thread_data *data,
			  struct tsp_packet *tsp_data,
			  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE idKeyHandle;
	TPM_AUTH *pIdKeyAuth = NULL, *pOwnerAuth = NULL, auth1, auth2;
	UINT32 SymmetricKeySize, blobSize;
	BYTE *SymmetricKey, *blob;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr), i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &idKeyHandle, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &blobSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if ((blob = malloc(blobSize)) == NULL)
		return TCSERR(TSS_E_OUTOFMEMORY);

	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, blob, blobSize, tsp_data)) {
		free(blob);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &auth1, 0, tsp_data)) {
		free(blob);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = getData(TCSD_PACKET_TYPE_AUTH, 5, &auth2, 0, tsp_data);
	if (result == TSS_TCP_RPC_BAD_PACKET_TYPE)
		pOwnerAuth = &auth1;
	else if (result) {
		free(blob);
		return result;
	} else {
		pIdKeyAuth = &auth1;
		pOwnerAuth = &auth2;
	}

	result = TCSP_ActivateTPMIdentity_Internal(hContext, idKeyHandle, blobSize,
						   blob, pIdKeyAuth, pOwnerAuth,
						   &SymmetricKeySize,
						   &SymmetricKey);
	free(blob);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + (2 * sizeof(TPM_AUTH)) + sizeof(UINT32)
					+ SymmetricKeySize);
		if (*hdr == NULL) {
			free(SymmetricKey);
			LogError("malloc of %zd bytes failed.", size +
						(2 * sizeof(TPM_AUTH)) +
						sizeof(UINT32) + blobSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		i = 0;
		if (pIdKeyAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pIdKeyAuth, 0, *hdr)) {
				free(*hdr);
				free(SymmetricKey);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, *hdr)) {
			free(*hdr);
			free(SymmetricKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &SymmetricKeySize, 0, *hdr)) {
			free(*hdr);
			free(SymmetricKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, SymmetricKey, SymmetricKeySize, *hdr)) {
			free(*hdr);
			free(SymmetricKey);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(SymmetricKey);
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
