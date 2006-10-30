
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
#include <string.h>
#include <assert.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"
#include "rpc_tcstp_tsp.h"


TSS_RESULT
TCSP_GetRegisteredKeyByPublicInfo_TP(struct host_table_entry *hte,
				     TCS_CONTEXT_HANDLE hContext,
				     TCPA_ALGORITHM_ID algID,	/* in */
				     UINT32 ulPublicInfoLength,	/* in */
				     BYTE * rgbPublicInfo,	/* in */
				     UINT32 * keySize,		/* out */
				     BYTE ** keyBlob)		/* out */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETREGISTEREDKEYBYPUBLICINFO;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &algID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &ulPublicInfoLength, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, rgbPublicInfo, ulPublicInfoLength, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, keySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*keyBlob = (BYTE *) malloc(*keySize);
		if (*keyBlob == NULL) {
			LogError("malloc of %u bytes failed.", *keySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *keyBlob, *keySize, hdr)) {
			free(*keyBlob);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_RegisterKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_UUID WrappingKeyUUID,	/* in */
			       TSS_UUID KeyUUID,	/* in */
			       UINT32 cKeySize,	/* in */
			       BYTE * rgbKey,	/* in */
			       UINT32 cVendorData,	/* in */
			       BYTE * gbVendorData	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_REGISTERKEY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &WrappingKeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 2, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &cKeySize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, rgbKey, cKeySize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 5, &cVendorData, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 6, gbVendorData, cVendorData, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_UnregisterKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TSS_UUID KeyUUID	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_UNREGISTERKEY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCS_EnumRegisteredKeys_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				      TSS_UUID * pKeyUUID,	/* in */
				      UINT32 * pcKeyHierarchySize,	/* out */
				      TSS_KM_KEYINFO ** ppKeyHierarchy	/* out */
    ) {
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	int i, j;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_ENUMREGISTEREDKEYS;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (pKeyUUID != NULL) {
		if (setData(TCSD_PACKET_TYPE_UUID, 1, pKeyUUID, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcKeyHierarchySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		if (*pcKeyHierarchySize > 0) {
			*ppKeyHierarchy = malloc((*pcKeyHierarchySize) * sizeof(TSS_KM_KEYINFO));
			if (*ppKeyHierarchy == NULL) {
				LogError("malloc of %zu bytes failed.", (*pcKeyHierarchySize) *
					 sizeof(TSS_KM_KEYINFO));
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto done;
			}
			for (j = 0; (UINT32)j < *pcKeyHierarchySize; j++) {
				if (getData(TCSD_PACKET_TYPE_KM_KEYINFO, i++,
					    &((*ppKeyHierarchy)[j]), 0, hdr)) {
					free(*ppKeyHierarchy);
					result = TSPERR(TSS_E_INTERNAL_ERROR);
					goto done;
				}
			}
		} else {
			*ppKeyHierarchy = NULL;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_GetRegisteredKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TSS_UUID KeyUUID,	/* in */
				    TSS_KM_KEYINFO ** ppKeyInfo	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCS_GetRegisteredKeyBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TSS_UUID KeyUUID,	/* in */
					UINT32 * pcKeySize,	/* out */
					BYTE ** prgbKey	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETREGISTEREDKEYBLOB;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pcKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*prgbKey = malloc(*pcKeySize);
		if (*prgbKey == NULL) {
			LogError("malloc of %u bytes failed.", *pcKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *prgbKey, *pcKeySize, hdr)) {
			free(*prgbKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;

}

TSS_RESULT
TCSP_LoadKeyByUUID_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TSS_UUID KeyUUID,	/* in */
				  TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in, out */
				  TCS_KEY_HANDLE * phKeyTCSI	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_LOADKEYBYUUID;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (pLoadKeyInfo != NULL) {
		if (setData(TCSD_PACKET_TYPE_LOADKEY_INFO, 2, pLoadKeyInfo, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, phKeyTCSI, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);

		LogDebugFn("TCS key handle: 0x%x", *phKeyTCSI);
	} else if (pLoadKeyInfo && (result == TCSERR(TCS_E_KM_LOADFAILED))) {
		if (getData(TCSD_PACKET_TYPE_LOADKEY_INFO, 0, pLoadKeyInfo, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

void
LoadBlob_LOADKEY_INFO(UINT64 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	Trspi_LoadBlob_UUID(offset, blob, info->keyUUID);
	Trspi_LoadBlob_UUID(offset, blob, info->parentKeyUUID);
	Trspi_LoadBlob(offset, TCPA_DIGEST_SIZE, blob, info->paramDigest.digest);
	Trspi_LoadBlob_UINT32(offset, info->authData.AuthHandle, blob);
	Trspi_LoadBlob(offset, TCPA_NONCE_SIZE, blob, (BYTE *)&info->authData.NonceOdd.nonce);
	Trspi_LoadBlob(offset, TCPA_NONCE_SIZE, blob, (BYTE *)&info->authData.NonceEven.nonce);
	Trspi_LoadBlob_BOOL(offset, info->authData.fContinueAuthSession, blob);
	Trspi_LoadBlob(offset, TCPA_DIGEST_SIZE, blob, (BYTE *)&info->authData.HMAC);
}

void
UnloadBlob_LOADKEY_INFO(UINT64 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	Trspi_UnloadBlob_UUID(offset, blob, &info->keyUUID);
	Trspi_UnloadBlob_UUID(offset, blob, &info->parentKeyUUID);
	Trspi_UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, (BYTE *)&info->paramDigest.digest);
	Trspi_UnloadBlob_UINT32(offset, &info->authData.AuthHandle, blob);
	Trspi_UnloadBlob(offset, TCPA_NONCE_SIZE, blob, (BYTE *)&info->authData.NonceOdd.nonce);
	Trspi_UnloadBlob(offset, TCPA_NONCE_SIZE, blob, (BYTE *)&info->authData.NonceEven.nonce);
	Trspi_UnloadBlob_BOOL(offset, &info->authData.fContinueAuthSession, blob);
	Trspi_UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, (BYTE *)&info->authData.HMAC);
}

