
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
TCSP_ChangeAuth_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCS_KEY_HANDLE parentHandle,	/* in */
			       TCPA_PROTOCOL_ID protocolID,	/* in */
			       TCPA_ENCAUTH newAuth,	/* in */
			       TCPA_ENTITY_TYPE entityType,	/* in */
			       UINT32 encDataSize,	/* in */
			       BYTE * encData,	/* in */
			       TPM_AUTH * ownerAuth,	/* in, out */
			       TPM_AUTH * entityAuth,	/* in, out */
			       UINT32 * outDataSize,	/* out */
			       BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CHANGEAUTH;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 2, &protocolID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 3, &newAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 4, &entityType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 5, &encDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 6, encData, encDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 7, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 8, entityAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, 1, entityAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, 2, outDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = (BYTE *) malloc(*outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, *outData, *outDataSize, hdr)) {
			free(*outData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthOwner_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCPA_PROTOCOL_ID protocolID,	/* in */
				    TCPA_ENCAUTH newAuth,	/* in */
				    TCPA_ENTITY_TYPE entityType,	/* in */
				    TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CHANGEAUTHOWNER;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 2, &newAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 3, &entityType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 4, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (hdr->result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthAsymStart_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE idHandle,	/* in */
					TCPA_NONCE antiReplay,	/* in */
					UINT32 KeySizeIn,	/* in */
					BYTE * KeyDataIn,	/* in */
					TPM_AUTH * pAuth,	/* in, out */
					UINT32 * KeySizeOut,	/* out */
					BYTE ** KeyDataOut,	/* out */
					UINT32 * CertifyInfoSize,	/* out */
					BYTE ** CertifyInfo,	/* out */
					UINT32 * sigSize,	/* out */
					BYTE ** sig,	/* out */
					TCS_KEY_HANDLE * ephHandle	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_ChangeAuthAsymFinish_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCS_KEY_HANDLE parentHandle,	/* in */
					 TCS_KEY_HANDLE ephHandle,	/* in */
					 TCPA_ENTITY_TYPE entityType,	/* in */
					 TCPA_HMAC newAuthLink,	/* in */
					 UINT32 newAuthSize,	/* in */
					 BYTE * encNewAuth,	/* in */
					 UINT32 encDataSizeIn,	/* in */
					 BYTE * encDataIn,	/* in */
					 TPM_AUTH * ownerAuth,	/* in, out */
					 UINT32 * encDataSizeOut,	/* out */
					 BYTE ** encDataOut,	/* out */
					 TCPA_SALT_NONCE * saltNonce,	/* out */
					 TCPA_DIGEST * changeProof	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}
