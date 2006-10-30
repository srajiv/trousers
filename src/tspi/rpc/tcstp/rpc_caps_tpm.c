
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
TCSP_GetCapability_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCPA_CAPABILITY_AREA capArea,	/* in */
				  UINT32 subCapSize,	/* in */
				  BYTE * subCap,	/* in */
				  UINT32 * respSize,	/* out */
				  BYTE ** resp)	/* out */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETCAPABILITY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, respSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*resp = (BYTE *) malloc(*respSize);
		if (*resp == NULL) {
			LogError("malloc of %u bytes failed.", *respSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *resp, *respSize, hdr)) {
			free(*resp);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetCapabilitySigned_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE keyHandle,	/* in */
					TCPA_NONCE antiReplay,	/* in */
					TCPA_CAPABILITY_AREA capArea,	/* in */
					UINT32 subCapSize,	/* in */
					BYTE * subCap,	/* in */
					TPM_AUTH * privAuth,	/* in, out */
					TCPA_VERSION * Version,	/* out */
					UINT32 * respSize,	/* out */
					BYTE ** resp,	/* out */
					UINT32 * sigSize,	/* out */
					BYTE ** sig)	/* out */
{
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_GetCapabilityOwner_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				       TPM_AUTH * pOwnerAuth,	/* out */
				       TCPA_VERSION * pVersion,	/* out */
				       UINT32 * pNonVolatileFlags,	/* out */
				       UINT32 * pVolatileFlags)	/* out */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETCAPABILITYOWNER;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 1, pOwnerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_VERSION, 0, pVersion, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_UINT32, 1, pNonVolatileFlags, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_UINT32, 2, pVolatileFlags, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_AUTH, 3, pOwnerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}
