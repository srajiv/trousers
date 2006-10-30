
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
TCSP_OIAP_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCS_AUTHHANDLE * authHandle,	/* out */
			 TCPA_NONCE * nonce0	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OIAP;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, authHandle, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_NONCE, 1, nonce0, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_OSAP_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_ENTITY_TYPE entityType,	/* in */
			 UINT32 entityValue,	/* in */
			 TCPA_NONCE nonceOddOSAP,	/* in */
			 TCS_AUTHHANDLE * authHandle,	/* out */
			 TCPA_NONCE * nonceEven,	/* out */
			 TCPA_NONCE * nonceEvenOSAP	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OSAP;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &entityType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &entityValue, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 3, &nonceOddOSAP, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, authHandle, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_NONCE, 1, nonceEven, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_NONCE, 2, nonceEvenOSAP, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}
