
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
TCSP_TakeOwnership_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  UINT16 protocolID,	/* in */
				  UINT32 encOwnerAuthSize,	/* in */
				  BYTE * encOwnerAuth,	/* in */
				  UINT32 encSrkAuthSize,	/* in */
				  BYTE * encSrkAuth,	/* in */
				  UINT32 srkInfoSize,	/* in */
				  BYTE * srkInfo,	/* in */
				  TPM_AUTH * ownerAuth,	/* in, out */
				  UINT32 * srkKeySize, BYTE ** srkKey) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_TAKEOWNERSHIP;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &encOwnerAuthSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, encOwnerAuth, encOwnerAuthSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 4, &encSrkAuthSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 5, encSrkAuth, encSrkAuthSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 6, &srkInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 7, srkInfo, srkInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 8, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, 1, srkKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*srkKey = (BYTE *) malloc(*srkKeySize);
		if (*srkKey == NULL) {
			LogError("malloc of %u bytes failed.", *srkKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 2, *srkKey, *srkKeySize, hdr)) {
			free(*srkKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}


TSS_RESULT
TCSP_OwnerClear_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       TPM_AUTH * ownerAuth	/* in, out */
    ) {
        TSS_RESULT result;
        struct tsp_packet data;
        struct tcsd_packet_hdr *hdr;

        memset(&data, 0, sizeof(struct tsp_packet));

        data.ordinal = TCSD_ORD_OWNERCLEAR;
	LogDebugFn("TCS Context: 0x%x", hContext);

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte, 0, &data, &hdr);

        if (result == TSS_SUCCESS)
                result = hdr->result;

        if (result == TSS_SUCCESS ){
                if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
        }

        free(hdr);
        return result;
}
