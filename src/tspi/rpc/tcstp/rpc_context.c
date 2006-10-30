
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
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
//#include "obj.h"
#include "rpc_tcstp_tsp.h"


TSS_RESULT
TCS_OpenContext_RPC_TP(struct host_table_entry	*hte,
		       TCS_CONTEXT_HANDLE *hContext)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OPENCONTEXT;
	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, hContext, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);

		LogDebugFn("Received TCS Context: 0x%x", *hContext);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCS_CloseContext_TP(struct host_table_entry *hte,
		    TCS_CONTEXT_HANDLE hContext)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CLOSECONTEXT;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCS_FreeMemory_TP(struct host_table_entry *hte,
		  TCS_CONTEXT_HANDLE hContext,	/*  in */
		  BYTE * pMemory)		/*  in */
{
	free(pMemory);

	return TSS_SUCCESS;
}
