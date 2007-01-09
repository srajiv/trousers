
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
TCSP_GetRandom_TP(struct host_table_entry *hte,
		  TCS_CONTEXT_HANDLE hContext,	/* in */
		  UINT32 bytesRequested,	/* in */
		  BYTE ** randomBytes)	/* out */
{
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	initData(&hte->comm, 2);
	hte->comm.hdr.u.ordinal = TCSD_ORD_GETRANDOM;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &bytesRequested, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, &bytesRequested, 0, &hte->comm)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*randomBytes = (BYTE *) calloc_tspi(tspContext, bytesRequested);
		if (*randomBytes == NULL) {
			LogError("malloc of %u bytes failed.", bytesRequested);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *randomBytes, bytesRequested, &hte->comm)) {
			free_tspi(tspContext, *randomBytes);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	return result;
}

TSS_RESULT
TCSP_StirRandom_TP(struct host_table_entry *hte,
		   TCS_CONTEXT_HANDLE hContext,	/* in */
		   UINT32 inDataSize,	/* in */
		   BYTE * inData)	/* in */
{
	TSS_RESULT result;

	initData(&hte->comm, 3);
	hte->comm.hdr.u.ordinal = TCSD_ORD_STIRRANDOM;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &inDataSize, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 2, inData, inDataSize, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	return result;
}
