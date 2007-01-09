
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
TCS_GetCapability_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_CAPABILITY_AREA capArea,	/* in */
				 UINT32 subCapSize,	/* in */
				 BYTE * subCap,	/* in */
				 UINT32 * respSize,	/* out */
				 BYTE ** resp)	/* out */
{
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	initData(&hte->comm, 4);
	hte->comm.hdr.u.ordinal = TCSD_ORD_TCSGETCAPABILITY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, &hte->comm))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte);

	if (result == TSS_SUCCESS)
		result = hte->comm.hdr.u.result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, respSize, 0, &hte->comm)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*resp = (BYTE *) calloc_tspi(tspContext, *respSize);
		if (*resp == NULL) {
			LogError("malloc of %u bytes failed.", *respSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *resp, *respSize, &hte->comm)) {
			free_tspi(tspContext, *resp);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	return result;
}
