
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
TCSP_SelfTestFull_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_SELFTESTFULL;
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
TCSP_CertifySelfTest_TP(struct host_table_entry *hte,
			TCS_CONTEXT_HANDLE hContext,	/* in */
			TCS_KEY_HANDLE keyHandle,	/* in */
			TCPA_NONCE antiReplay,	/* in */
			TPM_AUTH * privAuth,	/* in, out */
			UINT32 * sigSize,	/* out */
			BYTE ** sig)	/* out */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	int i;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CERTIFYSELFTEST;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (privAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 3, privAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (privAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, privAuth, 0, hdr)) {
				LogDebug("privAuth");
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, sigSize, 0, hdr)) {
			LogDebug("sigSize");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*sig = (BYTE *) malloc(*sigSize);
		if (*sig == NULL) {
			LogError("malloc of %u bytes failed.", *sigSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *sig, *sigSize, hdr)) {
			LogDebug("sig");
			free(*sig);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetTestResult_TP(struct host_table_entry *hte,
		      TCS_CONTEXT_HANDLE hContext,	/* in */
		      UINT32 * outDataSize,	/* out */
		      BYTE ** outData)	/* out */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETTESTRESULT;
	LogDebugFn("TCS Context: 0x%x", hContext);

	LogDebug("TCSP_GetTestResult_TP");
	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		LogDebug("sendTCSDPacket succeeded");
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, outDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = calloc_tspi(tspContext, *outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *outData, *outDataSize, hdr)) {
			free_tspi(tspContext, *outData);
			*outData = NULL;
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}
	LogDebug("TCSP_GetTestResult_TP exit");

done:
	free(hdr);
	return result;
}
