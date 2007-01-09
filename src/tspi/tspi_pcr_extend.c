
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_TPM_PcrExtend(TSS_HTPM hTPM,		/* in */
		   UINT32 ulPcrIndex,		/* in */
		   UINT32 ulPcrDataLength,	/* in */
		   BYTE *pbPcrData,		/* in */
		   TSS_PCR_EVENT *pPcrEvent,	/* in */
		   UINT32 * pulPcrValueLength,	/* out */
		   BYTE ** prgbPcrValue)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_PCRVALUE outDigest;
	TSS_RESULT result;
	BYTE *extendData;
	TPM_DIGEST digest;
	UINT32 number;
	TSS_HCONTEXT tspContext;
	Trspi_HashCtx hashCtx;

	if (pulPcrValueLength == NULL || prgbPcrValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulPcrDataLength > 0 && pbPcrData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if (pPcrEvent) {
		/* Create data to extend according to the TSS 1.2 spec section 2.6.2
		 * 'TSS_PCR_EVENT', in the 'rgbPcrValue' parameter description. */
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, ulPcrIndex);
		result |= Trspi_HashUpdate(&hashCtx, ulPcrDataLength, pbPcrData);
		result |= Trspi_Hash_UINT32(&hashCtx, pPcrEvent->eventType);
		result |= Trspi_HashUpdate(&hashCtx, pPcrEvent->ulEventLength, pPcrEvent->rgbEvent);
		if ((result |= Trspi_HashFinal(&hashCtx, (BYTE *)&digest.digest)))
			return result;

		extendData = (BYTE *)&digest.digest;
	} else {
		if (ulPcrDataLength != TPM_SHA1_160_HASH_LEN)
			return TSPERR(TSS_E_BAD_PARAMETER);

		extendData = pbPcrData;
	}

	if ((result = TCSP_Extend(tcsContext, ulPcrIndex, *(TPM_DIGEST *)extendData, &outDigest)))
		return result;

	/* log the event structure if its passed in */
	if (pPcrEvent) {
		if ((result = TCS_LogPcrEvent(tcsContext, *pPcrEvent, &number)))
			return result;

		if ((pPcrEvent->rgbPcrValue = calloc_tspi(tspContext,
							  TPM_SHA1_160_HASH_LEN)) == NULL) {
			LogError("malloc of %d bytes failed.", TPM_SHA1_160_HASH_LEN);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		memcpy(pPcrEvent->rgbPcrValue, (BYTE *)&digest.digest, TPM_SHA1_160_HASH_LEN);
		pPcrEvent->ulPcrValueLength = TPM_SHA1_160_HASH_LEN;
	}

	*prgbPcrValue = calloc_tspi(tspContext, sizeof(TPM_PCRVALUE));
	if (*prgbPcrValue == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TPM_PCRVALUE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	memcpy(*prgbPcrValue, &outDigest, sizeof(TPM_PCRVALUE));
	*pulPcrValueLength = sizeof(TPM_PCRVALUE);

	return result;
}

TSS_RESULT
Tspi_TPM_PcrRead(TSS_HTPM hTPM,			/* in */
		 UINT32 ulPcrIndex,		/* in */
		 UINT32 *pulPcrValueLength,	/* out */
		 BYTE **prgbPcrValue)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_PCRVALUE outDigest;
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if (pulPcrValueLength == NULL || prgbPcrValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCSP_PcrRead(tcsContext, ulPcrIndex, &outDigest)))
		return result;

	*prgbPcrValue = calloc_tspi(tspContext, sizeof(TCPA_PCRVALUE));
	if (*prgbPcrValue == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TCPA_PCRVALUE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(*prgbPcrValue, outDigest.digest, sizeof(TCPA_PCRVALUE));
	*pulPcrValueLength = sizeof(TCPA_PCRVALUE);

	return TSS_SUCCESS;
}
