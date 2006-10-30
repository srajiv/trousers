
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
Tspi_TPM_PcrExtend(TSS_HTPM hTPM,			/* in */
			UINT32 ulPcrIndex,		/* in */
			UINT32 ulPcrDataLength,		/* in */
			BYTE *pbPcrData,		/* in */
			TSS_PCR_EVENT *pPcrEvent,	/* in */
			UINT32 * pulPcrValueLength,	/* out */
			BYTE ** prgbPcrValue)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_PCRVALUE outDigest;
	TSS_RESULT result;
	BYTE *inDigest;
	UINT32 number;
	TSS_HCONTEXT tspContext;

	if (pulPcrValueLength == NULL || prgbPcrValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulPcrDataLength > 0 && pbPcrData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	inDigest = malloc(TCPA_DIGEST_SIZE);
	if (inDigest == NULL) {
		LogError("malloc of %zd bytes failed.", TCPA_DIGEST_SIZE);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if ((result = Trspi_Hash(TSS_HASH_SHA1, ulPcrDataLength, pbPcrData, inDigest)))
		return result;

	if ((result = TCSP_Extend(tcsContext, ulPcrIndex, *(TCPA_DIGEST *)inDigest, &outDigest)))
		return result;

	*prgbPcrValue = calloc_tspi(tspContext, sizeof(TCPA_PCRVALUE));
	if (*prgbPcrValue == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TCPA_PCRVALUE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	memcpy(*prgbPcrValue, &outDigest, sizeof(TCPA_PCRVALUE));
	*pulPcrValueLength = sizeof(TCPA_PCRVALUE);

	/* log the event structure if its passed in */
	if (pPcrEvent != NULL) {
		if ((result = TCS_LogPcrEvent(tcsContext, *pPcrEvent, &number))) {
			free(inDigest);
		}
	}

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
