
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"


TSS_RESULT
TCSP_Quote_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		    TCS_KEY_HANDLE keyHandle,	/* in */
		    TCPA_NONCE antiReplay,	/* in */
		    UINT32 pcrDataSizeIn,	/* in */
		    BYTE * pcrDataIn,	/* in */
		    TPM_AUTH * privAuth,	/* in, out */
		    UINT32 * pcrDataSizeOut,	/* out */
		    BYTE ** pcrDataOut,	/* out */
		    UINT32 * sigSize,	/* out */
		    BYTE ** sig)	/* out */
{

	UINT64 offset = 0;
	UINT32 paramSize;
	TSS_RESULT result;
	UINT32 keySlot;
	TCPA_PCR_COMPOSITE pcrComp;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering quote");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (privAuth != NULL) {
		LogDebug("Auth Used");
		if ((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No Auth");
	}
	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	if ((result = tpm_rqu_build(TPM_ORD_Quote, &offset, txBlob, keySlot, antiReplay.nonce,
				    pcrDataSizeIn, pcrDataIn, privAuth)))
		goto done;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		if ((result = UnloadBlob_PCR_COMPOSITE(&offset, txBlob, &pcrComp)))
			goto done;
		free(pcrComp.select.pcrSelect);
		free(pcrComp.pcrValue);

		*pcrDataSizeOut = offset - 10;
		*pcrDataOut = calloc(1, *pcrDataSizeOut);
		if (*pcrDataOut == NULL) {
			LogError("malloc of %u bytes failed.", *pcrDataSizeOut);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*pcrDataOut, &txBlob[10], *pcrDataSizeOut);
		UnloadBlob_UINT32(&offset, sigSize, txBlob);
		*sig = calloc(1, *sigSize);
		if (*sig == NULL) {
			free(*pcrDataOut);
			LogError("malloc of %u bytes failed.", *sigSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig);
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
	LogResult("Quote", result);
done:
	auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}

