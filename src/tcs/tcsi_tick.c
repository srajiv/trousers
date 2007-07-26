
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsps.h"
#include "req_mgr.h"


TSS_RESULT
TCSP_ReadCurrentTicks_Internal(TCS_CONTEXT_HANDLE hContext,
			       UINT32*            pulCurrentTime,
			       BYTE**             prgbCurrentTime)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset = 0;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = tpm_rqu_build(TPM_ORD_GetTicks, &offset, txBlob, NULL)))
		return result;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result)
		result = tpm_rsp_parse(TPM_ORD_GetTicks, txBlob, paramSize, pulCurrentTime,
				       prgbCurrentTime);

done:
	return result;
}

TSS_RESULT
TCSP_TickStampBlob_Internal(TCS_CONTEXT_HANDLE hContext,
			    TCS_KEY_HANDLE     hKey,
			    TPM_NONCE*         antiReplay,
			    TPM_DIGEST*        digestToStamp,
			    TPM_AUTH*          privAuth,
			    UINT32*            pulSignatureLength,
			    BYTE**             prgbSignature,
			    UINT32*            pulTickCountLength,
			    BYTE**             prgbTickCount)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset = 0;
	TPM_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth) {
		if ((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			goto done;
	}

	if ((result = ensureKeyIsLoaded(hContext, hKey, &keySlot)))
		goto done;

	if ((result = tpm_rqu_build(TPM_ORD_TickStampBlob, &offset, txBlob, keySlot, antiReplay,
				    digestToStamp, privAuth)))
		return result;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto done;
	}

	offset = 10;
	/* 32 is hard coded in the TPM spec, so I'll hard code it here */
	*pulTickCountLength = 32;

	*prgbTickCount = malloc(*pulTickCountLength);
	if (*prgbTickCount == NULL) {
		result = TCSERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	UnloadBlob(&offset, *pulTickCountLength, txBlob, *prgbTickCount);
	UnloadBlob_UINT32(&offset, pulSignatureLength, txBlob);

	*prgbSignature = malloc(*pulSignatureLength);
	if (*prgbSignature == NULL) {
		free(*prgbTickCount);
		result = TCSERR(TSS_E_OUTOFMEMORY);
		goto done;
	}

	UnloadBlob(&offset, *pulSignatureLength, txBlob, *prgbSignature);
	if (privAuth)
		UnloadBlob_Auth(&offset, txBlob, privAuth);
done:
	return result;
}
