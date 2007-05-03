
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
#include "spi_internal_types.h"
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
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_GetTicks, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto done;
	}

	*prgbCurrentTime = malloc(sizeof(TPM_CURRENT_TICKS));
	if (*prgbCurrentTime == NULL) {
		result = TCSERR(TSS_E_OUTOFMEMORY);
		goto done;
	}

	offset = 10;
	UnloadBlob(&offset, sizeof(TPM_CURRENT_TICKS), txBlob, *prgbCurrentTime);
	*pulCurrentTime = sizeof(TPM_CURRENT_TICKS);
done:
	return result;
}

TSS_RESULT
TCSP_TickStampBlob_Internal(TCS_CONTEXT_HANDLE hContext,
			    TCS_KEY_HANDLE     hKey,
			    TPM_NONCE          antiReplay,
			    TPM_DIGEST         digestToStamp,
			    TPM_AUTH*          privAuth,
			    UINT32*            pulSignatureLength,
			    BYTE**             prgbSignature,
			    UINT32*            pulTickCountLength,
			    BYTE**             prgbTickCount)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
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

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob(&offset, sizeof(TPM_NONCE), txBlob, (BYTE *)&antiReplay);
	LoadBlob(&offset, sizeof(TPM_DIGEST), txBlob, (BYTE *)&digestToStamp);
	if (privAuth) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_TickStampBlob, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_TickStampBlob, txBlob);
	}

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
