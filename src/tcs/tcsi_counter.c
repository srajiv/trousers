
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
TCSP_ReadCounter_Internal(TCS_CONTEXT_HANDLE hContext,
			  TSS_COUNTER_ID     idCounter,
			  TPM_COUNTER_VALUE* counterValue)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, idCounter, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_ReadCounter, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto out;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto out;
	}

	offset = 10;
	UnloadBlob_COUNTER_VALUE(&offset, txBlob, counterValue);

out:
	return result;
}

TSS_RESULT
TCSP_CreateCounter_Internal(TCS_CONTEXT_HANDLE hContext,
			    UINT32             LabelSize,
			    BYTE*              pLabel,
			    TPM_ENCAUTH        CounterAuth,
			    TPM_AUTH*          pOwnerAuth,
			    TSS_COUNTER_ID*    idCounter,
			    TPM_COUNTER_VALUE* counterValue)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if (LabelSize != 4) {
		LogDebugFn("BAD_PARAMETER: LabelSize != 4");
		return TCSERR(TSS_E_BAD_PARAMETER);
	}

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, &pOwnerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob(&offset, sizeof(TPM_ENCAUTH), txBlob, (BYTE *)&CounterAuth);
	LoadBlob(&offset, 4, txBlob, pLabel);
	LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_CreateCounter, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto out;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto out;
	}

	offset = 10;
	UnloadBlob_UINT32(&offset, idCounter, txBlob);
	UnloadBlob_COUNTER_VALUE(&offset, txBlob, counterValue);
	UnloadBlob_Auth(&offset, txBlob, pOwnerAuth);

out:
	return result;
}

TSS_RESULT
TCSP_IncrementCounter_Internal(TCS_CONTEXT_HANDLE hContext,
			       TSS_COUNTER_ID     idCounter,
			       TPM_AUTH*          pCounterAuth,
			       TPM_COUNTER_VALUE* counterValue)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, &pCounterAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, idCounter, txBlob);
	LoadBlob_Auth(&offset, txBlob, pCounterAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_IncrementCounter, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto out;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto out;
	}

	offset = 10;
	UnloadBlob_COUNTER_VALUE(&offset, txBlob, counterValue);
	UnloadBlob_Auth(&offset, txBlob, pCounterAuth);
out:
	return result;
}

TSS_RESULT
TCSP_ReleaseCounter_Internal(TCS_CONTEXT_HANDLE hContext,
			     TSS_COUNTER_ID     idCounter,
			     TPM_AUTH*          pCounterAuth)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, &pCounterAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, idCounter, txBlob);
	LoadBlob_Auth(&offset, txBlob, pCounterAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_ReleaseCounter, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto out;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto out;
	}

	offset = 10;
	UnloadBlob_Auth(&offset, txBlob, pCounterAuth);
out:
	return result;
}

TSS_RESULT
TCSP_ReleaseCounterOwner_Internal(TCS_CONTEXT_HANDLE hContext,
				  TSS_COUNTER_ID     idCounter,
				  TPM_AUTH*          pOwnerAuth)
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, &pOwnerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, idCounter, txBlob);
	LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_ReleaseCounterOwner, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto out;

	if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
		LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
		goto out;
	}

	offset = 10;
	UnloadBlob_Auth(&offset, txBlob, pOwnerAuth);
out:
	return result;
}

