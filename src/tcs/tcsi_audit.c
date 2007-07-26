
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
#include "tcs_utils.h"
#include "tcslog.h"
#include "req_mgr.h"

TSS_RESULT
TCSP_SetOrdinalAuditStatus_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				    TPM_AUTH *ownerAuth,		/* in/out */
				    UINT32 ulOrdinal,			/* in */
				    TSS_BOOL bAuditState)		/* in */
{
	TSS_RESULT result;
	UINT64 offset = 0;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		return result;

	if ((result = tpm_rqu_build(TPM_ORD_SetOrdinalAuditStatus, &offset, txBlob, ulOrdinal,
				    bAuditState, ownerAuth)))
		goto done;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}

	LogResult("SetOrdinalAuditStatus", result);

done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);

	return result;
}

TSS_RESULT
TCSP_GetAuditDigest_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			     UINT32 startOrdinal,		/* in */
			     TPM_DIGEST *auditDigest,		/* out */
			     UINT32 *counterValueSize,		/* out */
			     BYTE **counterValue,		/* out */
			     TSS_BOOL *more,			/* out */
			     UINT32 *ordSize,			/* out */
			     UINT32 **ordList)			/* out */
{
	TSS_RESULT result;
	UINT64 offset = 0, old_offset;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = tpm_rqu_build(TPM_ORD_GetAuditDigest, &offset, txBlob, startOrdinal, NULL)))
		return result;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		TPM_COUNTER_VALUE tmpCounterValue;

		old_offset = offset;
		UnloadBlob_COUNTER_VALUE(&offset, txBlob, &tmpCounterValue);
		*counterValueSize = offset - old_offset;
		*counterValue = malloc(*counterValueSize);
		if (*counterValue == NULL) {
			LogError("malloc of %u bytes failed.", *counterValueSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*counterValue, &txBlob[old_offset], *counterValueSize);

		UnloadBlob_DIGEST(&offset, txBlob, auditDigest);
		UnloadBlob_BOOL(&offset, more, txBlob);
		UnloadBlob_UINT32(&offset, ordSize, txBlob);
		*ordList = malloc(*ordSize);
		if (*ordList == NULL) {
			LogError("malloc of %u bytes failed.", *ordSize);
			free(*counterValue);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		UnloadBlob(&offset, *ordSize, txBlob, (BYTE *)*ordList);

		/* ordSize is returned from the TPM as the number of bytes in ordList
		   so ordSize needs to be converted to comply with the TSS spec which
		   returns the number of ordinals contained in ordList */
		*ordSize = *ordSize / sizeof(UINT32);
	}

	LogResult("GetAuditDigest", result);

done:
	return result;
}

TSS_RESULT
TCSP_GetAuditDigestSigned_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE keyHandle,	/* in */
				   TSS_BOOL closeAudit,		/* in */
				   TPM_NONCE antiReplay,	/* in */
				   TPM_AUTH *privAuth,		/* in/out */
				   UINT32 *counterValueSize,	/* out */
				   BYTE **counterValue,		/* out */
				   TPM_DIGEST *auditDigest,	/* out */
				   TPM_DIGEST *ordinalDigest,	/* out */
				   UINT32 *sigSize,		/* out */
				   BYTE **sig)			/* out */
{
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	UINT64 offset = 0, old_offset;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL)
		if ((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			return result;

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	if ((result = tpm_rqu_build(TPM_ORD_GetAuditDigestSigned, &offset, txBlob, keySlot,
				    closeAudit, antiReplay.nonce, privAuth)))
		goto done;

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		TPM_COUNTER_VALUE tmpCounterValue;

		old_offset = offset;
		UnloadBlob_COUNTER_VALUE(&offset, txBlob, &tmpCounterValue);
		*counterValueSize = offset - old_offset;
		*counterValue = malloc(*counterValueSize);
		if (*counterValue == NULL) {
			LogError("malloc of %u bytes failed.", *counterValueSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*counterValue, &txBlob[old_offset], *counterValueSize);

		UnloadBlob_DIGEST(&offset, txBlob, auditDigest);
		UnloadBlob_DIGEST(&offset, txBlob, ordinalDigest);
		UnloadBlob_UINT32(&offset, sigSize, txBlob);
		*sig = malloc(*sigSize);
		if (*sig == NULL) {
			LogError("malloc of %u bytes failed.", *sigSize);
			free(*counterValue);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig);

		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}

	LogResult("GetAuditDigestSigned", result);

done:
	auth_mgr_release_auth(privAuth, NULL, hContext);

	return result;
}
