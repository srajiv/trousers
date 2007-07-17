
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
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
TCSP_SetOwnerInstall_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TSS_BOOL state)	/* in  */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering SetOwnerInstall");
	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_BOOL(&offset, state, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_SetOwnerInstall, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("SetOwnerInstall", result);
	return result;
}

TSS_RESULT
TCSP_OwnerSetDisable_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TSS_BOOL disableState,	/* in */
			      TPM_AUTH * ownerAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	offset = 10;

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	LoadBlob_BOOL(&offset, disableState, txBlob);
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerSetDisable, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_DisableOwnerClear_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				TPM_AUTH * ownerAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering DisableownerClear");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_DisableOwnerClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("DisableOwnerClear", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_ForceClear_Internal(TCS_CONTEXT_HANDLE hContext)	/* in */
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Force Clear");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A, TPM_ORD_ForceClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Force Clear", result);
	return result;
}

TSS_RESULT
TCSP_DisableForceClear_Internal(TCS_CONTEXT_HANDLE hContext)	/* in */
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Disable Force Clear");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_DisableForceClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Disable Force Clear", result);
	return result;

}

TSS_RESULT
TCSP_PhysicalPresence_Internal(TCS_CONTEXT_HANDLE hContext, /* in */
			TCPA_PHYSICAL_PRESENCE fPhysicalPresence) /* in */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result = TCSERR(TSS_E_NOTIMPL);
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];
	char runlevel;

	runlevel = platform_get_runlevel();

	if (runlevel != 's' && runlevel != 'S' && runlevel != '1') {
		LogInfo("Physical Presence command denied: Must be in single"
				" user mode.");
		return TCSERR(TSS_E_NOTIMPL);
	}

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_UINT16(&offset, fPhysicalPresence, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TSC_ORD_PhysicalPresence, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	return UnloadBlob_Header(txBlob, &paramSize);
}

TSS_RESULT
TCSP_PhysicalDisable_Internal(TCS_CONTEXT_HANDLE hContext)	/* in */
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Physical Disable");
	if ((result = ctx_verify_context(hContext)))
		return result;

	/* XXX ooh, magic */
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_PhysicalDisable, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Physical Disable", result);

	return result;
}

TSS_RESULT
TCSP_PhysicalEnable_Internal(TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Physical Enable");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_PhysicalEnable, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Physical Enable", result);

	return result;
}

TSS_RESULT
TCSP_PhysicalSetDeactivated_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TSS_BOOL state)	/* in */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Physical Set Decativated");
	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_BOOL(&offset, state, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_PhysicalSetDeactivated, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("PhysicalSetDeactivated", result);
	return result;
}

TSS_RESULT
TCSP_SetTempDeactivated_Internal(TCS_CONTEXT_HANDLE hContext)	/* in */
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Set Temp Deactivated");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_SetTempDeactivated, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("SetTempDeactivated", result);

	return result;
}

TSS_RESULT
TCSP_FieldUpgrade_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   UINT32 dataInSize,	/* in */
			   BYTE * dataIn,	/* in */
			   UINT32 * dataOutSize,	/* out */
			   BYTE ** dataOut,	/* out */
			   TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Field Upgrade");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	if (dataInSize != 0) {
		LoadBlob_UINT32(&offset, dataInSize, txBlob);
		LoadBlob(&offset, dataInSize, txBlob, dataIn);
	}
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_FieldUpgrade, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		offset = 10;
		if (dataInSize != 0) {
			UnloadBlob_UINT32(&offset, dataOutSize, txBlob);
			*dataOut = malloc(*dataOutSize);
			if (*dataOut == NULL) {
				LogError("malloc of %u bytes failed.", *dataOutSize);
				result = TCSERR(TSS_E_OUTOFMEMORY);
				goto done;
			}
			UnloadBlob(&offset, *dataOutSize, txBlob, *dataOut);
		}
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Field Upgrade", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_SetRedirection_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			     TCS_KEY_HANDLE keyHandle,	/* in */
			     UINT32 c1,	/* in */
			     UINT32 c2,	/* in */
			     TPM_AUTH * privAuth)	/* in, out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Set Redirection");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (privAuth != NULL) {
		if ((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			goto done;
	}

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot))) {
		result = TCSERR(TSS_E_FAIL);
		goto done;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob_UINT32(&offset, c1, txBlob);
	LoadBlob_UINT32(&offset, c2, txBlob);
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_SetRedirection, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_SetRedirection, txBlob);
	}
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		offset = 10;
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
	LogResult("Set Redirection", result);
done:
	auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_ResetLockValue_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			     TPM_AUTH * ownerAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	offset = 10;

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_ResetLockValue, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result)
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);

done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

