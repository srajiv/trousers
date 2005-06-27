
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

#include "trousers/tss.h"
#include "tcs_tsp.h"
#include "tcs_internal_types.h"
#include "tcs_int_literals.h"
#include "tcs_utils.h"
#include "capabilities.h"
#include "req_mgr.h"
#include "tcslog.h"

#if 0
#include "atmel.h"

TCPA_RESULT
Atmel_TPM_SetState_Internal(TCS_CONTEXT_HANDLE hContext, TCPA_STATE_ID stateID, UINT32 sizeState,
				BYTE * stateValue)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM SetState");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_BYTE(&offset, stateID, txBlob, "state id");
	LoadBlob_UINT32(&offset, sizeState, txBlob, "size");
	LoadBlob(&offset, sizeState, txBlob, stateValue, "value");

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_SetState, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("setState", result);
	return result;
}

TCPA_RESULT
Atmel_TPM_OwnerSetState_Internal(TCS_CONTEXT_HANDLE hContext, TCPA_STATE_ID stateID,
				 UINT32 sizeState, BYTE * stateValue, TCS_AUTH * ownerAuth)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM OwnerSetState");

	do {
		if ((result = ctx_verify_context(hContext)))
			break;

		if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
			break;
	} while (0);
	if (result) {
		internal_TerminateHandle(ownerAuth->AuthHandle);
		return result;
	}

	offset = 10;
	LoadBlob_BYTE(&offset, stateID, txBlob, "state id");
	LoadBlob_UINT32(&offset, sizeState, txBlob, "size");
	LoadBlob(&offset, sizeState, txBlob, stateValue, "value");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerSetState, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("ownersetState", result);
	return result;
}

TCPA_RESULT
Atmel_TPM_GetState_Internal(TCS_CONTEXT_HANDLE hContext,
			    TCPA_STATE_ID stateID,
			    UINT32 * sizeState,
			    BYTE ** stateValue)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM GetState");
	offset = 10;
	LoadBlob_BYTE(&offset, stateID, txBlob, "state id");

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_GetState, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, sizeState, txBlob, "size");
		*stateValue = getSomeMemory(*sizeState, hContext);
		if (*stateValue == NULL) {
			LogError1("Malloc Failure.");
			result = TSS_E_OUTOFMEMORY;
		} else
			UnloadBlob(&offset, *sizeState, txBlob, *stateValue, "value");
	}
	LogResult("get state", result);
	return result;
}

TCPA_RESULT
TPM_Identify(TCS_CONTEXT_HANDLE hContext, BYTE mode, UINT32 inputSize,
	     BYTE * inputValue, UINT32 * outputSize, BYTE ** outData)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM Identify");
	offset = 10;
	LoadBlob_BYTE(&offset, mode, txBlob, "state id");
	LoadBlob_UINT32(&offset, inputSize, txBlob, "input size");
	LoadBlob(&offset, inputSize, txBlob, inputValue, "value");

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_Identify, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, outputSize, txBlob, "output size");
		*outData = getSomeMemory(*outputSize, hContext);
		if (*outData == NULL) {
			LogError1("Malloc Failure.");
			result = TSS_E_OUTOFMEMORY;
		} else
			UnloadBlob(&offset, *outputSize, txBlob, *outData, "out data");
	}
	LogResult("tpm identify", result);
	return result;
}

TCPA_RESULT
TPM_VerifySignature(UINT32 digestSize, BYTE * digest, UINT32 sigSize,
		    BYTE * sig, TCPA_PUBKEY pubSigningKey)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM VerifySig");
	offset = 10;
	LoadBlob_UINT32(&offset, digestSize, txBlob, "digest size");
	LoadBlob(&offset, digestSize, txBlob, digest, "digest");
	LoadBlob_UINT32(&offset, sigSize, txBlob, "sig size");
	LoadBlob(&offset, sigSize, txBlob, sig, "sig");
	LoadBlob_PUBKEY(&offset, txBlob, &pubSigningKey);

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_VerifySignature,
			txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("tpm verify sig", result);
	return result;
}

TCPA_RESULT
TPM_BindV20(TCS_CONTEXT_HANDLE hContext, TCPA_STORE_PUBKEY pubBindingKey,
	    UINT32 dataSize, BYTE * inData, UINT32 * encDataSize,
	    BYTE ** encData)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM BindV20");
	offset = 10;
	LoadBlob_STORE_PUBKEY(&offset, txBlob, &pubBindingKey);
	LoadBlob_UINT32(&offset, dataSize, txBlob, "data size");
	LoadBlob(&offset, dataSize, txBlob, inData, "data");

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_BindV20, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, encDataSize, txBlob, "encData size");
		*encData = getSomeMemory(*encDataSize, hContext);
		if (*encData == NULL) {
			LogError1("Malloc Failure.");
			result = TSS_E_OUTOFMEMORY;
		} else
			UnloadBlob(&offset, *encDataSize, txBlob, *encData, "enc data");
	}
	LogResult("tpm bindV20", result);
	return result;
}

TCPA_RESULT
TSC_PhysicalPresence_Internal(UINT16 physPres)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Phys Pres");
	offset = 10;
	LoadBlob_UINT16(&offset, physPres, txBlob, "flag");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_PhysicalPresence,
			txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Phys Pres", result);

	return result;
}

#endif
