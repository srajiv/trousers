
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
TCSP_Seal_Internal(UINT32 sealOrdinal,		/* in */
		   TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCS_KEY_HANDLE keyHandle,	/* in */
		   TCPA_ENCAUTH encAuth,	/* in */
		   UINT32 pcrInfoSize,	/* in */
		   BYTE * PcrInfo,	/* in */
		   UINT32 inDataSize,	/* in */
		   BYTE * inData,	/* in */
		   TPM_AUTH * pubAuth,	/* in, out */
		   UINT32 * SealedDataSize,	/* out */
		   BYTE ** SealedData)	/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	TCPA_KEY_HANDLE keySlot;
	TCPA_STORED_DATA storedData;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Seal");
	if (!pubAuth)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &pubAuth->AuthHandle)))
		goto done;

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	if (keySlot == 0) {
		result = TCSERR(TSS_E_FAIL);
		goto done;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob, encAuth.authdata);
	LoadBlob_UINT32(&offset, pcrInfoSize, txBlob);
	LoadBlob(&offset, pcrInfoSize, txBlob, PcrInfo);
	LoadBlob_UINT32(&offset, inDataSize, txBlob);
	LoadBlob(&offset, inDataSize, txBlob, inData);

	LoadBlob_Auth(&offset, txBlob, pubAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, sealOrdinal, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		if ((result = UnloadBlob_STORED_DATA(&offset, txBlob, &storedData)))
			goto done;
		free(storedData.sealInfo);
		free(storedData.encData);

		*SealedDataSize = offset - 10;
		*SealedData = calloc(1, *SealedDataSize);
		if (*SealedData == NULL) {
			LogError("malloc of %u bytes failed.", *SealedDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*SealedData, &txBlob[10], *SealedDataSize);
		UnloadBlob_Auth(&offset, txBlob, pubAuth);
	}
	LogResult("Seal", result);
done:
	auth_mgr_release_auth(pubAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_Unseal_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		     TCS_KEY_HANDLE parentHandle,	/* in */
		     UINT32 SealedDataSize,	/* in */
		     BYTE * SealedData,	/* in */
		     TPM_AUTH * parentAuth,	/* in, out */
		     TPM_AUTH * dataAuth,	/* in, out */
		     UINT32 * DataSize,	/* out */
		     BYTE ** Data)	/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Unseal");

	if (dataAuth == NULL)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (parentAuth != NULL) {
		LogDebug("Auth used");
		if ((result = auth_mgr_check(hContext, &parentAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No Auth");
	}

	if ((result = auth_mgr_check(hContext, &dataAuth->AuthHandle)))
		goto done;

	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keySlot)))
		goto done;

	if (keySlot == 0) {
		result = TCSERR(TSS_E_FAIL);
		goto done;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob(&offset, SealedDataSize, txBlob, SealedData);
	if (parentAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, parentAuth);
		LoadBlob_Auth(&offset, txBlob, dataAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND,
				offset, TPM_ORD_Unseal, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, dataAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_Unseal, txBlob);
	}
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_UINT32(&offset, DataSize, txBlob);
		*Data = calloc(1, *DataSize);
		if (*Data == NULL) {
			LogError("malloc of %u bytes failed.", *DataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		UnloadBlob(&offset, *DataSize, txBlob, *Data);
		if (parentAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, parentAuth);
		UnloadBlob_Auth(&offset, txBlob, dataAuth);
	}
	LogResult("Unseal", result);
done:
	auth_mgr_release_auth(parentAuth, dataAuth, hContext);
	return result;
}
