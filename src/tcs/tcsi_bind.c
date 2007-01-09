
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
#include "spi_internal_types.h"
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
TCSP_UnBind_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		     TCS_KEY_HANDLE keyHandle,	/* in */
		     UINT32 inDataSize,	/* in */
		     BYTE * inData,	/* in */
		     TPM_AUTH * privAuth,	/* in, out */
		     UINT32 * outDataSize,	/* out */
		     BYTE ** outData)	/* out */
{
	UINT32 paramSize;
	TSS_RESULT result;
	UINT64 offset;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering TCSI_UnBind");
	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (privAuth != NULL) {
		LogDebug("Auth Used");
		if ((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No Auth");
	}

	LogDebugFn("calling ensureKeyIsLoaded for TCS handle 0x%x", keyHandle);
	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob_UINT32(&offset, inDataSize, txBlob);
	LoadBlob(&offset, inDataSize, txBlob, inData);
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_UnBind, txBlob);
	} else
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_UnBind, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_UINT32(&offset, outDataSize, txBlob);
		*outData = calloc(1, *outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %d bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, (*outDataSize), txBlob, *outData);
		}
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}

done:
	auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}

