
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
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
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
TCSP_Sign_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCS_KEY_HANDLE keyHandle,	/* in */
		   UINT32 areaToSignSize,	/* in */
		   BYTE * areaToSign,	/* in */
		   TPM_AUTH * privAuth,	/* in, out */
		   UINT32 * sigSize,	/* out */
		   BYTE ** sig	/* out */
    )
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Sign");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug("Auth Used");
		if ((result = auth_mgr_check(hContext, privAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No Auth");
	}

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		goto done;

	offset = 10;

	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob_UINT32(&offset, areaToSignSize, txBlob);
	LoadBlob(&offset, areaToSignSize, txBlob, areaToSign);
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_Sign, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_Sign, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_UINT32(&offset, sigSize, txBlob);
		*sig = calloc(1, *sigSize);
		if (*sig == NULL) {
			LogError("malloc of %d bytes failed.", *sigSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig);
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
	LogResult("sign", result);
done:
	auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}

