
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
TCSP_GetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCPA_CAPABILITY_AREA capArea,	/* in */
			    UINT32 subCapSize,	/* in */
			    BYTE * subCap,	/* in */
			    UINT32 * respSize,	/* out */
			    BYTE ** resp)	/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	LogDebug("Entering Get Cap");
	offset = 10;
	LoadBlob_UINT32(&offset, capArea, txBlob);
	LoadBlob_UINT32(&offset, subCapSize, txBlob);
	LoadBlob(&offset, subCapSize, txBlob, subCap);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_GetCapability, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, respSize, txBlob);
		*resp = malloc(*respSize);
		if (*resp == NULL) {
			LogError("malloc of %d bytes failed.", *respSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *respSize, txBlob, *resp);
	}
	LogResult("Get Cap", result);
	return result;
}

TSS_RESULT
TCSP_GetCapabilityOwner_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TPM_AUTH * pOwnerAuth,	/* out */
				 TCPA_VERSION * pVersion,	/* out */
				 UINT32 * pNonVolatileFlags,	/* out */
				 UINT32 * pVolatileFlags)	/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Getcap owner");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &pOwnerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_GetCapabilityOwner, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_VERSION(&offset, txBlob, pVersion);
		UnloadBlob_UINT32(&offset, pNonVolatileFlags, txBlob);
		UnloadBlob_UINT32(&offset, pVolatileFlags, txBlob);
		UnloadBlob_Auth(&offset, txBlob, pOwnerAuth);
	}

	LogResult("GetCapowner", result);
done:
	auth_mgr_release_auth(pOwnerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_SetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCPA_CAPABILITY_AREA capArea,	/* in */
			    UINT32 subCapSize,	/* in */
			    BYTE * subCap,	/* in */
			    UINT32 valueSize,	/* in */
			    BYTE * value,	/* in */
			    TPM_AUTH * pOwnerAuth)	/* in, out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &pOwnerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_UINT32(&offset, capArea, txBlob);
	LoadBlob_UINT32(&offset, subCapSize, txBlob);
	LoadBlob(&offset, subCapSize, txBlob, subCap);
	LoadBlob_UINT32(&offset, valueSize, txBlob);
	LoadBlob(&offset, valueSize, txBlob, value);

	if (pOwnerAuth) {
		LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_SetCapability, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_SetCapability, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result)
		UnloadBlob_Auth(&offset, txBlob, pOwnerAuth);

done:
	auth_mgr_release_auth(pOwnerAuth, NULL, hContext);
	return result;
}

