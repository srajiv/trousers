
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
TCSP_DirWriteAuth_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_DIRINDEX dirIndex,	/* in */
			   TCPA_DIRVALUE newContents,	/* in */
			   TPM_AUTH * ownerAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering dirwriteauth");
	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	if (dirIndex > tpm_metrics.num_dirs) {
		result = TCSERR(TSS_E_BAD_PARAMETER);
		goto done;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, dirIndex, txBlob);
	LoadBlob(&offset, TCPA_DIRVALUE_SIZE, txBlob, newContents.digest);
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_DirWriteAuth, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("DirWriteAuth", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_DirRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCPA_DIRINDEX dirIndex,	/* in */
		      TCPA_DIRVALUE * dirValue)	/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering DirRead");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (dirValue == NULL)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if (dirIndex > tpm_metrics.num_dirs)
		return TCSERR(TSS_E_BAD_PARAMETER);

	offset = 10;
	LoadBlob_UINT32(&offset, dirIndex, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_DirRead, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob(&offset, TCPA_DIRVALUE_SIZE, txBlob, dirValue->digest);
	}
	LogResult("DirRead", result);
	return result;
}

