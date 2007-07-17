
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
TCSP_OIAP_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCS_AUTHHANDLE *authHandle,	/* out */
		   TCPA_NONCE *nonce0)	/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering TCSI_OIAP");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_OIAP, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_UINT32(&offset, authHandle, txBlob);
		UnloadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonce0->nonce);
	}

	LogResult("OIAP", result);
	return result;
}

TSS_RESULT
TCSP_OSAP_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCPA_ENTITY_TYPE entityType,	/* in */
		   UINT32 entityValue,	/* in */
		   TCPA_NONCE nonceOddOSAP,	/* in */
		   TCS_AUTHHANDLE * authHandle,	/* out */
		   TCPA_NONCE * nonceEven,	/* out */
		   TCPA_NONCE * nonceEvenOSAP)	/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering OSAP");
	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_UINT16(&offset, entityType, txBlob);
	LoadBlob_UINT32(&offset, entityValue, txBlob);
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonceOddOSAP.nonce);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_OSAP, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, authHandle, txBlob);
		UnloadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonceEven->nonce);
		UnloadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonceEvenOSAP->nonce);
	}
	LogResult("OSAP", result);

	return result;
}

TSS_RESULT
internal_TerminateHandle(TCS_AUTHHANDLE handle)
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	offset = 10;
	LoadBlob_UINT32(&offset, handle, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_Terminate_Handle, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	return UnloadBlob_Header(txBlob, &paramSize);
}

