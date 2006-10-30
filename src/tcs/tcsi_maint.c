
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
TCSP_CreateMaintenanceArchive_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TSS_BOOL generateRandom,	/* in */
				       TPM_AUTH * ownerAuth,	/* in, out */
				       UINT32 * randomSize,	/* out */
				       BYTE ** random,	/* out */
				       UINT32 * archiveSize,	/* out */
				       BYTE ** archive)	/* out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Create Main Archive");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_BOOL(&offset, generateRandom, txBlob);
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_CreateMaintenanceArchive, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		offset = 10;
		UnloadBlob_UINT32(&offset, randomSize, txBlob);
		*random = malloc(*randomSize);
		if (*random == NULL) {
			LogError("malloc of %d bytes failed.", *randomSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		} else {
			UnloadBlob(&offset, *randomSize, txBlob, *random);
		}

		UnloadBlob_UINT32(&offset, archiveSize, txBlob);
		*archive = malloc(*archiveSize);
		if (*archive == NULL) {
			free(*random);
			LogError("malloc of %d bytes failed.", *archiveSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		} else {
			UnloadBlob(&offset, *archiveSize, txBlob, *archive);
		}

		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Create Main Archive", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_LoadMaintenanceArchive_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				     UINT32 dataInSize,	/* in */
				     BYTE * dataIn,	/* in */
				     TPM_AUTH * ownerAuth,	/* in, out */
				     UINT32 * dataOutSize,	/* out */
				     BYTE ** dataOut)	/* out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Load Maint Archive");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	if (dataInSize != 0) {
		LoadBlob_UINT32(&offset, dataInSize, txBlob);
		LoadBlob(&offset, dataInSize, txBlob, dataIn);
	}
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_LoadMaintenanceArchive, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		offset = 10;
		if (dataInSize != 0) {
			UnloadBlob_UINT32(&offset, dataOutSize, txBlob);
			*dataOut = calloc(1, *dataOutSize);
			if (*dataOut == NULL) {
				LogError("malloc of %u bytes failed.", *dataOutSize);
				result = TCSERR(TSS_E_OUTOFMEMORY);
				goto done;
			}
			UnloadBlob(&offset, *dataOutSize, txBlob, *dataOut);
		}
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Load Maint Archive", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_KillMaintenanceFeature_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_KillMaintenanceFeature, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		offset = 10;
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_LoadManuMaintPub_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCPA_NONCE antiReplay,	/* in */
			       UINT32 PubKeySize,	/* in */
			       BYTE * PubKey,	/* in */
			       TCPA_DIGEST * checksum)	/* out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Load Manu Maint Pub");

	offset = 10;
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce);
	LoadBlob(&offset, PubKeySize, txBlob, PubKey);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_LoadManuMaintPub, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		offset = 10;
		UnloadBlob(&offset, 20, txBlob, checksum->digest);
	}
	LogResult("Load Manu Maint Pub", result);
	return result;
}

TSS_RESULT
TCSP_ReadManuMaintPub_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCPA_NONCE antiReplay,	/* in */
			       TCPA_DIGEST * checksum)	/* out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Read Manu Maint Pub");

	offset = 10;
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_ReadManuMaintPub, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		offset = 10;
		UnloadBlob(&offset, 20, txBlob, checksum->digest);
	}
	LogResult("Read Manu Maint Pub", result);
	return result;
}

