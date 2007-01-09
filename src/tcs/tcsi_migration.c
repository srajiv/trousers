
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
TCSP_CreateMigrationBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE parentHandle,	/* in */
				  TSS_MIGRATE_SCHEME migrationType,	/* in */
				  UINT32 MigrationKeyAuthSize,	/* in */
				  BYTE * MigrationKeyAuth,	/* in */
				  UINT32 encDataSize,	/* in */
				  BYTE * encData,	/* in */
				  TPM_AUTH * parentAuth,	/* in, out */
				  TPM_AUTH * entityAuth,	/* in, out */
				  UINT32 * randomSize,	/* out */
				  BYTE ** random,	/* out */
				  UINT32 * outDataSize,	/* out */
				  BYTE ** outData)	/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keyHandle;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering TPM_CreateMigrationBlob");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (parentAuth != NULL) {
		if ((result = auth_mgr_check(hContext, &parentAuth->AuthHandle)))
			goto done;
	}

	if ((result = auth_mgr_check(hContext, &entityAuth->AuthHandle)))
		goto done;

	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keyHandle)))
		goto done;

	switch (migrationType) {
		case TSS_MS_MIGRATE:
			migrationType = TCPA_MS_MIGRATE;
			break;
		case TSS_MS_REWRAP:
			migrationType = TCPA_MS_REWRAP;
			break;
		case TSS_MS_MAINT:
			migrationType = TCPA_MS_MAINT;
			break;
		default:
			/* Let the TPM return an error */
			break;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keyHandle, txBlob);
	LoadBlob_UINT16(&offset, migrationType, txBlob);
	LoadBlob(&offset, MigrationKeyAuthSize, txBlob, MigrationKeyAuth);
	LoadBlob_UINT32(&offset, encDataSize, txBlob);
	LoadBlob(&offset, encDataSize, txBlob, encData);
	if (parentAuth) {
		LoadBlob_Auth(&offset, txBlob, parentAuth);
		LoadBlob_Auth(&offset, txBlob, entityAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, offset,
				TPM_ORD_CreateMigrationBlob, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, entityAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
				TPM_ORD_CreateMigrationBlob, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (result == TSS_SUCCESS) {
		UnloadBlob_UINT32(&offset, randomSize, txBlob);
		*random = calloc(1, *randomSize);
		if (*random == NULL) {
			LogError("malloc of %u bytes failed.", *randomSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		UnloadBlob(&offset, *randomSize, txBlob, *random);
		UnloadBlob_UINT32(&offset, outDataSize, txBlob);
		*outData = calloc(1, *outDataSize);
		if (*outData == NULL) {
			free(*random);
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		} else {
			UnloadBlob(&offset, *outDataSize, txBlob, *outData);
		}
		if (parentAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, parentAuth);
		UnloadBlob_Auth(&offset, txBlob, entityAuth);
	}
	LogResult("TPM_CreateMigrationBlob", result);

done:
	auth_mgr_release_auth(entityAuth, parentAuth, hContext);
	return result;
}

TSS_RESULT
TCSP_ConvertMigrationBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE parentHandle,	/* in */
				   UINT32 inDataSize,	/* in */
				   BYTE * inData,	/* in */
				   UINT32 randomSize,	/* in */
				   BYTE * random,	/* in */
				   TPM_AUTH * parentAuth,	/* in, out */
				   UINT32 * outDataSize,	/* out */
				   BYTE ** outData)	/* out */
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("ConvertMigBlob");
	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (parentAuth != NULL) {
		LogDebug("Auth Used");
		if ((result = auth_mgr_check(hContext, &parentAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No Auth");
	}
	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keySlot)))
		goto done;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob_UINT32(&offset, inDataSize, txBlob);
	LoadBlob(&offset, inDataSize, txBlob, inData);
	LoadBlob_UINT32(&offset, randomSize, txBlob);
	LoadBlob(&offset, randomSize, txBlob, random);
	if (parentAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, parentAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset,
				TPM_ORD_ConvertMigrationBlob, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_ConvertMigrationBlob, txBlob);
	}

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
			UnloadBlob(&offset, *outDataSize, txBlob, *outData);
		}
		if (parentAuth != NULL) {
			UnloadBlob_Auth(&offset, txBlob, parentAuth);
		}
	}
	LogResult("***Leaving ConvertMigrationBlob with result ", result);
done:
	auth_mgr_release_auth(parentAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_AuthorizeMigrationKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				    TSS_MIGRATE_SCHEME migrateScheme,	/* in */
				    UINT32 MigrationKeySize,	/* in */
				    BYTE * MigrationKey,	/* in */
				    TPM_AUTH * ownerAuth,	/* in, out */
				    UINT32 * MigrationKeyAuthSize,	/* out */
				    BYTE ** MigrationKeyAuth)	/* out */
{

	TSS_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	TCPA_MIGRATIONKEYAUTH container;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("TCSP_AuthorizeMigrationKey");
	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	switch (migrateScheme) {
		case TSS_MS_MIGRATE:
			migrateScheme = TCPA_MS_MIGRATE;
			break;
		case TSS_MS_REWRAP:
			migrateScheme = TCPA_MS_REWRAP;
			break;
		case TSS_MS_MAINT:
			migrateScheme = TCPA_MS_MAINT;
			break;
		default:
			/* Let the TPM return an error */
			break;
	}

	offset = 10;
	LoadBlob_UINT16(&offset, migrateScheme, txBlob);
	LoadBlob(&offset, MigrationKeySize, txBlob, MigrationKey);
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_AuthorizeMigrationKey, txBlob);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		if ((result = UnloadBlob_MIGRATIONKEYAUTH(&offset, txBlob, &container)))
			goto done;
		free(container.migrationKey.pubKey.key);
		free(container.migrationKey.algorithmParms.parms);

		*MigrationKeyAuthSize = offset - 10;
		*MigrationKeyAuth = calloc(1, *MigrationKeyAuthSize);
		if (*MigrationKeyAuth == NULL) {
			LogError("malloc of %d bytes failed.", *MigrationKeyAuthSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			memcpy(*MigrationKeyAuth, &txBlob[10], *MigrationKeyAuthSize);
		}

		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogDebugFn("TPM_AuthorizeMigrationKey result: 0x%x", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;

}

