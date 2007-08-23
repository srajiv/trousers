
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Trspi_UnloadBlob_MigrationKeyAuth(UINT64 *offset, BYTE *blob, TCPA_MIGRATIONKEYAUTH *migAuth)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_PUBKEY(offset, blob, &migAuth->migrationKey)))
		return result;

	Trspi_UnloadBlob_UINT16(offset, &migAuth->migrationScheme, blob);
	Trspi_UnloadBlob_DIGEST(offset, blob, &migAuth->digest);

	return TSS_SUCCESS;
}

#ifdef TSS_BUILD_TRANSPORT
TSS_RESULT
Transport_CreateMigrationBlob(TSS_HCONTEXT tspContext,	/* in */
			      TCS_KEY_HANDLE parentHandle,	/* in */
			      TCPA_MIGRATE_SCHEME migrationType,	/* in */
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
	TSS_RESULT result;
	UINT32 handlesLen, dataLen, decLen;
	TCS_HANDLE *handles;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;
	BYTE *data, *dec;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(parentHandle, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = parentHandle;

	dataLen = sizeof(TCPA_MIGRATE_SCHEME) + MigrationKeyAuthSize + encDataSize;
	if ((data = malloc(dataLen)) == NULL) {
		free(handles);
		LogError("malloc of %u bytes failed", dataLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_LoadBlob_UINT16(&offset, migrationType, data);
	Trspi_LoadBlob(&offset, MigrationKeyAuthSize, data, MigrationKeyAuth);
	Trspi_LoadBlob_UINT32(&offset, encDataSize, data);
	Trspi_LoadBlob(&offset, encDataSize, data, encData);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_CreateMigrationBlob,
						    dataLen, data, &pubKeyHash, &handlesLen,
						    &handles, parentAuth, entityAuth, &decLen,
						    &dec))) {
		free(data);
		return result;
	}
	free(data);

	offset = 0;
	Trspi_UnloadBlob_UINT32(&offset, randomSize, dec);

	if ((*random = malloc(*randomSize)) == NULL) {
		free(dec);
		LogError("malloc of %u bytes failed", *randomSize);
		*randomSize = 0;
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *randomSize, dec, *random);

	Trspi_UnloadBlob_UINT32(&offset, outDataSize, dec);

	if ((*outData = malloc(*outDataSize)) == NULL) {
		free(random);
		*random = NULL;
		*randomSize = 0;
		free(dec);
		LogError("malloc of %u bytes failed", *outDataSize);
		*outDataSize = 0;
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *outDataSize, dec, *outData);
	free(dec);

	return result;
}

TSS_RESULT
Transport_ConvertMigrationBlob(TSS_HCONTEXT tspContext,	/* in */
			       TCS_KEY_HANDLE parentHandle,	/* in */
			       UINT32 inDataSize,	/* in */
			       BYTE * inData,	/* in */
			       UINT32 randomSize,	/* in */
			       BYTE * random,	/* in */
			       TPM_AUTH * parentAuth,	/* in, out */
			       UINT32 * outDataSize,	/* out */
			       BYTE ** outData)	/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 handlesLen, dataLen, decLen;
	TCS_HANDLE *handles;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;
	BYTE *data, *dec;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(parentHandle, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = parentHandle;

	dataLen = (2 * sizeof(UINT32)) + randomSize + inDataSize;
	if ((data = malloc(dataLen)) == NULL) {
		free(handles);
		LogError("malloc of %u bytes failed", dataLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, inDataSize, data);
	Trspi_LoadBlob(&offset, inDataSize, data, inData);
	Trspi_LoadBlob_UINT32(&offset, randomSize, data);
	Trspi_LoadBlob(&offset, randomSize, data, random);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_ConvertMigrationBlob,
						    dataLen, data, &pubKeyHash, &handlesLen,
						    &handles, parentAuth, NULL, &decLen, &dec))) {
		free(data);
		return result;
	}
	free(data);

	offset = 0;
	Trspi_UnloadBlob_UINT32(&offset, outDataSize, dec);

	if ((*outData = malloc(*outDataSize)) == NULL) {
		free(dec);
		LogError("malloc of %u bytes failed", *outDataSize);
		*outDataSize = 0;
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *outDataSize, dec, *outData);
	free(dec);

	return result;
}

TSS_RESULT
Transport_AuthorizeMigrationKey(TSS_HCONTEXT tspContext,	/* in */
				TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
				UINT32 MigrationKeySize,	/* in */
				BYTE * MigrationKey,	/* in */
				TPM_AUTH * ownerAuth,	/* in, out */
				UINT32 * MigrationKeyAuthSize,	/* out */
				BYTE ** MigrationKeyAuth)	/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 handlesLen = 0, dataLen, decLen;
	TPM_DIGEST pubKeyHash;
	BYTE *data, *dec;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	dataLen = sizeof(TCPA_MIGRATE_SCHEME) + MigrationKeySize;
	if ((data = malloc(dataLen)) == NULL) {
		LogError("malloc of %u bytes failed", dataLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_LoadBlob_UINT16(&offset, migrateScheme, data);
	Trspi_LoadBlob(&offset, MigrationKeySize, data, MigrationKey);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_AuthorizeMigrationKey,
						    dataLen, data, &pubKeyHash, &handlesLen, NULL,
						    ownerAuth, NULL, &decLen, &dec))) {
		free(data);
		return result;
	}
	free(data);

	*MigrationKeyAuthSize = decLen;
	*MigrationKeyAuth = dec;

	return result;
}

#endif

