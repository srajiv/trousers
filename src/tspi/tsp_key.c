
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <stdlib.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


void
free_key_refs(TCPA_KEY *key)
{
	free(key->algorithmParms.parms);
	key->algorithmParms.parms = NULL;
	key->algorithmParms.parmSize = 0;

	free(key->pubKey.key);
	key->pubKey.key = NULL;
	key->pubKey.keyLength = 0;

	free(key->encData);
	key->encData = NULL;
	key->encSize = 0;

	free(key->PCRInfo);
	key->PCRInfo = NULL;
	key->PCRInfoSize = 0;
}

#ifdef TSS_BUILD_TRANSPORT
TSS_RESULT
Transport_EvictKey(TSS_HCONTEXT tspContext,
		   TCS_KEY_HANDLE hKey)
{
	TSS_RESULT result;
	UINT32 handlesLen;
	TCS_HANDLE *handles;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(hKey, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	/* Call ExecuteTransport */
	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = hKey;

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_Terminate_Handle, 0, NULL,
						    &pubKeyHash, &handlesLen, &handles, NULL, NULL,
						    NULL, NULL))) {
		free(handles);
		return result;
	}

	free(handles);

	return result;
}

TSS_RESULT
Transport_GetPubKey(TSS_HCONTEXT   tspContext,
		    TCS_KEY_HANDLE hKey,
		    TPM_AUTH *pAuth,
		    UINT32 *pcPubKeySize,
		    BYTE **prgbPubKey)
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles;
	BYTE *dec = NULL;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(hKey, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	/* Call ExecuteTransport */
	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = hKey;

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_GetPubKey, 0, NULL,
						    &pubKeyHash, &handlesLen, &handles, pAuth, NULL,
						    &decLen, &dec))) {
		free(handles);
		return result;
	}

	free(handles);

	if ((result = add_mem_entry(tspContext, dec)))
		return result;

	*prgbPubKey = dec;
	*pcPubKeySize = decLen;

	return result;
}

TSS_RESULT
Transport_CertifyKey(TSS_HCONTEXT tspContext,	/* in */
		     TCS_KEY_HANDLE certHandle,	/* in */
		     TCS_KEY_HANDLE keyHandle,	/* in */
		     TPM_NONCE * antiReplay,	/* in */
		     TPM_AUTH * certAuth,	/* in, out */
		     TPM_AUTH * keyAuth,	/* in, out */
		     UINT32 * CertifyInfoSize,	/* out */
		     BYTE ** CertifyInfo,	/* out */
		     UINT32 * outDataSize,	/* out */
		     BYTE ** outData)		/* out */
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles;
	BYTE *dec = NULL;
	TPM_DIGEST pubKeyHash1, pubKeyHash2;
	Trspi_HashCtx hashCtx;
	UINT64 offset;
	BYTE data[sizeof(TPM_NONCE)];


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(certHandle, pubKeyHash1.digest)))
		return result;

	if ((result = obj_tcskey_get_pubkeyhash(keyHandle, pubKeyHash2.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash1.digest);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash2.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash1.digest)))
		return result;

	handlesLen = 2;
	if ((handles = malloc(2 * sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", 2 * sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	handles[0] = certHandle;
	handles[1] = keyHandle;

	offset = 0;
	Trspi_LoadBlob_NONCE(&offset, data, antiReplay);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_CertifyKey, sizeof(data),
						    data, &pubKeyHash1, &handlesLen, &handles,
						    certAuth, keyAuth, &decLen, &dec))) {
		free(handles);
		return result;
	}

	free(handles);

	offset = 0;
	Trspi_UnloadBlob_CERTIFY_INFO(&offset, dec, NULL);
	*CertifyInfoSize = offset;

	if ((*CertifyInfo = malloc(*CertifyInfoSize)) == NULL) {
		*CertifyInfoSize = 0;
		free(dec);
		LogError("malloc of %u bytes failed", *CertifyInfoSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_UnloadBlob(&offset, *CertifyInfoSize, dec, *CertifyInfo);
	Trspi_UnloadBlob_UINT32(&offset, outDataSize, dec);

	if ((*outData = malloc(*outDataSize)) == NULL) {
		free(*CertifyInfo);
		*CertifyInfo = NULL;
		*CertifyInfoSize = 0;
		*outDataSize = 0;
		free(dec);
		LogError("malloc of %u bytes failed", *outDataSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *outDataSize, dec, *outData);

	free(dec);

	return result;
}

TSS_RESULT
Transport_CreateWrapKey(TSS_HCONTEXT tspContext,	/* in */
			TCS_KEY_HANDLE hWrappingKey,	/* in */
			TPM_ENCAUTH KeyUsageAuth,	/* in */
			TPM_ENCAUTH KeyMigrationAuth,	/* in */
			UINT32 keyInfoSize,		/* in */
			BYTE * keyInfo,			/* in */
			UINT32 * keyDataSize,		/* out */
			BYTE ** keyData,		/* out */
			TPM_AUTH * pAuth)		/* in, out */
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles;
	BYTE *dec = NULL;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;
	UINT64 offset;
	BYTE *data;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(hWrappingKey, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	/* Call ExecuteTransport */
	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = hWrappingKey;

	if ((data = malloc(2 * sizeof(TPM_ENCAUTH) + keyInfoSize)) == NULL) {
		free(handles);
		LogError("malloc of %zd bytes failed", 2 * sizeof(TPM_ENCAUTH) + keyInfoSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_LoadBlob(&offset, sizeof(TPM_ENCAUTH), data, KeyUsageAuth.authdata);
	Trspi_LoadBlob(&offset, sizeof(TPM_ENCAUTH), data, KeyMigrationAuth.authdata);
	Trspi_LoadBlob(&offset, keyInfoSize, data, keyInfo);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_CreateWrapKey,
						    (2 * sizeof(TPM_ENCAUTH) + keyInfoSize), data,
						    &pubKeyHash, &handlesLen, &handles, pAuth, NULL,
						    &decLen, &dec)))
		goto done;

	*keyDataSize = decLen;
	*keyData = dec;
done:
	free(data);
	free(handles);

	return result;
}

TSS_RESULT
Transport_LoadKeyByBlob(TSS_HCONTEXT     tspContext,
			TCS_KEY_HANDLE   hParentKey,
			UINT32           ulBlobLength,
			BYTE*            rgbBlobData,
			TPM_AUTH*        pAuth,
			TCS_KEY_HANDLE*  phKey,
			TPM_KEY_HANDLE*  phSlot)
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles;
	BYTE *dec = NULL;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(hParentKey, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	/* Call ExecuteTransport */
	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = hParentKey;

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_LoadKey2, ulBlobLength,
						    rgbBlobData, &pubKeyHash, &handlesLen,
						    &handles, pAuth, NULL, &decLen, &dec))) {
		free(handles);
		return result;
	}

	if (handlesLen == 1)
		*phKey = *(TCS_KEY_HANDLE *)handles;
	else
		result = TSPERR(TSS_E_INTERNAL_ERROR);

	free(handles);
	free(dec);

	return result;
}
#endif

