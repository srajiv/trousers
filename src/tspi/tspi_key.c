
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

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_Key_UnloadKey(TSS_HKEY hKey)	/* in */
{
	TSS_HCONTEXT tspContext;
	TCS_KEY_HANDLE hTcsKey;
	TSS_RESULT result;

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &hTcsKey)))
		return result;

	return TCS_API(tspContext)->EvictKey(tspContext, hTcsKey);
}

TSS_RESULT
Tspi_Key_LoadKey(TSS_HKEY hKey,			/* in */
		 TSS_HKEY hUnwrappingKey)	/* in */
{
	TPM_AUTH auth;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 keyslot;
	TSS_HCONTEXT tspContext;
	TSS_HPOLICY hPolicy;
	UINT32 keySize;
	BYTE *keyBlob;
	TCS_KEY_HANDLE tcsKey, tcsParentHandle;
	TSS_BOOL usesAuth;
	TPM_AUTH *pAuth;
	Trspi_HashCtx hashCtx;
	TPM_COMMAND_CODE ordinal;

	if (!obj_is_rsakey(hUnwrappingKey))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if ((result = obj_context_get_loadkey_ordinal(tspContext, &ordinal)))
		return result;

	if ((result = obj_rsakey_get_blob(hKey, &keySize, &keyBlob)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hUnwrappingKey, &tcsParentHandle)))
		return result;

	if ((result = obj_rsakey_get_policy(hUnwrappingKey, TSS_POLICY_USAGE, &hPolicy,
					    &usesAuth))) {
		free_tspi(tspContext, keyBlob);
		return result;
	}

	if (usesAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, ordinal);
		result |= Trspi_HashUpdate(&hashCtx, keySize, keyBlob);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest))) {
			free_tspi(tspContext, keyBlob);
			return result;
		}

		if ((result = secret_PerformAuth_OIAP(hUnwrappingKey, ordinal, hPolicy, FALSE,
						      &digest, &auth))) {
			free_tspi(tspContext, keyBlob);
			return result;
		}
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCS_API(tspContext)->LoadKeyByBlob(tspContext, tcsParentHandle, keySize,
							 keyBlob, pAuth, &tcsKey, &keyslot))) {
		free_tspi(tspContext, keyBlob);
		return result;
	}

	free_tspi(tspContext, keyBlob);

	if (usesAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, ordinal);
		if (ordinal == TPM_ORD_LoadKey)
			result |= Trspi_Hash_UINT32(&hashCtx, keyslot);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth)))
			return result;
	}

	return obj_rsakey_set_tcs_handle(hKey, tcsKey);
}

TSS_RESULT
Tspi_Key_GetPubKey(TSS_HKEY hKey,		/* in */
		   UINT32 * pulPubKeyLength,	/* out */
		   BYTE ** prgbPubKey)		/* out */
{
	TPM_AUTH auth;
	TPM_AUTH *pAuth;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TSS_HCONTEXT tspContext;
	TSS_HPOLICY hPolicy;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_BOOL usesAuth;
	Trspi_HashCtx hashCtx;

	if (pulPubKeyLength == NULL || prgbPubKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hPolicy, &usesAuth)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &tcsKeyHandle)))
		return result;

	if (usesAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_GetPubKey);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_GetPubKey, hPolicy, FALSE,
						      &digest, &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCS_API(tspContext)->GetPubKey(tspContext, tcsKeyHandle, pAuth,
						     pulPubKeyLength, prgbPubKey)))
		return result;

	if (usesAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_GetPubKey);
		result |= Trspi_HashUpdate(&hashCtx, *pulPubKeyLength, *prgbPubKey);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto error;

		/* goto error here since prgbPubKey has been set */
		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth)))
			goto error;
	}

	if (tcsKeyHandle == TPM_KEYHND_SRK)
		obj_rsakey_set_pubkey(hKey, TRUE, *prgbPubKey);

	return TSS_SUCCESS;
error:
	free_tspi(tspContext, *prgbPubKey);
	*prgbPubKey = NULL;
	*pulPubKeyLength = 0;
	return result;
}

TSS_RESULT
Tspi_Key_CreateKey(TSS_HKEY hKey,		/* in */
		   TSS_HKEY hWrappingKey,	/* in */
		   TSS_HPCRS hPcrComposite)	/* in, may be NULL */
{
	BYTE sharedSecret[20];
	TPM_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TSS_HPOLICY hUsagePolicy;
	TSS_HPOLICY hMigPolicy = NULL_HPOLICY;
	TSS_HPOLICY hWrapPolicy;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	BYTE *keyBlob = NULL;
	UINT32 keySize;
	TCPA_NONCE nonceEvenOSAP;
	UINT32 newKeySize;
	BYTE *newKey;
	TSS_BOOL usesAuth;
	TSS_HCONTEXT tspContext;
	Trspi_HashCtx hashCtx;

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hUsagePolicy, &usesAuth)))
		return result;

	if (obj_rsakey_is_migratable(hKey)) {
		if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_MIGRATION, &hMigPolicy, NULL)))
			return result;
	}

	if ((result = obj_rsakey_get_policy(hWrappingKey, TSS_POLICY_USAGE, &hWrapPolicy, NULL)))
		return result;

	if (hPcrComposite) {
		/* its possible that hPcrComposite could be a bad handle here,
		 * or that no indices of it are yet set, which would throw
		 * internal error. Blanket both those codes with bad
		 * parameter to help the user out */
		if ((result = obj_rsakey_set_pcr_data(hKey, hPcrComposite)))
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	if ((result = obj_rsakey_get_blob(hKey, &keySize, &keyBlob)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hWrappingKey, &parentTCSKeyHandle)))
		return result;

	/*****************************************
	 * To create the authorization, the first step is to call
	 * secret_PerformXOR_OSAP, which will call OSAP and do the xorenc of
	 * the secrets.  Then, the hashdata is done so that
	 * secret_PerformAuth_OSAP can calculate the HMAC.
	 ******************************************/

	/* Do the first part of the OSAP */
	if ((result =
	    secret_PerformXOR_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy,
				   hWrappingKey, TCPA_ET_KEYHANDLE,
				   parentTCSKeyHandle, &encAuthUsage,
				   &encAuthMig, sharedSecret, &auth,
				   &nonceEvenOSAP)))
		return result;

	/* Setup the Hash Data for the HMAC */
	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CreateWrapKey);
	result |= Trspi_HashUpdate(&hashCtx, sizeof(encAuthUsage.authdata), encAuthUsage.authdata);
	result |= Trspi_HashUpdate(&hashCtx, sizeof(encAuthMig.authdata), encAuthMig.authdata);
	result |= Trspi_HashUpdate(&hashCtx, keySize, keyBlob);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	/* Complete the Auth Structure */
	if ((result = secret_PerformAuth_OSAP(hWrappingKey,
					      TPM_ORD_CreateWrapKey,
					      hWrapPolicy, hUsagePolicy,
					      hMigPolicy, sharedSecret, &auth,
					      digest.digest, &nonceEvenOSAP)))
		return result;

	/* Now call the function */
	if ((result = TCS_API(tspContext)->CreateWrapKey(tspContext, parentTCSKeyHandle,
							 encAuthUsage, encAuthMig, keySize, keyBlob,
							 &newKeySize, &newKey, &auth)))
		return result;

	/* Validate the Authorization before using the new key */
	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CreateWrapKey);
	result |= Trspi_HashUpdate(&hashCtx, newKeySize, newKey);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_ValidateAuth_OSAP(hWrappingKey,
					       TPM_ORD_CreateWrapKey,
					       hWrapPolicy, hUsagePolicy,
					       hMigPolicy, sharedSecret, &auth,
					       digest.digest,
					       &nonceEvenOSAP))) {
		free(newKey);
		return result;
	}

	/* Push the new key into the existing object */
	if ((result = obj_rsakey_set_tcpakey(hKey, newKeySize, newKey))) {
		free(newKey);
		return result;
	}

	free(newKey);
	return result;
}

TSS_RESULT
Tspi_Key_WrapKey(TSS_HKEY hKey,			/* in */
		 TSS_HKEY hWrappingKey,		/* in */
		 TSS_HPCRS hPcrComposite)	/* in, may be NULL */
{
	TSS_HPOLICY hUsePolicy, hMigPolicy;
	TCPA_SECRET usage, migration;
	TSS_RESULT result;
	BYTE *keyPrivBlob = NULL, *wrappingPubKey = NULL, *keyBlob = NULL;
	UINT32 keyPrivBlobLen, wrappingPubKeyLen, keyBlobLen;
	BYTE newPrivKey[214]; /* its not magic, see TPM 1.1b spec p.71 */
	BYTE encPrivKey[256];
	UINT32 newPrivKeyLen = 214, encPrivKeyLen = 256;
	UINT64 offset;
	TCPA_KEY keyContainer;
	//BYTE hashBlob[1024];
	TCPA_DIGEST digest;
	TSS_HCONTEXT tspContext;
	Trspi_HashCtx hashCtx;

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if (hPcrComposite) {
		if ((result = obj_rsakey_set_pcr_data(hKey, hPcrComposite)))
			return result;
	}

	/* get the key to be wrapped's private key */
	if ((result = obj_rsakey_get_priv_blob(hKey, &keyPrivBlobLen, &keyPrivBlob)))
		goto done;

	/* get the key to be wrapped's blob */
	if ((result = obj_rsakey_get_blob(hKey, &keyBlobLen, &keyBlob)))
		goto done;

	/* get the wrapping key's public key */
	if ((result = obj_rsakey_get_modulus(hWrappingKey, &wrappingPubKeyLen, &wrappingPubKey)))
		goto done;

	/* get the key to be wrapped's usage policy */
	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hUsePolicy, NULL)))
		goto done;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_MIGRATION, &hMigPolicy, NULL)))
		goto done;

	if ((result = obj_policy_get_secret(hUsePolicy, TR_SECRET_CTX_NEW, &usage)))
		goto done;

	if ((result = obj_policy_get_secret(hMigPolicy, TR_SECRET_CTX_NEW, &migration)))
		goto done;

	memset(&keyContainer, 0, sizeof(TCPA_KEY));

	/* unload the key to be wrapped's blob */
	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(&offset, keyBlob, &keyContainer)))
		return result;

	/* load the key's attributes into an object and get its hash value */
	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_PRIVKEY_DIGEST(&hashCtx, &keyContainer);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	free_key_refs(&keyContainer);

	/* create the plaintext private key blob */
	offset = 0;
	Trspi_LoadBlob_BYTE(&offset, TCPA_PT_ASYM, newPrivKey);
	Trspi_LoadBlob(&offset, 20, newPrivKey, usage.authdata);
	Trspi_LoadBlob(&offset, 20, newPrivKey, migration.authdata);
	Trspi_LoadBlob(&offset, 20, newPrivKey, digest.digest);
	Trspi_LoadBlob_UINT32(&offset, keyPrivBlobLen, newPrivKey);
	Trspi_LoadBlob(&offset, keyPrivBlobLen, newPrivKey, keyPrivBlob);
	newPrivKeyLen = offset;

	/* encrypt the private key blob */
	if ((result = Trspi_RSA_Encrypt(newPrivKey, newPrivKeyLen, encPrivKey,
					&encPrivKeyLen, wrappingPubKey,
					wrappingPubKeyLen)))
		goto done;

	/* set the new encrypted private key in the wrapped key object */
	if ((result = obj_rsakey_set_privkey(hKey, FALSE, encPrivKeyLen, encPrivKey)))
		goto done;

done:
	free_tspi(tspContext, keyPrivBlob);
	free_tspi(tspContext, keyBlob);
	free_tspi(tspContext, wrappingPubKey);
	return result;
}

TSS_RESULT
Tspi_Context_LoadKeyByBlob(TSS_HCONTEXT tspContext,	/* in */
			   TSS_HKEY hUnwrappingKey,	/* in */
			   UINT32 ulBlobLength,		/* in */
			   BYTE * rgbBlobData,		/* in */
			   TSS_HKEY * phKey)		/* out */
{
	TPM_AUTH auth;
	UINT64 offset;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 keyslot;
	TSS_HPOLICY hPolicy;
	TCS_KEY_HANDLE myTCSKeyHandle;
	TCPA_KEY keyContainer;
	TSS_BOOL useAuth;
	TPM_AUTH *pAuth;
	TSS_FLAG initFlags;
	UINT16 realKeyBlobSize;
	TCPA_KEY_USAGE keyUsage;
	UINT32 pubLen;
	Trspi_HashCtx hashCtx;
	TPM_COMMAND_CODE ordinal;

	if (phKey == NULL || rgbBlobData == NULL )
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_rsakey(hUnwrappingKey))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if ((result = obj_context_get_loadkey_ordinal(tspContext, &ordinal)))
		return result;

	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(&offset, rgbBlobData, &keyContainer)))
		return result;
	realKeyBlobSize = offset;
	pubLen = keyContainer.pubKey.keyLength;
	keyUsage = keyContainer.keyUsage;
	/* free these now, since they're not used below */
	free_key_refs(&keyContainer);

	if ((result = obj_rsakey_get_policy(hUnwrappingKey, TSS_POLICY_USAGE, &hPolicy, &useAuth)))
		return result;

	if (useAuth) {
		/* Create the Authorization */
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, ordinal);
		result |= Trspi_HashUpdate(&hashCtx, ulBlobLength, rgbBlobData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hUnwrappingKey, ordinal, hPolicy, FALSE,
						      &digest, &auth)))
			return result;

		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCS_API(tspContext)->LoadKeyByBlob(tspContext, hUnwrappingKey, ulBlobLength,
							 rgbBlobData, pAuth, &myTCSKeyHandle,
							 &keyslot)))
		return result;

	if (useAuth) {
		/* ---  Validate return auth */
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, ordinal);
		if (ordinal == TPM_ORD_LoadKey)
			result |= Trspi_Hash_UINT32(&hashCtx, keyslot);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth)))
			return result;
	}

	/* ---  Create a new Object */
	initFlags = 0;
	if (pubLen == 0x100)
		initFlags |= TSS_KEY_SIZE_2048;
	else if (pubLen == 0x80)
		initFlags |= TSS_KEY_SIZE_1024;
	else if (pubLen == 0x40)
		initFlags |= TSS_KEY_SIZE_512;

	/* clear the key type field */
	initFlags &= ~TSS_KEY_TYPE_MASK;

	if (keyUsage == TPM_KEY_STORAGE)
		initFlags |= TSS_KEY_TYPE_STORAGE;
	else
		initFlags |= TSS_KEY_TYPE_SIGNING;	/* loading the blob
							   will fix this
							   back to what it
							   should be. */

	if ((result = obj_rsakey_add(tspContext, initFlags, phKey))) {
		LogDebug("Failed create object");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if ((result = obj_rsakey_set_tcpakey(*phKey,realKeyBlobSize, rgbBlobData))) {
		LogDebug("Key loaded but failed to setup the key object"
			  "correctly");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return obj_rsakey_set_tcs_handle(*phKey, myTCSKeyHandle);
}

TSS_RESULT
Tspi_TPM_OwnerGetSRKPubKey(TSS_HTPM hTPM,		/* in */
			   UINT32 * pulPuKeyLength,	/* out */
			   BYTE ** prgbPubKey)		/* out */
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;
	TSS_HCONTEXT tspContext;
	TCS_KEY_HANDLE hKey;
	TPM_AUTH auth;
	Trspi_HashCtx hashCtx;
	TCPA_DIGEST digest;

	if (pulPuKeyLength == NULL || prgbPubKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	hKey = TPM_KEYHND_SRK;

	if ((result = obj_tpm_get_policy(hTPM, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	/* do an owner authorized get capability call */
	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerReadInternalPub);
	result |= Trspi_Hash_UINT32(&hashCtx, hKey);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_OwnerReadInternalPub,
					      hPolicy, FALSE, &digest, &auth)))
		return result;

	if ((result = TCS_API(tspContext)->OwnerReadInternalPub(tspContext, hKey, &auth,
								pulPuKeyLength, prgbPubKey)))
		return result;

	/* Validate return auth */
	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TSS_SUCCESS);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerReadInternalPub);
	result |= Trspi_HashUpdate(&hashCtx, *pulPuKeyLength, *prgbPubKey);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		goto error;

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth)))
		goto error;

	obj_rsakey_set_pubkey(hKey, TRUE, *prgbPubKey);

	if ((result = add_mem_entry(tspContext, *prgbPubKey)))
		goto error;

	return result;

error:
	free(*prgbPubKey);
	pulPuKeyLength = 0;
	return result;
}
