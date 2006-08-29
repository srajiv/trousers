
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

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_Key_UnloadKey(TSS_HKEY hKey)	/* in */
{
	TCS_KEY_HANDLE hTcsKey;
	TSS_HCONTEXT tcsContext;
	TSS_RESULT result;

	if ((result = obj_rsakey_is_connected(hKey, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &hTcsKey)))
		return result;

	return TCSP_EvictKey(tcsContext, hTcsKey);
}

TSS_RESULT
Tspi_Key_LoadKey(TSS_HKEY hKey,			/* in */
		 TSS_HKEY hUnwrappingKey)	/* in */
{

	TPM_AUTH auth;
	BYTE blob[1000];
	UINT16 offset;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 keyslot;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HCONTEXT tspContext;
	TSS_HPOLICY hPolicy;
	UINT32 keySize;
	BYTE *keyBlob;
	TCS_KEY_HANDLE parentTCSKeyHandle, tcsKey;
	TSS_BOOL usesAuth;
	TPM_AUTH *pAuth;

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if (!obj_is_rsakey(hUnwrappingKey))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_blob(hKey, &keySize, &keyBlob)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hUnwrappingKey, &parentTCSKeyHandle)))
		return result;

	if ((result = obj_rsakey_get_policy(hUnwrappingKey, TSS_POLICY_USAGE,
					    &hPolicy, &usesAuth)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		Trspi_LoadBlob(&offset, keySize, blob, keyBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);
		if ((result = secret_PerformAuth_OIAP(hUnwrappingKey,
						      TPM_ORD_LoadKey,
						      hPolicy, &digest,
						      &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_LoadKeyByBlob(tcsContext,
					parentTCSKeyHandle,
					keySize,
					keyBlob,
					pAuth,
					&tcsKey,
					&keyslot)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, blob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		Trspi_LoadBlob_UINT32(&offset, keyslot, blob);
		Trspi_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);

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
	BYTE hashblob[1024];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	UINT16 offset;
	TSS_HPOLICY hPolicy;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_BOOL usesAuth;
	TCPA_PUBKEY pubKey;

	if (pulPubKeyLength == NULL || prgbPubKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_rsakey_is_connected(hKey, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hPolicy, &usesAuth)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &tcsKeyHandle)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_GetPubKey,
						      hPolicy, &digest,
						      &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_GetPubKey(tcsContext,
				    tcsKeyHandle,
				    pAuth,
				    pulPubKeyLength,
				    prgbPubKey)))
		return result;

	memset(&pubKey, 0, sizeof(TCPA_PUBKEY));

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashblob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		Trspi_LoadBlob(&offset, *pulPubKeyLength, hashblob, *prgbPubKey);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		/* goto error here since prgbPubKey has been set */
		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth)))
			goto error;
	}

	if ((result = obj_rsakey_set_pubkey(hKey, *prgbPubKey)))
		goto error;

	return TSS_SUCCESS;
error:
	free(*prgbPubKey);
	*prgbPubKey = NULL;
	*pulPubKeyLength = 0;
	return result;
}

TSS_RESULT
Tspi_Key_CertifyKey(TSS_HKEY hKey,			/* in */
		    TSS_HKEY hCertifyingKey,		/* in */
		    TSS_VALIDATION * pValidationData)	/* in, out */
{

	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_RESULT result;
	TPM_AUTH certAuth;
	TPM_AUTH keyAuth;
	UINT16 offset = 0;
	BYTE hashBlob[1024];
	TCPA_DIGEST hash;
	TCPA_NONCE antiReplay;
	UINT32 CertifyInfoSize;
	BYTE *CertifyInfo;
	UINT32 outDataSize;
	BYTE *outData;
	TSS_HPOLICY hPolicy;
	TSS_HPOLICY hCertPolicy;
	TCS_KEY_HANDLE certifyTCSKeyHandle, keyTCSKeyHandle;
	BYTE *keyData = NULL;
	UINT32 keyDataSize;
	TCPA_KEY keyContainer;
	TSS_BOOL useAuthCert;
	TSS_BOOL useAuthKey;
	TPM_AUTH *pCertAuth = &certAuth;
	TPM_AUTH *pKeyAuth = &keyAuth;
	TSS_HCONTEXT tspContext;


	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hPolicy, &useAuthKey)))
		return result;

	if ((result = obj_rsakey_get_policy(hCertifyingKey, TSS_POLICY_USAGE,
					    &hCertPolicy, &useAuthCert)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hCertifyingKey, &certifyTCSKeyHandle)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &keyTCSKeyHandle)))
		return result;

	if (pValidationData == NULL) {
		LogDebug("Internal Verify");
		if ((result = internal_GetRandomNonce(tcsContext, &antiReplay)))
			return result;
	} else {
		LogDebug("External Verify");
		if (pValidationData->ulExternalDataLength < sizeof(antiReplay.nonce))
			return TSPERR(TSS_E_BAD_PARAMETER);

		memcpy(antiReplay.nonce, pValidationData->rgbExternalData,
		       sizeof(antiReplay.nonce));
	}

	if (useAuthCert && !useAuthKey)
		return TSPERR(TSS_E_BAD_PARAMETER);

	/* Setup the auths */
	if (useAuthCert || useAuthKey) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		Trspi_LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
	}

	if (useAuthKey) {
		if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_CertifyKey,
						      hPolicy, &hash,
						      &keyAuth)))
			return result;
	} else
		pKeyAuth = NULL;

	if (useAuthCert) {
		if ((result = secret_PerformAuth_OIAP(hCertifyingKey,
						      TPM_ORD_CertifyKey,
						      hCertPolicy, &hash,
						      &certAuth)))
			return result;
	} else
		pCertAuth = NULL;

	if ((result = TCSP_CertifyKey(tcsContext,
				     certifyTCSKeyHandle,
				     keyTCSKeyHandle,
				     antiReplay,
				     pCertAuth,
				     pKeyAuth,
				     &CertifyInfoSize,
				     &CertifyInfo,
				     &outDataSize,
				     &outData))) {
		if (useAuthKey)
			TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
		if (useAuthCert)
			TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);
		return result;
	}

	/* Validate auth */
	if (useAuthCert || useAuthKey) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		Trspi_LoadBlob(&offset, CertifyInfoSize, hashBlob, CertifyInfo);
		Trspi_LoadBlob_UINT32(&offset, outDataSize, hashBlob);
		Trspi_LoadBlob(&offset, outDataSize, hashBlob, outData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		if (useAuthKey) {
			if ((result = obj_policy_validate_auth_oiap(hPolicy, &hash, &keyAuth))) {
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
				if (useAuthCert)
					TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);
				return result;
			}
		}
		if (useAuthCert) {
			if ((result = obj_policy_validate_auth_oiap(hCertPolicy, &hash, &certAuth))) {
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);
				if (useAuthKey)
					TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
				return result;
			}
		}
	}

	if (pValidationData == NULL) {
		if ((result = obj_rsakey_get_blob(hCertifyingKey,
							&keyDataSize, &keyData))) {
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			LogError("Error in calling GetAttribData internally");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		memset(&keyContainer, 0, sizeof(TCPA_KEY));

		offset = 0;
		if ((result = Trspi_UnloadBlob_KEY(&offset, keyData, &keyContainer)))
			return result;

		Trspi_Hash(TSS_HASH_SHA1, CertifyInfoSize, CertifyInfo, hash.digest);

		if ((result = Trspi_Verify(TSS_HASH_SHA1, hash.digest, 20,
					   keyContainer.pubKey.key,
					   keyContainer.pubKey.keyLength,
					   outData, outDataSize))) {
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			free_key_refs(&keyContainer);
			return TSPERR(TSS_E_VERIFICATION_FAILED);
		}
		free_key_refs(&keyContainer);
	} else {
		pValidationData->ulDataLength = CertifyInfoSize;
		pValidationData->rgbData = calloc_tspi(tspContext, CertifyInfoSize);
		if (pValidationData->rgbData == NULL) {
			LogError("malloc of %d bytes failed.", CertifyInfoSize);
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->rgbData, CertifyInfo, CertifyInfoSize);
		pValidationData->ulValidationDataLength = outDataSize;
		pValidationData->rgbValidationData = calloc_tspi(tspContext, outDataSize);
		if (pValidationData->rgbValidationData == NULL) {
			LogError("malloc of %d bytes failed.", outDataSize);
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->rgbValidationData, outData, outDataSize);
#if 0
		memcpy(&pValidationData->versionInfo,
		       getCurrentVersion(tspContext), sizeof (TCPA_VERSION));
#endif
	}

	if (useAuthKey)
		TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
	if (useAuthCert)
		TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Key_CreateKey(TSS_HKEY hKey,		/* in */
		   TSS_HKEY hWrappingKey,	/* in */
		   TSS_HPCRS hPcrComposite)	/* in, may be NULL */
{

	UINT16 offset;
	BYTE hashBlob[0x1000];
	BYTE sharedSecret[20];
	TPM_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hUsagePolicy;
	TSS_HPOLICY hMigPolicy;
	TSS_HPOLICY hWrapPolicy;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	BYTE *keyBlob = NULL;
	UINT32 keySize;
	TCPA_NONCE nonceEvenOSAP;
	UINT32 newKeySize;
	BYTE *newKey;
	TSS_BOOL usesAuth;
	TSS_HCONTEXT tspContext;

	if ((result = obj_rsakey_get_tsp_context(hKey, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hUsagePolicy, &usesAuth)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_MIGRATION, &hMigPolicy, NULL)))
		return result;

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
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	Trspi_LoadBlob(&offset, 20, hashBlob, encAuthUsage.authdata);
	Trspi_LoadBlob(&offset, 20, hashBlob, encAuthMig.authdata);
	Trspi_LoadBlob(&offset, keySize, hashBlob, keyBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	/* Complete the Auth Structure */
	if ((result = secret_PerformAuth_OSAP(hWrappingKey,
					      TPM_ORD_CreateWrapKey,
					      hWrapPolicy, hUsagePolicy,
					      hMigPolicy, sharedSecret, &auth,
					      digest.digest, &nonceEvenOSAP)))
		return result;

	/* Now call the function */
	if ((result = TCSP_CreateWrapKey(tcsContext,
					parentTCSKeyHandle,
					encAuthUsage,
					encAuthMig,
					keySize,
					keyBlob,
					&newKeySize, &newKey, &auth)))
		return result;

	/* Validate the Authorization before using the new key */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	Trspi_LoadBlob(&offset, newKeySize, hashBlob, newKey);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);
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
	UINT16 offset;
	TCPA_KEY keyContainer;
	BYTE hashBlob[1024];
	TCPA_DIGEST digest;
	TSS_HCONTEXT tspContext;

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

	if ((result = obj_policy_get_secret(hUsePolicy, &usage)))
		goto done;

	if ((result = obj_policy_get_secret(hMigPolicy, &migration)))
		goto done;

	memset(&keyContainer, 0, sizeof(TCPA_KEY));

	/* unload the key to be wrapped's blob */
	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(&offset, keyBlob, &keyContainer)))
		return result;

	/* load the key's attributes into an object and get its hash value */
	offset = 0;
	Trspi_LoadBlob_PRIVKEY_DIGEST(&offset, hashBlob, &keyContainer);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

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
	if ((result = obj_rsakey_set_privkey(hKey, encPrivKeyLen, encPrivKey)))
		goto done;

done:
	free_tspi(tspContext, keyPrivBlob);
	free_tspi(tspContext, keyBlob);
	free_tspi(tspContext, wrappingPubKey);
	return result;
}
#if 0
TSS_RESULT
create_migration_blob_encdata(TSS_HENCDATA hDataToMigrate,
			      TSS_HKEY hParentKey,
			      UINT32 ulMigTicketLength,
			      BYTE * rgbMigTicket,
			      UINT32 * pulRandomLength,
			      BYTE ** prgbRandom,
			      UINT32 * pulMigrationBlobLength,
			      BYTE ** prgbMigrationBlob)
{
	TCS_CONTEXT_HANDLE tcsContext;
	TPM_AUTH parentAuth;
	TPM_AUTH entityAuth;
	TCPA_RESULT result;
	UINT16 offset;
	BYTE hashblob[0x1000];
	TCPA_DIGEST digest;
	UINT32 parentKeySize;
	BYTE *parentKeyBlob;
	UINT32 dataToMigrateSize;
	BYTE *dataToMigrateBlob;
	TSS_HPOLICY hParentPolicy;
	TSS_HPOLICY hMigratePolicy;
	TCPA_MIGRATIONKEYAUTH migAuth;
	TCS_KEY_HANDLE parentHandle;
	TPM_AUTH *pParentAuth;
	TSS_BOOL useAuth;
	UINT32 blobSize;
	BYTE *blob;
	TCPA_STORED_DATA storedData;
	TSS_HCONTEXT tspContext;

	if ((result = obj_encdata_get_tsp_context(hDataToMigrate, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_blob(hParentKey, &parentKeySize, &parentKeyBlob)))
		return result;

	if ((result = obj_encdata_get_data(hDataToMigrate, &dataToMigrateSize, &dataToMigrateBlob)))
		return result;

	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE, &hParentPolicy,
					    &useAuth)))
		return result;

	if ((result = obj_encdata_get_policy(hDataToMigrate, TSS_POLICY_MIGRATION, &hMigratePolicy)))
		return result;

	/*  Parsing the migration scheme from the blob and key object */
	memset(&migAuth, 0, sizeof(TCPA_MIGRATIONKEYAUTH));

	offset = 0;
	if ((result = Trspi_UnloadBlob_MigrationKeyAuth(&offset, rgbMigTicket, &migAuth)))
		return result;

	/* free these now, since none are used below */
	free(migAuth.migrationKey.algorithmParms.parms);
	migAuth.migrationKey.algorithmParms.parmSize = 0;
	free(migAuth.migrationKey.pubKey.key);
	migAuth.migrationKey.pubKey.keyLength = 0;
#if 1
	offset = 0;
	if ((result = Trspi_UnloadBlob_STORED_DATA(&offset, dataToMigrateBlob, &storedData)))
		return result;
#endif
	/* Generate the Authorization data */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT16(&offset, migAuth.migrationScheme, hashblob);
	Trspi_LoadBlob(&offset, ulMigTicketLength, hashblob, rgbMigTicket);
#if 1
	Trspi_LoadBlob_UINT32(&offset, storedData.encDataSize, hashblob);
	Trspi_LoadBlob(&offset, storedData.encDataSize, hashblob, storedData.encData);
#else
	Trspi_LoadBlob_UINT32(&offset, dataToMigrateSize, hashblob);
	Trspi_LoadBlob(&offset, dataToMigrateSize, hashblob, dataToMigrateBlob);
#endif
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy,
						      TPM_ORD_CreateMigrationBlob,
						      hParentPolicy, &digest,
						      &parentAuth))) {
			//free(storedData.sealInfo);
			//free(storedData.encData);
			return result;
		}
		pParentAuth = &parentAuth;
	} else
		pParentAuth = NULL;

	if ((result = secret_PerformAuth_OIAP(hDataToMigrate,
					      TPM_ORD_CreateMigrationBlob,
					      hMigratePolicy, &digest,
					      &entityAuth))) {
		//free(storedData.sealInfo);
		//free(storedData.encData);
		return result;
	}

	if ((parentHandle = getTCSKeyHandle(hParentKey)) == NULL_HKEY) {
		//free(storedData.sealInfo);
		//free(storedData.encData);
		return TSPERR(TSS_E_KEY_NOT_LOADED);
	}

	if ((result = TCSP_CreateMigrationBlob(tcsContext, parentHandle, migAuth.migrationScheme,
					       ulMigTicketLength, rgbMigTicket,
					       //storedData.encDataSize, storedData.encData,
					       dataToMigrateSize, dataToMigrateBlob,
					       pParentAuth, &entityAuth, pulRandomLength,
					       prgbRandom, pulMigrationBlobLength,
					       prgbMigrationBlob))) {
		//free(storedData.sealInfo);
		//free(storedData.encData);
		return result;
	}
	//free(storedData.sealInfo);
	//free(storedData.encData);

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT32(&offset, *pulRandomLength, hashblob);
	Trspi_LoadBlob(&offset, *pulRandomLength, hashblob, *prgbRandom);
	Trspi_LoadBlob_UINT32(&offset, *pulMigrationBlobLength, hashblob);
	Trspi_LoadBlob(&offset, *pulMigrationBlobLength, hashblob, *prgbMigrationBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = obj_policy_validate_auth_oiap(hParentPolicy, &digest, &parentAuth)))
			goto error;
	}
	if ((result = obj_policy_validate_auth_oiap(hMigratePolicy, &digest, &entityAuth)))
		goto error;

	if (migAuth.migrationScheme == TSS_MS_REWRAP) {
#if 1
		if ((result = obj_encdata_get_data(hDataToMigrate, &blobSize, &blob)))
			goto error;

		offset = 0;
		if ((result = Trspi_UnloadBlob_STORED_DATA(&offset, blob, &storedData)))
			goto error;

		/* keyContainer.encData = calloc_tspi(tspContext, outDataSize); */
		storedData.encDataSize = *pulMigrationBlobLength;
		memcpy(storedData.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

		offset = 0;
		Trspi_LoadBlob_STORED_DATA(&offset, blob, &storedData);
		free(storedData.sealInfo);
		free(storedData.encData);

		if ((result = obj_encdata_set_data(hDataToMigrate, blobSize, blob)))
			goto error;
#else
		if ((result = obj_encdata_set_data(hDataToMigrate, *pulMigrationBlobLength,
						   *prgbMigrationBlob)))
			goto error;
#endif
	}

	return result;
error:
	if (*pulRandomLength)
		free_tspi(tspContext, prgbRandom);
	free_tspi(tspContext, prgbMigrationBlob);
	return result;
}
#endif

TSS_RESULT
create_migration_blob_key(TSS_HKEY hKeyToMigrate,
			  TSS_HKEY hParentKey,
			  UINT32 ulMigTicketLength,
			  BYTE * rgbMigTicket,
			  UINT32 * pulRandomLength,
			  BYTE ** prgbRandom,
			  UINT32 * pulMigrationBlobLength,
			  BYTE ** prgbMigrationBlob)
{
	TCS_CONTEXT_HANDLE tcsContext;
	TPM_AUTH parentAuth, entityAuth;
	TPM_AUTH *pParentAuth;
	TCPA_RESULT result;
	UINT16 offset;
	BYTE hashblob[0x1000];
	TCPA_DIGEST digest;
	UINT32 parentKeySize;
	BYTE *parentKeyBlob;
	UINT32 keyToMigrateSize;
	BYTE *keyToMigrateBlob;
	TSS_HPOLICY hParentPolicy;
	TSS_HPOLICY hMigratePolicy;
	TCPA_MIGRATIONKEYAUTH migAuth;
	TCPA_KEY tcpaKey;
	TCS_KEY_HANDLE parentHandle;
	TSS_BOOL parentUsesAuth;
	UINT32 blobSize;
	BYTE *blob;
	TCPA_KEY keyContainer;
	TSS_HCONTEXT tspContext;

	if ((result = obj_rsakey_get_tsp_context(hKeyToMigrate, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_blob(hParentKey, &parentKeySize, &parentKeyBlob)))
		return result;

	if ((result = obj_rsakey_get_blob(hKeyToMigrate, &keyToMigrateSize, &keyToMigrateBlob)))
		return result;

	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE, &hParentPolicy,
					    &parentUsesAuth)))
		return result;

	if ((result = obj_rsakey_get_policy(hKeyToMigrate, TSS_POLICY_MIGRATION, &hMigratePolicy,
					    NULL)))
		return result;

	/*  Parsing the migration scheme from the blob and key object */
	memset(&migAuth, 0, sizeof(TCPA_MIGRATIONKEYAUTH));

	offset = 0;
	if ((result = Trspi_UnloadBlob_MigrationKeyAuth(&offset, rgbMigTicket, &migAuth)))
		return result;

	/* free these now, since none are used below */
	free(migAuth.migrationKey.algorithmParms.parms);
	migAuth.migrationKey.algorithmParms.parmSize = 0;
	free(migAuth.migrationKey.pubKey.key);
	migAuth.migrationKey.pubKey.keyLength = 0;

	memset(&tcpaKey, 0, sizeof(TCPA_KEY));

	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(&offset, keyToMigrateBlob, &tcpaKey)))
		return result;

	/* Generate the Authorization data */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT16(&offset, migAuth.migrationScheme, hashblob);
	Trspi_LoadBlob(&offset, ulMigTicketLength, hashblob, rgbMigTicket);
	Trspi_LoadBlob_UINT32(&offset, tcpaKey.encSize, hashblob);
	Trspi_LoadBlob(&offset, tcpaKey.encSize, hashblob, tcpaKey.encData);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (parentUsesAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy,
						      TPM_ORD_CreateMigrationBlob,
						      hParentPolicy, &digest,
						      &parentAuth))) {
			free_key_refs(&tcpaKey);
			return result;
		}
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}

	if ((result = secret_PerformAuth_OIAP(hKeyToMigrate,
					      TPM_ORD_CreateMigrationBlob,
					      hMigratePolicy, &digest,
					      &entityAuth))) {
		free_key_refs(&tcpaKey);
		return result;
	}

	if ((result = obj_rsakey_get_tcs_handle(hParentKey, &parentHandle)))
		return result;

	if ((result = TCSP_CreateMigrationBlob(tcsContext, parentHandle, migAuth.migrationScheme,
					       ulMigTicketLength, rgbMigTicket, tcpaKey.encSize,
					       tcpaKey.encData, pParentAuth, &entityAuth,
					       pulRandomLength, prgbRandom, pulMigrationBlobLength,
					       prgbMigrationBlob))) {
		free_key_refs(&tcpaKey);
		return result;
	}
	free_key_refs(&tcpaKey);

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT32(&offset, *pulRandomLength, hashblob);
	Trspi_LoadBlob(&offset, *pulRandomLength, hashblob, *prgbRandom);
	Trspi_LoadBlob_UINT32(&offset, *pulMigrationBlobLength, hashblob);
	Trspi_LoadBlob(&offset, *pulMigrationBlobLength, hashblob, *prgbMigrationBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (parentUsesAuth) {
		if ((result = obj_policy_validate_auth_oiap(hParentPolicy, &digest, &parentAuth)))
			goto error;
	}

	if ((result = obj_policy_validate_auth_oiap(hMigratePolicy, &digest, &entityAuth)))
		goto error;

	if (migAuth.migrationScheme == TCPA_MS_REWRAP) {
		if ((result = obj_rsakey_get_blob(hKeyToMigrate, &blobSize, &blob)))
			goto error;

		memset(&keyContainer, 0, sizeof(TCPA_KEY));

		offset = 0;
		if ((result = Trspi_UnloadBlob_KEY(&offset, blob, &keyContainer)))
			goto error;

		if (keyContainer.encSize > 0)
			free(keyContainer.encData);

		keyContainer.encSize = *pulMigrationBlobLength;
		keyContainer.encData = *prgbMigrationBlob;

		offset = 0;
		Trspi_LoadBlob_KEY(&offset, hashblob, &keyContainer);

		/* Free manually here since free_key_refs() would free encData, ugh. */
		free(keyContainer.algorithmParms.parms);
		keyContainer.algorithmParms.parms = NULL;
		keyContainer.algorithmParms.parmSize = 0;

		free(keyContainer.pubKey.key);
		keyContainer.pubKey.key = NULL;
		keyContainer.pubKey.keyLength = 0;

		free(keyContainer.PCRInfo);
		keyContainer.PCRInfo = NULL;
		keyContainer.PCRInfoSize = 0;

		if ((result = obj_rsakey_set_tcpakey(hKeyToMigrate, offset, hashblob)))
			goto error;
	}

	return result;
error:
	if (*pulRandomLength)
		free_tspi(tspContext, prgbRandom);
	free_tspi(tspContext, prgbMigrationBlob);
	return result;
}


TSS_RESULT
Tspi_Key_CreateMigrationBlob(TSS_HKEY hKeyToMigrate,		/* in */
			     TSS_HKEY hParentKey,		/* in */
			     UINT32 ulMigTicketLength,		/* in */
			     BYTE * rgbMigTicket,		/* in */
			     UINT32 * pulRandomLength,		/* out */
			     BYTE ** prgbRandom,		/* out */
			     UINT32 * pulMigrationBlobLength,	/* out */
			     BYTE ** prgbMigrationBlob)		/* out */
{
	if (pulRandomLength == NULL || prgbRandom == NULL || rgbMigTicket == NULL ||
	    pulMigrationBlobLength == NULL || prgbMigrationBlob == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (obj_is_rsakey(hKeyToMigrate))
		return create_migration_blob_key(hKeyToMigrate, hParentKey, ulMigTicketLength,
						 rgbMigTicket, pulRandomLength, prgbRandom,
						 pulMigrationBlobLength, prgbMigrationBlob);

	return TSPERR(TSS_E_INVALID_HANDLE);
}

TSS_RESULT
Tspi_Key_ConvertMigrationBlob(TSS_HKEY hKeyToMigrate,		/* in */
			      TSS_HKEY hParentKey,		/* in */
			      UINT32 ulRandomLength,		/* in */
			      BYTE * rgbRandom,			/* in */
			      UINT32 ulMigrationBlobLength,	/* in */
			      BYTE * rgbMigrationBlob)		/* in */
{

	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_RESULT result;
	UINT32 outDataSize;
	BYTE *outData;
	TCS_KEY_HANDLE parentHandle;
	TPM_AUTH parentAuth;
	TSS_HPOLICY hParentPolicy;
	UINT16 offset;
	BYTE hashblob[0x1000];
	TCPA_DIGEST digest;
	TSS_BOOL useAuth;
	TPM_AUTH *pParentAuth;
	UINT32 blobSize;
	BYTE *blob;
	TCPA_KEY keyContainer;
	TSS_HCONTEXT tspContext;

	if ((result = obj_rsakey_get_tsp_context(hKeyToMigrate, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if (!obj_is_rsakey(hParentKey))
		return TSPERR(TSS_E_INVALID_HANDLE);

	/* Get the parent key handle */
	if ((result = obj_rsakey_get_tcs_handle(hParentKey, &parentHandle)))
		return result;

	/* Get the policy */
	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE,
					&hParentPolicy, &useAuth)))
		return result;

	/* Generate the authorization */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ConvertMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT32(&offset, ulMigrationBlobLength, hashblob);
	Trspi_LoadBlob(&offset, ulMigrationBlobLength, hashblob, rgbMigrationBlob);
	Trspi_LoadBlob_UINT32(&offset, ulRandomLength, hashblob);
	Trspi_LoadBlob(&offset, ulRandomLength, hashblob, rgbRandom);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy,
						      TPM_ORD_ConvertMigrationBlob,
						      hParentPolicy, &digest,
						      &parentAuth)))
			return result;
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}

	if ((result = TCSP_ConvertMigrationBlob(tcsContext, parentHandle, ulMigrationBlobLength,
				     rgbMigrationBlob, ulRandomLength, rgbRandom, pParentAuth,
				     &outDataSize, &outData)))
		return result;

	/* add validation */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ConvertMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT32(&offset, outDataSize, hashblob);
	Trspi_LoadBlob(&offset, outDataSize, hashblob, outData);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = obj_policy_validate_auth_oiap(hParentPolicy, &digest, &parentAuth))) {
			free(outData);
			return result;
		}
	}

	if ((result = obj_rsakey_get_blob(hKeyToMigrate, &blobSize, &blob))) {
		free(outData);
		return result;
	}

	memset(&keyContainer, 0, sizeof(TCPA_KEY));

	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(&offset, blob, &keyContainer))) {
		free(outData);
		return result;
	}
	free(blob);

	if (keyContainer.encSize > 0)
		free(keyContainer.encData);

	keyContainer.encSize = outDataSize;
	keyContainer.encData = outData;

	offset = 0;
	Trspi_LoadBlob_KEY(&offset, hashblob, &keyContainer);

	free_key_refs(&keyContainer);

	return obj_rsakey_set_tcpakey(hKeyToMigrate, offset, hashblob);
}
