
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
Tspi_Key_UnloadKey(TSS_HKEY hKey)	/*  in */
{
	TSS_HCONTEXT tcsContext;
	TSS_RESULT result;

	if ((result = obj_rsakey_is_connected(hKey, &tcsContext)))
		return result;

	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
Tspi_Key_LoadKey(TSS_HKEY hKey,			/*  in */
		 TSS_HKEY hUnwrappingKey	/*  in */
    )
{

	TPM_AUTH auth;
	BYTE blob[1000];
	UINT16 offset;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 keyslot;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HCONTEXT tspContext;
	TSS_HKEY phKey;
	TSS_HPOLICY hPolicy;
	UINT32 keySize;
	BYTE *keyBlob;
	TCS_KEY_HANDLE parentTCSKeyHandle;
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

	parentTCSKeyHandle = getTCSKeyHandle(hUnwrappingKey);
	if (parentTCSKeyHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	if ((result = obj_rsakey_get_policy(hUnwrappingKey, TSS_POLICY_USAGE,
					    &hPolicy, &usesAuth)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		Trspi_LoadBlob(&offset, keySize, blob, keyBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);
		if ((result = secret_PerformAuth_OIAP(hPolicy, &digest, &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_LoadKeyByBlob(tcsContext,	/*  in */
					parentTCSKeyHandle,	/* hUnwrappingKey,          // in */
					keySize,	/*  in */
					keyBlob,	/*  in */
					pAuth,	/* &auth,                // in, out */
					&phKey,	/*   this may change.....what to do with the handle? */
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
#if 0
	else {
		if (result = TCSP_LoadKeyByBlob(tcsContext,	// in
						parentTCSKeyHandle,	//hUnwrappingKey,           // in
						keySize,	// in
						keyBlob,	// in
						NULL,	// in, out
						&phKey,	//  this may change.....what to do with the handle?
						&keyslot))
			return result;
	}
#endif

	LogDebug1("Adding key to table");
	addKeyHandle(phKey, hKey);

	LogDebug1("Leaving loadkey");
	return result;
}

TSS_RESULT
Tspi_Key_GetPubKey(TSS_HKEY hKey,		/* in */
		   UINT32 * pulPubKeyLength,	/* out */
		   BYTE ** prgbPubKey		/* out */
    )
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

	if (pulPubKeyLength == NULL || prgbPubKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_rsakey_is_connected(hKey, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hPolicy, &usesAuth)))
		return result;

	tcsKeyHandle = getTCSKeyHandle(hKey);
	if (tcsKeyHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hPolicy, &digest, &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_GetPubKey(tcsContext,	/*  in */
				    tcsKeyHandle,	/* hKey,                          // in */
				    pAuth,	/* &auth,                        // in, out */
				    pulPubKeyLength,	/*  out */
				    prgbPubKey	/*  out */
	    )))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashblob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		Trspi_LoadBlob(&offset, *pulPubKeyLength, hashblob, *prgbPubKey);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth))) {
			free(*prgbPubKey);
			return result;
		}
	}

	if ((result = obj_rsakey_set_pubkey(hKey, *pulPubKeyLength, *prgbPubKey))) {
		free(*prgbPubKey);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Key_CertifyKey(TSS_HKEY hKey,	/*  in */
		    TSS_HKEY hCertifyingKey,	/*  in */
		    TSS_VALIDATION * pValidationData	/*  in, out */
    )
{

	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_RESULT result;
	TPM_AUTH certAuth;
	TPM_AUTH keyAuth;
	UINT16 offset = 0;
	BYTE *hashBlob;
	TCPA_DIGEST hash;
	TCPA_NONCE antiReplay;
	UINT32 CertifyInfoSize;
	BYTE *CertifyInfo;
	UINT32 outDataSize;
	BYTE *outData;
	TSS_HPOLICY hPolicy;
	TSS_HPOLICY hCertPolicy;
	TCS_KEY_HANDLE certifyTCSKeyHandle, keyTCSKeyHandle;
	BYTE verifyInternally = 0;
	BYTE *keyData = NULL;
	UINT32 keyDataSize;
	TCPA_KEY keyContainer;
	TSS_BOOL useAuthCert;
	TSS_BOOL useAuthKey;
	void *pCertAuth = &certAuth;
	void *pKeyAuth = &keyAuth;
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

	certifyTCSKeyHandle = getTCSKeyHandle(hCertifyingKey);
	if (certifyTCSKeyHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	keyTCSKeyHandle = getTCSKeyHandle(hKey);
	if (keyTCSKeyHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	if (pValidationData == NULL)
		verifyInternally = 1;

	if (verifyInternally) {
		LogDebug1("Internal Verify");
		memset(antiReplay.nonce, 0xBB, 20);	/* change to random */
	} else {
		LogDebug1("External Verify");
		memcpy(antiReplay.nonce, &pValidationData->ExternalData, 20);
	}

	if (useAuthCert && !useAuthKey)
		return TSPERR(TSS_E_BAD_PARAMETER);

	/* ===  now setup the auth's */
	if (useAuthCert || useAuthKey) {
		hashBlob = malloc(24);
		if (hashBlob == NULL) {
			LogError("malloc of %d bytes failed.", 24);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		Trspi_LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		free(hashBlob);
	}
#if 0
	else {
		pKeyAuth = pCertAuth = NULL;
	}
#endif
	if (useAuthKey) {
		if ((result = secret_PerformAuth_OIAP(hPolicy, &hash, &keyAuth)))
			return result;
	} else
		pKeyAuth = NULL;

	if (useAuthCert) {
		if ((result = secret_PerformAuth_OIAP(hCertPolicy, &hash, &certAuth))) {
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			return result;
		}
	} else
		pCertAuth = NULL;

	if ((result = TCSP_CertifyKey(tcsContext,	/*  in */
				     certifyTCSKeyHandle,	/* hCertifyingKey,                 // in */
				     keyTCSKeyHandle,	/* hKey,                       // in */
				     antiReplay,	/*  in */
				     pCertAuth,	/* &certAuth,                        // in, out */
				     pKeyAuth,	/* &keyAuth,                          // in, out */
				     &CertifyInfoSize,	/*  out */
				     &CertifyInfo,	/*  out */
				     &outDataSize,	/*  out  data signature */
				     &outData	/*  out */
				))) {
		if (useAuthKey)
			TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
		if (useAuthCert)
			TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);
		return result;
	}

	/* =============================== */
	/*      validate auth */
	if (useAuthCert || useAuthKey) {
		offset = 0;
		hashBlob = malloc(1024);
		if (hashBlob == NULL) {
			LogError("malloc of %d bytes failed.", 1024);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		Trspi_LoadBlob(&offset, CertifyInfoSize, hashBlob, CertifyInfo);
		Trspi_LoadBlob_UINT32(&offset, outDataSize, hashBlob);
		Trspi_LoadBlob(&offset, outDataSize, hashBlob, outData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		free(hashBlob);
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

	if (verifyInternally) {
		if ((result = obj_rsakey_get_blob(hCertifyingKey,
							&keyDataSize, &keyData))) {
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			LogError1("Error in calling GetAttribData internally");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		offset = 0;
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyData, &keyContainer);

		Trspi_Hash(TSS_HASH_SHA1, CertifyInfoSize, CertifyInfo, hash.digest);

		if ((result = Trspi_Verify(TSS_HASH_SHA1, hash.digest, 20,
				       keyContainer.pubKey.key, keyContainer.pubKey.keyLength,
				       outData, outDataSize))) {
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSPERR(TSS_E_VERIFICATION_FAILED);
		}

	} else {
		pValidationData->DataLength = CertifyInfoSize;
		pValidationData->Data = calloc_tspi(tspContext, CertifyInfoSize);
		if (pValidationData->Data == NULL) {
			LogError("malloc of %d bytes failed.", CertifyInfoSize);
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->Data, CertifyInfo, CertifyInfoSize);
		pValidationData->ValidationDataLength = outDataSize;
		pValidationData->ValidationData = calloc_tspi(tspContext, outDataSize);
		if (pValidationData->ValidationData == NULL) {
			LogError("malloc of %d bytes failed.", outDataSize);
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->ValidationData, outData, outDataSize);
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
		   TSS_HPCRS hPcrComposite	/* in, may be NULL */
    )
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
		/* this call triggers the formation of hPcrComposite */
		if ((result = obj_rsakey_set_pcr_data(hKey, hPcrComposite)))
			return result;
#if 0
		offset = 0;
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob, &keyContainer);

		anObject = getAnObjectByHandle(hPcrComposite);
		if (anObject == NULL || anObject->memPointer == NULL) {
			LogError1("Cannot find key by PcrComposite Handle!");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}
#if 0
		/* ---  Stuff the data from the pcr object into the pcrInfo structure */
		memcpy(pcrInfo.digestAtCreation.digest,
				((TCPA_PCR_OBJECT *) anObject->memPointer)->
				digAtCreation.digest, sizeof (TCPA_DIGEST));
		memcpy(pcrInfo.digestAtRelease.digest,
				((TCPA_PCR_OBJECT *) anObject->memPointer)->
				digAtRelease.digest, sizeof (TCPA_DIGEST));
		pcrInfo.pcrSelection.sizeOfSelect =
			((TCPA_PCR_OBJECT *) anObject->memPointer)->
			pcrComposite.select.sizeOfSelect;
		pcrInfo.pcrSelection.pcrSelect =
			calloc_tspi(tspContext, pcrInfo.pcrSelection.sizeOfSelect);
		memcpy(pcrInfo.pcrSelection.pcrSelect,
				((TCPA_PCR_OBJECT *) anObject->memPointer)->
				pcrComposite.select.pcrSelect, pcrInfo.pcrSelection.sizeOfSelect);
#endif
		/* ---  Now into blob form */
		if ((result = obj_pcrs_get_selection(hPcrComposite, &pcrSelect)))
			return result;

		if ((result = obj_pcrs_get_composite(hPcrComposite, &pcrComposite)))
			return result;

		offset = 0;
		Trspi_LoadBlob_PCR_SELECTION(&offset, pcrInfoData, pcrSelect);
		memcpy(&pcrInfoData[offset], pcrComposite, sizeof(TCPA_PCRVALUE));
		offset += 20;
		memset(&pcrInfoData[offset], 0, 20);
		offset += 20;

		/* ---  Stuff it into the key container */
		pcrInfoSize = offset;
		keyContainer.PCRInfo = calloc_tspi(tspContext, offset);
		if (keyContainer.PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		keyContainer.PCRInfoSize = pcrInfoSize;
		memcpy(keyContainer.PCRInfo, pcrInfoData, pcrInfoSize);

		newKey = calloc_tspi(tspContext, 1024);
		if (newKey == NULL) {
			LogError("malloc of %d bytes failed.", 1024);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		/* ---  New key Blob */
		offset = 0;
		Trspi_LoadBlob_KEY(&offset, newKey, &keyContainer);

		if ((result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB, offset, newKey))) {
			return result;
		}

		if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB, &keySize, &keyBlob))) {
			return result;
		}

		/* keyBlob now has the updated key blob */
#endif
	}

	if ((result = obj_rsakey_get_blob(hKey, &keySize, &keyBlob)))
		return result;

	parentTCSKeyHandle = getTCSKeyHandle(hWrappingKey);
	if (parentTCSKeyHandle == NULL_HKEY) {
		return TSPERR(TSS_E_KEY_NOT_LOADED);
	}

	/*****************************************
	 * To create the authorization, the first step is to call
	 * secret_PerformXOR_OSAP, which will call OSAP and do the xorenc of
	 * the secrets.  Then, the hashdata is done so that
	 * secret_PerformAuth_OSAP can calculate the HMAC.
	 ******************************************/

	/* ---  do the first part of the OSAP */
	if ((result =
	    secret_PerformXOR_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy, hKey,
				   TCPA_ET_KEYHANDLE, parentTCSKeyHandle,
				   &encAuthUsage, &encAuthMig, sharedSecret, &auth, &nonceEvenOSAP)))
		return result;

	/* ---  Setup the Hash Data for the HMAC */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	Trspi_LoadBlob(&offset, 20, hashBlob, encAuthUsage.authdata);
	Trspi_LoadBlob(&offset, 20, hashBlob, encAuthMig.authdata);
	Trspi_LoadBlob(&offset, keySize, hashBlob, keyBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	/* ---  Complete the Auth Structure */
	if ((result = secret_PerformAuth_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy, hKey,
				    sharedSecret, &auth, digest.digest, &nonceEvenOSAP))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		return result;
	}

	/* ---  Now call the function */
	if ((result = TCSP_CreateWrapKey(tcsContext,
					parentTCSKeyHandle,
					encAuthUsage,
					encAuthMig,
					keySize,
					keyBlob,
					&newKeySize, &newKey, &auth))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		return result;
	}

	/* ---  Validate the Authorization before using the new key */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	Trspi_LoadBlob(&offset, newKeySize, hashBlob, newKey);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);
	if ((result = secret_ValidateAuth_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy,
				     sharedSecret, &auth, digest.digest, &nonceEvenOSAP))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		free(newKey);
		return result;
	}

	/* ---  Push the new key into the existing object */
#if 0
	if ((result = Tspi_SetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, newKeySize, newKey))) {
#else
	if ((result = obj_rsakey_set_tcpakey(hKey, newKeySize, newKey))) {
#endif
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		free(newKey);
		return result;
	}

	free(newKey);
	return result;
}

TSS_RESULT
Tspi_Key_WrapKey(TSS_HKEY hKey,			/* in */
		 TSS_HKEY hWrappingKey,		/* in */
		 TSS_HPCRS hPcrComposite	/* in, may be NULL */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy;
	TCPA_SECRET secret;
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

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	memset(&keyContainer, 0, sizeof(TCPA_KEY));

	/* get the key to be wrapped's private key */
	if ((result = obj_rsakey_get_priv_blob(hKey, &keyPrivBlobLen, &keyPrivBlob)))
		goto done;

	/* get the key to be wrapped's blob */
	if ((result = obj_rsakey_get_blob(hKey, &keyBlobLen, &keyBlob)))
		goto done;

	/* get the wrapping key's public key */
	if ((result = obj_rsakey_get_pub_blob(hWrappingKey,
					&wrappingPubKeyLen, &wrappingPubKey)))
		goto done;

	/* get the key to be wrapped's usage policy */
	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hPolicy, NULL)))
		goto done;

	if ((result = obj_policy_get_secret(hPolicy, &secret)))
		return result;

	/* unload the key to be wrapped's blob */
	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob, &keyContainer);

	/* load the key's attributes into an object and get its hash value */
	offset = 0;
	Trspi_LoadBlob_PRIVKEY_DIGEST(&offset, hashBlob, &keyContainer);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	/* create the plaintext private key blob */
	offset = 0;
	Trspi_LoadBlob_BYTE(&offset, TCPA_PT_ASYM, newPrivKey);
	Trspi_LoadBlob(&offset, 20, newPrivKey, secret.authdata);
	Trspi_LoadBlob(&offset, 20, newPrivKey, secret.authdata);
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
	if (keyPrivBlob)
		free_tspi(tspContext, keyPrivBlob);
	if (keyBlob)
		free_tspi(tspContext, keyBlob);
	if (wrappingPubKey)
		free_tspi(tspContext, wrappingPubKey);
	return result;
}

TSS_RESULT
Tspi_Key_CreateMigrationBlob(TSS_HKEY hKeyToMigrate,	/*  in */
			     TSS_HKEY hParentKey,	/*  in */
			     UINT32 ulMigTicketLength,	/*  in */
			     BYTE * rgbMigTicket,	/*  in */
			     UINT32 * pulRandomLength,	/*  out */
			     BYTE ** prgbRandom,	/*  out */
			     UINT32 * pulMigrationBlobLength,	/*  out */
			     BYTE ** prgbMigrationBlob	/*  out */
    )
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
	UINT32 keyToMigrateSize;
	BYTE *keyToMigrateBlob;
	TSS_HPOLICY hParentPolicy;
	TSS_HPOLICY hMigratePolicy;
	TCPA_MIGRATIONKEYAUTH migAuth;
	TCPA_KEY tcpaKey;
	TCS_KEY_HANDLE parentHandle;
	TPM_AUTH *pParentAuth;
	TSS_BOOL useAuth;
	UINT32 blobSize;
	BYTE *blob;
	TCPA_KEY keyContainer;
	TCPA_STORED_DATA storedData;
	TSS_HCONTEXT tspContext;
	UINT32 migratingKey = 1;

	if (pulRandomLength == NULL || prgbRandom == NULL || rgbMigTicket == NULL ||
	    pulMigrationBlobLength == NULL || prgbMigrationBlob == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_rsakey(hKeyToMigrate))
		migratingKey = 0;

	if (migratingKey) {
		if ((result = obj_rsakey_get_tsp_context(hKeyToMigrate, &tspContext)))
			return result;
	} else {
		if ((result = obj_encdata_get_tsp_context(hKeyToMigrate, &tspContext)))
			return result;
	}

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_blob(hParentKey,
					&parentKeySize, &parentKeyBlob)))
		return result;

	if (migratingKey) {
		if ((result = obj_rsakey_get_blob(hKeyToMigrate,
						&keyToMigrateSize, &keyToMigrateBlob)))
			return result;
	} else {
		if ((result = obj_encdata_get_data(hKeyToMigrate,
						&keyToMigrateSize, &keyToMigrateBlob)))
			return result;
	}

	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE,
					    &hParentPolicy, &useAuth)))
		return result;

	if ((result = obj_rsakey_get_policy(hKeyToMigrate, TSS_POLICY_MIGRATION,
					    &hMigratePolicy, NULL)))
		return result;

	/* ////////////////////////////////////////////////////////////////////// */
	/*  Parsing the migration scheme from the blob and key object */
	offset = 0;
	Trspi_UnloadBlob_MigrationKeyAuth(tspContext, &offset, &migAuth, rgbMigTicket);

	offset = 0;
	if (migratingKey) {
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyToMigrateBlob, &tcpaKey);
	} else {
		if ((result = Trspi_UnloadBlob_STORED_DATA(tspContext, &offset,
						keyToMigrateBlob, &storedData)))
			return result;
	}

	/* //////////////////////////////////////////////////////////////////////////////////// */
	/* Generate the Authorization data */
	if (migratingKey) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
		Trspi_LoadBlob_UINT16(&offset, migAuth.migrationScheme, hashblob);
		Trspi_LoadBlob(&offset, ulMigTicketLength, hashblob, rgbMigTicket);
		Trspi_LoadBlob_UINT32(&offset, tcpaKey.encSize, hashblob);
		Trspi_LoadBlob(&offset, tcpaKey.encSize, hashblob, tcpaKey.encData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	} else {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
		Trspi_LoadBlob_UINT16(&offset, migAuth.migrationScheme, hashblob);
		Trspi_LoadBlob(&offset, ulMigTicketLength, hashblob, rgbMigTicket);
		Trspi_LoadBlob_UINT32(&offset, storedData.encDataSize, hashblob);
		Trspi_LoadBlob(&offset, storedData.encDataSize, hashblob, storedData.encData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	}
	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy, &digest, &parentAuth)))
			return result;
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}
	if ((result = secret_PerformAuth_OIAP(hMigratePolicy, &digest, &entityAuth))) {
		if (useAuth)
			TCSP_TerminateHandle(tcsContext, parentAuth.AuthHandle);
		return result;
	}

	parentHandle = getTCSKeyHandle(hParentKey);
	if (parentHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	if (migratingKey) {
		if ((result = TCSP_CreateMigrationBlob(tcsContext,
					parentHandle, migAuth.migrationScheme, ulMigTicketLength,
					rgbMigTicket, tcpaKey.encSize, tcpaKey.encData, pParentAuth,
					&entityAuth, pulRandomLength, prgbRandom,
					pulMigrationBlobLength, prgbMigrationBlob))) {
			if (pParentAuth)
				TCSP_TerminateHandle(tcsContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(tcsContext, entityAuth.AuthHandle);
			return result;
		}
	} else {
		if ((result = TCSP_CreateMigrationBlob(tcsContext,
						parentHandle, migAuth.migrationScheme,
						ulMigTicketLength, rgbMigTicket,
						storedData.encDataSize, storedData.encData,
						pParentAuth, &entityAuth, pulRandomLength,
						prgbRandom, pulMigrationBlobLength,
						prgbMigrationBlob))) {
			if (pParentAuth)
				TCSP_TerminateHandle(tcsContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(tcsContext, entityAuth.AuthHandle);
			return result;
		}
	}

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT32(&offset, *pulRandomLength, hashblob);
	Trspi_LoadBlob(&offset, *pulRandomLength, hashblob, *prgbRandom);
	Trspi_LoadBlob_UINT32(&offset, *pulMigrationBlobLength, hashblob);
	Trspi_LoadBlob(&offset, *pulMigrationBlobLength, hashblob, *prgbMigrationBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = obj_policy_validate_auth_oiap(hParentPolicy, &digest, &parentAuth))) {
			if (pParentAuth)
				TCSP_TerminateHandle(tcsContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(tcsContext, entityAuth.AuthHandle);
			return result;
		}
	}
	if ((result = obj_policy_validate_auth_oiap(hMigratePolicy, &digest, &entityAuth))) {
		if (pParentAuth)
			TCSP_TerminateHandle(tcsContext, pParentAuth->AuthHandle);
		TCSP_TerminateHandle(tcsContext, entityAuth.AuthHandle);
		return result;
	}

	if (migAuth.migrationScheme == TSS_MS_REWRAP) {
		if (migratingKey) {
			if ((result = obj_rsakey_get_blob(hKeyToMigrate, &blobSize, &blob)))
				return result;

			offset = 0;
			Trspi_UnloadBlob_KEY(tspContext, &offset, blob, &keyContainer);

			/* keyContainer.encData =       calloc_tspi( tspContext, outDataSize ); */
			keyContainer.encSize = *pulMigrationBlobLength;
			memcpy(keyContainer.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

			offset = 0;
			Trspi_LoadBlob_KEY(&offset, blob, &keyContainer);

			if ((result = obj_rsakey_set_tcpakey(hKeyToMigrate,
							blobSize, blob)))
				return result;

		} else {

			if ((result = obj_encdata_get_data(hKeyToMigrate,
							&blobSize, &blob)))
				return result;

			offset = 0;
			if ((result = Trspi_UnloadBlob_STORED_DATA(tspContext, &offset, blob, &storedData)))
				return result;

			/* keyContainer.encData =       calloc_tspi( tspContext, outDataSize ); */
			storedData.encDataSize = *pulMigrationBlobLength;
			memcpy(storedData.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

			offset = 0;
			Trspi_LoadBlob_STORED_DATA(&offset, blob, &storedData);

			if ((result = obj_encdata_set_data(hKeyToMigrate,
							blobSize, blob)))
				return result;
		}
	}

	return result;
}

TSS_RESULT
Tspi_Key_ConvertMigrationBlob(TSS_HKEY hKeyToMigrate,	/*  in */
			      TSS_HKEY hParentKey,	/*  in */
			      UINT32 ulRandomLength,	/*  in */
			      BYTE * rgbRandom,	/*  in  */
			      UINT32 ulMigrationBlobLength,	/*  in */
			      BYTE * rgbMigrationBlob	/*  in */
    )
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

	/* ///////////////////////////////////////////////////////////////////////////// */
	/*  Get the parent Key */

	parentHandle = getTCSKeyHandle(hParentKey);
	if (parentHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	/* ////////////////////////////////////////////////////////////////////////////// */
	/*  Get the secret  */

	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE,
					&hParentPolicy, &useAuth)))
		return result;

	/* ///////////////////////////////////////////////////////////////////////////// */
	/*   Generate the authorization */

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ConvertMigrationBlob, hashblob);
	Trspi_LoadBlob_UINT32(&offset, ulMigrationBlobLength, hashblob);
	Trspi_LoadBlob(&offset, ulMigrationBlobLength, hashblob, rgbMigrationBlob);
	Trspi_LoadBlob_UINT32(&offset, ulRandomLength, hashblob);
	Trspi_LoadBlob(&offset, ulRandomLength, hashblob, rgbRandom);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy, &digest, &parentAuth)))
			return result;
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}

/* 	if( result = secret_PerformAuth_OIAP( hParentPolicy, digest, &parentAuth )) */
/* 		return result; */

	if ((result = TCSP_ConvertMigrationBlob(tcsContext, parentHandle, ulMigrationBlobLength,
				     rgbMigrationBlob, pParentAuth, ulRandomLength, rgbRandom,
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
		if ((result = obj_policy_validate_auth_oiap(hParentPolicy, &digest, &parentAuth)))
			return result;
	}

	result = obj_rsakey_get_blob(hKeyToMigrate, &blobSize, &blob);
	if (result)
		return result;

	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, blob, &keyContainer);

	/* keyContainer.encData =       calloc_tspi( tspContext, outDataSize ); */
	keyContainer.encSize = outDataSize;
	memcpy(keyContainer.encData, outData, outDataSize);

	offset = 0;
	Trspi_LoadBlob_KEY(&offset, blob, &keyContainer);

	return obj_rsakey_set_tcpakey(hKeyToMigrate, blobSize, blob);
}
