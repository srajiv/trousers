
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

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "tss_crypto.h"

TSS_RESULT
Tspi_Key_UnloadKey(TSS_HKEY hKey)	/*  in */
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;

	if ((result = internal_CheckObjectType_1(hKey, TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = internal_CheckContext_1(hKey, &hContext)))
		return result;

	return TSS_E_NOTIMPL;
}

TSS_RESULT
Tspi_Key_LoadKey(TSS_HKEY hKey,	/*  in */
		 TSS_HKEY hUnwrappingKey	/*  in */
    )
{

	TCS_AUTH auth;
	BYTE blob[1000];
	UINT16 offset;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 keyslot;
	TCS_CONTEXT_HANDLE hContext;
	TSS_HKEY phKey;
	TSS_HPOLICY hPolicy;
	UINT32 keySize;
	BYTE *keyBlob;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	BOOL usesAuth;
	TCS_AUTH *pAuth;

	LogDebug1("Tspi_Key_LoadKey");
	for (;;) {
		if ((result = internal_CheckObjectType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hUnwrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((result = internal_CheckContext_2(hKey, hUnwrappingKey, &hContext)))
			break;	/* return result; */

		if ((result = Tspi_GetAttribData(hKey,
						TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB, &keySize, &keyBlob)))
			break;	/* return result; */

		parentTCSKeyHandle = getTCSKeyHandle(hUnwrappingKey);
		if (parentTCSKeyHandle == 0) {
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}

		if ((result = Tspi_GetPolicyObject(hUnwrappingKey, TSS_POLICY_USAGE, &hPolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hPolicy, &usesAuth)))
			break;	/* return result; */

		break;
	}
	if (result) {
		LogDebug("Failed loadkey with result %.8X", result);
		return result;
	}

	if (usesAuth) {
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		LoadBlob(&offset, keySize, blob, keyBlob);
		TSS_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);
		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_LoadKeyByBlob(hContext,	/*  in */
					parentTCSKeyHandle,	/* hUnwrappingKey,          // in */
					keySize,	/*  in */
					keyBlob,	/*  in */
					pAuth,	/* &auth,                // in, out */
					&phKey,	/*   this may change.....what to do with the handle? */
					&keyslot)))
		return result;

	if (usesAuth) {
		offset = 0;
		LoadBlob_UINT32(&offset, result, blob);
		LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		LoadBlob_UINT32(&offset, keyslot, blob);
		TSS_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth)))
			return result;
	}
#if 0
	else {
		if (result = TCSP_LoadKeyByBlob(hContext,	// in
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
	addNewKeyHandle(phKey, hKey);

	LogDebug1("Leavingf loadkey");
	return result;
}

TSS_RESULT
Tspi_Key_GetPubKey(TSS_HKEY hKey,	/*  in */
		   UINT32 * pulPubKeyLength,	/*  out */
		   BYTE ** prgbPubKey	/*  out */
    )
{

	TCS_AUTH auth;
	TCS_AUTH *pAuth;
	BYTE hashblob[1024];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE hContext;
	UINT16 offset;
	TSS_HPOLICY hPolicy;
	TCS_KEY_HANDLE tcsKeyHandle;
	BOOL usesAuth;

	if (pulPubKeyLength == NULL || prgbPubKey == NULL)
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_Key_GetPubKey");
	for (;;) {
		if ((result = internal_CheckObjectType_1(hKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((result = internal_CheckContext_1(hKey, &hContext)))
			break;	/* return result; */

		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hPolicy, &usesAuth)))
			break;	/* return result; */

		tcsKeyHandle = getTCSKeyHandle(hKey);
		if (tcsKeyHandle == 0) {
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}
		break;
	}
	if (result) {
		LogDebug("failed getpubkey with result %.8X", result);
		return result;
	}

	if (usesAuth) {
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth)))
			return result;
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_GetPubKey(hContext,	/*  in */
				    tcsKeyHandle,	/* hKey,                          // in */
				    pAuth,	/* &auth,                        // in, out */
				    pulPubKeyLength,	/*  out */
				    prgbPubKey	/*  out */
	    )))
		return result;

	if (usesAuth) {
		offset = 0;
		LoadBlob_UINT32(&offset, result, hashblob);
		LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		LoadBlob(&offset, *pulPubKeyLength, hashblob, *prgbPubKey);
		TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth)))
			return result;
	}
#if 0
	else {
		if (result = TCSP_GetPubKey(hContext,	/*  in */
					    tcsKeyHandle,	/* hKey,                          // in */
					    NULL,	/*  in, out */
					    pulPubKeyLength,	/*  out */
					    prgbPubKey	/*  out */
		    ))
			return result;

	}
#endif
	LogDebug1("Stuffing info into key object");
	if ((result = Tspi_SetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					*pulPubKeyLength, *prgbPubKey)))
		return result;

	LogDebug1("Leaving GetPubKey");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Key_CertifyKey(TSS_HKEY hKey,	/*  in */
		    TSS_HKEY hCertifyingKey,	/*  in */
		    TSS_VALIDATION * pValidationData	/*  in, out */
    )
{

	TCS_CONTEXT_HANDLE hContext;
	TCPA_RESULT result;
	TCS_AUTH certAuth;
	TCS_AUTH keyAuth;
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
	BYTE verfiyInternally = 0;
	BYTE *keyData = NULL;
	UINT32 keyDataSize;
	TCPA_KEY keyContainer;
	BOOL useAuthCert;
	BOOL useAuthKey;
	void *pCertAuth = &certAuth;
	void *pKeyAuth = &keyAuth;


	for (;;) {

		if ((result = internal_CheckObjectType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hCertifyingKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((result = internal_CheckContext_2(hKey, hCertifyingKey, &hContext)))
			break;	/* return result; */

		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hPolicy, &useAuthKey)))
			break;	/* return result; */

		if ((result = Tspi_GetPolicyObject(hCertifyingKey, TSS_POLICY_USAGE, &hCertPolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hCertPolicy, &useAuthCert)))
			break;	/* return result; */

		certifyTCSKeyHandle = getTCSKeyHandle(hCertifyingKey);
		if (certifyTCSKeyHandle == 0) {
			LogDebug1("Failed to get tcs key handle for cert");
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}

		keyTCSKeyHandle = getTCSKeyHandle(hKey);
		if (keyTCSKeyHandle == 0) {
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}

		if (pValidationData == NULL)
			verfiyInternally = 1;

		if (verfiyInternally) {
			LogDebug1("Internal Verify");
			memset(antiReplay.nonce, 0xBB, 20);	/* change to random */
		} else {
			LogDebug1("External Verify");
			memcpy(antiReplay.nonce, pValidationData->rgbExternalData, 20);
		}
		break;
	}
	if (result) {
		LogDebug("Failed certify with result %.8X", result);
		return result;
	}

	if (useAuthCert && !useAuthKey)
		return TSS_E_BAD_PARAMETER;

	/* ===  now setup the auth's */
	if (useAuthCert || useAuthKey) {
		hashBlob = malloc(24);
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);
		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		/*      free( hashBlob ); */
		try_FreeMemory(hashBlob);
	}
#if 0
	else {
		pKeyAuth = pCertAuth = NULL;
	}
#endif
	if (useAuthKey) {
		if ((result = secret_PerformAuth_OIAP(hPolicy, hash, &keyAuth)))
			return result;
	} else
		pKeyAuth = NULL;

	if (useAuthCert) {
		if ((result = secret_PerformAuth_OIAP(hCertPolicy, hash, &certAuth))) {
			if (useAuthKey)
				TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
			return result;
		}
	} else
		pCertAuth = NULL;

	if ((result = TCSP_CertifyKey(hContext,	/*  in */
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
			TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
		if (useAuthCert)
			TCSP_TerminateHandle(hContext, certAuth.AuthHandle);
		return result;
	}

	/* =============================== */
	/*      validate auth */
	if (useAuthCert || useAuthKey) {
		offset = 0;
		hashBlob = malloc(1024);
		LoadBlob_UINT32(&offset, result, hashBlob);
		LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		LoadBlob(&offset, CertifyInfoSize, hashBlob, CertifyInfo);
		LoadBlob_UINT32(&offset, outDataSize, hashBlob);
		LoadBlob(&offset, outDataSize, hashBlob, outData);
		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		/*      free( hashBlob ); */
		try_FreeMemory(hashBlob);
		if (useAuthKey) {
			if ((result = secret_ValidateAuth_OIAP(hPolicy, hash, &keyAuth))) {
				TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
				if (useAuthCert)
					TCSP_TerminateHandle(hContext, certAuth.AuthHandle);
				return result;
			}
		}
		if (useAuthCert) {
			if ((result = secret_ValidateAuth_OIAP(hCertPolicy, hash, &certAuth))) {
				TCSP_TerminateHandle(hContext, certAuth.AuthHandle);
				if (useAuthKey)
					TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
				return result;
			}
		}
	}

	if (verfiyInternally) {
		if ((result = Tspi_GetAttribData(hCertifyingKey, TSS_TSPATTRIB_KEY_BLOB,
				       TSS_TSPATTRIB_KEYBLOB_BLOB, &keyDataSize, &keyData))) {
			if (useAuthKey)
				TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(hContext, certAuth.AuthHandle);

			LogError1("Error in calling GetAttribData internally");
			return TSS_E_INTERNAL_ERROR;
		}

		offset = 0;
		UnloadBlob_KEY(hContext, &offset, keyData, &keyContainer);

		TSS_Hash(TSS_HASH_SHA1, CertifyInfoSize, CertifyInfo, hash.digest);

		if ((result = TSS_Verify(TSS_HASH_SHA1, hash.digest, 20,
				       keyContainer.pubKey.key, keyContainer.pubKey.keyLength,
				       outData, outDataSize))) {
			if (useAuthKey)
				TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(hContext, certAuth.AuthHandle);

			return TSS_E_VERIFICATION_FAILED;
		}

	} else {
		pValidationData->ulDataLength = CertifyInfoSize;
		pValidationData->rgbData = calloc_tspi(hContext, CertifyInfoSize);
		if (pValidationData->rgbData == NULL) {
			LogError("malloc of %d bytes failed.", CertifyInfoSize);
			if (useAuthKey)
				TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(hContext, certAuth.AuthHandle);

			return TSS_E_OUTOFMEMORY;
		}
		memcpy(pValidationData->rgbData, CertifyInfo, CertifyInfoSize);
		pValidationData->ulValidationLength = outDataSize;
		pValidationData->rgbValdationData = calloc_tspi(hContext, outDataSize);
		if (pValidationData->rgbValdationData == NULL) {
			LogError("malloc of %d bytes failed.", outDataSize);
			if (useAuthKey)
				TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(hContext, certAuth.AuthHandle);

			return TSS_E_OUTOFMEMORY;
		}
		memcpy(pValidationData->rgbValdationData, outData, outDataSize);
		memcpy(&pValidationData->versionInfo,
		       getCurrentVersion(hContext), sizeof (TCPA_VERSION));

	}

	if (useAuthKey)
		TCSP_TerminateHandle(hContext, keyAuth.AuthHandle);
	if (useAuthCert)
		TCSP_TerminateHandle(hContext, certAuth.AuthHandle);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Key_CreateKey(TSS_HKEY hKey,	/*  in */
		   TSS_HKEY hWrappingKey,	/*  in */
		   TSS_HPCRS hPcrComposite	/*  in, may be NULL */
    )
{

	UINT16 offset;
	BYTE hashBlob[0x1000];
	BYTE sharedSecret[20];
	TCS_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE hContext;
/* 	TSS_HPOLICY				hPolicy; */
	TSS_HPOLICY hUsagePolicy;
	TSS_HPOLICY hMigPolicy;
	TSS_HPOLICY hWrapPolicy;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	BYTE *keyBlob = NULL;
	UINT32 keySize;
	TCPA_NONCE nonceEvenOSAP;
	UINT32 newKeySize;
	BYTE *newKey;
	BOOL usesAuth;
	TCPA_KEY keyContainer;
	UINT32 pcrInfoSize;
	BYTE pcrInfoData[512];
/* 	BYTE					pcrInfo[512]; */
/* 	TCPA_PCR_INFO			pcrInfo; */
	AnObject *anObject;

	LogDebug1("Tspi_Key_CreateKey");
	for (;;) {
		if (hPcrComposite == 0) {
			if ((result = internal_CheckObjectType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
						       hWrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
				break;	/* return result; */
			if ((result = internal_CheckContext_2(hKey, hWrappingKey, &hContext)))
				break;	/* return result; */
		} else {
			if ((result =
			    internal_CheckObjectType_3(hKey,
						       TSS_OBJECT_TYPE_RSAKEY,
						       hWrappingKey,
						       TSS_OBJECT_TYPE_RSAKEY,
						       hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
				break;	/* return result; */
			if ((result = internal_CheckContext_3(hKey, hWrappingKey, hPcrComposite, &hContext)))
				break;	/* return result; */
		}

		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hUsagePolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hUsagePolicy, &usesAuth)))
			break;	/*        return result; */

		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_MIGRATION, &hMigPolicy)))
			break;	/* return result; */

		if ((result = Tspi_GetPolicyObject(hWrappingKey, TSS_POLICY_USAGE, &hWrapPolicy)))
			break;	/* return result; */

		if ((result = Tspi_GetAttribData(hKey,
						TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB, &keySize, &keyBlob)))
			break;	/* return result; */

		if (hPcrComposite) {
			LogDebug1("Add Pcr info to the key");
			offset = 0;
			UnloadBlob_KEY(hContext, &offset, keyBlob, &keyContainer);

			/* --------------------------- */
			anObject = getAnObjectByHandle(hPcrComposite);
			if (anObject == NULL || anObject->memPointer == NULL) {
				LogError1("Cannot find key by PcrComposite Handle!");
				free(keyBlob);
				return TSS_E_INTERNAL_ERROR;
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
			    calloc_tspi(hContext, pcrInfo.pcrSelection.sizeOfSelect);
			memcpy(pcrInfo.pcrSelection.pcrSelect,
			       ((TCPA_PCR_OBJECT *) anObject->memPointer)->
			       pcrComposite.select.pcrSelect, pcrInfo.pcrSelection.sizeOfSelect);
#endif
			/* ---  Now into blob form */
			offset = 0;
/* 			LoadBlob_PCR_INFO( &offset, pcrInfoData, &pcrInfo ); */
			LoadBlob_PCR_SELECTION(&offset, pcrInfoData,
					       ((TCPA_PCR_OBJECT *) anObject->memPointer)->select);
			memcpy(&pcrInfoData[offset],
			       ((TCPA_PCR_OBJECT *) anObject->memPointer)->compositeHash.digest, 20);
			offset += 20;
/* 			LoadBlob_PCR_INFO( &offset, pcrInfoData, ((TCPA_PCR_OBJECT*)anObject->memPointer)-> */
			memset(&pcrInfoData[offset], 0, 20);
			offset += 20;

			/* ---  Stuff it into the key container */
			pcrInfoSize = offset;
			keyContainer.PCRInfo = malloc(offset);
			if (keyContainer.PCRInfo == NULL) {
				LogError("malloc of %d bytes failed.", offset);
				free(keyBlob);
				return TSS_E_OUTOFMEMORY;
			}
			keyContainer.PCRInfoSize = pcrInfoSize;
			memcpy(keyContainer.PCRInfo, pcrInfoData, pcrInfoSize);

			newKey = malloc(1024);
			if (newKey == NULL) {
				LogError("malloc of %d bytes failed.", 1024);
				free(keyContainer.PCRInfo);
				free(keyBlob);
				return TSS_E_OUTOFMEMORY;
			}

			/* ---  New key Blob */
			offset = 0;
			LoadBlob_KEY(&offset, newKey, &keyContainer);
			free(keyContainer.PCRInfo);

			if ((result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
					   TSS_TSPATTRIB_KEYBLOB_BLOB, offset, newKey))) {
				free(keyBlob);
				try_FreeMemory(newKey);
				return result;
			}
			try_FreeMemory(keyBlob);

			if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
					   TSS_TSPATTRIB_KEYBLOB_BLOB, &keySize, &keyBlob))) {
				try_FreeMemory(newKey);
				return result;
			}
			try_FreeMemory(newKey);

			/* ---  keyBlob now has the updated key blob */
		}

		parentTCSKeyHandle = getTCSKeyHandle(hWrappingKey);
		if (parentTCSKeyHandle == 0) {
			if (hPcrComposite)
				free(keyContainer.PCRInfo);
			free(keyBlob);
			return TSS_E_KEY_NOT_LOADED;
		}

		break;
	}
	if (result) {
		LogDebug("Failed create with result %.8X", result);
		return result;
	}
	/*****************************************
	 *	To create the authorization, the first step is to call secret_PerformXOR_OSAP,
	 *		which will call OSAP and do the xorenc of the secrets.  Then, the hashdata is done
	 *		so that secret_PerformAuth_OSAP can calcualte the HMAC.
	 ******************************************/

	/* ---  do the first part of the OSAP */
	if ((result =
	    secret_PerformXOR_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy, hKey,
				   TCPA_ET_KEYHANDLE, parentTCSKeyHandle,
				   &encAuthUsage, &encAuthMig, sharedSecret, &auth, &nonceEvenOSAP)))
		return result;

	/* ---  Setup the Hash Data for the HMAC */
	offset = 0;
	LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
	LoadBlob(&offset, 20, hashBlob, encAuthMig.encauth);
	LoadBlob(&offset, keySize, hashBlob, keyBlob);
	TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	/* ---  Complete the Auth Structure */
	if ((result = secret_PerformAuth_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy, hKey,
				    sharedSecret, &auth, digest.digest, nonceEvenOSAP))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		return result;
	}

	/* ---  Now call the function */
	if ((result = TCSP_CreateWrapKey(hContext,	/*  in */
					parentTCSKeyHandle,	/*  in */
					encAuthUsage,	/*  in */
					encAuthMig,	/*  in */
					keySize,	/* &pcKeySize,                 // in */
					keyBlob,	/* &pcKey,                             // in */
					&newKeySize, &newKey, &auth	/*  in, out */
	    ))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		return result;
	}

	/* ---  Validate the Authorization before using the new key */
	offset = 0;
	LoadBlob_UINT32(&offset, result, hashBlob);
	LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	LoadBlob(&offset, newKeySize, hashBlob, newKey);
	TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);
	if ((result = secret_ValidateAuth_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy,
				     sharedSecret, &auth, digest.digest, nonceEvenOSAP))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		TCS_FreeMemory(hContext, newKey);
		return result;
	}

	LogDebug1("Stuff data into object");
	/* ---  Push the new key into the existing object */
	if ((result = Tspi_SetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, newKeySize, newKey))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		TCS_FreeMemory(hContext, newKey);
		return result;
	}

	TCS_FreeMemory(hContext, newKey);
	LogDebug1("Leaving Create Key");
	return result;
}

TSS_RESULT
Tspi_Key_WrapKey(TSS_HKEY hKey,	/*  in */
		 TSS_HKEY hWrappingKey,	/*  in */
		 TSS_HPCRS hPcrComposite	/*  in, may be NULL */
    )
{

/* 	TCPA_RSAKEY_OBJECT				*keyObject; */
	AnObject *anObject;
/* 	TCPA_RSAKEY_OBJECT				*wrappingKeyObject; */
	TCS_CONTEXT_HANDLE hContext;
	TSS_HPOLICY hPolicy;
	TCPA_SECRET secret;
	TSS_RESULT result;
/* 	TSS_HPOLICY						hKeyPolicy; */
	TCPA_POLICY_OBJECT *myKeyPolicy;
	UINT32 myPrivLength;
	BYTE *myPriv = NULL;
	UINT32 wrapLength;
	BYTE *wrap;
	UINT16 offset;
	TCPA_KEY keyContainer = {{0, 0, 0, 0}, 0, 0, 0, {0, 0, 0, 0, NULL}, 0, NULL, {0, NULL}, 0, NULL};
	UINT32 pubKeySize;
	BYTE pubKey[260];
	UINT32 myKeyBlobLength;
	BYTE *myKeyBlob;
	BYTE hashBlob[1024];
	TCPA_DIGEST digest;
/* 	UINT32	encDataSize; */
/* 	BYTE	encData[256]; */
	TCPA_NONCE seed;	/* nice container */
	void *keyObject;

	if (hPcrComposite == 0) {
		if ((result = internal_CheckObjectType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hWrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
			return result;
		if ((result = internal_CheckContext_2(hKey, hWrappingKey, &hContext)))
			return result;

	} else {
		if ((result =
		    internal_CheckObjectType_3(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hWrappingKey,
					       TSS_OBJECT_TYPE_RSAKEY,
					       hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
			return result;
		if ((result = internal_CheckContext_3(hKey, hWrappingKey, hPcrComposite, &hContext)))
			return result;
	}

/*	if( result = Tspi_GetAttribData(
		hKey,
		TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY,
		&myPrivLength,
		&myPriv ))
		return result;
*/
	keyObject = getAnObjectByHandle(hKey);
	if (keyObject == NULL || ((AnObject *) keyObject)->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hKey);
		return TSS_E_INTERNAL_ERROR;
	}

	keyObject = ((AnObject *) keyObject)->memPointer;

	myPrivLength = ((TCPA_RSAKEY_OBJECT *) keyObject)->privateKey.Privlen;
	myPriv = malloc(myPrivLength);
	if (myPriv == NULL) {
		LogError("malloc of %d bytes failed.", myPrivLength);
		return TSS_E_OUTOFMEMORY;
	}
	memcpy(myPriv, ((TCPA_RSAKEY_OBJECT *) keyObject)->privateKey.Privkey, myPrivLength);

	if ((result = Tspi_GetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, &myKeyBlobLength, &myKeyBlob)))
		goto done;

	if ((result = Tspi_GetAttribData(hWrappingKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, &wrapLength, &wrap)))
		goto done;

	offset = 0;
	UnloadBlob_KEY(hContext, &offset, wrap, &keyContainer);
	offset = 0;
	LoadBlob_STORE_PUBKEY(&offset, pubKey, &keyContainer.pubKey);
	pubKeySize = offset;

	if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
		goto done;

	anObject = getAnObjectByHandle(hPolicy);
	if (anObject == NULL || anObject->memPointer == NULL) {
		result = TSS_E_INVALID_HANDLE;
		goto done;
	}

	myKeyPolicy = &((TSP_INTERNAL_POLICY_OBJECT *)anObject->memPointer)->p;

	if (myKeyPolicy->SecretMode != TSS_SECRET_MODE_SHA1 &&
	    myKeyPolicy->SecretMode != TSS_SECRET_MODE_PLAIN) {
		LogError("Key policy 0x%x is not secret mode SHA1 or PLAIN", hPolicy);
		result = TSS_E_INTERNAL_ERROR;
		goto done;
	}

	memcpy(secret.secret, myKeyPolicy->Secret, myKeyPolicy->SecretSize);
	/* --------------------------- */
	offset = 0;
	UnloadBlob_KEY(hContext, &offset, myKeyBlob, &keyContainer);

	offset = 0;
	LoadBlob_KEY_ForHash(&offset, hashBlob, &keyContainer);
	TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

/* 	offset = 0; */
/* 	LoadBlob_STORE_ASYMKEY( &offset, blob, &storeAsymkey ); */

	offset = 1;
/* 	LoadBlob_BYTE( &offset, TCPA_PT_ASYM, hashBlob ); */
	hashBlob[0] = TCPA_PT_ASYM;
	LoadBlob(&offset, 20, hashBlob, secret.secret);
	LoadBlob(&offset, 20, hashBlob, secret.secret);
	LoadBlob(&offset, 20, hashBlob, digest.digest);
	LoadBlob_UINT32(&offset, myPrivLength, hashBlob);
	LoadBlob(&offset, myPrivLength, hashBlob, myPriv);

	if ((result = internal_GetRandomNonce(hContext, &seed)))
		goto done;

	keyContainer.encData = calloc_tspi(hContext, 256);
	if (keyContainer.encData == NULL) {
		LogError("malloc of %d bytes failed.", 256);
		result = TSS_E_OUTOFMEMORY;
		goto done;
	}
	if ((result = TSS_RSA_Encrypt(hashBlob, offset, keyContainer.encData,	/* keyObject->tcpaKey.encData,    */
				    &keyContainer.encSize,	/* &keyObject->tcpaKey.encSize,  */
				    &pubKey[4],	/* pubkey, */
				    pubKeySize - sizeof (UINT32))))	/* pubKeyLength,  */
		goto done;

	offset = 0;
	LoadBlob_KEY(&offset, hashBlob, &keyContainer);

	Tspi_SetAttribData(hKey,
			   TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, offset, hashBlob);

#if 0
	if (result = EncryptStoreAsymKey(hContext, TCPA_PT_ASYM, myPrivLength,	/* keyObject->privateKey.Privlen,  */
					 myPriv,	/* keyObject->privateKey.Privkey,  */
					 secret.secret, secret.secret, 0,	/* keyObject, */
					 pubKey,	/* wrappingKeyObject->tcpaKey.pubKey.key,  */
					 pubKeySize))	/* wrappingKeyObject->tcpaKey.pubKey.keyLength        )) */
		return result;
#endif
done:
	if (myPriv)
		free(myPriv);
	if (keyContainer.encData)
		free(keyContainer.encData);
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
	TCS_CONTEXT_HANDLE hContext;
	TCS_AUTH parentAuth;
	TCS_AUTH entityAuth;
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
	TCS_AUTH *pParentAuth;
	BOOL useAuth;
	UINT32 blobSize;
	BYTE *blob;
	TCPA_KEY keyContainer;
	AnObject *anObject;
	TCPA_STORED_DATA storedData;

	if (pulRandomLength == NULL || prgbRandom == NULL || rgbMigTicket == NULL ||
	    pulMigrationBlobLength == NULL || prgbMigrationBlob == NULL)
		return TSS_E_BAD_PARAMETER;

	anObject = getAnObjectByHandle(hKeyToMigrate);
	if (anObject == NULL)
		return TSS_E_INVALID_HANDLE;

	result =
	    internal_CheckObjectType_2(hKeyToMigrate, TSS_OBJECT_TYPE_RSAKEY,
				       hParentKey, TSS_OBJECT_TYPE_RSAKEY);
	if (result) {
		result =
		    internal_CheckObjectType_2(hKeyToMigrate,
					       TSS_OBJECT_TYPE_ENCDATA,
					       hParentKey, TSS_OBJECT_TYPE_RSAKEY);
		if (result)
			return result;
	}
#if 0
//      hContext = obj_getContextForObject( hKeyToMigrate );
//      if( hContext == 0 )
//              return TSS_E_INVALID_HANDLE;
#endif

	if ((result = internal_CheckContext_2(hKeyToMigrate, hParentKey, &hContext)))
		return result;

	if ((result = Tspi_GetAttribData(hParentKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, &parentKeySize, &parentKeyBlob)))
		return result;

	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
		if ((result = Tspi_GetAttribData(hKeyToMigrate,
						TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB,
						&keyToMigrateSize, &keyToMigrateBlob)))
			return result;
	} else {
		if ((result = Tspi_GetAttribData(hKeyToMigrate,
						TSS_TSPATTRIB_ENCDATA_BLOB,
						TSS_TSPATTRIB_ENCDATABLOB_BLOB,
						&keyToMigrateSize, &keyToMigrateBlob)))
			return result;
	}

	if ((result = Tspi_GetPolicyObject(hParentKey, TSS_POLICY_USAGE, &hParentPolicy)))
		return result;

	if ((result = policy_UsesAuth(hParentPolicy, &useAuth)))
		return result;

	if ((result = Tspi_GetPolicyObject(hKeyToMigrate, TSS_POLICY_MIGRATION, &hMigratePolicy)))
		return result;

	/* ////////////////////////////////////////////////////////////////////// */
	/*  Parsing the migration scheme from the blob and key object */
	offset = 0;
	UnloadBlob_MigrationKeyAuth(hContext, &offset, &migAuth, rgbMigTicket);

	offset = 0;
	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
		UnloadBlob_KEY(hContext, &offset, keyToMigrateBlob, &tcpaKey);
	} else {
		if ((result = UnloadBlob_STORED_DATA(hContext, &offset, keyToMigrateBlob, &storedData)))
			return result;
	}

	/* //////////////////////////////////////////////////////////////////////////////////// */
	/* Generate the Authorization data */
	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
		LoadBlob_UINT16(&offset, migAuth.migrationScheme, hashblob);
		LoadBlob(&offset, ulMigTicketLength, hashblob, rgbMigTicket);
		LoadBlob_UINT32(&offset, tcpaKey.encSize, hashblob);
		LoadBlob(&offset, tcpaKey.encSize, hashblob, tcpaKey.encData);
		TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	} else {
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
		LoadBlob_UINT16(&offset, migAuth.migrationScheme, hashblob);
		LoadBlob(&offset, ulMigTicketLength, hashblob, rgbMigTicket);
		LoadBlob_UINT32(&offset, storedData.encDataSize, hashblob);
		LoadBlob(&offset, storedData.encDataSize, hashblob, storedData.encData);
		TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	}
	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy, digest, &parentAuth)))
			return result;
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}
	if ((result = secret_PerformAuth_OIAP(hMigratePolicy, digest, &entityAuth))) {
		if (useAuth)
			TCSP_TerminateHandle(hContext, parentAuth.AuthHandle);
		return result;
	}

	parentHandle = getTCSKeyHandle(hParentKey);
	if (parentHandle == 0)
		return TSS_E_KEY_NOT_LOADED;
	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
		if ((result = TCSP_CreateMigrationBlob(hContext,
					parentHandle, migAuth.migrationScheme, ulMigTicketLength,
					rgbMigTicket, tcpaKey.encSize, tcpaKey.encData, pParentAuth,
					&entityAuth, pulRandomLength, prgbRandom,
					pulMigrationBlobLength, prgbMigrationBlob))) {
			if (pParentAuth)
				TCSP_TerminateHandle(hContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(hContext, entityAuth.AuthHandle);
			return result;
		}
	} else {
		if ((result = TCSP_CreateMigrationBlob(hContext,
						parentHandle, migAuth.migrationScheme,
						ulMigTicketLength, rgbMigTicket,
						storedData.encDataSize, storedData.encData,
						pParentAuth, &entityAuth, pulRandomLength,
						prgbRandom, pulMigrationBlobLength,
						prgbMigrationBlob))) {
			if (pParentAuth)
				TCSP_TerminateHandle(hContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(hContext, entityAuth.AuthHandle);
			return result;
		}
	}

	offset = 0;
	LoadBlob_UINT32(&offset, result, hashblob);
	LoadBlob_UINT32(&offset, TPM_ORD_CreateMigrationBlob, hashblob);
	LoadBlob_UINT32(&offset, *pulRandomLength, hashblob);
	LoadBlob(&offset, *pulRandomLength, hashblob, *prgbRandom);
	LoadBlob_UINT32(&offset, *pulMigrationBlobLength, hashblob);
	LoadBlob(&offset, *pulMigrationBlobLength, hashblob, *prgbMigrationBlob);
	TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = secret_ValidateAuth_OIAP(hParentPolicy, digest, &parentAuth))) {
			if (pParentAuth)
				TCSP_TerminateHandle(hContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(hContext, entityAuth.AuthHandle);
			return result;
		}
	}
	if ((result = secret_ValidateAuth_OIAP(hMigratePolicy, digest, &entityAuth))) {
		if (pParentAuth)
			TCSP_TerminateHandle(hContext, pParentAuth->AuthHandle);
		TCSP_TerminateHandle(hContext, entityAuth.AuthHandle);
		return result;
	}

	if (migAuth.migrationScheme == TSS_MS_REWRAP) {
		if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
			result = Tspi_GetAttribData(hKeyToMigrate,
						    TSS_TSPATTRIB_KEY_BLOB,
						    TSS_TSPATTRIB_KEYBLOB_BLOB, &blobSize, &blob);
			if (result)
				return result;

			offset = 0;
			UnloadBlob_KEY(hContext, &offset, blob, &keyContainer);

			/* keyContainer.encData =       calloc_tspi( hContext, outDataSize ); */
			keyContainer.encSize = *pulMigrationBlobLength;
			memcpy(keyContainer.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

			offset = 0;
			LoadBlob_KEY(&offset, blob, &keyContainer);

			if ((result = Tspi_SetAttribData(hKeyToMigrate,
							TSS_TSPATTRIB_KEY_BLOB,
							TSS_TSPATTRIB_KEYBLOB_BLOB, blobSize, blob)))
				return result;

		} else {

			if ((result = Tspi_GetAttribData(hKeyToMigrate,
							TSS_TSPATTRIB_ENCDATA_BLOB,
							TSS_TSPATTRIB_ENCDATABLOB_BLOB,
							&blobSize, &blob)))
				return result;

			offset = 0;
			if ((result = UnloadBlob_STORED_DATA(hContext, &offset, blob, &storedData)))
				return result;

			/* keyContainer.encData =       calloc_tspi( hContext, outDataSize ); */
			storedData.encDataSize = *pulMigrationBlobLength;
			memcpy(storedData.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

			offset = 0;
			LoadBlob_STORED_DATA(&offset, blob, &storedData);

			if ((result = Tspi_SetAttribData(hKeyToMigrate,
							TSS_TSPATTRIB_ENCDATA_BLOB,
							TSS_TSPATTRIB_ENCDATABLOB_BLOB,
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

	TCS_CONTEXT_HANDLE hContext;
	TCPA_RESULT result;
	UINT32 outDataSize;
	BYTE *outData;
	TCS_KEY_HANDLE parentHandle;
	TCS_AUTH parentAuth;
	TSS_HPOLICY hParentPolicy;
/* 	TCPA_SECRET				parentSecret; */
	UINT16 offset;
	BYTE hashblob[0x1000];
	TCPA_DIGEST digest;
	UINT32 useAuth;
	TCS_AUTH *pParentAuth;
	UINT32 blobSize;
	BYTE *blob;
	TCPA_KEY keyContainer;

	if ((result = internal_CheckObjectType_2(hKeyToMigrate, TSS_OBJECT_TYPE_RSAKEY,
				       hParentKey, TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = internal_CheckContext_2(hKeyToMigrate, hParentKey, &hContext)))
		return result;

/* 	hContext = obj_getContextForObject( hKeyToMigrate ); */
/* 	if( hContext == 0 ) */
/* 		return TSS_E_INVALID_HANDLE; */

	/* ///////////////////////////////////////////////////////////////////////////// */
	/*  Get the parent Key */

	parentHandle = getTCSKeyHandle(hParentKey);
	if (parentHandle == 0)
		return TSS_E_KEY_NOT_LOADED;

	/* ////////////////////////////////////////////////////////////////////////////// */
	/*  Get the secret  */

	if ((result = Tspi_GetPolicyObject(hParentKey, TSS_POLICY_USAGE, &hParentPolicy)))
		return result;

	/* ///////////////////////////////////////////////////////////////////////////// */
	/*   Generate the authorization */

	offset = 0;
	LoadBlob_UINT32(&offset, TPM_ORD_ConvertMigrationBlob, hashblob);
	LoadBlob_UINT32(&offset, ulMigrationBlobLength, hashblob);
	LoadBlob(&offset, ulMigrationBlobLength, hashblob, rgbMigrationBlob);
	LoadBlob_UINT32(&offset, ulRandomLength, hashblob);
	LoadBlob(&offset, ulRandomLength, hashblob, rgbRandom);
	TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (((result = policy_UsesAuth(hParentPolicy, &useAuth))))
		return result;

	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hParentPolicy, digest, &parentAuth)))
			return result;
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}

/* 	if( result = secret_PerformAuth_OIAP( hParentPolicy, digest, &parentAuth )) */
/* 		return result; */

	if ((result = TCSP_ConvertMigrationBlob(hContext, parentHandle, ulMigrationBlobLength,
				     rgbMigrationBlob, pParentAuth, ulRandomLength, rgbRandom,
				     &outDataSize, &outData)))
		return result;

	/* add validation */
	offset = 0;
	LoadBlob_UINT32(&offset, result, hashblob);
	LoadBlob_UINT32(&offset, TPM_ORD_ConvertMigrationBlob, hashblob);
	LoadBlob_UINT32(&offset, outDataSize, hashblob);
	LoadBlob(&offset, outDataSize, hashblob, outData);
	TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = secret_ValidateAuth_OIAP(hParentPolicy, digest, &parentAuth)))
			return result;
	}

	result = Tspi_GetAttribData(hKeyToMigrate,
				    TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_BLOB, &blobSize, &blob);
	if (result)
		return result;

	offset = 0;
	UnloadBlob_KEY(hContext, &offset, blob, &keyContainer);

	/* keyContainer.encData =       calloc_tspi( hContext, outDataSize ); */
	keyContainer.encSize = outDataSize;
	memcpy(keyContainer.encData, outData, outDataSize);

	offset = 0;
	LoadBlob_KEY(&offset, blob, &keyContainer);

	if ((result = Tspi_SetAttribData(hKeyToMigrate,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, blobSize, blob)))
		return result;

	return result;

}
