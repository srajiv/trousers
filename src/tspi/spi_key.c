
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
#include "tsplog.h"
#include "obj.h"
#include "tss/trousers.h"

TSS_RESULT
Tspi_Key_UnloadKey(TSS_HKEY hKey)	/*  in */
{
	TSS_HCONTEXT tcsContext;
	TSS_RESULT result;

	if ((result = obj_checkType_1(hKey, TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = obj_isConnected_1(hKey, &tcsContext)))
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
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HKEY phKey;
	TSS_HPOLICY hPolicy;
	UINT32 keySize;
	BYTE *keyBlob;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	BOOL usesAuth;
	TCS_AUTH *pAuth;

	LogDebug1("Tspi_Key_LoadKey");
	for (;;) {
		if ((result = obj_checkType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hUnwrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((result = obj_isConnected_2(hKey, hUnwrappingKey, &tcsContext)))
			break;	/* return result; */

		if ((result = Tspi_GetAttribData(hKey,
						TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB, &keySize, &keyBlob)))
			break;	/* return result; */

		parentTCSKeyHandle = getTCSKeyHandle(hUnwrappingKey);
		if (parentTCSKeyHandle == NULL_HKEY) {
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
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		Trspi_LoadBlob(&offset, keySize, blob, keyBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);
		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth)))
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

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth)))
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
	TCS_CONTEXT_HANDLE tcsContext;
	UINT16 offset;
	TSS_HPOLICY hPolicy;
	TCS_KEY_HANDLE tcsKeyHandle;
	BOOL usesAuth;

	if (pulPubKeyLength == NULL || prgbPubKey == NULL)
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_Key_GetPubKey");
	for (;;) {
		if ((result = obj_checkType_1(hKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((result = obj_isConnected_1(hKey, &tcsContext)))
			break;	/* return result; */

		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hPolicy, &usesAuth)))
			break;	/* return result; */

		tcsKeyHandle = getTCSKeyHandle(hKey);
		if (tcsKeyHandle == NULL_HKEY) {
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
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetPubKey, hashblob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth)))
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

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth))) {
			free(*prgbPubKey);
			return result;
		}
	}

	LogDebug1("Stuffing info into key object");
	if ((result = Tspi_SetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					*pulPubKeyLength, *prgbPubKey))) {
		free(*prgbPubKey);
		return result;
	}

	LogDebug1("Leaving GetPubKey");
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
	TSS_HCONTEXT tspContext;


	for (;;) {

		if ((result = obj_checkType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hCertifyingKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((tspContext = obj_getTspContext(hKey)) == NULL_HCONTEXT) {
			result = TSS_E_INTERNAL_ERROR;
			break;
		}

		if ((result = obj_isConnected_2(hKey, hCertifyingKey, &tcsContext)))
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
		if (certifyTCSKeyHandle == NULL_HKEY) {
			LogDebug1("Failed to get tcs key handle for cert");
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}

		keyTCSKeyHandle = getTCSKeyHandle(hKey);
		if (keyTCSKeyHandle == NULL_HKEY) {
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
		if (hashBlob == NULL) {
			LogError("malloc of %d bytes failed.", 24);
			return TSS_E_OUTOFMEMORY;
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
		if ((result = secret_PerformAuth_OIAP(hPolicy, hash, &keyAuth)))
			return result;
	} else
		pKeyAuth = NULL;

	if (useAuthCert) {
		if ((result = secret_PerformAuth_OIAP(hCertPolicy, hash, &certAuth))) {
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
			return TSS_E_OUTOFMEMORY;
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifyKey, hashBlob);
		Trspi_LoadBlob(&offset, CertifyInfoSize, hashBlob, CertifyInfo);
		Trspi_LoadBlob_UINT32(&offset, outDataSize, hashBlob);
		Trspi_LoadBlob(&offset, outDataSize, hashBlob, outData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		free(hashBlob);
		if (useAuthKey) {
			if ((result = secret_ValidateAuth_OIAP(hPolicy, hash, &keyAuth))) {
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
				if (useAuthCert)
					TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);
				return result;
			}
		}
		if (useAuthCert) {
			if ((result = secret_ValidateAuth_OIAP(hCertPolicy, hash, &certAuth))) {
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);
				if (useAuthKey)
					TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
				return result;
			}
		}
	}

	if (verfiyInternally) {
		if ((result = Tspi_GetAttribData(hCertifyingKey, TSS_TSPATTRIB_KEY_BLOB,
				       TSS_TSPATTRIB_KEYBLOB_BLOB, &keyDataSize, &keyData))) {
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			LogError1("Error in calling GetAttribData internally");
			return TSS_E_INTERNAL_ERROR;
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

			return TSS_E_VERIFICATION_FAILED;
		}

	} else {
		pValidationData->ulDataLength = CertifyInfoSize;
		pValidationData->rgbData = calloc_tspi(tspContext, CertifyInfoSize);
		if (pValidationData->rgbData == NULL) {
			LogError("malloc of %d bytes failed.", CertifyInfoSize);
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSS_E_OUTOFMEMORY;
		}
		memcpy(pValidationData->rgbData, CertifyInfo, CertifyInfoSize);
		pValidationData->ulValidationLength = outDataSize;
		pValidationData->rgbValidationData = calloc_tspi(tspContext, outDataSize);
		if (pValidationData->rgbValidationData == NULL) {
			LogError("malloc of %d bytes failed.", outDataSize);
			if (useAuthKey)
				TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
			if (useAuthCert)
				TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

			return TSS_E_OUTOFMEMORY;
		}
		memcpy(pValidationData->rgbValidationData, outData, outDataSize);
		memcpy(&pValidationData->versionInfo,
		       getCurrentVersion(tspContext), sizeof (TCPA_VERSION));
	}

	if (useAuthKey)
		TCSP_TerminateHandle(tcsContext, keyAuth.AuthHandle);
	if (useAuthCert)
		TCSP_TerminateHandle(tcsContext, certAuth.AuthHandle);

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
	TCS_CONTEXT_HANDLE tcsContext;
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
	TSS_HCONTEXT tspContext;

	LogDebug1("Tspi_Key_CreateKey");
	for (;;) {
		if (hPcrComposite == NULL_HPCRS) {
			if ((result = obj_checkType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
						       hWrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
				break;	/* return result; */
			if ((result = obj_isConnected_2(hKey, hWrappingKey, &tcsContext)))
				break;	/* return result; */
		} else {
			if ((result =
			    obj_checkType_3(hKey,
						       TSS_OBJECT_TYPE_RSAKEY,
						       hWrappingKey,
						       TSS_OBJECT_TYPE_RSAKEY,
						       hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
				break;	/* return result; */
			if ((result = obj_isConnected_3(hKey, hWrappingKey, hPcrComposite, &tcsContext)))
				break;	/* return result; */
		}

		if ((tspContext = obj_getTspContext(hKey)) == NULL_HCONTEXT)
			return TSS_E_INTERNAL_ERROR;

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
			Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob, &keyContainer);

			/* --------------------------- */
			anObject = getAnObjectByHandle(hPcrComposite);
			if (anObject == NULL || anObject->memPointer == NULL) {
				LogError1("Cannot find key by PcrComposite Handle!");
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
			    calloc_tspi(tspContext, pcrInfo.pcrSelection.sizeOfSelect);
			memcpy(pcrInfo.pcrSelection.pcrSelect,
			       ((TCPA_PCR_OBJECT *) anObject->memPointer)->
			       pcrComposite.select.pcrSelect, pcrInfo.pcrSelection.sizeOfSelect);
#endif
			/* ---  Now into blob form */
			offset = 0;
/* 			Trspi_LoadBlob_PCR_INFO( &offset, pcrInfoData, &pcrInfo ); */
			Trspi_LoadBlob_PCR_SELECTION(&offset, pcrInfoData,
					       ((TCPA_PCR_OBJECT *) anObject->memPointer)->select);
			memcpy(&pcrInfoData[offset],
			       ((TCPA_PCR_OBJECT *) anObject->memPointer)->compositeHash.digest, 20);
			offset += 20;
/* 			Trspi_LoadBlob_PCR_INFO( &offset, pcrInfoData, ((TCPA_PCR_OBJECT*)anObject->memPointer)-> */
			memset(&pcrInfoData[offset], 0, 20);
			offset += 20;

			/* ---  Stuff it into the key container */
			pcrInfoSize = offset;
			keyContainer.PCRInfo = calloc_tspi(tspContext, offset);
			if (keyContainer.PCRInfo == NULL) {
				LogError("malloc of %d bytes failed.", offset);
				return TSS_E_OUTOFMEMORY;
			}
			keyContainer.PCRInfoSize = pcrInfoSize;
			memcpy(keyContainer.PCRInfo, pcrInfoData, pcrInfoSize);

			newKey = calloc_tspi(tspContext, 1024);
			if (newKey == NULL) {
				LogError("malloc of %d bytes failed.", 1024);
				return TSS_E_OUTOFMEMORY;
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

			/* ---  keyBlob now has the updated key blob */
		}

		parentTCSKeyHandle = getTCSKeyHandle(hWrappingKey);
		if (parentTCSKeyHandle == NULL_HKEY) {
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
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	Trspi_LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
	Trspi_LoadBlob(&offset, 20, hashBlob, encAuthMig.encauth);
	Trspi_LoadBlob(&offset, keySize, hashBlob, keyBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	/* ---  Complete the Auth Structure */
	if ((result = secret_PerformAuth_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy, hKey,
				    sharedSecret, &auth, digest.digest, nonceEvenOSAP))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		return result;
	}

	/* ---  Now call the function */
	if ((result = TCSP_CreateWrapKey(tcsContext,	/*  in */
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
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateWrapKey, hashBlob);
	Trspi_LoadBlob(&offset, newKeySize, hashBlob, newKey);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);
	if ((result = secret_ValidateAuth_OSAP(hWrapPolicy, hUsagePolicy, hMigPolicy,
				     sharedSecret, &auth, digest.digest, nonceEvenOSAP))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		free(newKey);
		return result;
	}

	LogDebug1("Stuff data into object");
	/* ---  Push the new key into the existing object */
	if ((result = Tspi_SetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, newKeySize, newKey))) {
		TCSP_TerminateHandle(hWrapPolicy, auth.AuthHandle);
		free(newKey);
		return result;
	}

	free(newKey);
	LogDebug1("Leaving Create Key");
	return result;
}

TSS_RESULT
Tspi_Key_WrapKey(TSS_HKEY hKey,	/*  in */
		 TSS_HKEY hWrappingKey,	/*  in */
		 TSS_HPCRS hPcrComposite	/*  in, may be NULL */
    )
{

	AnObject *anObject;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy;
	TCPA_SECRET secret;
	TSS_RESULT result;
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
	TCPA_NONCE seed;	/* nice container */
	void *keyObject;
	TSS_HCONTEXT tspContext;

	if (hPcrComposite == NULL_HPCRS) {
		if ((result = obj_checkType_2(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hWrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
			return result;
		if ((result = obj_isConnected_2(hKey, hWrappingKey, &tcsContext)))
			return result;

	} else {
		if ((result =
		    obj_checkType_3(hKey, TSS_OBJECT_TYPE_RSAKEY,
					       hWrappingKey,
					       TSS_OBJECT_TYPE_RSAKEY,
					       hPcrComposite, TSS_OBJECT_TYPE_PCRS)))
			return result;
		if ((result = obj_isConnected_3(hKey, hWrappingKey, hPcrComposite, &tcsContext)))
			return result;
	}

	if ((tspContext = obj_getTspContext(hKey)) == NULL_HCONTEXT)
		return TSS_E_INTERNAL_ERROR;

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
	myPriv = calloc_tspi(tspContext, myPrivLength);
	if (myPriv == NULL) {
		LogError("malloc of %d bytes failed.", myPrivLength);
		return TSS_E_OUTOFMEMORY;
	}

	/* get the key to be wrapped's private key */
	memcpy(myPriv, ((TCPA_RSAKEY_OBJECT *) keyObject)->privateKey.Privkey, myPrivLength);

	/* get the key to be wrapped's blob */
	if ((result = Tspi_GetAttribData(hKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, &myKeyBlobLength, &myKeyBlob)))
		goto done;

	/* get the wrapping key's blob */
	if ((result = Tspi_GetAttribData(hWrappingKey,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, &wrapLength, &wrap)))
		goto done;

	/* unload the wrapping key */
	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, wrap, &keyContainer);
	offset = 0;
	Trspi_LoadBlob_STORE_PUBKEY(&offset, pubKey, &keyContainer.pubKey);
	pubKeySize = offset;

	/* get the key to be wrapped's usage policy */
	if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
		goto done;

	anObject = getAnObjectByHandle(hPolicy);
	if (anObject == NULL || anObject->memPointer == NULL) {
		result = TSS_E_INVALID_HANDLE;
		goto done;
	}

	myKeyPolicy = &((TSP_INTERNAL_POLICY_OBJECT *)anObject->memPointer)->p;

	/* XXX why is this a problem? Shouldn't popup secret be ok? */
	if (myKeyPolicy->SecretMode != TSS_SECRET_MODE_SHA1 &&
	    myKeyPolicy->SecretMode != TSS_SECRET_MODE_PLAIN) {
		LogError("Key policy 0x%x is not secret mode SHA1 or PLAIN", hPolicy);
		result = TSS_E_INTERNAL_ERROR;
		goto done;
	}

	memcpy(secret.secret, myKeyPolicy->Secret, myKeyPolicy->SecretSize);
	/* unload the wrapping key */
	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, myKeyBlob, &keyContainer);

	offset = 0;
	Trspi_LoadBlob_KEY_ForHash(&offset, hashBlob, &keyContainer);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

/* 	offset = 0; */
/* 	Trspi_LoadBlob_STORE_ASYMKEY( &offset, blob, &storeAsymkey ); */

	offset = 1;
/* 	Trspi_LoadBlob_BYTE( &offset, TCPA_PT_ASYM, hashBlob ); */
	hashBlob[0] = TCPA_PT_ASYM;
	Trspi_LoadBlob(&offset, 20, hashBlob, secret.secret);
	Trspi_LoadBlob(&offset, 20, hashBlob, secret.secret);
	Trspi_LoadBlob(&offset, 20, hashBlob, digest.digest);
	Trspi_LoadBlob_UINT32(&offset, myPrivLength, hashBlob);
	Trspi_LoadBlob(&offset, myPrivLength, hashBlob, myPriv);

	if ((result = internal_GetRandomNonce(tcsContext, &seed)))
		goto done;

	keyContainer.encData = calloc_tspi(tspContext, 256);
	if (keyContainer.encData == NULL) {
		LogError("malloc of %d bytes failed.", 256);
		result = TSS_E_OUTOFMEMORY;
		goto done;
	}
	if ((result = Trspi_RSA_Encrypt(hashBlob, offset, keyContainer.encData,	/* keyObject->tcpaKey.encData,    */
				    &keyContainer.encSize,	/* &keyObject->tcpaKey.encSize,  */
				    &pubKey[4],	/* pubkey, */
				    pubKeySize - sizeof (UINT32))))	/* pubKeyLength,  */
		goto done;

	offset = 0;
	Trspi_LoadBlob_KEY(&offset, hashBlob, &keyContainer);

	Tspi_SetAttribData(hKey,
			   TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, offset, hashBlob);

#if 0
	if (result = EncryptStoreAsymKey(tcsContext, TCPA_PT_ASYM, myPrivLength,	/* keyObject->privateKey.Privlen,  */
					 myPriv,	/* keyObject->privateKey.Privkey,  */
					 secret.secret, secret.secret, 0,	/* keyObject, */
					 pubKey,	/* wrappingKeyObject->tcpaKey.pubKey.key,  */
					 pubKeySize))	/* wrappingKeyObject->tcpaKey.pubKey.keyLength        )) */
		return result;
#endif
done:
	free_tspi(tspContext, myPriv);
	free_tspi(tspContext, keyContainer.encData);
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
	TSS_HCONTEXT tspContext;

	if (pulRandomLength == NULL || prgbRandom == NULL || rgbMigTicket == NULL ||
	    pulMigrationBlobLength == NULL || prgbMigrationBlob == NULL)
		return TSS_E_BAD_PARAMETER;

	anObject = getAnObjectByHandle(hKeyToMigrate);
	if (anObject == NULL)
		return TSS_E_INVALID_HANDLE;

	/* FIXME What is this? */
	result =
	    obj_checkType_2(hKeyToMigrate, TSS_OBJECT_TYPE_RSAKEY,
				       hParentKey, TSS_OBJECT_TYPE_RSAKEY);
	if (result) {
		result =
		    obj_checkType_2(hKeyToMigrate,
					       TSS_OBJECT_TYPE_ENCDATA,
					       hParentKey, TSS_OBJECT_TYPE_RSAKEY);
		if (result)
			return result;
	}

	if ((tspContext = obj_getTspContext(hKeyToMigrate)) == NULL_HCONTEXT)
		return TSS_E_INTERNAL_ERROR;

	if ((result = obj_isConnected_2(hKeyToMigrate, hParentKey, &tcsContext)))
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
	Trspi_UnloadBlob_MigrationKeyAuth(tspContext, &offset, &migAuth, rgbMigTicket);

	offset = 0;
	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyToMigrateBlob, &tcpaKey);
	} else {
		if ((result = Trspi_UnloadBlob_STORED_DATA(tspContext, &offset, keyToMigrateBlob, &storedData)))
			return result;
	}

	/* //////////////////////////////////////////////////////////////////////////////////// */
	/* Generate the Authorization data */
	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
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
		if ((result = secret_PerformAuth_OIAP(hParentPolicy, digest, &parentAuth)))
			return result;
		pParentAuth = &parentAuth;
	} else {
		pParentAuth = NULL;
	}
	if ((result = secret_PerformAuth_OIAP(hMigratePolicy, digest, &entityAuth))) {
		if (useAuth)
			TCSP_TerminateHandle(tcsContext, parentAuth.AuthHandle);
		return result;
	}

	parentHandle = getTCSKeyHandle(hParentKey);
	if (parentHandle == NULL_HKEY)
		return TSS_E_KEY_NOT_LOADED;
	if (anObject->objectType == TSS_OBJECT_TYPE_RSAKEY) {
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
		if ((result = secret_ValidateAuth_OIAP(hParentPolicy, digest, &parentAuth))) {
			if (pParentAuth)
				TCSP_TerminateHandle(tcsContext, pParentAuth->AuthHandle);
			TCSP_TerminateHandle(tcsContext, entityAuth.AuthHandle);
			return result;
		}
	}
	if ((result = secret_ValidateAuth_OIAP(hMigratePolicy, digest, &entityAuth))) {
		if (pParentAuth)
			TCSP_TerminateHandle(tcsContext, pParentAuth->AuthHandle);
		TCSP_TerminateHandle(tcsContext, entityAuth.AuthHandle);
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
			Trspi_UnloadBlob_KEY(tspContext, &offset, blob, &keyContainer);

			/* keyContainer.encData =       calloc_tspi( tspContext, outDataSize ); */
			keyContainer.encSize = *pulMigrationBlobLength;
			memcpy(keyContainer.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

			offset = 0;
			Trspi_LoadBlob_KEY(&offset, blob, &keyContainer);

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
			if ((result = Trspi_UnloadBlob_STORED_DATA(tspContext, &offset, blob, &storedData)))
				return result;

			/* keyContainer.encData =       calloc_tspi( tspContext, outDataSize ); */
			storedData.encDataSize = *pulMigrationBlobLength;
			memcpy(storedData.encData, *prgbMigrationBlob, *pulMigrationBlobLength);

			offset = 0;
			Trspi_LoadBlob_STORED_DATA(&offset, blob, &storedData);

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

	TCS_CONTEXT_HANDLE tcsContext;
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
	TSS_HCONTEXT tspContext;

	if ((result = obj_checkType_2(hKeyToMigrate, TSS_OBJECT_TYPE_RSAKEY,
				       hParentKey, TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = obj_isConnected_2(hKeyToMigrate, hParentKey, &tcsContext)))
		return result;

	if ((tspContext = obj_getTspContext(hKeyToMigrate)) == NULL_HCONTEXT)
		return TSS_E_INTERNAL_ERROR;

	/* ///////////////////////////////////////////////////////////////////////////// */
	/*  Get the parent Key */

	parentHandle = getTCSKeyHandle(hParentKey);
	if (parentHandle == NULL_HKEY)
		return TSS_E_KEY_NOT_LOADED;

	/* ////////////////////////////////////////////////////////////////////////////// */
	/*  Get the secret  */

	if ((result = Tspi_GetPolicyObject(hParentKey, TSS_POLICY_USAGE, &hParentPolicy)))
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
		if ((result = secret_ValidateAuth_OIAP(hParentPolicy, digest, &parentAuth)))
			return result;
	}

	result = Tspi_GetAttribData(hKeyToMigrate,
				    TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_BLOB, &blobSize, &blob);
	if (result)
		return result;

	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, blob, &keyContainer);

	/* keyContainer.encData =       calloc_tspi( tspContext, outDataSize ); */
	keyContainer.encSize = outDataSize;
	memcpy(keyContainer.encData, outData, outDataSize);

	offset = 0;
	Trspi_LoadBlob_KEY(&offset, blob, &keyContainer);

	if ((result = Tspi_SetAttribData(hKeyToMigrate,
					TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, blobSize, blob)))
		return result;

	return result;

}
