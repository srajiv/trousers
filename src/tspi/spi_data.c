
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
Tspi_Data_Bind(TSS_HENCDATA hEncData,	/*  in */
	       TSS_HKEY hEncKey,	/*  in */
	       UINT32 ulDataLength,	/*  in */
	       BYTE *rgbDataToBind	/*  in */
    )
{
	UINT32 encDataLength;
	BYTE encData[256];
	BYTE *keyData;
	UINT32 keyDataLength;
	TCPA_BOUND_DATA boundData;
	UINT16 offset;
	BYTE bdblob[256];
	TCPA_RESULT result;
	TCPA_KEY keyContainer;
	TSS_HCONTEXT tspContext;
#if 0
	TCPA_NONCE randomSeed;
	BYTE seed[260];		/* RCC - Fixed to match the 13*20 for loop below */
	UINT32 i;
#endif

	if (rgbDataToBind == NULL)
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_Data_Bind");

	if ((result = obj_checkType_2(hEncData,
					TSS_OBJECT_TYPE_ENCDATA, hEncKey,
					TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((tspContext = obj_getTspContext(hEncData)) == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	if ((result = obj_checkSession_2(hEncData, hEncKey)))
		return result;

	if ((result = Tspi_GetAttribData(hEncKey, TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB, &keyDataLength, &keyData)))
		return result;

	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(tspContext, &offset, keyData, &keyContainer)))
		return result;

	if (keyContainer.keyUsage != TSS_KEYUSAGE_BIND &&
		keyContainer.keyUsage != TSS_KEYUSAGE_LEGACY) {
		return TSS_E_INVALID_KEYUSAGE;
	}

	if (keyContainer.algorithmParms.encScheme == TSS_ES_RSAESPKCSV15 &&
	    keyContainer.keyUsage == TSS_KEYUSAGE_LEGACY) {

		if ((result = Trspi_RSA_PKCS15_Encrypt(rgbDataToBind,
						   ulDataLength,
						   encData,
						   &encDataLength,
						   keyContainer.pubKey.key,
						   keyContainer.pubKey.keyLength))) {
			return result;
		}
	} else if (keyContainer.algorithmParms.encScheme == TSS_ES_RSAESPKCSV15
		   && keyContainer.keyUsage == TSS_KEYUSAGE_BIND) {
		boundData.payload = TCPA_PT_BIND;

		memcpy(&boundData.ver, getCurrentVersion(tspContext), sizeof (TCPA_VERSION));

		boundData.payloadData = malloc(ulDataLength);
		if (boundData.payloadData == NULL) {
			return TSS_E_OUTOFMEMORY;
		}
		memcpy(boundData.payloadData, rgbDataToBind, ulDataLength);

		offset = 0;
		Trspi_LoadBlob_BOUND_DATA(&offset, boundData, ulDataLength, bdblob);

		if ((result = Trspi_RSA_PKCS15_Encrypt(bdblob,
							   offset,
							   encData,
							   &encDataLength,
							   keyContainer.pubKey.key,
							   keyContainer.pubKey.keyLength))) {
			return result;
		}
		free(boundData.payloadData);
	} else {
		boundData.payload = TCPA_PT_BIND;

		memcpy(&boundData.ver, getCurrentVersion(tspContext), sizeof (TCPA_VERSION));

		boundData.payloadData = malloc(ulDataLength);
		if (boundData.payloadData == NULL) {
			LogError("malloc of %d bytes failed.", ulDataLength);
			return TSS_E_OUTOFMEMORY;
		}
		memcpy(boundData.payloadData, rgbDataToBind, ulDataLength);

		offset = 0;
		Trspi_LoadBlob_BOUND_DATA(&offset, boundData, ulDataLength, bdblob);

		LogDebug("SM DEBUG Enc len = %d", offset);

#if 0
		/*  DUMMY */
		LogDebug1("SM DEBUG DUMMY RSA_Encrypt");

		encDataLength = offset;
		memcpy(encData, bdblob, offset);

#else
		if ((result = Trspi_RSA_Encrypt(bdblob,	/* in */
					    offset,	/* in */
					    encData,	/* encObject->encryptedData,   */
					    &encDataLength,	/* &encObject->encryptedDataLength,  */
					    keyContainer.pubKey.key,	/* keyObject->tcpa_key.pubKey.key, */
					    keyContainer.pubKey.keyLength/* keyObject->tcpa_key.pubKey.keyLength, */
		    ))) {
			return result;
		}
#endif

		free(boundData.payloadData);
	}

	if ((result = Tspi_SetAttribData(hEncData,
					TSS_TSPATTRIB_ENCDATA_BLOB,
					TSS_TSPATTRIB_ENCDATABLOB_BLOB, encDataLength, encData))) {
		LogError1("Error in calling SetAttribData on the encrypted data object.");
		return TSS_E_INTERNAL_ERROR;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Data_Unbind(TSS_HENCDATA hEncData,	/*  in */
		 TSS_HKEY hKey,	/*  in */
		 UINT32 * pulUnboundDataLength,	/*  out */
		 BYTE ** prgbUnboundData	/*  out */
    )
{
	TCPA_RESULT result;

	TCS_AUTH privAuth;
	TCPA_DIGEST digest;
	UINT16 offset;
	TSS_HPOLICY hPolicy;
	BYTE *encData;
	UINT32 encDataSize;
	TCS_CONTEXT_HANDLE tcsContext;
	BYTE hashBlob[1024];
	TCS_KEY_HANDLE tcsKeyHandle;
	BOOL usesAuth;
	TCS_AUTH *pPrivAuth;
        TSS_HCONTEXT tspContext;

	if (pulUnboundDataLength == NULL || prgbUnboundData == NULL)
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_Data_Unbind");

	if ((tspContext = obj_getTspContext(hEncData)) == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	if ((result = obj_checkType_2(hEncData,
					TSS_OBJECT_TYPE_ENCDATA, hKey,
					TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = obj_isConnected_2(hEncData, hKey, &tcsContext)))
		return result;

	if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
					TSS_TSPATTRIB_ENCDATABLOB_BLOB, &encDataSize, &encData)))
		return result;

	tcsKeyHandle = getTCSKeyHandle(hKey);
	if (tcsKeyHandle == NULL_HKEY) {
		result = TSS_E_KEY_NOT_LOADED;
		return result;
	}

	if ((result = policy_UsesAuth(hPolicy, &usesAuth)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_UnBind, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, encDataSize, hashBlob);
		Trspi_LoadBlob(&offset, encDataSize, hashBlob, encData);

		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &privAuth)))
			return result;
		pPrivAuth = &privAuth;
	} else {
		pPrivAuth = NULL;
	}

	if ((result = TCSP_UnBind(tcsContext, tcsKeyHandle,	/* hKey, //keyHandle,              */
				 encDataSize,	/* encObject->encryptedDataLength,  */
				 encData,	/* encObject->encryptedData,  */
				 pPrivAuth,	/* &privAuth, */
				 pulUnboundDataLength, prgbUnboundData)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_UnBind, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, *pulUnboundDataLength, hashBlob);
		Trspi_LoadBlob(&offset, *pulUnboundDataLength, hashBlob, *prgbUnboundData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &privAuth))) {
			free_tspi(tspContext, *prgbUnboundData);
			return result;
		}
	}
	LogDebug1("Leaving unbind");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Data_Seal(TSS_HENCDATA hEncData,	/*  in */
	       TSS_HKEY hEncKey,	/*  in */
	       UINT32 ulDataLength,	/*  in */
	       BYTE * rgbDataToSeal,	/*  in */
	       TSS_HPCRS hPcrComposite	/*  in */
    )
{
	UINT16 offset;
	BYTE hashBlob[0x1000];
	BYTE sharedSecret[20];
	TCS_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_RESULT rc;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy, hEncPolicy;
	BYTE *encData = NULL;
	UINT32 encDataSize;
	UINT32 pcrDataSize;
	BYTE pcrData[256];
	AnObject *anObject;
	TCPA_PCR_OBJECT *pcrObject;
	TCPA_ENCDATA_OBJECT *encObject;
	TCS_KEY_HANDLE tcsKeyHandle;
	TCPA_NONCE nonceEvenOSAP;
	BOOL useAuth;
	TCS_AUTH *pAuth;
	TCPA_DIGEST digAtCreation;
	TSS_HCONTEXT tspContext;

	if (rgbDataToSeal == NULL)
		return TSS_E_BAD_PARAMETER;

	for (;;) {
		if ((rc = obj_checkType_2(hEncData,
					       TSS_OBJECT_TYPE_ENCDATA, hEncKey,
					       TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return rc; */

		if ((tspContext = obj_getTspContext(hEncData)) == NULL_HCONTEXT)
			return TSS_E_INVALID_HANDLE;

		if (hPcrComposite == NULL_HPCRS) {
			if ((rc = obj_isConnected_2(hEncData, hEncData, &tcsContext)))
				break;	/* return rc; */
		} else {
			if ((rc = obj_isConnected_3(hEncData, hEncData, hPcrComposite, &tcsContext)))
				break;	/* return rc; */
		}

		if ((rc = Tspi_GetPolicyObject(hEncKey, TSS_POLICY_USAGE, &hPolicy)))
			break;	/* return rc; */

		if ((rc = policy_UsesAuth(hPolicy, &useAuth)))
			break;

		if ((rc = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
					    TSS_TSPATTRIB_ENCDATABLOB_BLOB,
					    &encDataSize, &encData)))
			break;	/* return rc; */

		if ((rc = Tspi_GetPolicyObject(hEncData, TSS_POLICY_USAGE, &hEncPolicy)))
			break;	/* return rc; */

		tcsKeyHandle = getTCSKeyHandle(hEncKey);
		if (tcsKeyHandle == NULL_HKEY) {
			rc = TSS_E_KEY_NOT_LOADED;
			break;
		}

		break;
	}
	if (rc) {
		LogDebug("Failed with result %.8X", rc);
		return rc;
	}

	/* ---  If PCR's are of interest */
	pcrDataSize = 0;
	if (hPcrComposite != 0) {
		LogDebug1("Uses Pcr's");
		anObject = getAnObjectByHandle(hPcrComposite);
		if (anObject == NULL || anObject->memPointer == NULL)
			return TSS_E_INVALID_HANDLE;
		pcrObject = anObject->memPointer;

		if ((rc = generateCompositeFromTPM(tcsContext, pcrObject->select, &digAtCreation)))
			return rc;
/* 		memcpy( pcrObject->digAtRelease.digest, pcrObject->compositeHash.digest, 20 ); */

/* 		offset = pcrDataSize; */
		offset = 0;
/* 		Trspi_LoadBlob_PCR_SELECTION( &offset, pcrData, pcrObject->pcrComposite.select ); */
		Trspi_LoadBlob_PCR_SELECTION(&offset, pcrData, pcrObject->select);
		Trspi_LoadBlob(&offset, 20, pcrData, digAtCreation.digest);
/* 		Trspi_LoadBlob( &offset, 20, pcrData, pcrObject->digAtRelease.digest ); */
		Trspi_LoadBlob(&offset, 20, pcrData, pcrObject->compositeHash.digest);
		pcrDataSize = offset;

	}

	if ((rc = secret_PerformXOR_OSAP(hPolicy, hEncPolicy, hEncPolicy, hEncKey,
				   TCPA_ET_KEYHANDLE, tcsKeyHandle,
				   &encAuthUsage, &encAuthMig, sharedSecret, &auth, &nonceEvenOSAP)))
		return rc;

	if (useAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Seal, hashBlob);
		Trspi_LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
		Trspi_LoadBlob_UINT32(&offset, pcrDataSize, hashBlob);
		Trspi_LoadBlob(&offset, pcrDataSize, hashBlob, pcrData);
		Trspi_LoadBlob_UINT32(&offset, ulDataLength, hashBlob);
		Trspi_LoadBlob(&offset, ulDataLength, hashBlob, rgbDataToSeal);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);
		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((rc = secret_PerformAuth_OSAP(hPolicy, hEncPolicy, hEncPolicy, hEncKey,
				    sharedSecret, &auth, digest.digest, nonceEvenOSAP)))
		return rc;

	if ((rc = TCSP_Seal(tcsContext, tcsKeyHandle, encAuthUsage, pcrDataSize,
				pcrData, ulDataLength, rgbDataToSeal, pAuth,
				&encDataSize, &encData)))
		return rc;

	if (useAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, rc, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Seal, hashBlob);
		Trspi_LoadBlob(&offset, encDataSize, hashBlob, encData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((rc = secret_ValidateAuth_OSAP(hPolicy, hEncPolicy, hEncPolicy,
					     sharedSecret, &auth, digest.digest, nonceEvenOSAP))) {
			free(encData);
			return rc;
		}
	}

	/* ---  Need to set the encObject with the blob and the pcr's */
	anObject = getAnObjectByHandle(hEncData);
	if (anObject == NULL || anObject->memPointer == NULL) {
		free(encData);
		return TSS_E_INVALID_HANDLE;
	}

	encObject = anObject->memPointer;
	encObject->encryptedDataLength = encDataSize;
	memcpy(encObject->encryptedData, encData, encDataSize);
	free(encData);

	offset = 0;
	if (pcrDataSize) {
		if ((rc = Trspi_UnloadBlob_PCR_INFO(tspContext, &offset, pcrData, &encObject->pcrInfo)))
			return rc;
		encObject->usePCRs = 1;
	} else
		encObject->usePCRs = 0;

	LogDebug1("Leaving Seal");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Data_Unseal(TSS_HENCDATA hEncData,	/*  in */
		 TSS_HKEY hKey,	/*  in */
		 UINT32 * pulUnsealedDataLength,	/*  out */
		 BYTE ** prgbUnsealedData	/*  out */
    )
{
	TCS_AUTH privAuth, privAuth2;
	TCS_AUTH *pPrivAuth;
	UINT16 offset;
	BYTE hashblob[0x400];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy, hEncPolicy;
	TCPA_ENCDATA_OBJECT *encObject;
	AnObject *anObject;
	TCS_KEY_HANDLE tcsKeyHandle;
	BOOL useAuth;
        TSS_HCONTEXT tspContext;

	if (pulUnsealedDataLength == NULL || prgbUnsealedData == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((tspContext = obj_getTspContext(hEncData)) == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	for (;;) {
		if ((result = obj_checkType_2(hEncData,
					       TSS_OBJECT_TYPE_ENCDATA, hKey,
					       TSS_OBJECT_TYPE_RSAKEY)))
			break;

		if ((result = obj_isConnected_2(hEncData, hKey, &tcsContext)))
			break;

		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
			break;

		if ((result = policy_UsesAuth(hPolicy, &useAuth)))
			break;

		if ((result = Tspi_GetPolicyObject(hEncData, TSS_POLICY_USAGE, &hEncPolicy)))
			break;

		anObject = getAnObjectByHandle(hEncData);
		if (anObject == NULL || anObject->memPointer == NULL) {
			LogDebug1("Failed to get the enc object");
			result = TSS_E_INVALID_HANDLE;
			break;
		}

		encObject = anObject->memPointer;

		tcsKeyHandle = getTCSKeyHandle(hKey);
		if (tcsKeyHandle == NULL_HKEY) {
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}
		break;
	}
	if (result) {
		LogDebug("Failed unseal with result %.8X", result);
		return result;
	}

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Unseal, hashblob);
	Trspi_LoadBlob(&offset, encObject->encryptedDataLength, hashblob, encObject->encryptedData);	/*      Trspi_LoadBlob_STORED_DATA(&offset, hashblob, &encObject->storedData ); */
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &privAuth)))
			return result;
		pPrivAuth = &privAuth;
	} else {
		pPrivAuth = NULL;
	}

	if ((result = secret_PerformAuth_OIAP(hEncPolicy, digest, &privAuth2))) {
		if (useAuth)
			TCSP_TerminateHandle(tcsContext, privAuth.AuthHandle);
		return result;
	}

	if ((result = TCSP_Unseal(tcsContext, tcsKeyHandle, encObject->encryptedDataLength,
				encObject->encryptedData, pPrivAuth, &privAuth2,
				pulUnsealedDataLength, prgbUnsealedData)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Unseal, hashblob);
	Trspi_LoadBlob_UINT32(&offset, *pulUnsealedDataLength, hashblob);
	Trspi_LoadBlob(&offset, *pulUnsealedDataLength, hashblob, *prgbUnsealedData);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
	if (useAuth) {
		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &privAuth))) {
			free_tspi(tspContext, *prgbUnsealedData);
			return result;
		}
	}

	if ((result = secret_ValidateAuth_OIAP(hEncPolicy, digest, &privAuth2))) {
		free_tspi(tspContext, *prgbUnsealedData);
		return result;
	}

	return TSS_SUCCESS;
}
