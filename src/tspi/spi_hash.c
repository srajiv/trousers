
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
Tspi_Hash_Sign(TSS_HHASH hHash,	/* in */
	       TSS_HKEY hKey,	/* in */
	       UINT32 * pulSignatureLength,	/* out */
	       BYTE ** prgbSignature	/* out */
    )
{
	TCS_AUTH privAuth;
	TCS_AUTH *pPrivAuth = &privAuth;
	BYTE hashblob[512];
	UINT16 offset;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TSS_HPOLICY hPolicy;
	TCS_CONTEXT_HANDLE tcsContext;
	TCS_KEY_HANDLE tcsKeyHandle;
	AnObject *anObject;
	TCPA_HASH_OBJECT *hashObject;
	BOOL usesAuth;
	TSS_HCONTEXT tspContext;

	if (pulSignatureLength == NULL || prgbSignature == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((tspContext = obj_getTspContext(hHash)) == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	LogDebug1("Entering Tspi_Hash_Sign");
	if ((result = obj_checkType_2(hHash, TSS_OBJECT_TYPE_HASH, hKey, TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = obj_isConnected_2(hHash, hKey, &tcsContext)))
		return result;

	if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((result = policy_UsesAuth(hPolicy, &usesAuth)))
		return result;

	anObject = getAnObjectByHandle(hHash);

	if (anObject == NULL || anObject->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;

	hashObject = anObject->memPointer;
#if 0
	if (hashObject->hashType != TSS_HASH_SHA1)
		return TSS_E_NOTIMPL;
#endif
	tcsKeyHandle = getTCSKeyHandle(hKey);
	if (tcsKeyHandle == NULL_HKEY) {
		return TSS_E_KEY_NOT_LOADED;
	}

	if (usesAuth == FALSE) {
		pPrivAuth = NULL;
	} else {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Sign, hashblob);
		Trspi_LoadBlob_UINT32(&offset, hashObject->hashSize, hashblob);
		Trspi_LoadBlob(&offset, hashObject->hashSize, hashblob, hashObject->hashData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
		pPrivAuth = &privAuth;

		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &privAuth)))
			return result;
	}

	if ((result = TCSP_Sign(tcsContext,
			       tcsKeyHandle,
			       hashObject->hashSize,
			       hashObject->hashData, pPrivAuth, pulSignatureLength, prgbSignature)))
		return result;

	if (usesAuth == TRUE) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashblob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Sign, hashblob);
		Trspi_LoadBlob_UINT32(&offset, *pulSignatureLength, hashblob);
		Trspi_LoadBlob(&offset, *pulSignatureLength, hashblob, *prgbSignature);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &privAuth))) {
			free_tspi(tspContext, *prgbSignature);
			return result;
		}
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Hash_VerifySignature(TSS_HHASH hHash,	/* in  */
			  TSS_HKEY hKey,	/* in */
			  UINT32 ulSignatureLength,	/* in */
			  BYTE * rgbSignature	/* in */
    )
{
	TCPA_RESULT result;
	BYTE *pubKey = NULL;
	UINT32 pubKeySize;
	BYTE *hashData = NULL;
	UINT32 hashDataSize;
	UINT32 sigScheme;

	if (ulSignatureLength > 0 && rgbSignature == NULL)
		return TSS_E_BAD_PARAMETER;

	for (;;) {
		if ((result = obj_checkType_2(hHash, TSS_OBJECT_TYPE_HASH,
					       hKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;

		if ((result = obj_checkSession_2(hHash, hKey)))
			break;

		if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				       TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &pubKeySize, &pubKey)))
			break;

		if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				       TSS_TSPATTRIB_KEYINFO_SIGSCHEME, &sigScheme)))
			break;

		if ((result = Tspi_Hash_GetHashValue(hHash, &hashDataSize, &hashData)))
			break;

		if (sigScheme == TSS_SS_RSASSAPKCS1V15_SHA1) {
			result = Trspi_Verify(TSS_HASH_SHA1, hashData, hashDataSize,
						pubKey, pubKeySize,
						rgbSignature, ulSignatureLength);
		} else if (sigScheme == TSS_SS_RSASSAPKCS1V15_DER) {
			result = Trspi_Verify(TSS_HASH_OTHER, hashData, hashDataSize,
						pubKey, pubKeySize,
						rgbSignature, ulSignatureLength);
		} else {
			result = TSS_E_INVALID_SIGSCHEME;
		}

		break;
	}

	return result;
}

TSS_RESULT
Tspi_Hash_SetHashValue(TSS_HHASH hHash,	/* in */
		       UINT32 ulHashValueLength,	/* in */
		       BYTE * rgbHashValue	/* in */
    )
{
	TSS_RESULT result = TSS_SUCCESS;
	AnObject *object = NULL;
	TCPA_HASH_OBJECT *hashObject = NULL;

	if (ulHashValueLength == 0 || rgbHashValue == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = obj_checkType_1(hHash, TSS_OBJECT_TYPE_HASH)))
		return result;

	object = getAnObjectByHandle(hHash);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;

	if (object->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hHash);
		return TSS_E_INTERNAL_ERROR;
	}

	hashObject = object->memPointer;

	/*---	Copy the new size into the object */
	hashObject->hashSize = ulHashValueLength;

	/*---	If the current data in the hasObject exists, free it */
	if (hashObject->hashData != NULL)
		free(hashObject->hashData);

	/*---	Malloc new space */
	hashObject->hashData = malloc(hashObject->hashSize);
	if (hashObject->hashData == NULL) {
		LogError("malloc of %d bytes failed.", hashObject->hashSize);
		return TSS_E_OUTOFMEMORY;
	}

	/*---	Copy the new Data in */
	memcpy(hashObject->hashData, rgbHashValue, ulHashValueLength);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Hash_GetHashValue(TSS_HHASH hHash,	/* in */
		       UINT32 * pulHashValueLength,	/* out */
		       BYTE ** prgbHashValue	/* out */
    )
{
	AnObject *object = NULL;
	TSS_RESULT result = TSS_SUCCESS;
	TCPA_HASH_OBJECT *hashObject = NULL;
	TSS_HCONTEXT tspContext;

	if (pulHashValueLength == NULL || prgbHashValue == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = obj_checkType_1(hHash, TSS_OBJECT_TYPE_HASH)))
		return result;

	if ((tspContext = obj_getTspContext(hHash)) == NULL_HCONTEXT)
		return TSS_E_INTERNAL_ERROR;

	object = getAnObjectByHandle(hHash);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;

	if (object->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hHash);
		return TSS_E_INTERNAL_ERROR;
	}

	hashObject = object->memPointer;

	if (hashObject->hashData == NULL)
		return TSS_E_HASH_NO_DATA;

	if (hashObject->hashSize == 0)
		return TSS_E_HASH_INVALID_LENGTH;

	/*---	The size */
	*pulHashValueLength = hashObject->hashSize;

	/*---	The data */
	*prgbHashValue = calloc_tspi(tspContext, *pulHashValueLength);
	if (*prgbHashValue == NULL) {
		LogError("malloc of %d bytes failed.", *pulHashValueLength);
		return TSS_E_OUTOFMEMORY;
	}
	memcpy(*prgbHashValue, hashObject->hashData, *pulHashValueLength);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Hash_UpdateHashValue(TSS_HHASH hHash,	/* in */
			  UINT32 ulDataLength,	/* in */
			  BYTE * rgbData	/* in */
    )
{
#if 0
	BYTE *tempBuf = NULL;
#endif
	AnObject *object = NULL;
	TSS_RESULT result = TSS_SUCCESS;
	TCPA_HASH_OBJECT *hashObject = NULL;

	if (rgbData == NULL && ulDataLength != 0)
		return TSS_E_BAD_PARAMETER;

	if ((result = obj_checkType_1(hHash, TSS_OBJECT_TYPE_HASH)))
		return result;

	object = getAnObjectByHandle(hHash);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;

	if (object->memPointer == NULL) {
		LogError("internal object pointer for handle 0x%x not found!", hHash);
		return TSS_E_INTERNAL_ERROR;
	}

	hashObject = object->memPointer;

	/* If this is not a SHA1 hash object, then we don't know what to do with the passed
	 * in data, so fail.
	 */
	if (hashObject->hashType != TSS_HASH_SHA1 &&
	    hashObject->hashType != TSS_HASH_DEFAULT)
		return TSS_E_FAIL;

#if 0
	tempBuf = malloc(hashObject->hashUpdateSize + ulDataLength);
	if (tempBuf == NULL) {
		LogError("malloc of %x bytes failed.", hashObject->hashSize + ulDataLength);
		return TSS_E_OUTOFMEMORY;
	}
#endif

	if (hashObject->hashUpdateBuffer == NULL) {
		hashObject->hashUpdateBuffer = malloc(ulDataLength);
		if (hashObject->hashUpdateBuffer == NULL) {
			LogError("malloc of %x bytes failed.", hashObject->hashSize + ulDataLength);
			return TSS_E_OUTOFMEMORY;
		}
	} else {
		hashObject->hashUpdateBuffer = realloc(hashObject->hashUpdateBuffer,
						       ulDataLength + hashObject->hashUpdateSize);

		if (hashObject->hashUpdateBuffer == NULL) {
			LogError("malloc of %x bytes failed.", ulDataLength + hashObject->hashUpdateSize);
			return TSS_E_OUTOFMEMORY;
		}
	}

	if (ulDataLength != 0) {
		memcpy(&hashObject->hashUpdateBuffer[hashObject->hashUpdateSize], rgbData, ulDataLength);
		hashObject->hashUpdateBuffer += ulDataLength;
	}

	if (hashObject->hashData == NULL) {
		hashObject->hashData = malloc(TPM_DIGEST_SIZE);
		if (hashObject->hashData == NULL) {
			LogError("malloc of %d bytes failed.", TPM_DIGEST_SIZE);
			return TSS_E_OUTOFMEMORY;
		}
	}
	Trspi_Hash(TSS_HASH_SHA1, hashObject->hashUpdateSize,
			hashObject->hashUpdateBuffer, hashObject->hashData);

	return TSS_SUCCESS;
}
