
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
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_Hash_Sign(TSS_HHASH hHash,			/* in */
	       TSS_HKEY hKey,			/* in */
	       UINT32 * pulSignatureLength,	/* out */
	       BYTE ** prgbSignature		/* out */
    )
{
	TPM_AUTH privAuth;
	TPM_AUTH *pPrivAuth = &privAuth;
	BYTE hashblob[512];
	UINT16 offset;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TSS_HPOLICY hPolicy;
	TCS_CONTEXT_HANDLE tcsContext;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_BOOL usesAuth;
	TSS_HCONTEXT tspContext;
	UINT32 ulDataLen;
	BYTE *data;

	if (pulSignatureLength == NULL || prgbSignature == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_hash_get_tsp_context(hHash, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hPolicy, &usesAuth)))
		return result;

	if ((result = obj_hash_get_value(hHash, &ulDataLen, &data)))
		return result;

	tcsKeyHandle = getTCSKeyHandle(hKey);
	if (tcsKeyHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Sign, hashblob);
		Trspi_LoadBlob_UINT32(&offset, ulDataLen, hashblob);
		Trspi_LoadBlob(&offset, ulDataLen, hashblob, data);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);
		pPrivAuth = &privAuth;

		if ((result = secret_PerformAuth_OIAP(hPolicy, &digest, &privAuth)))
			return result;
	} else {
		pPrivAuth = NULL;
	}

	if ((result = TCSP_Sign(tcsContext, tcsKeyHandle,
			       ulDataLen, data,
			       pPrivAuth, pulSignatureLength, prgbSignature)))
		return result;

	if (usesAuth) {
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashblob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Sign, hashblob);
		Trspi_LoadBlob_UINT32(&offset, *pulSignatureLength, hashblob);
		Trspi_LoadBlob(&offset, *pulSignatureLength, hashblob, *prgbSignature);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &privAuth))) {
			free_tspi(tspContext, *prgbSignature);
			return result;
		}
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Hash_VerifySignature(TSS_HHASH hHash,		/* in */
			  TSS_HKEY hKey,		/* in */
			  UINT32 ulSignatureLength,	/* in */
			  BYTE * rgbSignature		/* in */
    )
{
	TCPA_RESULT result;
	BYTE *pubKey = NULL;
	UINT32 pubKeySize;
	BYTE *hashData = NULL;
	UINT32 hashDataSize;
	UINT32 sigScheme;

	if (ulSignatureLength > 0 && rgbSignature == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_rsakey_get_pub_blob(hKey, &pubKeySize, &pubKey)))
		return result;

	if ((result = obj_rsakey_get_ss(hKey, &sigScheme)))
		return result;

	if ((result = obj_hash_get_value(hHash, &hashDataSize, &hashData)))
		return result;

	if (sigScheme == TSS_SS_RSASSAPKCS1V15_SHA1) {
		result = Trspi_Verify(TSS_HASH_SHA1, hashData, hashDataSize,
				pubKey, pubKeySize,
				rgbSignature, ulSignatureLength);
	} else if (sigScheme == TSS_SS_RSASSAPKCS1V15_DER) {
		result = Trspi_Verify(TSS_HASH_OTHER, hashData, hashDataSize,
				pubKey, pubKeySize,
				rgbSignature, ulSignatureLength);
	} else {
		result = TSPERR(TSS_E_INVALID_SIGSCHEME);
	}

	return result;
}

TSS_RESULT
Tspi_Hash_SetHashValue(TSS_HHASH hHash,			/* in */
		       UINT32 ulHashValueLength,	/* in */
		       BYTE * rgbHashValue		/* in */
    )
{
	if (ulHashValueLength == 0 || rgbHashValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_hash_set_value(hHash, ulHashValueLength, rgbHashValue);
}

TSS_RESULT
Tspi_Hash_GetHashValue(TSS_HHASH hHash,			/* in */
		       UINT32 * pulHashValueLength,	/* out */
		       BYTE ** prgbHashValue		/* out */
    )
{
	if (pulHashValueLength == NULL || prgbHashValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_hash_get_value(hHash, pulHashValueLength, prgbHashValue);
}

TSS_RESULT
Tspi_Hash_UpdateHashValue(TSS_HHASH hHash,	/* in */
			  UINT32 ulDataLength,	/* in */
			  BYTE *rgbData		/* in */
    )
{
	if (rgbData == NULL && ulDataLength != 0)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulDataLength == 0)
		return TSS_SUCCESS;

	return obj_hash_update_value(hHash, ulDataLength, rgbData);
}
