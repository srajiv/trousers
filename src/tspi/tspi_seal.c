
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
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_Data_Seal(TSS_HENCDATA hEncData,	/* in */
	       TSS_HKEY hEncKey,	/* in */
	       UINT32 ulDataLength,	/* in */
	       BYTE * rgbDataToSeal,	/* in */
	       TSS_HPCRS hPcrComposite)	/* in */
{
	UINT64 offset;
	//BYTE hashBlob[0x1000];
	BYTE sharedSecret[20];
	TPM_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy, hEncPolicy;
	BYTE *encData = NULL;
	UINT32 encDataSize;
	UINT32 pcrDataSize;
	BYTE pcrData[256];
	TCS_KEY_HANDLE tcsKeyHandle;
	TCPA_NONCE nonceEvenOSAP;
	TCPA_DIGEST digAtCreation;
	TSS_HCONTEXT tspContext;
	TCPA_PCR_SELECTION pcrSelect = { 0, NULL };
	Trspi_HashCtx hashCtx;

	if (rgbDataToSeal == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_encdata_get_tsp_context(hEncData, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hEncKey, TSS_POLICY_USAGE,
					    &hPolicy, NULL)))
		return result;

	if ((result = obj_encdata_get_policy(hEncData, TSS_POLICY_USAGE,
					     &hEncPolicy)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hEncKey, &tcsKeyHandle)))
		return result;

	/* If PCR's are of interest */
	pcrDataSize = 0;
	if (hPcrComposite) {
		if ((result = obj_pcrs_get_composite(hPcrComposite,
						     &digAtCreation)))
			return result;

		if ((result = obj_pcrs_get_selection(hPcrComposite,
						     &pcrSelect)))
			return result;

		LogDebug("Digest at Creation:");
		LogDebugData(sizeof(digAtCreation), (BYTE *)&digAtCreation);

		offset = 0;
		Trspi_LoadBlob_PCR_SELECTION(&offset, pcrData, &pcrSelect);
		free(pcrSelect.pcrSelect);
		Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, pcrData,
			       digAtCreation.digest);
		/* XXX */
		Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, pcrData,
			       digAtCreation.digest);
		pcrDataSize = offset;
	}

	if ((result = secret_PerformXOR_OSAP(hPolicy, hEncPolicy, hEncPolicy,
					     hEncKey, TCPA_ET_KEYHANDLE,
					     tcsKeyHandle,
					     &encAuthUsage, &encAuthMig,
					     sharedSecret, &auth,
					     &nonceEvenOSAP)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Seal);
	result |= Trspi_HashUpdate(&hashCtx, TCPA_SHA1_160_HASH_LEN, encAuthUsage.authdata);
	result |= Trspi_Hash_UINT32(&hashCtx, pcrDataSize);
	result |= Trspi_HashUpdate(&hashCtx, pcrDataSize, pcrData);
	result |= Trspi_Hash_UINT32(&hashCtx, ulDataLength);
	result |= Trspi_HashUpdate(&hashCtx, ulDataLength, rgbDataToSeal);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OSAP(hEncKey, TPM_ORD_Seal, hPolicy,
					      hEncPolicy, hEncPolicy,
					      sharedSecret, &auth,
					      digest.digest, &nonceEvenOSAP)))
		return result;

	if ((result = TCSP_Seal(tcsContext, tcsKeyHandle, encAuthUsage,
				pcrDataSize, pcrData, ulDataLength,
				rgbDataToSeal, &auth, &encDataSize, &encData)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Seal);
	result |= Trspi_HashUpdate(&hashCtx, encDataSize, encData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_ValidateAuth_OSAP(hEncKey, TPM_ORD_Seal, hPolicy,
					       hEncPolicy, hEncPolicy,
					       sharedSecret, &auth,
					       digest.digest,
					       &nonceEvenOSAP))) {
		free(encData);
		return result;
	}

	/* Need to set the object with the blob and the pcr's */
	if ((result = obj_encdata_set_data(hEncData, encDataSize, encData)))
		return result;

	free(encData);

	if (pcrDataSize) {
		if ((result = obj_encdata_set_pcr_info(hEncData, pcrData)))
			return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Data_Unseal(TSS_HENCDATA hEncData,		/* in */
		 TSS_HKEY hKey,			/* in */
		 UINT32 * pulUnsealedDataLength,/* out */
		 BYTE ** prgbUnsealedData)	/* out */
{
	TPM_AUTH privAuth, privAuth2;
	//UINT64 offset;
	//BYTE hashblob[0x400];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy, hEncPolicy;
	TCS_KEY_HANDLE tcsKeyHandle;
        TSS_HCONTEXT tspContext;
	UINT32 ulDataLen;
	BYTE *data;
	Trspi_HashCtx hashCtx;

	if (pulUnsealedDataLength == NULL || prgbUnsealedData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_encdata_get_tsp_context(hEncData, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hPolicy, NULL)))
		return result;

	if ((result = obj_encdata_get_policy(hEncData, TSS_POLICY_USAGE,
					     &hEncPolicy)))
		return result;

	if ((result = obj_encdata_get_data(hEncData, &ulDataLen, &data)))
		return result == TSPERR(TSS_E_INVALID_OBJ_ACCESS) ?
		       TSPERR(TSS_E_ENC_NO_DATA) :
		       result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &tcsKeyHandle)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Unseal);
	result |= Trspi_HashUpdate(&hashCtx, ulDataLen, data);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_Unseal,
					      hPolicy, &digest,
					      &privAuth)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hEncData, TPM_ORD_Unseal,
					      hEncPolicy, &digest,
					      &privAuth2)))
		return result;

	if ((result = TCSP_Unseal(tcsContext, tcsKeyHandle,
				  ulDataLen, data, &privAuth,
				  &privAuth2, pulUnsealedDataLength,
				  prgbUnsealedData)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Unseal);
	result |= Trspi_Hash_UINT32(&hashCtx, *pulUnsealedDataLength);
	result |= Trspi_HashUpdate(&hashCtx, *pulUnsealedDataLength, *prgbUnsealedData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest,
						    &privAuth))) {
		free_tspi(tspContext, *prgbUnsealedData);
		return result;
	}

	if ((result = obj_policy_validate_auth_oiap(hEncPolicy, &digest,
						    &privAuth2))) {
		free_tspi(tspContext, *prgbUnsealedData);
		return result;
	}

	return TSS_SUCCESS;
}
