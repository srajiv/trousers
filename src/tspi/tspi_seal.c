
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
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
	BYTE sharedSecret[20];
	TPM_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TSS_HPOLICY hPolicy, hEncPolicy;
	BYTE *encData = NULL;
	UINT32 encDataSize;
	UINT32 pcrInfoType;
	UINT32 pcrDataSize;
	BYTE *pcrData;
	TCS_KEY_HANDLE tcsKeyHandle;
	TCPA_NONCE nonceOddOSAP;
	TCPA_NONCE nonceEvenOSAP;
	TSS_HCONTEXT tspContext;
	Trspi_HashCtx hashCtx;
	UINT32 sealOrdinal;
	BYTE *sealData;
#ifdef TSS_BUILD_SEALX
	UINT32 protectMode;
#endif

	if (rgbDataToSeal == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_encdata_get_tsp_context(hEncData, &tspContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hEncKey, TSS_POLICY_USAGE,
					    &hPolicy, NULL)))
		return result;

	if ((result = obj_encdata_get_policy(hEncData, TSS_POLICY_USAGE,
					     &hEncPolicy)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hEncKey, &tcsKeyHandle)))
		return result;

#ifdef TSS_BUILD_SEALX
	/* Get the TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE attribute
	   to determine the seal function to invoke */
	if ((result = obj_encdata_get_seal_protect_mode(hEncData, &protectMode)))
		return result;

	if (protectMode == TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT) {
		sealOrdinal = TPM_ORD_Seal;
		pcrInfoType = 0;
	} else if (protectMode == TSS_TSPATTRIB_ENCDATASEAL_PROTECT) {
		sealOrdinal = TPM_ORD_Sealx;
		pcrInfoType = TSS_PCRS_STRUCT_INFO_LONG;
	} else
		return TSPERR(TSS_E_INTERNAL_ERROR);
#else
	sealOrdinal = TPM_ORD_Seal;
	pcrInfoType = 0;
#endif

	/* If PCR's are of interest */
	pcrDataSize = 0;
	if (hPcrComposite) {
		if ((result = obj_pcrs_create_info_type(hPcrComposite, pcrInfoType,
				&pcrDataSize, &pcrData)))
			return result;
	}

	if ((result = secret_PerformXOR_OSAP(hPolicy, hEncPolicy, hEncPolicy, hEncKey,
					     TCPA_ET_KEYHANDLE, tcsKeyHandle, &encAuthUsage,
					     &encAuthMig, sharedSecret, &auth, &nonceEvenOSAP)))
		return result;
	nonceOddOSAP = auth.NonceOdd;

#ifdef TSS_BUILD_SEALX
	if (sealOrdinal == TPM_ORD_Seal)
		sealData = rgbDataToSeal;
	else {
		/* Mask the input data before sending it */
		if ((result = obj_policy_do_sealx_mask(hEncPolicy, hEncKey, hEncData, &auth,
						       &nonceEvenOSAP, &nonceOddOSAP,
						       ulDataLength, rgbDataToSeal,
						       &sealData)))
			return result;
	}
#else
	sealData = rgbDataToSeal;
#endif

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, sealOrdinal);
	result |= Trspi_HashUpdate(&hashCtx, TCPA_SHA1_160_HASH_LEN, encAuthUsage.authdata);
	result |= Trspi_Hash_UINT32(&hashCtx, pcrDataSize);
	result |= Trspi_HashUpdate(&hashCtx, pcrDataSize, pcrData);
	result |= Trspi_Hash_UINT32(&hashCtx, ulDataLength);
	result |= Trspi_HashUpdate(&hashCtx, ulDataLength, sealData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest))) {
		if (sealData != rgbDataToSeal)
			free(sealData);
		return result;
	}

	if ((result = secret_PerformAuth_OSAP(hEncKey, TPM_ORD_Seal, hPolicy, hEncPolicy,
					      hEncPolicy, sharedSecret, &auth, digest.digest,
					      &nonceEvenOSAP))) {
		if (sealData != rgbDataToSeal)
			free(sealData);
		return result;
	}

#ifdef TSS_BUILD_SEALX
	if (sealOrdinal == TPM_ORD_Seal) {
		if ((result = TCS_API(tspContext)->Seal(tspContext, tcsKeyHandle, &encAuthUsage,
							pcrDataSize, pcrData, ulDataLength,
							sealData, &auth, &encDataSize, &encData)))
			return result;
	} else if (sealOrdinal == TPM_ORD_Sealx) {
		result = TCS_API(tspContext)->Sealx(tspContext, tcsKeyHandle, &encAuthUsage,
						    pcrDataSize, pcrData, ulDataLength, sealData,
						    &auth, &encDataSize, &encData);
		free(sealData);

		if (result != TSS_SUCCESS)
			return result;
	} else
		return TSPERR(TSS_E_INTERNAL_ERROR);
#else
	if ((result = TCS_API(tspContext)->Seal(tspContext, tcsKeyHandle, &encAuthUsage,
						pcrDataSize, pcrData, ulDataLength, sealData, &auth,
						&encDataSize, &encData)))
		return result;
#endif

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, sealOrdinal);
	result |= Trspi_HashUpdate(&hashCtx, encDataSize, encData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest))) {
		free(encData);
		return result;
	}

	if ((result = secret_ValidateAuth_OSAP(hEncKey, TPM_ORD_Seal, hPolicy, hEncPolicy,
					       hEncPolicy, sharedSecret, &auth, digest.digest,
					       &nonceEvenOSAP))) {
		free(encData);
		return result;
	}

	/* Need to set the object with the blob and the pcr's */
	if ((result = obj_encdata_set_data(hEncData, encDataSize, encData))) {
		free(encData);
		return result;
	}

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
	TCPA_DIGEST digest;
	TCPA_RESULT result;
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

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hPolicy, NULL)))
		return result;

	if ((result = obj_encdata_get_policy(hEncData, TSS_POLICY_USAGE, &hEncPolicy)))
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

	if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_Unseal, hPolicy, FALSE, &digest,
					      &privAuth)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hEncData, TPM_ORD_Unseal, hEncPolicy, FALSE, &digest,
					      &privAuth2)))
		return result;

	if ((result = TCS_API(tspContext)->Unseal(tspContext, tcsKeyHandle, ulDataLen, data,
						  &privAuth, &privAuth2, pulUnsealedDataLength,
						  prgbUnsealedData)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Unseal);
	result |= Trspi_Hash_UINT32(&hashCtx, *pulUnsealedDataLength);
	result |= Trspi_HashUpdate(&hashCtx, *pulUnsealedDataLength, *prgbUnsealedData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest))) {
		free(*prgbUnsealedData);
		return result;
	}

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &privAuth))) {
		free(*prgbUnsealedData);
		return result;
	}

	if ((result = obj_policy_validate_auth_oiap(hEncPolicy, &digest, &privAuth2))) {
		free(*prgbUnsealedData);
		return result;
	}

	if ((result = add_mem_entry(tspContext, *prgbUnsealedData))) {
		free(*prgbUnsealedData);
		return result;
	}

	return TSS_SUCCESS;
}
