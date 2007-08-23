/*
 * The Initial Developer of the Original Code is Intel Corporation.
 * Portions created by Intel Corporation are Copyright (C) 2007 Intel Corporation.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 *
 * trousers - An open source TCG Software Stack
 *
 * Author: james.xu@intel.com Rossey.liu@intel.com
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_NV_DefineSpace(TSS_HNVSTORE hNvstore,	/* in */
		    TSS_HPCRS hReadPcrComposite,	/* in, may be NULL */
		    TSS_HPCRS hWritePcrComposite)	/* in, may be NULL*/
{
	TSS_HCONTEXT  tspContext;
	TSS_HTPM hTpm;
	TSS_RESULT result;
	UINT32 uiResultLen;
	BYTE *pResult;
	UINT32 i;

	TPM_BOOL defined_index = FALSE;
	NV_DATA_PUBLIC nv_data_public;
	UINT32 need_authdata = FALSE;
	TSS_HPOLICY hPolicy, hEncPolicy;
	BYTE sharedSecret[20];
	TPM_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_NONCE nonceEvenOSAP;
	BYTE *pReadPCR;
	UINT32 pReadPCR_len;
	BYTE *pWritePCR;
	UINT32 pWritePCR_len;
	UINT64 NVPublic_DataSize;
	BYTE NVPublicData[MAX_PUBLIC_DATA_SIZE];
	Trspi_HashCtx hashCtx;
	UINT32 mode;
	TSS_BOOL bExpired;
	TCPA_SECRET usageSec;

	if((result = obj_nvstore_get_tsp_context(hNvstore, &tspContext)))
		return result;

	if ((result = obj_nvstore_get_index(hNvstore, &nv_data_public.nvIndex)))
		return result;

	if ((result = obj_nvstore_get_datasize(hNvstore, &nv_data_public.dataSize)))
		return result;

	if ((result = obj_nvstore_get_permission(hNvstore, &nv_data_public.permission.attributes)))
		return result;

	if ((result = obj_tpm_get(tspContext, &hTpm)))
		return result;

	if((result = Tspi_TPM_GetCapability(hTpm, TSS_TPMCAP_NV_LIST, 0,
					    NULL, &uiResultLen, &pResult)))
		return result;

	for (i = 0; i < uiResultLen/sizeof(UINT32); i++) {
		if (nv_data_public.nvIndex == Decode_UINT32(pResult + i * sizeof(UINT32))) {
			defined_index = TRUE;
			break;
		}
	}
	free_tspi(tspContext, pResult);

	if (defined_index) {
		result = TSPERR(TSS_E_NV_AREA_EXIST);
		return result;
	}

	if ((result = obj_nvstore_get_policy(hNvstore, TSS_POLICY_USAGE, &hEncPolicy)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if (!hEncPolicy) {
		if ((result = obj_context_get_policy(tspContext, TSS_POLICY_USAGE, &hEncPolicy)))
			return result;
	}

	if ((result = obj_policy_get_mode(hEncPolicy, &mode)))
		return result;

	if ((result = obj_policy_has_expired(hEncPolicy, &bExpired)))
		return result;

	need_authdata = nv_data_public.permission.attributes
			& (TPM_NV_PER_AUTHREAD |TPM_NV_PER_AUTHWRITE);

	if (need_authdata && (bExpired || (mode == TSS_SECRET_MODE_NONE))) {
		result = TSPERR(TSS_E_POLICY_NO_SECRET); /* need to define the policy; */
		return result;
	}

	nv_data_public.tag = TPM_TAG_NV_DATA_PUBLIC;

	if ((result = obj_nvstore_create_pcrshortinfo(hNvstore, hReadPcrComposite,
						      &pReadPCR_len, &pReadPCR)))
		return result;

	if ((result = obj_nvstore_create_pcrshortinfo(hNvstore, hWritePcrComposite,
						      &pWritePCR_len, &pWritePCR))) {
		free_tspi(tspContext, pReadPCR);
		return result;
	}

	NVPublic_DataSize = 0;
	Trspi_LoadBlob_UINT16(&NVPublic_DataSize, TPM_TAG_NV_DATA_PUBLIC, NVPublicData);
	Trspi_LoadBlob_UINT32(&NVPublic_DataSize, nv_data_public.nvIndex, NVPublicData);
	Trspi_LoadBlob(&NVPublic_DataSize, pReadPCR_len, NVPublicData, pReadPCR);
	Trspi_LoadBlob(&NVPublic_DataSize, pWritePCR_len, NVPublicData, pWritePCR);
	Trspi_LoadBlob_UINT16(&NVPublic_DataSize, TPM_TAG_NV_ATTRIBUTES, NVPublicData);
	Trspi_LoadBlob_UINT32(&NVPublic_DataSize, nv_data_public.permission.attributes, NVPublicData);
	Trspi_LoadBlob_BOOL(&NVPublic_DataSize, nv_data_public.bReadSTClear, NVPublicData);
	Trspi_LoadBlob_BOOL(&NVPublic_DataSize, nv_data_public.bWriteSTClear, NVPublicData);
	Trspi_LoadBlob_BOOL(&NVPublic_DataSize, nv_data_public.bWriteDefine, NVPublicData);
	Trspi_LoadBlob_UINT32(&NVPublic_DataSize, nv_data_public.dataSize, NVPublicData);
	free_tspi(tspContext, pReadPCR);
	free_tspi(tspContext, pWritePCR);

	if ((result = obj_policy_get_secret(hEncPolicy, TR_SECRET_CTX_NEW, &usageSec)))
		return result;

	memcpy(encAuthUsage.authdata, usageSec.authdata, sizeof(TCPA_SECRET));
	memset(&auth, 0 , sizeof(TPM_AUTH));

	if ((result = obj_policy_get_mode(hPolicy, &mode)))
		return result;

	/*if no secret, then the tspi will use the TPM_TAG_RQU_COMMAND*/
	if (mode != TSS_SECRET_MODE_NONE) {
		if ((result = secret_PerformXOR_OSAP(hPolicy, hEncPolicy, hEncPolicy, hNvstore,
						     TCPA_ET_OWNER, 0, &encAuthUsage,
						     &encAuthMig, sharedSecret, &auth, &nonceEvenOSAP)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_DefineSpace);
		result |= Trspi_HashUpdate(&hashCtx, NVPublic_DataSize, NVPublicData);
		result |= Trspi_HashUpdate(&hashCtx, TCPA_SHA1_160_HASH_LEN, encAuthUsage.authdata);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_PerformAuth_OSAP(hNvstore, TPM_ORD_NV_DefineSpace, hPolicy,
						      hEncPolicy, hEncPolicy, sharedSecret, &auth,
						      digest.digest, &nonceEvenOSAP)))
			return result;

		if ((result = TCS_API(tspContext)->NV_DefineOrReleaseSpace(tspContext,
									   NVPublic_DataSize,
									   NVPublicData,
									   encAuthUsage, &auth)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_DefineSpace);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_ValidateAuth_OSAP(hNvstore, TPM_ORD_NV_DefineSpace, hPolicy,
						       hEncPolicy, hEncPolicy, sharedSecret, &auth,
						       digest.digest, &nonceEvenOSAP)))
			return result;
	} else {
		if ((result = TCS_API(tspContext)->NV_DefineOrReleaseSpace(tspContext,
									   NVPublic_DataSize,
									   NVPublicData,
									   encAuthUsage, NULL)))
			return result;
	}

	return result;
}

TSS_RESULT
Tspi_NV_ReleaseSpace(TSS_HNVSTORE hNvstore)	/* in */
{
	TSS_HCONTEXT  tspContext;
	TSS_HTPM hTpm;
	TSS_RESULT result;
	UINT32 uiResultLen;
	BYTE *pResult;
	UINT32 i;
	TPM_BOOL defined_index = FALSE;
	NV_DATA_PUBLIC nv_data_public;
	TSS_HPOLICY hPolicy, hEncPolicy;
	BYTE sharedSecret[20];
	TPM_AUTH auth;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	TCPA_DIGEST digest;
	TCPA_NONCE nonceEvenOSAP;
	BYTE *pPCR;
	UINT32 pPCR_len;

	UINT64 NVPublic_DataSize;
	BYTE NVPublicData[MAX_PUBLIC_DATA_SIZE];
	Trspi_HashCtx hashCtx;
	UINT32 mode;
	TCPA_SECRET usageSec;

	if((result = obj_nvstore_get_tsp_context(hNvstore, &tspContext)))
		return result;

	if ((result = obj_nvstore_get_index(hNvstore, &nv_data_public.nvIndex)))
		return result;

	if ((result = obj_nvstore_get_datasize(hNvstore, &nv_data_public.dataSize)))
		return result;

	if ((result = obj_nvstore_get_permission(hNvstore, &nv_data_public.permission.attributes)))
		return result;

	if ((result = obj_tpm_get(tspContext, &hTpm)))
		return result;

	if((result = Tspi_TPM_GetCapability(hTpm, TSS_TPMCAP_NV_LIST, 0,
					    NULL, &uiResultLen, &pResult)))
		return result;

	for (i = 0; i < uiResultLen/sizeof(UINT32); i++) {
		if (nv_data_public.nvIndex == Decode_UINT32(pResult + i * sizeof(UINT32))) {
			defined_index = TRUE;
			break;
		}
	}
	free_tspi(tspContext, pResult);

	if (!defined_index) {
		result = TSPERR(TSS_E_NV_AREA_NOT_EXIST);
		return result;
	}

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((result = obj_nvstore_get_policy(hNvstore, TSS_POLICY_USAGE, &hEncPolicy)))
		return result;

	if (!hEncPolicy) {
		if ((result = obj_context_get_policy(tspContext, TSS_POLICY_USAGE, &hEncPolicy)))
			return result;
	}

	if ((result = obj_policy_get_mode(hPolicy, &mode)))
		return result;

	nv_data_public.tag = TPM_TAG_NV_DATA_PUBLIC;

	if ((result = obj_nvstore_create_pcrshortinfo(hNvstore, (TSS_HPCRS)NULL, &pPCR_len, &pPCR)))
		return result;

	NVPublic_DataSize = 0;
	Trspi_LoadBlob_UINT16(&NVPublic_DataSize, TPM_TAG_NV_DATA_PUBLIC, NVPublicData);
	Trspi_LoadBlob_UINT32(&NVPublic_DataSize, nv_data_public.nvIndex, NVPublicData);
	/* load the read pcr short info */
	Trspi_LoadBlob(&NVPublic_DataSize, pPCR_len, NVPublicData, pPCR);
	/* load the write pcr short info */
	Trspi_LoadBlob(&NVPublic_DataSize, pPCR_len, NVPublicData, pPCR);
	Trspi_LoadBlob_UINT16(&NVPublic_DataSize, TPM_TAG_NV_ATTRIBUTES, NVPublicData);
	Trspi_LoadBlob_UINT32(&NVPublic_DataSize,
			      nv_data_public.permission.attributes, NVPublicData);
	Trspi_LoadBlob_BOOL(&NVPublic_DataSize, nv_data_public.bReadSTClear, NVPublicData);
	Trspi_LoadBlob_BOOL(&NVPublic_DataSize, nv_data_public.bWriteSTClear, NVPublicData);
	Trspi_LoadBlob_BOOL(&NVPublic_DataSize, nv_data_public.bWriteDefine, NVPublicData);
	/*Trspi_LoadBlob_UINT32(&NVPublic_DataSize, nv_data_public.dataSize, NVPublicData);*/
	Trspi_LoadBlob_UINT32(&NVPublic_DataSize, 0, NVPublicData);
	free_tspi(tspContext, pPCR);

	if ((result = obj_policy_get_secret(hEncPolicy, TR_SECRET_CTX_NEW, &usageSec)))
		return result;

	memcpy(encAuthUsage.authdata, usageSec.authdata, sizeof(TCPA_SECRET));
	memset(&auth, 0 , sizeof(TPM_AUTH));

	if (mode != TSS_SECRET_MODE_NONE) {/*releasespace need the owner authentication!!!*/
		if ((result = secret_PerformXOR_OSAP(hPolicy, hEncPolicy, hEncPolicy, hNvstore,
						     TCPA_ET_OWNER, 0, &encAuthUsage,
						     &encAuthMig, sharedSecret,
						     &auth, &nonceEvenOSAP)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_DefineSpace);
		result |= Trspi_HashUpdate(&hashCtx, NVPublic_DataSize, NVPublicData);
		result |= Trspi_HashUpdate(&hashCtx, TCPA_SHA1_160_HASH_LEN, encAuthUsage.authdata);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_PerformAuth_OSAP(hNvstore, TPM_ORD_NV_DefineSpace, hPolicy,
						      hEncPolicy, hEncPolicy, sharedSecret, &auth,
						      digest.digest, &nonceEvenOSAP)))
			return result;

		if ((result = TCS_API(tspContext)->NV_DefineOrReleaseSpace(tspContext,
									   NVPublic_DataSize,
									   NVPublicData,
									   encAuthUsage, &auth)))
			return result;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_DefineSpace);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_ValidateAuth_OSAP(hNvstore, TPM_ORD_NV_DefineSpace, hPolicy,
						       hEncPolicy, hEncPolicy, sharedSecret, &auth,
						       digest.digest, &nonceEvenOSAP)))
			return result;
	} else {
		if ((result = TCS_API(tspContext)->NV_DefineOrReleaseSpace(tspContext,
									   NVPublic_DataSize,
									   NVPublicData,
									   encAuthUsage, NULL)))
			return result;
	}

	return result;
}

TSS_RESULT
Tspi_NV_WriteValue(TSS_HNVSTORE hNvstore,	/* in */
		   UINT32 offset,		/* in */
		   UINT32 ulDataLength,		/* in */
		   BYTE* rgbDataToWrite)	/* in */
{
	TSS_HCONTEXT  tspContext;
	TSS_HTPM hTpm;
	TSS_RESULT result;
	NV_DATA_PUBLIC nv_data_public;
	UINT32 need_authdata = 0;
	UINT32  authwrite =0;
	TSS_HPOLICY hPolicy;
	TPM_AUTH auth;
	TCPA_DIGEST digest;
	Trspi_HashCtx hashCtx;

	if ((ulDataLength != 0) && (rgbDataToWrite == NULL))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if((result = obj_nvstore_get_tsp_context(hNvstore, &tspContext)))
		return result;

	if ((result = obj_tpm_get(tspContext, &hTpm)))
		return result;

	if ((result = obj_nvstore_get_index(hNvstore, &nv_data_public.nvIndex)))
		return result;

	if ((result = obj_nvstore_get_policy(hNvstore, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if (hPolicy) {
		if ((result = obj_nvstore_get_permission_from_tpm(hNvstore,
					&nv_data_public.permission.attributes)))
			return result;

		need_authdata = nv_data_public.permission.attributes
				& (TPM_NV_PER_AUTHWRITE | TPM_NV_PER_OWNERWRITE);

		authwrite = nv_data_public.permission.attributes & TPM_NV_PER_AUTHWRITE;

		if (need_authdata) {
			if (!authwrite) {
				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_WriteValue);
				result |= Trspi_Hash_UINT32(&hashCtx, nv_data_public.nvIndex);
				result |= Trspi_Hash_UINT32(&hashCtx, offset);
				result |= Trspi_Hash_UINT32(&hashCtx, ulDataLength);
				result |= Trspi_HashUpdate(&hashCtx, ulDataLength, rgbDataToWrite);

				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = secret_PerformAuth_OIAP(hNvstore,
								      TPM_ORD_NV_WriteValue,
								      hPolicy, FALSE, &digest,
								      &auth)))
					return result;

				if ((result = TCS_API(tspContext)->NV_WriteValue(tspContext,
									nv_data_public.nvIndex,
									offset, ulDataLength,
									rgbDataToWrite, &auth)))
					return result;

				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, result);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_WriteValue);
				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = obj_policy_validate_auth_oiap(hPolicy,
									    &digest, &auth)))
					return result;
			} else {
				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_WriteValueAuth);
				result |= Trspi_Hash_UINT32(&hashCtx, nv_data_public.nvIndex);
				result |= Trspi_Hash_UINT32(&hashCtx, offset);
				result |= Trspi_Hash_UINT32(&hashCtx, ulDataLength);
				result |= Trspi_HashUpdate(&hashCtx, ulDataLength, rgbDataToWrite);

				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = secret_PerformAuth_OIAP(hNvstore,
								      TPM_ORD_NV_WriteValueAuth,
								      hPolicy, FALSE, &digest,
								      &auth)))
					return result;

				if ((result = TCS_API(tspContext)->NV_WriteValueAuth(tspContext,
									nv_data_public.nvIndex,
									offset, ulDataLength,
									rgbDataToWrite, &auth)))
					return result;

				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, result);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_WriteValueAuth);
				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = obj_policy_validate_auth_oiap(hPolicy,
									    &digest, &auth)))
					return result;
			}
		} else {
			if ((result = TCS_API(tspContext)->NV_WriteValue(tspContext,
									 nv_data_public.nvIndex,
									 offset, ulDataLength,
									 rgbDataToWrite, NULL)))
				return result;
		}
	} else {
		LogDebug("no policy, so noauthentication");
		if ((result = TCS_API(tspContext)->NV_WriteValue(tspContext, nv_data_public.nvIndex,
								 offset, ulDataLength,
								 rgbDataToWrite, NULL)))
			return result;
	}

	return result;
}

TSS_RESULT
Tspi_NV_ReadValue(TSS_HNVSTORE hNvstore,	/* in */
		  UINT32 offset,		/* in */
		  UINT32* ulDataLength,		/* in, out */
		  BYTE** rgbDataRead)		/* out */
{
	TSS_HCONTEXT  tspContext;
	TSS_HTPM hTpm;
	TSS_RESULT result;
	NV_DATA_PUBLIC nv_data_public;
	UINT32 need_authdata = 0;
	UINT32  authread =0;
	TSS_HPOLICY hPolicy;

	TPM_AUTH auth;
	TCPA_DIGEST digest;
	Trspi_HashCtx hashCtx;

	if (ulDataLength == NULL || rgbDataRead == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if((result = obj_nvstore_get_tsp_context(hNvstore, &tspContext)))
		return result;

	if ((result = obj_tpm_get(tspContext, &hTpm)))
		return result;

	if ((result = obj_nvstore_get_index(hNvstore, &nv_data_public.nvIndex)))
		return result;

	if ((result = obj_nvstore_get_policy(hNvstore, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if (hPolicy) {/*if the policy secret is set*/
		if ((result = obj_nvstore_get_permission_from_tpm(hNvstore,
							 &nv_data_public.permission.attributes)))
			return result;

		need_authdata = nv_data_public.permission.attributes
				& (TPM_NV_PER_AUTHREAD | TPM_NV_PER_OWNERREAD);

		authread = nv_data_public.permission.attributes & TPM_NV_PER_AUTHREAD;

		if (need_authdata) {
			if (!authread) {
				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_ReadValue);
				result |= Trspi_Hash_UINT32(&hashCtx, nv_data_public.nvIndex);
				result |= Trspi_Hash_UINT32(&hashCtx, offset);
				result |= Trspi_Hash_UINT32(&hashCtx, *ulDataLength);

				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = secret_PerformAuth_OIAP(hNvstore,
								      TPM_ORD_NV_ReadValue,
								      hPolicy, FALSE, &digest,
								      &auth)))
					return result;

				if ((result = TCS_API(tspContext)->NV_ReadValue(tspContext,
									nv_data_public.nvIndex,
									offset, ulDataLength,
									&auth, rgbDataRead)))
					return result;

				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, TSS_SUCCESS);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_ReadValue);
				result |= Trspi_Hash_UINT32(&hashCtx, *ulDataLength);
				result |= Trspi_HashUpdate(&hashCtx, *ulDataLength, *rgbDataRead);
				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = obj_policy_validate_auth_oiap(hPolicy,
									    &digest, &auth)))
					return result;
			} else {
				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_ReadValueAuth);
				result |= Trspi_Hash_UINT32(&hashCtx, nv_data_public.nvIndex);
				result |= Trspi_Hash_UINT32(&hashCtx, offset);
				result |= Trspi_Hash_UINT32(&hashCtx, *ulDataLength);

				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = secret_PerformAuth_OIAP(hNvstore,
								      TPM_ORD_NV_ReadValueAuth,
								      hPolicy, FALSE, &digest,
								      &auth)))
					return result;

				if ((result = TCS_API(tspContext)->NV_ReadValueAuth(tspContext,
									nv_data_public.nvIndex,
									offset, ulDataLength,
									&auth, rgbDataRead)))
					return result;

				result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
				result |= Trspi_Hash_UINT32(&hashCtx, TSS_SUCCESS);
				result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_NV_ReadValueAuth);
				result |= Trspi_Hash_UINT32(&hashCtx, *ulDataLength);
				result |= Trspi_HashUpdate(&hashCtx, *ulDataLength, *rgbDataRead);
				if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
					return result;

				if ((result = obj_policy_validate_auth_oiap(hPolicy,
									    &digest, &auth)))
					return result;
			}
		} else {
			if ((result = TCS_API(tspContext)->NV_ReadValue(tspContext,
									nv_data_public.nvIndex,
									offset, ulDataLength, NULL,
									rgbDataRead)))
				return result;
		}
	} else {
		if ((result = TCS_API(tspContext)->NV_ReadValue(tspContext, nv_data_public.nvIndex,
								offset, ulDataLength, NULL,
								rgbDataRead)))
			return result;
	}

	return result;
}
