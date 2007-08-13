
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "obj.h"
#include "tsplog.h"
#include "tsp_delegate.h"


TSS_RESULT
do_delegate_manage(TSS_HTPM hTpm, UINT32 familyID, UINT32 opFlag,
		   UINT32 opDataSize, BYTE *opData, UINT32 *outDataSize, BYTE **outData)
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	UINT32 secretMode = TSS_SECRET_MODE_NONE;
	Trspi_HashCtx hashCtx;
	TCPA_DIGEST digest;
	TPM_AUTH ownerAuth, *pAuth;
	UINT32 retDataSize;
	BYTE *retData = NULL;
	TSS_RESULT result;

	if ((result = obj_tpm_get_tsp_context(hTpm, &hContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if (hPolicy != NULL_HPOLICY) {
		if ((result = obj_policy_get_mode(hPolicy, &secretMode)))
			return result;
	}

	if (secretMode != TSS_SECRET_MODE_NONE) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Delegate_Manage);
		result |= Trspi_Hash_UINT32(&hashCtx, familyID);
		result |= Trspi_Hash_UINT32(&hashCtx, opFlag);
		result |= Trspi_Hash_UINT32(&hashCtx, opDataSize);
		result |= Trspi_HashUpdate(&hashCtx, opDataSize, opData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		pAuth = &ownerAuth;
		if ((result = secret_PerformAuth_OIAP(hTpm, TPM_ORD_Delegate_Manage,
				hPolicy, FALSE, &digest, pAuth)))
			return result;
	} else
		pAuth = NULL;

	/* Perform the delegation operation */
	if ((result = TCSP_Delegate_Manage(hContext, familyID, opFlag,
			opDataSize, opData, pAuth, &retDataSize, &retData))) 
		return result;

	if (pAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Delegate_Manage);
		result |= Trspi_Hash_UINT32(&hashCtx, retDataSize);
		result |= Trspi_HashUpdate(&hashCtx, retDataSize, retData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest))) {
			free(retData);
			goto done;
		}

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, pAuth))) {
			free(retData);
			goto done;
		}
	}

	*outDataSize = retDataSize;
	*outData = retData;

done:
	return result;
}

TSS_RESULT
create_owner_delegation(TSS_HTPM       hTpm,
			BYTE           bLabel,
			UINT32         ulFlags,
			TSS_HPCRS      hPcrs,
			TSS_HDELFAMILY hFamily,
			TSS_HPOLICY    hDelegation)
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	TSS_BOOL incrementCount = FALSE;
	UINT32 type;
	UINT32 secretMode = TSS_SECRET_MODE_NONE;
	UINT32 publicInfoSize;
	BYTE *publicInfo = NULL;
	Trspi_HashCtx hashCtx;
	TCPA_DIGEST digest;
	TCPA_ENCAUTH encAuthUsage, encAuthMig;
	BYTE sharedSecret[20];
	TCPA_NONCE nonceOddOSAP;
	TCPA_NONCE nonceEvenOSAP;
	TPM_AUTH ownerAuth, *pAuth;
	UINT32 blobSize;
	BYTE *blob;
	TSS_RESULT result;

	if ((result = obj_tpm_get_tsp_context(hTpm, &hContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((ulFlags & ~TSS_DELEGATE_INCREMENTVERIFICATIONCOUNT) > 0)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulFlags & TSS_DELEGATE_INCREMENTVERIFICATIONCOUNT)
		incrementCount = TRUE;

	if ((result = obj_policy_get_delegation_type(hDelegation, &type)))
		return result;

	if (type != TSS_DELEGATIONTYPE_OWNER)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (hPolicy != NULL_HPOLICY) {
		if ((result = obj_policy_get_mode(hPolicy, &secretMode)))
			return result;
	}

	if ((result = build_delegate_public_info(bLabel, hPcrs, hFamily, hDelegation,
			&publicInfoSize, &publicInfo)))
		return result;

	if (secretMode != TSS_SECRET_MODE_NONE) {
		pAuth = &ownerAuth;
		if ((result = secret_PerformXOR_OSAP(hPolicy, hDelegation, NULL_HPOLICY, TPM_KH_OWNER,
						     TCPA_ET_OWNER, TPM_KH_OWNER, &encAuthUsage,
						     &encAuthMig, sharedSecret, pAuth, &nonceEvenOSAP)))
			goto done;
		nonceOddOSAP = pAuth->NonceOdd;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Delegate_CreateOwnerDelegation);
		result |= Trspi_Hash_BOOL(&hashCtx, incrementCount);
		result |= Trspi_HashUpdate(&hashCtx, publicInfoSize, publicInfo);
		result |= Trspi_Hash_ENCAUTH(&hashCtx, encAuthUsage.authdata);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if ((result = secret_PerformAuth_OSAP(hTpm,
				TPM_ORD_Delegate_CreateOwnerDelegation, hPolicy, hPolicy,
				NULL_HPOLICY, sharedSecret, pAuth, digest.digest, &nonceEvenOSAP)))
			goto done;
	} else
		pAuth = NULL;

	/* Create the delegation */
	if ((result = TCSP_Delegate_CreateOwnerDelegation(hContext, incrementCount, publicInfoSize,
			publicInfo, encAuthUsage, pAuth, &blobSize, &blob)))
		return result;

	if (pAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Delegate_CreateOwnerDelegation);
		result |= Trspi_Hash_UINT32(&hashCtx, blobSize);
		result |= Trspi_HashUpdate(&hashCtx, blobSize, blob);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if ((result = secret_ValidateAuth_OSAP(TPM_KH_OWNER,
				TPM_ORD_Delegate_CreateOwnerDelegation, hPolicy, hPolicy,
				NULL_HPOLICY, sharedSecret, pAuth, digest.digest,
				&nonceEvenOSAP)))
			goto done;
	}

	result = obj_policy_set_delegation_blob(hDelegation, TSS_DELEGATIONTYPE_OWNER,
			blobSize, blob);

done:
	free(publicInfo);

	return result;
}

TSS_RESULT
create_key_delegation(TSS_HKEY       hKey,
		      BYTE           bLabel,
		      UINT32         ulFlags,
		      TSS_HPCRS      hPcrs,
		      TSS_HDELFAMILY hFamily,
		      TSS_HPOLICY    hDelegation)
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	TSS_BOOL useAuth;
	UINT32 type;
	UINT32 secretMode = TSS_SECRET_MODE_NONE;
	TCS_KEY_HANDLE tcsKeyHandle;
	UINT32 publicInfoSize;
	BYTE *publicInfo = NULL;
	Trspi_HashCtx hashCtx;
	TCPA_DIGEST digest;
	TCPA_ENCAUTH encAuthUsage, encAuthMig;
	BYTE sharedSecret[20];
	TCPA_NONCE nonceOddOSAP;
	TCPA_NONCE nonceEvenOSAP;
	TPM_AUTH keyAuth, *pAuth;
	UINT32 blobSize;
	BYTE *blob;
	TSS_RESULT result;

	if ((result = obj_rsakey_get_tsp_context(hKey, &hContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hPolicy, &useAuth)))
		return result;

	if (ulFlags != 0)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_policy_get_delegation_type(hDelegation, &type)))
		return result;

	if (type != TSS_DELEGATIONTYPE_KEY)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((hPolicy != NULL_HPOLICY) && (useAuth == TRUE)) {
		if ((result = obj_policy_get_mode(hPolicy, &secretMode)))
			return result;
	}

	if ((result = obj_rsakey_get_tcs_handle(hKey, &tcsKeyHandle)))
		return result;

	if ((result = build_delegate_public_info(bLabel, hPcrs, hFamily, hDelegation,
			&publicInfoSize, &publicInfo)))
		return result;

	if (secretMode != TSS_SECRET_MODE_NONE) {
		pAuth = &keyAuth;
		if ((result = secret_PerformXOR_OSAP(hPolicy, hDelegation, NULL_HPOLICY, hKey,
						     TCPA_ET_KEYHANDLE, tcsKeyHandle, &encAuthUsage,
						     &encAuthMig, sharedSecret, pAuth, &nonceEvenOSAP)))
			goto done;
		nonceOddOSAP = pAuth->NonceOdd;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Delegate_CreateKeyDelegation);
		result |= Trspi_HashUpdate(&hashCtx, publicInfoSize, publicInfo);
		result |= Trspi_Hash_ENCAUTH(&hashCtx, encAuthUsage.authdata);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_PerformAuth_OSAP(hKey,
				TPM_ORD_Delegate_CreateKeyDelegation, hPolicy, hPolicy,
				NULL_HPOLICY, sharedSecret, pAuth, digest.digest, &nonceEvenOSAP)))
			goto done;
	} else
		pAuth = NULL;

	/* Create the delegation */
	if ((result = TCSP_Delegate_CreateKeyDelegation(hContext, tcsKeyHandle, publicInfoSize,
			publicInfo, encAuthUsage, pAuth, &blobSize, &blob)))
		return result;

	if (pAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Delegate_CreateKeyDelegation);
		result |= Trspi_Hash_UINT32(&hashCtx, blobSize);
		result |= Trspi_HashUpdate(&hashCtx, blobSize, blob);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if ((result = secret_ValidateAuth_OSAP(hKey,
				TPM_ORD_Delegate_CreateKeyDelegation, hPolicy, hPolicy,
				NULL_HPOLICY, sharedSecret, pAuth, digest.digest,
				&nonceEvenOSAP)))
			goto done;
	}

	result = obj_policy_set_delegation_blob(hDelegation, TSS_DELEGATIONTYPE_KEY,
			blobSize, blob);

done:
	free(publicInfo);

	return result;
}

TSS_RESULT
update_delfamily_object(TSS_HTPM hTpm, UINT32 familyID)
{
	TSS_HCONTEXT hContext;
	UINT32 familyTableSize, delegateTableSize;
	BYTE *familyTable = NULL, *delegateTable = NULL;
	UINT64 offset;
	TPM_FAMILY_TABLE_ENTRY familyTableEntry;
	TSS_BOOL familyState;
	TSS_HDELFAMILY hFamily;
	TSS_RESULT result;

	if ((result = obj_tpm_get_tsp_context(hTpm, &hContext)))
		return result;

	if ((result = TCSP_Delegate_ReadTable(hContext, &familyTableSize, &familyTable,
			&delegateTableSize, &delegateTable)))
		return result;

	for (offset = 0; offset < familyTableSize;) {
		Trspi_UnloadBlob_TPM_FAMILY_TABLE_ENTRY(&offset, familyTable, &familyTableEntry);
		if (familyTableEntry.familyID == familyID) {
			obj_delfamily_find_by_familyid(hContext, familyID, &hFamily);
			if (hFamily == NULL_HDELFAMILY) {
				if ((result = obj_delfamily_add(hContext, &hFamily)))
					goto done;
				if ((result = obj_delfamily_set_familyid(hFamily, familyTableEntry.familyID)))
					goto done;
				if ((result = obj_delfamily_set_label(hFamily, familyTableEntry.label.label)))
					goto done;
			}

			/* Set/Update the family attributes */
			familyState = (familyTableEntry.flags & TPM_FAMFLAG_DELEGATE_ADMIN_LOCK) ? TRUE : FALSE;
			if ((result = obj_delfamily_set_locked(hFamily, familyState, FALSE)))
				goto done;
			familyState = (familyTableEntry.flags & TPM_FAMFLAG_ENABLE) ? TRUE : FALSE;
			if ((result = obj_delfamily_set_enabled(hFamily, familyState, FALSE)))
				goto done;
			if ((result = obj_delfamily_set_vercount(hFamily, familyTableEntry.verificationCount)))
				goto done;

			break;
		}
	}

done:
	free(familyTable);
	free(delegateTable);

	return result;
}

TSS_RESULT
get_delegate_index(TSS_HCONTEXT hContext, UINT32 index, TPM_DELEGATE_PUBLIC *public)
{
	UINT32 familyTableSize, delegateTableSize;
	BYTE *familyTable = NULL, *delegateTable = NULL;
	UINT64 offset;
	UINT32 tpmIndex;
	TPM_DELEGATE_PUBLIC tempPublic;
	TSS_RESULT result;

	if ((result = TCSP_Delegate_ReadTable(hContext, &familyTableSize, &familyTable,
			&delegateTableSize, &delegateTable)))
		goto done;

	for (offset = 0; offset < delegateTableSize;) {
		Trspi_UnloadBlob_UINT32(&offset, &tpmIndex, delegateTable);
		if (tpmIndex == index) {
			result = Trspi_UnloadBlob_TPM_DELEGATE_PUBLIC(&offset, delegateTable, public);
			goto done;
		} else {
			if ((result = Trspi_UnloadBlob_TPM_DELEGATE_PUBLIC(&offset, delegateTable, &tempPublic)))
				goto done;
		}

		free(tempPublic.pcrInfo.pcrSelection.pcrSelect);
	}

	/* Didn't find a matching index */
	result = TSPERR(TSS_E_BAD_PARAMETER);

done:
	free(familyTable);
	free(delegateTable);

	return result;
}

TSS_RESULT
build_delegate_public_info(BYTE           bLabel,
			   TSS_HPCRS      hPcrs,
			   TSS_HDELFAMILY hFamily,
			   TSS_HPOLICY    hDelegation,
			   UINT32        *publicInfoSize,
			   BYTE         **publicInfo)
{
	TPM_DELEGATE_PUBLIC public;
	UINT32 delegateType;
	UINT32 pcrInfoSize;
	BYTE *pcrInfo = NULL;
	UINT64 offset;
	TSS_RESULT result = TSS_SUCCESS;

	if (hDelegation == NULL_HPOLICY)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_policy_get_delegation_type(hDelegation, &delegateType)))
		return result;

	/* This call will create a "null" PCR_INFO_SHORT if hPcrs is null */
	if ((result = obj_pcrs_create_info_short(hPcrs, &pcrInfoSize, &pcrInfo)))
		return result;

	memset(&public, 0, sizeof(public));
	public.tag = TPM_TAG_DELEGATE_PUBLIC;
	public.label.label = bLabel;
	offset = 0;
	if ((result = Trspi_UnloadBlob_PCR_INFO_SHORT(&offset, pcrInfo, &public.pcrInfo)))
		goto done;
	public.permissions.tag = TPM_TAG_DELEGATIONS;
	public.permissions.delegateType =
		(delegateType == TSS_DELEGATIONTYPE_OWNER) ? TPM_DEL_OWNER_BITS : TPM_DEL_KEY_BITS;
	if ((result = obj_policy_get_delegation_per1(hDelegation, &public.permissions.per1)))
		goto done;
	if ((result = obj_policy_get_delegation_per2(hDelegation, &public.permissions.per2)))
		goto done;
	if ((result = obj_delfamily_get_familyid(hFamily, &public.familyID)))
		goto done;
	if ((result = obj_delfamily_get_vercount(hFamily, &public.verificationCount)))
		goto done;

	offset = 0;
	Trspi_LoadBlob_TPM_DELEGATE_PUBLIC(&offset, NULL, &public);
	*publicInfoSize = offset;
	*publicInfo = malloc(*publicInfoSize);
	if (*publicInfo == NULL) {
		LogError("malloc of %u bytes failed.", *publicInfoSize);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	offset = 0;
	Trspi_LoadBlob_TPM_DELEGATE_PUBLIC(&offset, *publicInfo, &public);

done:
	free(pcrInfo);
	free(public.pcrInfo.pcrSelection.pcrSelect);

	return result;
}

