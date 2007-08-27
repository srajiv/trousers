
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "obj.h"
#include "tsplog.h"


TSS_RESULT
Tspi_TPM_CMKSetRestrictions(TSS_HTPM         hTpm,		/* in */
			    TSS_CMK_DELEGATE CmkDelegate)	/* in */
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	Trspi_HashCtx hashCtx;
	TPM_DIGEST digest;
	TPM_AUTH ownerAuth;
	TSS_RESULT result;

	if ((result = obj_tpm_get_tsp_context(hTpm, &hContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_SetRestrictions);
	result |= Trspi_Hash_UINT32(&hashCtx, CmkDelegate);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hTpm, TPM_ORD_CMK_SetRestrictions,
			hPolicy, FALSE, &digest, &ownerAuth)))
		return result;

	if ((result = RPC_CMK_SetRestrictions(hContext, CmkDelegate, &ownerAuth)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_SetRestrictions);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &ownerAuth)))
		return result;

	return result;
}

TSS_RESULT
Tspi_TPM_CMKApproveMA(TSS_HTPM     hTpm,	/* in */
		      TSS_HMIGDATA hMaAuthData)	/* in */
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	UINT32 blobSize;
	BYTE *blob;
	TPM_DIGEST msaDigest;
	TPM_HMAC msaHmac;
	Trspi_HashCtx hashCtx;
	TPM_DIGEST digest;
	TPM_AUTH ownerAuth;
	TSS_RESULT result;

	if ((result = obj_tpm_get_tsp_context(hTpm, &hContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((result = obj_migdata_get_msa_digest(hMaAuthData, &blobSize, &blob)))
		return result;
	memcpy(msaDigest.digest, blob, sizeof(msaDigest.digest));
	free_tspi(hContext, blob);

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_ApproveMA);
	result |= Trspi_Hash_DIGEST(&hashCtx, msaDigest.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hTpm, TPM_ORD_CMK_ApproveMA,
			hPolicy, FALSE, &digest, &ownerAuth)))
		return result;

	if ((result = RPC_CMK_ApproveMA(hContext, msaDigest, &ownerAuth, &msaHmac)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_ApproveMA);
	result |= Trspi_Hash_HMAC(&hashCtx, msaHmac.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &ownerAuth)))
		return result;

	if ((result = obj_migdata_set_msa_hmac(hMaAuthData, sizeof(msaHmac.digest), msaHmac.digest)))
		return result;

	return result;
}

TSS_RESULT
Tspi_TPM_CMKCreateTicket(TSS_HTPM     hTpm,		/* in */
			 TSS_HKEY     hVerifyKey,	/* in */
			 TSS_HMIGDATA hSigData)		/* in */
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	UINT32 pubKeySize;
	BYTE *pubKey = NULL;
	UINT32 blobSize;
	BYTE *blob;
	TPM_DIGEST sigData;
	UINT32 sigSize;
	BYTE *sig = NULL;
	TPM_HMAC sigTicket;
	Trspi_HashCtx hashCtx;
	TPM_DIGEST digest;
	TPM_AUTH ownerAuth;
	TSS_RESULT result;

	if ((result = obj_tpm_get_tsp_context(hTpm, &hContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTpm, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((result = obj_rsakey_get_pub_blob(hVerifyKey, &pubKeySize, &pubKey)))
		return result;

	if ((result = obj_migdata_get_sig_data(hSigData, &blobSize, &blob)))
		goto done;
	memcpy(sigData.digest, blob, sizeof(sigData.digest));
	free_tspi(hContext, blob);

	if ((result = obj_migdata_get_sig_value(hSigData, &sigSize, &sig)))
		goto done;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_CreateTicket);
	result |= Trspi_HashUpdate(&hashCtx, pubKeySize, pubKey);
	result |= Trspi_Hash_DIGEST(&hashCtx, sigData.digest);
	result |= Trspi_Hash_UINT32(&hashCtx, sigSize);
	result |= Trspi_HashUpdate(&hashCtx, sigSize, sig);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		goto done;

	if ((result = secret_PerformAuth_OIAP(hTpm, TPM_ORD_CMK_CreateTicket,
			hPolicy, FALSE, &digest, &ownerAuth)))
		goto done;

	if ((result = RPC_CMK_CreateTicket(hContext, pubKeySize, pubKey, sigData, sigSize, sig,
			&ownerAuth, &sigTicket)))
		goto done;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_CreateTicket);
	result |= Trspi_Hash_HMAC(&hashCtx, sigTicket.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		goto done;

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &ownerAuth)))
		goto done;

	if ((result = obj_migdata_set_sig_ticket(hSigData, sizeof(sigTicket.digest), sigTicket.digest)))
		goto done;

done:
	free_tspi(hContext, pubKey);
	free_tspi(hContext, sig);

	return result;
}

TSS_RESULT
Tspi_Key_CMKCreateBlob(TSS_HKEY     hKeyToMigrate,	/* in */
		       TSS_HKEY     hParentKey,		/* in */
		       TSS_HMIGDATA hMigrationData,	/* in */
		       UINT32*      pulRandomLength,	/* out */
		       BYTE**       prgbRandom)		/* out */
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	TSS_BOOL usageAuth;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_MIGRATE_SCHEME migScheme;
	UINT32 migTicketSize;
	BYTE *migTicket = NULL;
	TPM_MIGRATIONKEYAUTH tpmMigKeyAuth;
	UINT32 msaListSize, restrictTicketSize, sigTicketSize, encDataSize;
	BYTE *msaList = NULL, *restrictTicket = NULL;
	BYTE *sigTicket = NULL, *encData = NULL;
	UINT32 pubBlobSize;
	BYTE *pubBlob = NULL;
	TPM_DIGEST srcPubKeyDigest;
	UINT32 randomDataSize, outDataSize;
	BYTE *randomData = NULL, *outData = NULL;
	Trspi_HashCtx hashCtx;
	TPM_DIGEST digest;
	TPM_AUTH parentAuth, *pAuth;
	UINT64 offset;
	TSS_RESULT result;

	if (!pulRandomLength || !prgbRandom)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_rsakey_is_cmk(hKeyToMigrate))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_rsakey_get_tsp_context(hKeyToMigrate, &hContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE, &hPolicy, &usageAuth)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hParentKey, &tcsKeyHandle)))
		return result;

	if ((result = obj_migdata_get_ticket_blob(hMigrationData, &migTicketSize, &migTicket)))
		return result;

	/* Just to get the migration scheme... */
	offset = 0;
	if ((result = Trspi_UnloadBlob_MIGRATIONKEYAUTH(&offset, migTicket, &tpmMigKeyAuth)))
		goto done;
	/* ... so free everything now */
	free(tpmMigKeyAuth.migrationKey.algorithmParms.parms);
	free(tpmMigKeyAuth.migrationKey.pubKey.key);
	migScheme = tpmMigKeyAuth.migrationScheme;

	if ((result = obj_rsakey_get_pub_blob(hKeyToMigrate, &pubBlobSize, &pubBlob)))
		goto done;
	if ((result = obj_migdata_calc_pubkey_digest(pubBlobSize, pubBlob, &srcPubKeyDigest)))
		goto done;

	if ((result = obj_migdata_get_msa_list_blob(hMigrationData, &msaListSize, &msaList)))
		goto done;

	if (tpmMigKeyAuth.migrationScheme == TPM_MS_RESTRICT_APPROVE_DOUBLE) {
		if ((result = obj_migdata_get_cmk_auth_blob(hMigrationData, &restrictTicketSize,
				&restrictTicket)))
			goto done;
		if ((result = obj_migdata_get_sig_ticket(hMigrationData, &sigTicketSize,
				&sigTicket)))
			goto done;
	} else {
		restrictTicketSize = 0;
		sigTicketSize = 0;
	}

	if ((result = obj_rsakey_get_priv_blob(hKeyToMigrate, &encDataSize, &encData)))
		goto done;

	if (usageAuth) {
		pAuth = &parentAuth;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_CreateBlob);
		result |= Trspi_Hash_UINT16(&hashCtx, migScheme);
		result |= Trspi_HashUpdate(&hashCtx, migTicketSize, migTicket);
		result |= Trspi_Hash_DIGEST(&hashCtx, srcPubKeyDigest.digest);
		result |= Trspi_Hash_UINT32(&hashCtx, msaListSize);
		result |= Trspi_HashUpdate(&hashCtx, msaListSize, msaList);
		result |= Trspi_Hash_UINT32(&hashCtx, restrictTicketSize);
		result |= Trspi_HashUpdate(&hashCtx, restrictTicketSize, restrictTicket);
		result |= Trspi_Hash_UINT32(&hashCtx, sigTicketSize);
		result |= Trspi_HashUpdate(&hashCtx, sigTicketSize, sigTicket);
		result |= Trspi_Hash_UINT32(&hashCtx, encDataSize);
		result |= Trspi_HashUpdate(&hashCtx, encDataSize, encData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if ((result = secret_PerformAuth_OIAP(hParentKey, TPM_ORD_CMK_CreateBlob,
				hPolicy, FALSE, &digest, pAuth)))
			goto done;
	} else
		pAuth = NULL;

	if ((result = RPC_CMK_CreateBlob(hContext, tcsKeyHandle, migScheme,
			migTicketSize, migTicket, srcPubKeyDigest, msaListSize, msaList,
			restrictTicketSize, restrictTicket, sigTicketSize, sigTicket,
			encDataSize, encData, pAuth, &randomDataSize, &randomData,
			&outDataSize, &outData)))
		goto done;

	if (pAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_CreateBlob);
		result |= Trspi_Hash_UINT32(&hashCtx, randomDataSize);
		result |= Trspi_HashUpdate(&hashCtx, randomDataSize, randomData);
		result |= Trspi_Hash_UINT32(&hashCtx, outDataSize);
		result |= Trspi_HashUpdate(&hashCtx, outDataSize, outData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;
	}

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, pAuth)))
		goto done;

	if ((result = obj_migdata_set_blob(hMigrationData, outDataSize, outData)))
		goto done;

	if ((*prgbRandom = calloc_tspi(hContext, randomDataSize)) == NULL) {
		LogError("malloc of %u bytes failed.", randomDataSize);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	memcpy(*prgbRandom, randomData, randomDataSize);
	*pulRandomLength = randomDataSize;

done:
	free_tspi(hContext, migTicket);
	free_tspi(hContext, pubBlob);
	free_tspi(hContext, msaList);
	free_tspi(hContext, restrictTicket);
	free_tspi(hContext, sigTicket);
	free_tspi(hContext, encData);
	free(randomData);
	free(outData);

	return result;
}

TSS_RESULT
Tspi_Key_CMKConvertMigration(TSS_HKEY     hKeyToMigrate,	/* in */
			     TSS_HKEY     hParentKey,		/* in */
			     TSS_HMIGDATA hMigrationData,	/* in */
			     UINT32       ulRandomLength,	/* in */
			     BYTE*        rgbRandom)		/* in */
{
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hPolicy;
	TSS_BOOL usageAuth;
	TCS_KEY_HANDLE tcsKeyHandle;
	TPM_CMK_AUTH restrictTicket;
	UINT32 blobSize;
	BYTE *blob;
	TPM_HMAC sigTicket;
	UINT32 keyDataSize, migDataSize, msaListSize;
	BYTE *keyData = NULL, *migData = NULL, *msaList = NULL;
	TPM_KEY12 key;
	UINT32 outDataSize;
	BYTE *outData = NULL;
	Trspi_HashCtx hashCtx;
	TPM_DIGEST digest;
	TPM_AUTH parentAuth, *pAuth;
	UINT64 offset;
	TSS_RESULT result;

	memset(&key, 0, sizeof(key));

	if (!obj_rsakey_is_cmk(hKeyToMigrate))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_rsakey_get_tsp_context(hKeyToMigrate, &hContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hParentKey, TSS_POLICY_USAGE, &hPolicy, &usageAuth)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hParentKey, &tcsKeyHandle)))
		return result;

	if ((result = obj_migdata_get_cmk_auth(hMigrationData, &restrictTicket)))
		return result;

	if ((result = obj_migdata_get_sig_ticket(hMigrationData, &blobSize, &blob)))
		return result;
	memcpy(sigTicket.digest, blob, sizeof(sigTicket.digest));
	free_tspi(hContext, blob);

	if ((result = obj_rsakey_get_blob(hKeyToMigrate, &keyDataSize, &keyData)))
		return result;

	if ((result = obj_migdata_get_blob(hMigrationData, &migDataSize, &migData)))
		goto done;

	/* Replace the key's encrypted data with the migration data blob */
	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY12(&offset, keyData, &key)))
		goto done;
	free(key.encData);
	key.encSize = migDataSize;
	if ((key.encData = malloc(migDataSize)) == NULL) {
		LogError("malloc of %u bytes failed.", migDataSize);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	memcpy(key.encData, migData, migDataSize);

	/* Generate a new keyData blob */
	free_tspi(hContext, keyData);
	offset = 0;
	Trspi_LoadBlob_KEY12(&offset, NULL, &key);
	keyDataSize = offset;
	if ((keyData = calloc_tspi(hContext, keyDataSize)) == NULL) {
		LogError("malloc of %u bytes failed.", keyDataSize);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	offset = 0;
	Trspi_LoadBlob_KEY12(&offset, keyData, &key);

	if ((result = obj_migdata_get_msa_list_blob(hMigrationData, &msaListSize, &msaList)))
		goto done;

	if (usageAuth) {
		pAuth = &parentAuth;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_ConvertMigration);
		result |= Trspi_HashUpdate(&hashCtx, sizeof(restrictTicket),
				(BYTE *)&restrictTicket);
		result |= Trspi_Hash_HMAC(&hashCtx, sigTicket.digest);
		result |= Trspi_HashUpdate(&hashCtx, keyDataSize, keyData);
		result |= Trspi_Hash_UINT32(&hashCtx, msaListSize);
		result |= Trspi_HashUpdate(&hashCtx, msaListSize, msaList);
		result |= Trspi_Hash_UINT32(&hashCtx, ulRandomLength);
		result |= Trspi_HashUpdate(&hashCtx, ulRandomLength, rgbRandom);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if ((result = secret_PerformAuth_OIAP(hParentKey, TPM_ORD_CMK_ConvertMigration,
				hPolicy, FALSE, &digest, pAuth)))
			goto done;
	} else
		pAuth = NULL;

	if ((result = RPC_CMK_ConvertMigration(hContext, tcsKeyHandle, restrictTicket, sigTicket,
			keyDataSize, keyData, msaListSize, msaList, ulRandomLength, rgbRandom,
			pAuth, &outDataSize, &outData)))
		goto done;

	if (pAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_CMK_ConvertMigration);
		result |= Trspi_Hash_UINT32(&hashCtx, outDataSize);
		result |= Trspi_HashUpdate(&hashCtx, outDataSize, outData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;
	}

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, pAuth)))
		goto done;

	result = obj_rsakey_set_privkey(hKeyToMigrate, TRUE, outDataSize, outData);

done:
	free_tspi(hContext, keyData);
	free_tspi(hContext, migData);
	free_tspi(hContext, msaList);
	free(key.algorithmParms.parms);
	free(key.PCRInfo);
	free(key.pubKey.key);
	free(key.encData);
	free(outData);

	return result;
}

