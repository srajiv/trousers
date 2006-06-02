
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
Tspi_TPM_CreateEndorsementKey(TSS_HTPM hTPM,			/* in */
			      TSS_HKEY hKey,			/* in */
			      TSS_VALIDATION * pValidationData)	/* in, out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_NONCE antiReplay;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 ekSize;
	BYTE *ek;
	BYTE verifyInternally = 0;
	TCPA_KEY dummyKey;
	UINT16 offset;
	TCPA_DIGEST hash;
	BYTE hashBlob[1024];
	UINT32 newEKSize;
	BYTE *newEK;
	TSS_HCONTEXT tspContext;
	TCPA_PUBKEY pubEK;

	memset(&pubEK, 0, sizeof(TCPA_PUBKEY));
	memset(&dummyKey, 0, sizeof(TCPA_KEY));

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_blob(hKey, &ekSize, &ek)))
		return result;

	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY(&offset, ek, &dummyKey)))
		return result;

	offset = 0;
	Trspi_LoadBlob_KEY_PARMS(&offset, ek, &dummyKey.algorithmParms);
	free_key_refs(&dummyKey);
	ekSize = offset;

	if (pValidationData == NULL)
		verifyInternally = 1;

	if (verifyInternally) {
		if ((result = internal_GetRandomNonce(tcsContext, &antiReplay))) {
			LogError("Failed to create random nonce");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}
	} else
		memcpy(antiReplay.nonce, &pValidationData->ExternalData, 20);

	if ((result = TCSP_CreateEndorsementKeyPair(tcsContext, antiReplay,
						   ekSize, ek, &newEKSize, &newEK, &digest)))
		return result;

	if (verifyInternally) {
		offset = 0;
		Trspi_LoadBlob(&offset, newEKSize, hashBlob, newEK);
		Trspi_LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);

		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);

		if (memcmp(hash.digest, digest.digest, TCPA_SHA1_160_HASH_LEN)) {
			LogError("Internal verification failed");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}
	} else {
		pValidationData->DataLength = newEKSize;
		pValidationData->Data = calloc_tspi(tspContext, newEKSize);
		if (pValidationData->Data == NULL) {
			LogError("malloc of %d bytes failed.", newEKSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->Data, newEK, newEKSize);
		memcpy(&pValidationData->Data[ekSize], antiReplay.nonce,
				TCPA_SHA1_160_HASH_LEN);

		pValidationData->ValidationDataLength = TCPA_SHA1_160_HASH_LEN;
		pValidationData->ValidationData = calloc_tspi(tspContext,
							TCPA_SHA1_160_HASH_LEN);
		if (pValidationData == NULL) {
			LogError("malloc of %d bytes failed.",
					TCPA_SHA1_160_HASH_LEN);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->ValidationData, digest.digest,
				TCPA_SHA1_160_HASH_LEN);
	}

	/* unload the blob into our local objects, then store inside hKey */
	offset = 0;
	if ((result = Trspi_UnloadBlob_PUBKEY(&offset, newEK, &pubEK)))
		return result;

	if ((result = obj_rsakey_set_key_parms(hKey, &pubEK.algorithmParms)))
		goto done;

	if ((result = obj_rsakey_set_pubkey(hKey, pubEK.pubKey.keyLength, pubEK.pubKey.key)))
		goto done;

done:
	free(pubEK.pubKey.key);
	free(pubEK.algorithmParms.parms);
	free(newEK);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetPubEndorsementKey(TSS_HTPM hTPM,			/* in */
			      TSS_BOOL fOwnerAuthorized,	/* in */
			      TSS_VALIDATION *pValidationData,	/* in, out */
			      TSS_HKEY *phEndorsementPubKey)	/* out */
{
	TCPA_DIGEST digest;
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TPM_AUTH ownerAuth;
	UINT16 offset;
	BYTE hashblob[1000];
	TSS_HPOLICY hPolicy;
	UINT32 pubEKSize;
	BYTE *pubEK;
	TCPA_NONCE antiReplay;
	TCPA_DIGEST checkSum;
	TSS_HOBJECT retKey;
	TSS_HCONTEXT tspContext;
	TCPA_PUBKEY pubKey;

	memset(&pubKey, 0, sizeof(TCPA_PUBKEY));

	if (phEndorsementPubKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if (fOwnerAuthorized) {
		if ((result = obj_tpm_get_policy(hTPM, &hPolicy)))
			return result;

		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_OwnerReadPubek, hashblob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_OwnerReadPubek,
						      hPolicy, &digest,
						      &ownerAuth)))
			return result;

		if ((result = TCSP_OwnerReadPubek(tcsContext, &ownerAuth, &pubEKSize, &pubEK)))
			return result;

		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashblob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_OwnerReadPubek, hashblob);
		Trspi_LoadBlob(&offset, pubEKSize, hashblob, pubEK);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &ownerAuth)))
			goto done;
	} else {
		if (pValidationData == NULL) {
			if ((result = internal_GetRandomNonce(tcsContext, &antiReplay))) {
				LogDebug("Failed to generate random nonce");
				return TSPERR(TSS_E_INTERNAL_ERROR);
			}
		} else
			memcpy(antiReplay.nonce, &pValidationData->ExternalData, TCPA_SHA1_160_HASH_LEN);

		/* call down to the TPM */
		if ((result = TCSP_ReadPubek(tcsContext, antiReplay, &pubEKSize, &pubEK, &checkSum)))
			return result;

		/* validate the returned hash, or set up the return so that the user can */
		if (pValidationData == NULL) {
			offset = 0;
			Trspi_LoadBlob(&offset, pubEKSize, hashblob, pubEK);
			Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, hashblob, antiReplay.nonce);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

			/* check validation of the entire pubkey structure */
			if (memcmp(digest.digest, checkSum.digest, TCPA_SHA1_160_HASH_LEN)) {
				/* validation failed, unload the pubEK in order to hash
				 * just the pubKey portion of the pubEK. This is done on
				 * Atmel chips specifically.
				 */
				offset = 0;
				memset(&pubKey, 0, sizeof(TCPA_PUBKEY));
				if ((result = Trspi_UnloadBlob_PUBKEY(&offset, pubEK, &pubKey)))
					goto done;

				offset = 0;
				Trspi_LoadBlob(&offset, pubKey.pubKey.keyLength, hashblob, pubKey.pubKey.key);
				Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, hashblob, antiReplay.nonce);
				Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

				if (memcmp(digest.digest, checkSum.digest, TCPA_SHA1_160_HASH_LEN)) {
					result = TSPERR(TSS_E_VALIDATION_FAILED);
					goto done;
				}
			}
		} else {
			/* validate the entire TCPA_PUBKEY structure */
			pValidationData->DataLength = pubEKSize + TCPA_SHA1_160_HASH_LEN;
			pValidationData->Data = calloc_tspi(tspContext, pValidationData->DataLength);
			if (pValidationData->Data == NULL) {
				LogError("malloc of %d bytes failed.", pValidationData->DataLength);
				return TSPERR(TSS_E_OUTOFMEMORY);
			}

			memcpy(pValidationData->Data, pubEK, pubEKSize);
			memcpy(&(pValidationData->Data[pubEKSize]), antiReplay.nonce,
			       TCPA_SHA1_160_HASH_LEN);

			pValidationData->ValidationDataLength = TCPA_SHA1_160_HASH_LEN;
			pValidationData->ValidationData = calloc_tspi(tspContext, TCPA_SHA1_160_HASH_LEN);
			if (pValidationData->ValidationData == NULL) {
				LogError("malloc of %d bytes failed.", TCPA_SHA1_160_HASH_LEN);
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto done;
			}

			memcpy(pValidationData->ValidationData, checkSum.digest, TCPA_SHA1_160_HASH_LEN);
		}
	}

	if ((result = obj_rsakey_add(tspContext,
				     TSS_KEY_SIZE_2048|TSS_KEY_TYPE_LEGACY,
				     &retKey)))
		return result;

	offset = 0;
	if ((result = Trspi_UnloadBlob_PUBKEY(&offset, pubEK, &pubKey)))
		goto done;

	if ((result = obj_rsakey_set_key_parms(retKey, &pubKey.algorithmParms)))
		goto done;

	if ((result = obj_rsakey_set_pubkey(retKey, pubKey.pubKey.keyLength, pubKey.pubKey.key)))
		goto done;

	*phEndorsementPubKey = retKey;

done:
	free(pubEK);
	free(pubKey.pubKey.key);
	free(pubKey.algorithmParms.parms);

	return result;
}

TSS_RESULT
Tspi_TPM_TakeOwnership(TSS_HTPM hTPM,			/* in */
		       TSS_HKEY hKeySRK,		/* in */
		       TSS_HKEY hEndorsementPubKey)	/* in */
{
	TPM_AUTH privAuth;

	BYTE encOwnerAuth[256];
	UINT32 encOwnerAuthLength;
	BYTE encSRKAuth[256];
	UINT32 encSRKAuthLength;
	UINT16 offset;

	BYTE hashblob[1024];
	TCPA_DIGEST digest;
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	UINT32 srkKeyBlobLength;
	BYTE *srkKeyBlob;
	TSS_HPOLICY hOwnerPolicy;
	UINT32 newSrkBlobSize;
	BYTE *newSrkBlob = NULL;
	BYTE oldAuthDataUsage;
	TSS_HKEY hPubEK;

	/* The first step is to get context and to get the SRK Key Blob.
	 * If these succeed, then the auth should be init'd. */

	if (hEndorsementPubKey == NULL_HKEY) {
		if ((result = Tspi_TPM_GetPubEndorsementKey(hTPM, FALSE, NULL, &hPubEK))) {
			return result;
		}
	} else {
		hPubEK = hEndorsementPubKey;
	}

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	/* Get the srkKeyData */
	if ((result = obj_rsakey_get_blob(hKeySRK, &srkKeyBlobLength, &srkKeyBlob)))
		return result;

	/* Need to check for Atmel bug where authDataUsage is changed */
	oldAuthDataUsage = srkKeyBlob[10];
	LogDebug("oldAuthDataUsage is %.2X.  Wait to see if it changes", oldAuthDataUsage);

	/* Now call the module that will encrypt the secrets.  This
	 * will either get the secrets from the policy objects or
	 * use the callback function to encrypt the secrets */

	if ((result = secret_TakeOwnership(hPubEK,
				      hTPM,
				      hKeySRK,
				      &privAuth,
				      &encOwnerAuthLength,
				      encOwnerAuth,
				      &encSRKAuthLength,
				      encSRKAuth)))
		return result;

	/* Now, take ownership is ready to call.  The auth structure should be complete
	 * and the encrypted data structures should be ready */

	if ((result = TCSP_TakeOwnership(tcsContext,
				TCPA_PID_OWNER,
				encOwnerAuthLength,
				encOwnerAuth,
				encSRKAuthLength,
				encSRKAuth,
				srkKeyBlobLength,
				srkKeyBlob,
				&privAuth,
				&newSrkBlobSize,
				&newSrkBlob)))
		return result;

	/* The final step is to validate the return Auth */

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_TakeOwnership, hashblob);
	Trspi_LoadBlob(&offset, newSrkBlobSize, hashblob, newSrkBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if ((result = obj_tpm_get_policy(hTPM, &hOwnerPolicy))) {
		free(newSrkBlob);
		return result;
	}
	if ((result = obj_policy_validate_auth_oiap(hOwnerPolicy, &digest, &privAuth))) {
		free(newSrkBlob);
		return result;
	}

	/* Now that it's all happy, stuff the keyBlob into the object
	 * If atmel, need to adjust the authDataUsage if it changed */
	if (oldAuthDataUsage != newSrkBlob[10]) {	/* hardcoded blob stuff */
		LogDebug("auth data usage changed. Atmel bug. Fixing in key object");
		newSrkBlob[10] = oldAuthDataUsage;	/* this will fix it  */
	}

	result = obj_rsakey_set_tcpakey(hKeySRK, newSrkBlobSize, newSrkBlob);
	free(newSrkBlob);

	if (result)
		return result;

	/* The SRK is loaded at this point, so insert it into the key handle list */
	return obj_rsakey_set_tcs_handle(hKeySRK, TPM_KEYHND_SRK);
}

/* XXX needs to be tied into TPM policy object's callbacks */
TSS_RESULT
Tspi_TPM_CollateIdentityRequest(TSS_HTPM hTPM,				/* in */
				TSS_HKEY hKeySRK,			/* in */
				TSS_HKEY hCAPubKey,			/* in */
				UINT32 ulIdentityLabelLength,		/* in */
				BYTE * rgbIdentityLabelData,		/* in */
				TSS_HKEY hIdentityKey,			/* in */
				TSS_ALGORITHM_ID algID,			/* in */
				UINT32 * pulTcpaIdentityReqLength,	/* out */
				BYTE ** prgbTcpaIdentityReq)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	BYTE sharedSecret[20];
	TPM_AUTH srkAuth, ownerAuth;
	TCPA_RESULT result;
	UINT16 offset;
	BYTE hashblob[0x2000], idReqBlob[0x4000], testblob[0x4000];
	TCPA_DIGEST digest;
	TSS_HPOLICY hSRKPolicy, hIDPolicy, hCAPolicy, hTPMPolicy;
	UINT32 caKeyBlobSize, idKeySize;
	BYTE *caKeyBlob, *idKey;
	TCPA_NONCE nonceEvenOSAP;
	TCPA_KEY keyContainer, caKey;
	TCPA_CHOSENID_HASH chosenIDHash = { { 0, } };
	UINT32 pcIdentityBindingSize;
	BYTE *prgbIdentityBinding = NULL;
	UINT32 pcEndorsementCredentialSize;
	BYTE *prgbEndorsementCredential = NULL;
	UINT32 pcPlatformCredentialSize;
	BYTE *prgbPlatformCredential = NULL;
	UINT32 pcConformanceCredentialSize;
	BYTE *prgbConformanceCredential = NULL;
#define CHOSENID_BLOB_SIZE 2048
	BYTE chosenIDBlob[CHOSENID_BLOB_SIZE];
	TSS_HCONTEXT tspContext;
	UINT32 encSymKeySize = 256, tmp;
	BYTE encSymKey[256];
	TSS_HPOLICY hIDMigPolicy;
	TSS_BOOL usesAuth;
	TPM_AUTH *pSrkAuth = &srkAuth;
	TCPA_IDENTITY_REQ rgbTcpaIdentityReq;
	TCPA_KEY_PARMS symParms, asymParms;
	TCPA_SYMMETRIC_KEY symKey;
	int padding;

	if (pulTcpaIdentityReqLength == NULL || prgbTcpaIdentityReq == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	/* Get and verify the context */
	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/* Get Policies */
	if ((result = obj_rsakey_get_policy(hKeySRK, TSS_POLICY_USAGE,
					    &hSRKPolicy, &usesAuth)))
		return result;

	if ((result = obj_tpm_get_policy(hTPM, &hTPMPolicy)))
		return result;

	if ((result = obj_rsakey_get_policy(hCAPubKey, TSS_POLICY_USAGE,
					    &hCAPolicy, NULL)))
		return result;

	if ((result = obj_rsakey_get_policy(hIdentityKey, TSS_POLICY_USAGE,
					   &hIDPolicy, NULL)))
		return result;

	if ((result = obj_rsakey_get_policy(hIdentityKey, TSS_POLICY_MIGRATION,
					   &hIDMigPolicy, NULL)))
		return result;

	/* setup the symmetric key's parms. For now, AES is all we support.
	 * TODO: 3DES, DES */
	memset(&symParms, 0, sizeof(TCPA_KEY_PARMS));
	switch (algID) {
		case TSS_ALG_AES:
			symParms.algorithmID = TCPA_ALG_AES;
			symKey.algId = TCPA_ALG_AES;
			symKey.size = 256/8;
			break;
		case TSS_ALG_DES:
			/* fall through */
		case TSS_ALG_3DES:
			/* fall through */
		default:
			result = TSPERR(TSS_E_BAD_PARAMETER);
			goto error;
			break;
	}

	/* get the CA Pubkey's encryption scheme */
	if ((result = obj_rsakey_get_es(hCAPubKey, &tmp)))
		return TSPERR(TSS_E_BAD_PARAMETER);

	switch (tmp) {
		case TSS_ES_RSAESPKCSV15:
			padding = RSA_PKCS1_PADDING;
			break;
		case TSS_ES_RSAESOAEP_SHA1_MGF1:
			padding = RSA_PKCS1_OAEP_PADDING;
			break;
		case TSS_ES_NONE:
			/* fall through */
		default:
			padding = RSA_NO_PADDING;
			break;
	}

	/* Get Key blobs */
	if ((result = Tspi_GetAttribData(hIdentityKey,
					 TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB, &idKeySize,
					 &idKey)))
		return result;

	if ((result = Tspi_GetAttribData(hCAPubKey,
					 TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB,
					 &caKeyBlobSize, &caKeyBlob)))
		return result;

	offset = 0;
	memset(&caKey, 0, sizeof(TCPA_KEY));
	if ((result = Trspi_UnloadBlob_KEY(&offset, caKeyBlob, &caKey)))
		return result;

	/* ChosenID hash =  SHA1(label || TCPA_PUBKEY(CApub)) */
	offset = 0;
	Trspi_LoadBlob(&offset, ulIdentityLabelLength, chosenIDBlob,
		       rgbIdentityLabelData);
	Trspi_LoadBlob_KEY_PARMS(&offset, chosenIDBlob, &caKey.algorithmParms);
	Trspi_LoadBlob_STORE_PUBKEY(&offset, chosenIDBlob, &caKey.pubKey);

	if (offset > CHOSENID_BLOB_SIZE)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	Trspi_Hash(TSS_HASH_SHA1, offset, chosenIDBlob, chosenIDHash.digest);

	/* XXX use chosenIDBlob temporarily */
	offset = 0;
	Trspi_LoadBlob_KEY_PARMS(&offset, chosenIDBlob, &caKey.algorithmParms);
	Trspi_LoadBlob_STORE_PUBKEY(&offset, chosenIDBlob, &caKey.pubKey);

	offset = 0;
	if ((result = Trspi_UnloadBlob_KEY_PARMS(&offset, chosenIDBlob,
						 &asymParms)))
		return result;

	if ((result = secret_PerformXOR_OSAP(hTPMPolicy, hIDPolicy,
					     hIDMigPolicy, hTPM, TCPA_ET_OWNER,
					     TPM_KEYHND_SRK, &encAuthUsage,
					     &encAuthMig, sharedSecret,
					     &ownerAuth, &nonceEvenOSAP)))
		return result;

	/* Hash the Auth data */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_MakeIdentity, hashblob);
	Trspi_LoadBlob(&offset, 20, hashblob, encAuthUsage.authdata);
	Trspi_LoadBlob(&offset, 20, hashblob, chosenIDHash.digest);
	Trspi_LoadBlob(&offset, idKeySize, hashblob, idKey);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	/* Do the Auth's */
	if (usesAuth) {
		if ((result = secret_PerformAuth_OIAP(hKeySRK,
						      TPM_ORD_MakeIdentity,
						      hSRKPolicy, &digest,
						      &srkAuth)))
			return result;
		pSrkAuth = &srkAuth;
	} else {
		pSrkAuth = NULL;
	}

	if ((result = secret_PerformAuth_OSAP(hTPM, TPM_ORD_MakeIdentity,
					      hTPMPolicy, hIDPolicy,
					      hIDMigPolicy, sharedSecret,
					      &ownerAuth, digest.digest,
					      &nonceEvenOSAP)))
		return result;

	if ((result = TCSP_MakeIdentity(tcsContext,
				       encAuthUsage,
				       chosenIDHash,
				       idKeySize,
				       idKey,
				       pSrkAuth,
				       &ownerAuth,
				       &idKeySize,
				       &idKey,
				       &pcIdentityBindingSize,
				       &prgbIdentityBinding,
				       &pcEndorsementCredentialSize,
				       &prgbEndorsementCredential,
				       &pcPlatformCredentialSize,
				       &prgbPlatformCredential,
				       &pcConformanceCredentialSize,
				       &prgbConformanceCredential)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_MakeIdentity, hashblob);
	Trspi_LoadBlob(&offset, idKeySize, hashblob, idKey);
	Trspi_LoadBlob_UINT32(&offset, pcIdentityBindingSize, hashblob);
	Trspi_LoadBlob(&offset, pcIdentityBindingSize, hashblob,
		       prgbIdentityBinding);

	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if ((result = secret_ValidateAuth_OSAP(hTPM, TPM_ORD_MakeIdentity,
					       hTPMPolicy, hIDPolicy,
					       hIDMigPolicy, sharedSecret,
					       &ownerAuth, digest.digest,
					       &nonceEvenOSAP)))
		goto error;

	if (usesAuth == TRUE) {
		if ((result = obj_policy_validate_auth_oiap(hSRKPolicy,
							    &digest,
							    &srkAuth)))
			goto error;
	}

	offset = 0;
	memset(&keyContainer, 0, sizeof(TCPA_KEY));
	if ((result = Trspi_UnloadBlob_KEY(&offset, idKey, &keyContainer)))
		goto error;

	/* Push the new key into the existing object */
	if ((result = Tspi_SetAttribData(hIdentityKey,
					 TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB, idKeySize,
					 idKey)))
		goto error;

	/* generate the symmetric key. */
	if ((result = get_local_random(tspContext, symKey.size, &symKey.data)))
		goto error;

	/* No encryption schemes exist in the TPM 1.1 spec for symmetric
	 * algorithms, so just set this to 0. */
	symKey.encScheme = 0;

	/* XXX This should be DER encoded first. TPM1.1b section 9.4 */
	offset = 0;
	Trspi_LoadBlob_SYMMETRIC_KEY(&offset, hashblob, &symKey);

	if ((result = Trspi_RSA_Public_Encrypt(hashblob, offset, encSymKey,
					       &encSymKeySize,
					       caKey.pubKey.key,
					       caKey.pubKey.keyLength,
					       65537, padding)))
		goto error;

	/* set up the TCPA_IDENTITY_PROOF structure */
	/* XXX This should be DER encoded first. TPM1.1b section 9.4 */
	offset = 0;
	Trspi_LoadBlob_TSS_VERSION(&offset, hashblob, VERSION_1_1);
	Trspi_LoadBlob_UINT32(&offset, ulIdentityLabelLength, hashblob);
	Trspi_LoadBlob_UINT32(&offset, pcIdentityBindingSize, hashblob);
	Trspi_LoadBlob_UINT32(&offset, pcEndorsementCredentialSize, hashblob);
	Trspi_LoadBlob_UINT32(&offset, pcPlatformCredentialSize, hashblob);
	Trspi_LoadBlob_UINT32(&offset, pcConformanceCredentialSize, hashblob);
	Trspi_LoadBlob_KEY_PARMS(&offset, hashblob, &keyContainer.algorithmParms);
	Trspi_LoadBlob_STORE_PUBKEY(&offset, hashblob, &keyContainer.pubKey);
	Trspi_LoadBlob(&offset, ulIdentityLabelLength, hashblob,
		       rgbIdentityLabelData);
	Trspi_LoadBlob(&offset, pcIdentityBindingSize, hashblob,
		       prgbIdentityBinding);
	Trspi_LoadBlob(&offset, pcEndorsementCredentialSize, hashblob,
		       prgbEndorsementCredential);
	Trspi_LoadBlob(&offset, pcPlatformCredentialSize, hashblob,
		       prgbPlatformCredential);
	Trspi_LoadBlob(&offset, pcConformanceCredentialSize, hashblob,
		       prgbConformanceCredential);

	/* encrypt the proof */
	rgbTcpaIdentityReq.symSize = sizeof(testblob);
	if ((result = Trspi_Encrypt_ECB(TSS_ALG_AES, symKey.data, hashblob,
					offset, testblob,
					&rgbTcpaIdentityReq.symSize)))
		goto error;

	rgbTcpaIdentityReq.asymSize = encSymKeySize;
	rgbTcpaIdentityReq.asymAlgorithm = asymParms;
	rgbTcpaIdentityReq.symAlgorithm = symParms;
	rgbTcpaIdentityReq.asymBlob = encSymKey;
	rgbTcpaIdentityReq.symBlob = testblob;

	/* XXX This should be DER encoded first. TPM1.1b section 9.4 */
	offset = 0;
	Trspi_LoadBlob_IDENTITY_REQ(&offset, idReqBlob, &rgbTcpaIdentityReq);

	if ((*prgbTcpaIdentityReq = calloc_tspi(tspContext, offset)) == NULL) {
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto error;
	}

	memcpy(*prgbTcpaIdentityReq, idReqBlob, offset);
	*pulTcpaIdentityReqLength = offset;
error:
	free_key_refs(&keyContainer);
	free_key_refs(&caKey);
	free_tspi(tspContext, symKey.data);
	free(idKey);
	free(prgbIdentityBinding);
	free(prgbEndorsementCredential);
	free(prgbPlatformCredential);
	free(prgbConformanceCredential);

	return result;
}

/* XXX needs to be tied into TPM policy object's callbacks */
TSS_RESULT
Tspi_TPM_ActivateIdentity(TSS_HTPM hTPM,			/* in */
			  TSS_HKEY hIdentKey,			/* in */
			  UINT32 ulAsymCAContentsBlobLength,	/* in */
			  BYTE * rgbAsymCAContentsBlob,		/* in */
			  UINT32 ulSymCAAttestationBlobLength,	/* in */
			  BYTE * rgbSymCAAttestationBlob,	/* in */
			  UINT32 * pulCredentialLength,		/* out */
			  BYTE ** prgbCredential)		/* out */
{
	TPM_AUTH idKeyAuth;
	TPM_AUTH ownerAuth;
	TSS_HCONTEXT tspContext;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hIDPolicy, hTPMPolicy;
	UINT16 offset;
	BYTE hashblob[0x1000], credBlob[0x1000];
	TCPA_DIGEST digest;
	TSS_RESULT result;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_BOOL usesAuth;
	TPM_AUTH *pIDKeyAuth;
	BYTE *symKey;
	UINT32 symKeyLen, credLen;

	if (pulCredentialLength == NULL || prgbCredential == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hIdentKey, &tcsKeyHandle)))
		return result;

	if ((result = obj_rsakey_get_policy(hIdentKey, TSS_POLICY_USAGE,
					    &hIDPolicy, &usesAuth)))
		return result;

	if ((result = obj_tpm_get_policy(hTPM, &hTPMPolicy)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ActivateTPMIdentity, hashblob);
	Trspi_LoadBlob_UINT32(&offset, ulAsymCAContentsBlobLength, hashblob);
	Trspi_LoadBlob(&offset, ulAsymCAContentsBlobLength, hashblob,
		       rgbAsymCAContentsBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (usesAuth) {
		if ((result = secret_PerformAuth_OIAP(hIDPolicy,
						      TPM_ORD_ActivateTPMIdentity,
						      hIDPolicy, &digest,
						      &idKeyAuth)))
			return result;
		pIDKeyAuth = &idKeyAuth;
	} else {
		pIDKeyAuth = NULL;
	}

	if ((result = secret_PerformAuth_OIAP(hTPM,
					      TPM_ORD_ActivateTPMIdentity,
					      hTPMPolicy, &digest,
					      &ownerAuth)))
		return result;

	if ((result = TCSP_ActivateTPMIdentity(tcsContext,
					      tcsKeyHandle,
					      ulAsymCAContentsBlobLength,
					      rgbAsymCAContentsBlob,
					      pIDKeyAuth,
					      &ownerAuth,
					      &symKeyLen,
					      &symKey)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ActivateTPMIdentity, hashblob);
	Trspi_LoadBlob_UINT32(&offset, symKeyLen, hashblob);
	Trspi_LoadBlob(&offset, symKeyLen, hashblob, symKey);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if (usesAuth) {
		if ((result = obj_policy_validate_auth_oiap(hIDPolicy, &digest,
							    &idKeyAuth))) {
			/* XXX For some reason, this always fails. */
			LogDebugFn("Identity key auth validation of the "
				    "symmetric key failed.");
		}
	}

	if ((result = obj_policy_validate_auth_oiap(hTPMPolicy, &digest,
						    &ownerAuth))) {
		/* XXX For some reason, this always fails. */
		LogDebugFn("Owner auth validation of the symmetric key "
			    "failed.");
	}

	/* decrypt the symmetric blob using the recovered symmetric key */
	if (symKeyLen != 32 ) { // XXX
		free(symKey);
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	if ((result = Trspi_Decrypt_ECB(TSS_ALG_AES, symKey,
					rgbSymCAAttestationBlob,
					ulSymCAAttestationBlobLength,
					credBlob, &credLen))) {
		free(symKey);
		return result;
	}

	if ((*prgbCredential = calloc_tspi(tspContext, credLen)) == NULL) {
		free(symKey);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	memcpy(*prgbCredential, credBlob, credLen);
	*pulCredentialLength = credLen;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_ClearOwner(TSS_HTPM hTPM,		/* in */
		    TSS_BOOL fForcedClear)	/* in */
{
	TCPA_RESULT result;
	TPM_AUTH auth;
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_DIGEST hashDigest;
	BYTE *hashBlob;
	UINT16 offset;
	TSS_HPOLICY hPolicy;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if (!fForcedClear) {	/*  TPM_OwnerClear */
		if ((result = obj_tpm_get_policy(hTPM, &hPolicy)))
			return result;

		/* Now do some Hash'ing */
		offset = 0;
		hashBlob = malloc(sizeof(UINT32));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_OwnerClear, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);
		/* hashDigest now has the hash result */

		if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_OwnerClear,
						      hPolicy, &hashDigest,
						      &auth)))
			return result;

		if ((result = TCSP_OwnerClear(tcsContext, &auth)))
			return result;

		/* validate auth */
		offset = 0;
		hashBlob = malloc(2 * sizeof(UINT32));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", 2 * sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_OwnerClear, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
	} else {
		if ((result = TCSP_ForceClear(tcsContext)))
			return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_SetStatus(TSS_HTPM hTPM,	/* in */
		   TSS_FLAG statusFlag,	/* in */
		   TSS_BOOL fTpmState)	/* in */
{
	TPM_AUTH auth;
	TSS_RESULT result;
	BYTE *hashBlob;
	UINT16 offset;
	TCPA_DIGEST hashDigest;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hPolicy;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTPM, &hPolicy)))
		return result;

	switch (statusFlag) {
	case TSS_TPMSTATUS_DISABLEOWNERCLEAR:

		hashBlob = malloc(sizeof(UINT32));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_DisableOwnerClear, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = secret_PerformAuth_OIAP(hTPM,
						      TPM_ORD_DisableOwnerClear,
						      hPolicy, &hashDigest,
						      &auth)))
			return result;

		if ((result = TCSP_DisableOwnerClear(tcsContext, &auth)))
			return result;

		offset = 0;
		hashBlob = malloc(2 * sizeof(UINT32));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", 2 * sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_DisableOwnerClear, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
	case TSS_TPMSTATUS_DISABLEFORCECLEAR:
		result = TCSP_DisableForceClear(tcsContext);
		break;
	case TSS_TPMSTATUS_OWNERSETDISABLE:

		hashBlob = malloc(sizeof(UINT32) + sizeof(TSS_BOOL));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(UINT32) + sizeof(TSS_BOOL));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_OwnerSetDisable, hashBlob);
		hashBlob[(offset++)] = fTpmState;
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = secret_PerformAuth_OIAP(hTPM,
						      TPM_ORD_OwnerSetDisable,
						      hPolicy, &hashDigest,
						      &auth)))
			return result;

		if ((result = TCSP_OwnerSetDisable(tcsContext, fTpmState, &auth)))
			return result;

		offset = 0;
		hashBlob = malloc(8);
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", 2 * sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_OwnerSetDisable, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
	case TSS_TPMSTATUS_PHYSICALDISABLE:
		if ( fTpmState )
			result = TCSP_PhysicalDisable(tcsContext);
		else
			result = TCSP_PhysicalEnable(tcsContext);
		break;
	case TSS_TPMSTATUS_PHYSICALSETDEACTIVATED:
		result = TCSP_PhysicalSetDeactivated(tcsContext, fTpmState);
		break;
	case TSS_TPMSTATUS_SETTEMPDEACTIVATED:
		result = TCSP_SetTempDeactivated(tcsContext);
		break;
	case TSS_TPMSTATUS_SETOWNERINSTALL:
		result = TCSP_SetOwnerInstall(tcsContext, fTpmState);
		break;
	case TSS_TPMSTATUS_DISABLEPUBEKREAD:

		hashBlob = malloc(sizeof(UINT32));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_DisablePubekRead, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = secret_PerformAuth_OIAP(hTPM,
						      TPM_ORD_DisablePubekRead,
						      hPolicy, &hashDigest,
						      &auth)))
			return result;

		if ((result = TCSP_DisablePubekRead(tcsContext, &auth)))
			return result;

		offset = 0;
		hashBlob = malloc(2 * sizeof(UINT32));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", 2 * sizeof(UINT32));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_DisablePubekRead, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth)))
			return result;
		break;
#ifndef TSS_SPEC_COMPLIANCE
	case TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK:
		/* set the lifetime lock bit */
		result = TCSP_PhysicalPresence(tcsContext, TCPA_PHYSICAL_PRESENCE_LIFETIME_LOCK);
		break;
	case TSS_TPMSTATUS_PHYSPRES_HWENABLE:
		/* set the HW enable bit */
		result = TCSP_PhysicalPresence(tcsContext, TCPA_PHYSICAL_PRESENCE_HW_ENABLE);
		break;
	case TSS_TPMSTATUS_PHYSPRES_CMDENABLE:
		/* set the command enable bit */
		result = TCSP_PhysicalPresence(tcsContext, TCPA_PHYSICAL_PRESENCE_CMD_ENABLE);
		break;
	case TSS_TPMSTATUS_PHYSPRES_LOCK:
		/* set the physical presence lock bit */
		result = TCSP_PhysicalPresence(tcsContext, TCPA_PHYSICAL_PRESENCE_LOCK);
		break;
	case TSS_TPMSTATUS_PHYSPRESENCE:
		/* set the physical presence state */
		result = TCSP_PhysicalPresence(tcsContext, (fTpmState ? TCPA_PHYSICAL_PRESENCE_PRESENT : TCPA_PHYSICAL_PRESENCE_NOTPRESENT));
		break;
#endif
	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	}

	return result;
}

TSS_RESULT
Tspi_TPM_GetStatus(TSS_HTPM hTPM,		/* in */
		   TSS_FLAG statusFlag,		/* in */
		   TSS_BOOL * pfTpmState)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	UINT32 nonVolFlags;
	UINT32 volFlags;

	if (pfTpmState == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = get_tpm_flags(tcsContext, hTPM, &volFlags, &nonVolFlags)))
		return result;

	switch (statusFlag) {
	case TSS_TPMSTATUS_DISABLEOWNERCLEAR:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_OWNER_CLEARABLE);
		break;
	case TSS_TPMSTATUS_DISABLEFORCECLEAR:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_PRES_CLEARABLE);
		break;
	case TSS_TPMSTATUS_DISABLED:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_DISABLED);
		break;
	case TSS_TPMSTATUS_PHYSICALSETDEACTIVATED:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_DEACTIVATED);
		break;
	case TSS_TPMSTATUS_SETTEMPDEACTIVATED:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_TEMP_DEACTIVATED);
		break;
	case TSS_TPMSTATUS_SETOWNERINSTALL:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_OWNABLE);
		break;
	case TSS_TPMSTATUS_DISABLEPUBEKREAD:
		*pfTpmState = INVBOOL(nonVolFlags & TPM11_NONVOL_READABLE_PUBEK);
		break;
	case TSS_TPMSTATUS_ALLOWMAINTENANCE:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_ALLOW_MAINT);
		break;
	case TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_LIFETIME_LOCK);
		break;
	case TSS_TPMSTATUS_PHYSPRES_HWENABLE:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_HW_PRES);
		break;
	case TSS_TPMSTATUS_PHYSPRES_CMDENABLE:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_CMD_PRES);
		break;
	case TSS_TPMSTATUS_CEKP_USED:
		*pfTpmState = BOOL(nonVolFlags & TPM11_NONVOL_CEKP_USED);
		break;
	case TSS_TPMSTATUS_PHYSPRESENCE:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_PRES);
		break;
	case TSS_TPMSTATUS_PHYSPRES_LOCK:
		*pfTpmState = BOOL(volFlags & TPM11_VOL_PRES_LOCK);
		break;

	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_SelfTestFull(TSS_HTPM hTPM)	/*  in */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	return TCSP_SelfTestFull(tcsContext);
}

TSS_RESULT
Tspi_TPM_CertifySelfTest(TSS_HTPM hTPM,				/* in */
			 TSS_HKEY hKey,				/* in */
			 TSS_VALIDATION *pValidationData)	/* in, out */
{

	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_RESULT result;
	TPM_AUTH keyAuth;
	UINT16 offset = 0;
	BYTE *hashBlob;
	TCPA_DIGEST hash;
	TCPA_NONCE antiReplay;
	UINT32 outDataSize;
	BYTE *outData;
	TSS_HPOLICY hPolicy;
	TCS_KEY_HANDLE keyTCSKeyHandle;
	BYTE verifyInternally = 0;
	BYTE *keyData = NULL;
	UINT32 keyDataSize;
	TCPA_KEY keyContainer;
	TPM_AUTH *pKeyAuth;
	TSS_BOOL useAuth;
	TSS_HCONTEXT tspContext;


	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE,
					    &hPolicy, &useAuth)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &keyTCSKeyHandle)))
		return result;

	if (pValidationData == NULL)
		verifyInternally = 1;

	if (verifyInternally) {
		if ((result = internal_GetRandomNonce(tcsContext, &antiReplay))) {
			LogError("Failed creating random nonce");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}
	} else
		memcpy(antiReplay.nonce, &pValidationData->ExternalData, 20);

	if (useAuth) {
		LogDebug("Uses Auth");

		/* ===  now setup the auth's */
		hashBlob = malloc(sizeof(UINT32) + sizeof(TCPA_NONCE));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(UINT32) + sizeof(TCPA_NONCE));
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifySelfTest, hashBlob);
		Trspi_LoadBlob(&offset, sizeof(TCPA_NONCE), hashBlob, antiReplay.nonce);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		free(hashBlob);

		if ((result = secret_PerformAuth_OIAP(hKey,
						      TPM_ORD_CertifySelfTest,
						      hPolicy, &hash,
						      &keyAuth)))
			return result;
		pKeyAuth = &keyAuth;
	} else {
		LogDebug("No Auth");
		pKeyAuth = NULL;
	}

	if ((result = TCSP_CertifySelfTest(tcsContext,
					  keyTCSKeyHandle,
					  antiReplay,
					  pKeyAuth,
					  &outDataSize,
					  &outData)))
		return result;

	/*      validate auth */
	if (useAuth) {
		offset = 0;
		hashBlob = malloc((3 * sizeof(UINT32)) + outDataSize);
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", (3 * sizeof(UINT32)) + outDataSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifySelfTest, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, outDataSize, hashBlob);
		Trspi_LoadBlob(&offset, outDataSize, hashBlob, outData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		free(hashBlob);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &hash, &keyAuth)))
			return result;
	}

	if (verifyInternally) {
		if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				       TSS_TSPATTRIB_KEYBLOB_BLOB, &keyDataSize, &keyData))) {
			LogError("Failed call to GetAttribData to get key blob");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		offset = 0;
		memset(&keyContainer, 0, sizeof(TCPA_KEY));
		if ((result = Trspi_UnloadBlob_KEY(&offset, keyData, &keyContainer)))
			return result;

		offset = 0;
		hashBlob = malloc(sizeof(UINT32) + sizeof(TCPA_NONCE) + strlen("Test Passed"));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(UINT32) + sizeof(TCPA_NONCE)
					+ strlen("Test Passed"));
			free_key_refs(&keyContainer);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob(&offset, strlen("Test Passed"), hashBlob, (BYTE *)"Test Passed");
		Trspi_LoadBlob(&offset, sizeof(TCPA_NONCE), hashBlob, antiReplay.nonce);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifySelfTest, hashBlob);

		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hash.digest);
		free(hashBlob);

		if ((result = Trspi_Verify(TSS_HASH_SHA1, hash.digest, 20,
					 keyContainer.pubKey.key, keyContainer.pubKey.keyLength,
					 outData, outDataSize))) {
			free(outData);
			free_key_refs(&keyContainer);
			return TSPERR(TSS_E_VERIFICATION_FAILED);
		}

	} else {
		pValidationData->DataLength = sizeof(TCPA_NONCE) + sizeof(UINT32) + strlen("Test Passed");
		pValidationData->Data = calloc_tspi(tspContext, pValidationData->DataLength);
		if (pValidationData->Data == NULL) {
			LogError("malloc of %d bytes failed.", pValidationData->DataLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		Trspi_LoadBlob(&offset, strlen("Test Passed"), pValidationData->Data,
			       (BYTE *)"Test Passed");
		Trspi_LoadBlob(&offset, sizeof(TCPA_NONCE), pValidationData->Data, antiReplay.nonce);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CertifySelfTest, pValidationData->Data);
		pValidationData->ValidationDataLength = outDataSize;
		pValidationData->ValidationData = calloc_tspi(tspContext, outDataSize);
		if (pValidationData->ValidationData == NULL) {
			LogError("malloc of %d bytes failed.", pValidationData->ValidationDataLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->ValidationData, outData, outDataSize);
		free(outData);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetTestResult(TSS_HTPM hTPM,			/* in */
		       UINT32 * pulTestResultLength,	/* out */
		       BYTE ** prgbTestResult)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if (pulTestResultLength == NULL || prgbTestResult == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	return TCSP_GetTestResult(tcsContext, pulTestResultLength, prgbTestResult);
}

TSS_RESULT
Tspi_TPM_GetCapability(TSS_HTPM hTPM,			/* in */
		       TSS_FLAG capArea,		/* in */
		       UINT32 ulSubCapLength,		/* in */
		       BYTE * rgbSubCap,		/* in */
		       UINT32 * pulRespDataLength,	/* out */
		       BYTE ** prgbRespData)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HCONTEXT tspContext;
	TCPA_CAPABILITY_AREA tcsCapArea;
	UINT32 tcsSubCap = 0;
	UINT32 tcsSubCapContainer;
	TSS_RESULT result;
	UINT32 nonVolFlags, volFlags, respLen, correct_endianess = 0;
	BYTE *respData;
	UINT16 offset;
	TSS_BOOL fOwnerAuth = FALSE; /* flag for caps that need owner auth */

	if (pulRespDataLength == NULL || prgbRespData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	/* Verify the caps and subcaps */
	switch (capArea) {
	case TSS_TPMCAP_ORD:
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TCPA_CAP_ORD;
		tcsSubCap = *(UINT32 *)rgbSubCap;
		break;
	case TSS_TPMCAP_FLAG:
		fOwnerAuth = TRUE;
		break;
	case TSS_TPMCAP_ALG:	/*  Queries whether an algorithm is supported. */
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TCPA_CAP_ALG;
		tcsSubCap = *(UINT32 *)rgbSubCap;
		break;
	case TSS_TPMCAP_PROPERTY:	/*     Determines a physical property of the TPM. */
		if ((ulSubCapLength != sizeof(UINT32)) || !rgbSubCap)
			return TSPERR(TSS_E_BAD_PARAMETER);

		tcsCapArea = TCPA_CAP_PROPERTY;
		tcsSubCapContainer = *(UINT32 *)rgbSubCap;

		if (tcsSubCapContainer == TSS_TPMCAP_PROP_PCR) {
			tcsSubCap = TPM_CAP_PROP_PCR;
			correct_endianess = 1;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_DIR) {
			tcsSubCap = TPM_CAP_PROP_DIR;
			correct_endianess = 1;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_SLOTS) {
			tcsSubCap = TPM_CAP_PROP_SLOTS;
			correct_endianess = 1;
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MANUFACTURER) {
			tcsSubCap = TPM_CAP_PROP_MANUFACTURER;
		} else
			return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	case TSS_TPMCAP_VERSION:	/*      Queries the current TPM version. */
		tcsCapArea = TCPA_CAP_VERSION;
		break;
	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	}

	if (fOwnerAuth) {
		/* do an owner authorized get capability call */
		if ((result = get_tpm_flags(tcsContext, hTPM, &volFlags, &nonVolFlags)))
			return result;

		respLen = 2 * sizeof(UINT32);
		respData = calloc_tspi(tspContext, respLen);
		if (respData == NULL) {
			LogError("malloc of %d bytes failed.", respLen);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, nonVolFlags, respData);
		Trspi_LoadBlob_UINT32(&offset, volFlags, respData);

		*pulRespDataLength = respLen;
		*prgbRespData = respData;
	} else {
		tcsSubCap = endian32(tcsSubCap);

		result = TCSP_GetCapability(tcsContext, tcsCapArea, ulSubCapLength, (BYTE *)&tcsSubCap,
				&respLen, &respData);

		*prgbRespData = calloc_tspi(tspContext, respLen);
		if (*prgbRespData == NULL) {
			free(respData);
			LogError("malloc of %d bytes failed.", respLen);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		*pulRespDataLength = respLen;
		memcpy(*prgbRespData, respData, respLen);
		free(respData);

		if (*pulRespDataLength == sizeof(UINT32) && correct_endianess) {
			*((UINT32 *)(*prgbRespData)) = endian32(*((UINT32 *)(*prgbRespData)));
		}
	}

	return result;
}

TSS_RESULT
Tspi_TPM_GetCapabilitySigned(TSS_HTPM hTPM,			/* in */
			     TSS_HTPM hKey,			/* in */
			     TSS_FLAG capArea,			/* in */
			     UINT32 ulSubCapLength,		/* in */
			     BYTE * rgbSubCap,			/* in */
			     TSS_VALIDATION * pValidationData,	/* in, out */
			     UINT32 * pulRespDataLength,	/* out */
			     BYTE ** prgbRespData)		/* out */
{
#if 1
	/*
	 * Function was found to have a vulnerability, so implementation is not
	 * required by the TSS 1.1b spec.
	 */
	return TSPERR(TSS_E_NOTIMPL);
#else
	TPM_AUTH auth;
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_RESULT result;
	BYTE *hashBlob;
	UINT16 offset;
	TCPA_DIGEST hashDigest;
	TCPA_VERSION version;
	TSS_HPOLICY hPolicy;
	TCPA_NONCE antiReplay;
	TCS_KEY_HANDLE tcsKeyHandle;
	TCPA_CAPABILITY_AREA tcsCapArea;
	UINT32 tcsSubCapContainer;
	BYTE tcsSubCap[4];
	BYTE verifyInternally = 0;
	UINT32 sigSize;
	BYTE *sig = NULL;
	UINT32 keyDataSize;
	BYTE *keyData;
	TCPA_KEY keyContainer;

	if (pulRespDataLength == NULL || prgbRespData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &tcsKeyHandle)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hPolicy, NULL)))
		return result;

	/* Verify the caps and subcaps */
	switch (capArea) {

	case TSS_TPMCAP_ALG:	/*  Queries whether an algorithm is supported. */
		tcsCapArea = TCPA_CAP_ALG;
		break;
	case TSS_TPMCAP_PROPERTY:	/*     Determines a physical property of the TPM. */
		tcsCapArea = TCPA_CAP_PROPERTY;
		tcsSubCapContainer = Decode_UINT32(rgbSubCap);
		if (tcsSubCapContainer == TSS_TPMCAP_PROP_PCR) {
			UINT32ToArray(TCPA_CAP_PROP_PCR, tcsSubCap);
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_DIR) {
			UINT32ToArray(TCPA_CAP_PROP_DIR, tcsSubCap);
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_SLOTS) {
			UINT32ToArray(TCPA_CAP_PROP_SLOTS, tcsSubCap);
		} else if (tcsSubCapContainer == TSS_TPMCAP_PROP_MANUFACTURER) {
			UINT32ToArray(TCPA_CAP_PROP_MANUFACTURER, tcsSubCap);
		} else
			return TSPERR(TSS_E_BAD_PARAMETER);
		break;
	case TSS_TPMCAP_VERSION:	/*      Queries the current TPM version. */
		tcsCapArea = TCPA_CAP_VERSION;
		break;
	default:
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	/* If we get to this point, then neither getCapOwner nor an internal
	 * getCap was called. */
	if (pValidationData == NULL)
		verifyInternally = 1;

	if (verifyInternally) {
		if ((result = internal_GetRandomNonce(tcsContext, &antiReplay))) {
			LogError("Failed creating random nonce");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}
	} else
		memcpy(antiReplay.nonce, pValidationData->Data, sizeof(TCPA_NONCE));

	/* Now do some Hashing */
	offset = 0;
	hashBlob = malloc((3 * sizeof(UINT32)) + sizeof(TCPA_NONCE) + ulSubCapLength);
	if (hashBlob == NULL) {
		LogError("malloc of %zd bytes failed.", (3 * sizeof(UINT32)) + sizeof(TCPA_NONCE)
				+ ulSubCapLength);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetCapabilitySigned, hashBlob);
	Trspi_LoadBlob(&offset, sizeof(TCPA_NONCE), hashBlob, antiReplay.nonce);
	Trspi_LoadBlob_UINT32(&offset, tcsCapArea, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, ulSubCapLength, hashBlob);
	Trspi_LoadBlob(&offset, ulSubCapLength, hashBlob, rgbSubCap);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
	free(hashBlob);

	/* hashDigest now has the hash result */
	if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_GetCapabilitySigned,
					      hPolicy, &hashDigest, &auth)))
		return result;

	if ((result = TCSP_GetCapabilitySigned(tcsContext,
					      tcsKeyHandle, antiReplay,
					      tcsCapArea,
					      ulSubCapLength,
					      rgbSubCap,
					      &auth, &version, pulRespDataLength,
					      prgbRespData,
					      &sigSize,
					      &sig)))
		return result;

	/* validate return auth */
	offset = 0;
	hashBlob = malloc(20 + *pulRespDataLength + sigSize);
	if (hashBlob == NULL) {
		LogError("malloc of %d bytes failed.", 20 + *pulRespDataLength + sigSize);
		free(sig);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetCapabilitySigned, hashBlob);
	Trspi_LoadBlob_TCPA_VERSION(&offset, hashBlob, version);
	Trspi_LoadBlob_UINT32(&offset, *pulRespDataLength, hashBlob);
	Trspi_LoadBlob(&offset, *pulRespDataLength, hashBlob, *prgbRespData);
	Trspi_LoadBlob_UINT32(&offset, sigSize, hashBlob);
	Trspi_LoadBlob(&offset, sigSize, hashBlob, sig);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
	free(hashBlob);

	if ((result = obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth))) {
		free(sig);
		return result;
	}

	if (verifyInternally) {
		if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				       TSS_TSPATTRIB_KEYBLOB_BLOB, &keyDataSize, &keyData))) {
			free(sig);
			LogError("Failed call to GetAttribData to get key blob");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		offset = 0;
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyData, &keyContainer);

		offset = 0;
		hashBlob = malloc(*pulRespDataLength + sizeof(TCPA_NONCE));
		if (hashBlob == NULL) {
			LogError("malloc of %zd bytes failed.", *pulRespDataLength + sizeof(TCPA_NONCE));
			free(sig);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_LoadBlob(&offset, *pulRespDataLength, hashBlob, *prgbRespData);
		Trspi_LoadBlob(&offset, sizeof(TCPA_NONCE), hashBlob, antiReplay.nonce);

		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);
		free(hashBlob);

		if ((result = Trspi_Verify(TSS_HASH_SHA1, hashDigest.digest, 20,
					 keyContainer.pubKey.key, keyContainer.pubKey.keyLength,
					 sig, sigSize))) {
			free(sig);
			return TSPERR(TSS_E_VERIFICATION_FAILED);
		}

	} else {
		pValidationData->DataLength = *pulRespDataLength + 20;
		pValidationData->Data = calloc_tspi(tspContext, *pulRespDataLength);
		if (pValidationData->Data == NULL) {
			LogError("malloc of %d bytes failed.", *pulRespDataLength);
			free(sig);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->Data, *prgbRespData, *pulRespDataLength);
		memcpy(&pValidationData->Data[(*pulRespDataLength)], antiReplay.nonce, 20);
		pValidationData->ValidationDataLength = sigSize;
		pValidationData->ValidationData = calloc_tspi(tspContext, sigSize);
		if (pValidationData->ValidationData == NULL) {
			LogError("malloc of %d bytes failed.", sigSize);
			free(sig);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->ValidationData, sig, sigSize);
	}

	return TSS_SUCCESS;
#endif
}

TSS_RESULT
Tspi_TPM_CreateMaintenanceArchive(TSS_HTPM hTPM,			/* in */
				  TSS_BOOL fGenerateRndNumber,		/* in */
				  UINT32 * pulRndNumberLength,		/* out */
				  BYTE ** prgbRndNumber,		/* out */
				  UINT32 * pulArchiveDataLength,	/* out */
				  BYTE ** prgbArchiveData)		/* out */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hOwnerPolicy;
	TPM_AUTH ownerAuth;
	TCPA_DIGEST digest;
	UINT16 offset;
	BYTE hashBlob[512];

	if (pulArchiveDataLength == NULL || prgbArchiveData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (fGenerateRndNumber &&
	    (pulRndNumberLength == NULL || prgbRndNumber == NULL))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hOwnerPolicy)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMaintenanceArchive, hashBlob);
	Trspi_LoadBlob_BYTE(&offset, fGenerateRndNumber, hashBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_CreateMaintenanceArchive,
					      hOwnerPolicy, &digest,
					      &ownerAuth)))
		return result;

	if ((result = TCSP_CreateMaintenanceArchive(tcsContext, fGenerateRndNumber, &ownerAuth,
						    pulRndNumberLength, prgbRndNumber,
						    pulArchiveDataLength, prgbArchiveData)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_CreateMaintenanceArchive, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, *pulRndNumberLength, hashBlob);
	Trspi_LoadBlob(&offset, *pulRndNumberLength, hashBlob, *prgbRndNumber);
	Trspi_LoadBlob_UINT32(&offset, *pulArchiveDataLength, hashBlob);
	Trspi_LoadBlob(&offset, *pulArchiveDataLength, hashBlob, *prgbArchiveData);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	if ((result = obj_policy_validate_auth_oiap(hOwnerPolicy, &digest, &ownerAuth)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_KillMaintenanceFeature(TSS_HTPM hTPM)	/*  in */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HPOLICY hOwnerPolicy;
	TPM_AUTH ownerAuth;
	TCPA_DIGEST digest;
	UINT16 offset;
	BYTE hashBlob[128];

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hOwnerPolicy)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_KillMaintenanceFeature, hashBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	if ((result = secret_PerformAuth_OIAP(hTPM,
					      TPM_ORD_KillMaintenanceFeature,
					      hOwnerPolicy, &digest,
					      &ownerAuth)))
		return result;

	if ((result = TCSP_KillMaintenanceFeature(tcsContext, &ownerAuth)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_KillMaintenanceFeature, hashBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	if ((result = obj_policy_validate_auth_oiap(hOwnerPolicy, &digest, &ownerAuth)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_LoadMaintenancePubKey(TSS_HTPM hTPM,				/* in */
			       TSS_HKEY hMaintenanceKey,		/* in */
			       TSS_VALIDATION * pValidationData)	/* in, out */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HCONTEXT tspContext;
	TCPA_DIGEST checkSum, digest;
	TCPA_NONCE nonce;
	UINT16 offset;
	UINT32 pubBlobSize;
	BYTE hashBlob[512], *pubBlob;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if (pValidationData) {
		memcpy(&nonce.nonce, &pValidationData->ExternalData.nonce,
		       TCPA_SHA1_160_HASH_LEN);
	} else {
		if ((result = internal_GetRandomNonce(tcsContext, &nonce)))
			return result;
	}

	if ((result = obj_rsakey_get_pub_blob(hMaintenanceKey, &pubBlobSize, &pubBlob)))
		return result;

	if ((result = TCSP_LoadManuMaintPub(tcsContext, nonce, pubBlobSize, pubBlob, &checkSum)))
		return result;

	offset = 0;
	Trspi_LoadBlob(&offset, pubBlobSize, hashBlob, pubBlob);
	Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, hashBlob, (BYTE *)&nonce.nonce);

	if (pValidationData) {
		pValidationData->DataLength = offset;
		if ((pValidationData->Data = calloc_tspi(tspContext, offset)) == NULL)
			return TSPERR(TSS_E_OUTOFMEMORY);

		memcpy(pValidationData->Data, hashBlob, offset);

		pValidationData->ValidationDataLength = TCPA_SHA1_160_HASH_LEN;
		if ((pValidationData->ValidationData = calloc_tspi(tspContext,
								   TCPA_SHA1_160_HASH_LEN))
		     == NULL) {
			free_tspi(tspContext, pValidationData->Data);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		memcpy(pValidationData->ValidationData, checkSum.digest, TCPA_SHA1_160_HASH_LEN);
	} else {
		if ((result = Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest)))
			return result;

		if (memcmp(&digest.digest, &checkSum.digest, TCPA_SHA1_160_HASH_LEN))
			result = TSPERR(TSS_E_FAIL);
	}

	return result;
}

TSS_RESULT
Tspi_TPM_CheckMaintenancePubKey(TSS_HTPM hTPM,				/* in */
				TSS_HKEY hMaintenanceKey,		/* in */
				TSS_VALIDATION * pValidationData)	/* in, out */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HCONTEXT tspContext;
	TCPA_DIGEST checkSum, digest;
	TCPA_NONCE nonce;
	UINT16 offset;
	UINT32 pubBlobSize;
	BYTE hashBlob[512], *pubBlob;

	if ((pValidationData && hMaintenanceKey) || (!pValidationData && !hMaintenanceKey))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if (pValidationData) {
		memcpy(&nonce.nonce, &pValidationData->ExternalData.nonce,
		       TCPA_SHA1_160_HASH_LEN);
	} else {
		if ((result = internal_GetRandomNonce(tcsContext, &nonce)))
			return result;
	}

	if ((result = TCSP_ReadManuMaintPub(tcsContext, nonce, &checkSum)))
		return result;

	if (pValidationData) {
		/* Ignore Data and DataLength, the application must already have this data.
		 * Do, however, copy out the checksum so that the application can verify */
		pValidationData->ValidationDataLength = TCPA_SHA1_160_HASH_LEN;
		if ((pValidationData->ValidationData = calloc_tspi(tspContext,
								   TCPA_SHA1_160_HASH_LEN))
		     == NULL) {
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		memcpy(pValidationData->ValidationData, checkSum.digest, TCPA_SHA1_160_HASH_LEN);
	} else {
		if ((result = obj_rsakey_get_pub_blob(hMaintenanceKey, &pubBlobSize, &pubBlob)))
			return result;

		offset = 0;
		Trspi_LoadBlob(&offset, pubBlobSize, hashBlob, pubBlob);
		Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, hashBlob, (BYTE *)&nonce.nonce);

		if ((result = Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest)))
			return result;

		if (memcmp(&digest.digest, &checkSum.digest, TCPA_SHA1_160_HASH_LEN))
			result = TSPERR(TSS_E_FAIL);
	}

	return result;
}

TSS_RESULT
Tspi_TPM_GetRandom(TSS_HTPM hTPM,		/* in */
		   UINT32 ulRandomDataLength,	/* in */
		   BYTE ** prgbRandomData)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if (prgbRandomData == NULL || ulRandomDataLength > 4096)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if (ulRandomDataLength == 0)
		return TSS_SUCCESS;

	if ((result = TCSP_GetRandom(tcsContext, ulRandomDataLength, prgbRandomData)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_StirRandom(TSS_HTPM hTPM,		/* in */
		    UINT32 ulEntropyDataLength,	/* in */
		    BYTE * rgbEntropyData)	/* in */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if (ulEntropyDataLength > 0 && rgbEntropyData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCSP_StirRandom(tcsContext, ulEntropyDataLength, rgbEntropyData)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_AuthorizeMigrationTicket(TSS_HTPM hTPM,			/* in */
				  TSS_HKEY hMigrationKey,		/* in */
				  TSS_MIGRATION_SCHEME migrationScheme,	/* in */
				  UINT32 * pulMigTicketLength,		/* out */
				  BYTE ** prgbMigTicket)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	UINT16 offset;
	BYTE hashblob[0x1000];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	TSS_HPOLICY hOwnerPolicy;
	UINT32 migrationKeySize;
	BYTE *migrationKeyBlob;
	TCPA_KEY tcpaKey;
	BYTE pubKeyBlob[0x1000];
	TPM_AUTH ownerAuth;
	UINT32 pubKeySize;
	TSS_HCONTEXT tspContext;
	UINT32 tpmMigrationScheme;

	if (pulMigTicketLength == NULL || prgbMigTicket == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	/*  get the tpm Policy */
	if ((result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hOwnerPolicy)))
		return result;

	switch (migrationScheme) {
		case TSS_MS_MIGRATE:
			tpmMigrationScheme = TCPA_MS_MIGRATE;
			break;
		case TSS_MS_REWRAP:
			tpmMigrationScheme = TCPA_MS_REWRAP;
			break;
		case TSS_MS_MAINT:
			tpmMigrationScheme = TCPA_MS_MAINT;
			break;
		default:
			return TSPERR(TSS_E_BAD_PARAMETER);
			break;
	}

	/*  Get the migration key blob */
	if ((result = obj_rsakey_get_blob(hMigrationKey,
					&migrationKeySize, &migrationKeyBlob)))
		return result;

	/* First, turn the keyBlob into a TCPA_KEY structure */
	offset = 0;
	memset(&tcpaKey, 0, sizeof(TCPA_KEY));
	if ((result = Trspi_UnloadBlob_KEY(&offset, migrationKeyBlob, &tcpaKey))) {
		free_tspi(tspContext, migrationKeyBlob);
		return result;
	}
	free_tspi(tspContext, migrationKeyBlob);

	/* Then pull the _PUBKEY portion out of that struct into a blob */
	offset = 0;
	Trspi_LoadBlob_KEY_PARMS(&offset, pubKeyBlob, &tcpaKey.algorithmParms);
	Trspi_LoadBlob_STORE_PUBKEY(&offset, pubKeyBlob, &tcpaKey.pubKey);
	pubKeySize = offset;
	free_key_refs(&tcpaKey);

	/* Auth */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_AuthorizeMigrationKey, hashblob);
	Trspi_LoadBlob_UINT16(&offset, tpmMigrationScheme, hashblob);
	Trspi_LoadBlob(&offset, pubKeySize, hashblob, pubKeyBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if ((result = secret_PerformAuth_OIAP(hTPM,
					      TPM_ORD_AuthorizeMigrationKey,
					      hOwnerPolicy, &digest,
					      &ownerAuth)))
		return result;

	/* Send command */
	if ((result = TCSP_AuthorizeMigrationKey(tcsContext,
						migrationScheme,
						pubKeySize,
						pubKeyBlob,
						&ownerAuth,
						pulMigTicketLength,
						prgbMigTicket)))
		return result;

	/* Validate Auth */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashblob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_AuthorizeMigrationKey, hashblob);
	Trspi_LoadBlob(&offset, *pulMigTicketLength, hashblob, *prgbMigTicket);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	if ((result = obj_policy_validate_auth_oiap(hOwnerPolicy, &digest, &ownerAuth))) {
		free_tspi(tspContext, prgbMigTicket);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetEvent(TSS_HTPM hTPM,		/* in */
		  UINT32 ulPcrIndex,		/* in */
		  UINT32 ulEventNumber,		/* in */
		  TSS_PCR_EVENT * pPcrEvent)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	TSS_PCR_EVENT *event = NULL;

	if (pPcrEvent == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCS_GetPcrEvent(tcsContext, ulPcrIndex, &ulEventNumber, &event)))
		return result;

	memcpy(pPcrEvent, event, sizeof(TSS_PCR_EVENT));
	free(event);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetEvents(TSS_HTPM hTPM,			/* in */
		   UINT32 ulPcrIndex,			/* in */
		   UINT32 ulStartNumber,		/* in */
		   UINT32 * pulEventNumber,		/* in, out */
		   TSS_PCR_EVENT ** prgbPcrEvents)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	TSS_PCR_EVENT *events = NULL;

	if (pulEventNumber == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if (prgbPcrEvents) {
		if ((result = TCS_GetPcrEventsByPcr(tcsContext, ulPcrIndex,
						    ulStartNumber,
						    pulEventNumber,
						    &events)))
			return result;

		*prgbPcrEvents = events;
	} else {
		/* if the pointer to receive events is NULL, the app only
		 * wants a total number of events for this PCR. */
		if ((result = TCS_GetPcrEvent(tcsContext, ulPcrIndex,
					      pulEventNumber, NULL)))
			return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetEventLog(TSS_HTPM hTPM,			/* in */
		     UINT32 * pulEventNumber,		/* out */
		     TSS_PCR_EVENT ** prgbPcrEvents)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if (pulEventNumber == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	/* if the pointer to receive events is NULL, the app only wants a
	 * total number of events for all PCRs. */
	if (prgbPcrEvents == NULL) {
		UINT16 numPcrs = get_num_pcrs(tcsContext);
		UINT32 i, numEvents;

		*pulEventNumber = 0;
		for (i = 0; i < numPcrs; i++) {
			if ((result = TCS_GetPcrEvent(tcsContext, i,
						      &numEvents, NULL)))
				return result;

			*pulEventNumber += numEvents;
		}
	} else {
		return TCS_GetPcrEventLog(tcsContext, pulEventNumber,
					  prgbPcrEvents);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_Quote(TSS_HTPM hTPM,				/* in */
	       TSS_HKEY hIdentKey,			/* in */
	       TSS_HPCRS hPcrComposite,			/* in */
	       TSS_VALIDATION * pValidationData)	/* in, out */
{
	TCPA_RESULT result;
	TPM_AUTH privAuth;
	TPM_AUTH *pPrivAuth = &privAuth;
	UINT16 offset;
	BYTE hashBlob[1000];
	TCPA_DIGEST digest, composite;
	TCS_CONTEXT_HANDLE tcsContext;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_HPOLICY hPolicy;
	TCPA_NONCE antiReplay;
	UINT32 pcrDataSize;
	BYTE pcrData[128];
	TCPA_PCR_SELECTION pcrSelect;
	TSS_BOOL verifyInternally = 0;
	UINT32 validationLength = 0;
	BYTE *validationData = NULL;
	UINT32 pcrDataOutSize;
	BYTE *pcrDataOut;
	UINT32 keyDataSize;
	BYTE *keyData;
	TCPA_KEY keyContainer;
	BYTE quoteinfo[1024];
	TSS_BOOL usesAuth;
	TSS_HCONTEXT tspContext;

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	if (hPcrComposite && !obj_is_pcrs(hPcrComposite))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (pValidationData == NULL)
		verifyInternally = TRUE;

	/*  get the identKey Policy */
	if ((result = obj_rsakey_get_policy(hIdentKey, TSS_POLICY_USAGE,
					    &hPolicy, &usesAuth)))
		return result;

	/*  get the Identity TCS keyHandle */
	if ((result = obj_rsakey_get_tcs_handle(hIdentKey, &tcsKeyHandle)))
		return result;

	if (verifyInternally) {
		if ((result = internal_GetRandomNonce(tcsContext, &antiReplay)))
			return result;
	} else {
		memcpy(antiReplay.nonce, &pValidationData->ExternalData, 20);
	}

	pcrDataSize = 0;
	if (hPcrComposite) {
		offset = 0;
		/* calling get_composite first forces the TSP to call the TCS
		 * to make sure the pcr selection structure is correct */
		if ((result = obj_pcrs_get_composite(hPcrComposite, &composite)))
			return result;

		if ((result = obj_pcrs_get_selection(hPcrComposite, &pcrSelect)))
			return result;

		Trspi_LoadBlob_PCR_SELECTION(&offset, pcrData, &pcrSelect);
		pcrDataSize = offset;
		free(pcrSelect.pcrSelect);
	}

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Quote, hashBlob);
	Trspi_LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);
	Trspi_LoadBlob(&offset, pcrDataSize, hashBlob, pcrData);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	if (usesAuth) {
		if ((result = secret_PerformAuth_OIAP(hIdentKey, TPM_ORD_Quote,
						      hPolicy, &digest,
						      &privAuth))) {
			return result;
		}
		pPrivAuth = &privAuth;
	} else {
		pPrivAuth = NULL;
	}

	if ((result = TCSP_Quote(tcsContext,
				tcsKeyHandle,
				antiReplay,
				pcrDataSize,
				pcrData,
				pPrivAuth,
				&pcrDataOutSize, &pcrDataOut, &validationLength,
				&validationData)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_Quote, hashBlob);
	Trspi_LoadBlob(&offset, pcrDataOutSize, hashBlob, pcrDataOut);
	Trspi_LoadBlob_UINT32(&offset, validationLength, hashBlob);
	Trspi_LoadBlob(&offset, validationLength, hashBlob, validationData);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	if (usesAuth == TRUE) {
		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &privAuth))) {
			free(pcrDataOut);
			free(validationData);
			return result;
		}
	}

	if (hPcrComposite) {
		TCPA_PCR_COMPOSITE pcrComp;

		offset = 0;
		if ((result = Trspi_UnloadBlob_PCR_COMPOSITE(&offset, pcrDataOut,
							     &pcrComp))) {
			free(pcrDataOut);
			free(validationData);
			return result;
		}

		if ((result = obj_pcrs_set_values(hPcrComposite, &pcrComp))) {
			free(pcrDataOut);
			free(validationData);
			return result;
		}
	}

	if ((result = Tspi_GetAttribData(hIdentKey, TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB,
					 &keyDataSize, &keyData))) {
		free(pcrDataOut);
		free(validationData);
		return result;
	}

	/* create the validation data */
	offset = 0;
	memset(&keyContainer, 0, sizeof(TCPA_KEY));
	if ((result = Trspi_UnloadBlob_KEY(&offset, keyData, &keyContainer)))
		return result;

	/*  creating pcrCompositeHash */
	Trspi_Hash(TSS_HASH_SHA1, pcrDataOutSize, pcrDataOut, digest.digest);
	free(pcrDataOut);

	/* generate Quote_info struct */
	/* 1. add version */
	offset = 0;
	Trspi_LoadBlob_TCPA_VERSION(&offset, quoteinfo, keyContainer.ver);
	/* 2. add "QUOT" */
	quoteinfo[offset++] = 'Q';
	quoteinfo[offset++] = 'U';
	quoteinfo[offset++] = 'O';
	quoteinfo[offset++] = 'T';
	/* 3. Composite Hash */
	Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, quoteinfo,
		       digest.digest);
	/* 4. AntiReplay Nonce */
	Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, quoteinfo,
		       antiReplay.nonce);

	if (verifyInternally) {
		/* validate the data here */
		Trspi_Hash(TSS_HASH_SHA1, offset, quoteinfo, digest.digest);

		if ((result = Trspi_Verify(TSS_HASH_SHA1, digest.digest, 20,
					   keyContainer.pubKey.key,
					   keyContainer.pubKey.keyLength,
					   validationData,
					   validationLength))) {
			free_key_refs(&keyContainer);
			free(validationData);
			return result;
		}
		free_key_refs(&keyContainer);
	} else {
		free_key_refs(&keyContainer);

		pValidationData->ValidationDataLength = validationLength;
		pValidationData->ValidationData = calloc_tspi(tspContext, validationLength);
		if (pValidationData->ValidationData == NULL) {
			LogError("malloc of %d bytes failed.", validationLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->ValidationData, validationData,
		       pValidationData->ValidationDataLength);
		free(validationData);

		pValidationData->DataLength = offset;
		pValidationData->Data = calloc_tspi(tspContext, offset);
		if (pValidationData->Data == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(pValidationData->Data, quoteinfo, offset);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_PcrExtend(TSS_HTPM hTPM,			/* in */
			UINT32 ulPcrIndex,		/* in */
			UINT32 ulPcrDataLength,		/* in */
			BYTE *pbPcrData,		/* in */
			TSS_PCR_EVENT *pPcrEvent,	/* in */
			UINT32 * pulPcrValueLength,	/* out */
			BYTE ** prgbPcrValue)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_PCRVALUE outDigest;
	TSS_RESULT result;
	BYTE *inDigest;
	UINT32 number;
	TSS_HCONTEXT tspContext;

	if (pulPcrValueLength == NULL || prgbPcrValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulPcrDataLength > 0 && pbPcrData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	inDigest = malloc(TCPA_DIGEST_SIZE);
	if (inDigest == NULL) {
		LogError("malloc of %zd bytes failed.", TCPA_DIGEST_SIZE);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if ((result = Trspi_Hash(TSS_HASH_SHA1, ulPcrDataLength, pbPcrData, inDigest)))
		return result;

	if ((result = TCSP_Extend(tcsContext, ulPcrIndex, *(TCPA_DIGEST *)inDigest, &outDigest)))
		return result;

	*prgbPcrValue = calloc_tspi(tspContext, sizeof(TCPA_PCRVALUE));
	if (*prgbPcrValue == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TCPA_PCRVALUE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	memcpy(*prgbPcrValue, &outDigest, sizeof(TCPA_PCRVALUE));
	*pulPcrValueLength = sizeof(TCPA_PCRVALUE);

	/* log the event structure if its passed in */
	if (pPcrEvent != NULL) {
		if ((result = TCS_LogPcrEvent(tcsContext, *pPcrEvent, &number))) {
			free(inDigest);
		}
	}

	return result;
}

TSS_RESULT
Tspi_TPM_PcrRead(TSS_HTPM hTPM,			/* in */
		 UINT32 ulPcrIndex,		/* in */
		 UINT32 *pulPcrValueLength,	/* out */
		 BYTE **prgbPcrValue)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_PCRVALUE outDigest;
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if (pulPcrValueLength == NULL || prgbPcrValue == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCSP_PcrRead(tcsContext, ulPcrIndex, &outDigest)))
		return result;

	*prgbPcrValue = calloc_tspi(tspContext, sizeof(TCPA_PCRVALUE));
	if (*prgbPcrValue == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TCPA_PCRVALUE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(*prgbPcrValue, outDigest.digest, sizeof(TCPA_PCRVALUE));
	*pulPcrValueLength = sizeof(TCPA_PCRVALUE);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_DirWrite(TSS_HTPM hTPM,		/* in */
		  UINT32 ulDirIndex,		/* in */
		  UINT32 ulDirDataLength,	/* in */
		  BYTE * rgbDirData)		/* in  */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_RESULT result;
	TPM_AUTH auth;
	TCPA_DIGEST hashDigest;
	UINT16 offset;
	BYTE hashBlob[32];
	TSS_HPOLICY hPolicy;
	TCPA_DIRVALUE dirValue = { { 0 } };

	if (rgbDirData == NULL && ulDirDataLength != 0)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = obj_tpm_get_policy(hTPM, &hPolicy)))
		return result;

	/* hash the input data */
	if ((result = Trspi_Hash(TSS_HASH_SHA1, ulDirDataLength, rgbDirData, dirValue.digest)))
		return result;

	/* hash to be used for the OIAP calc */
	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_DirWriteAuth, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, ulDirIndex, hashBlob);
	Trspi_LoadBlob(&offset, sizeof(TCPA_DIGEST), hashBlob, (BYTE *)(&dirValue));
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);

	/*  hashDigest now has the hash result       */
	if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_DirWriteAuth,
					      hPolicy, &hashDigest,
					      &auth)))
		return result;

	if ((result = TCSP_DirWriteAuth(tcsContext,
				       ulDirIndex,
				       dirValue,
				       &auth)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_DirWriteAuth, hashBlob);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, hashDigest.digest);

	return obj_policy_validate_auth_oiap(hPolicy, &hashDigest, &auth);
}

TSS_RESULT
Tspi_TPM_DirRead(TSS_HTPM hTPM,			/* in */
		 UINT32 ulDirIndex,		/* in */
		 UINT32 * pulDirDataLength,	/* out */
		 BYTE ** prgbDirData)		/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_DIRVALUE dirValue;
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;

	if (pulDirDataLength == NULL || prgbDirData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		return result;

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCSP_DirRead(tcsContext,
				  ulDirIndex,
				  &dirValue)))
		return result;

	*pulDirDataLength = 20;
	*prgbDirData = calloc_tspi(tspContext, *pulDirDataLength);
	if (*prgbDirData == NULL) {
		LogError("malloc of %d bytes failed.", *pulDirDataLength);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(*prgbDirData, dirValue.digest, *pulDirDataLength);
	return TSS_SUCCESS;
}
