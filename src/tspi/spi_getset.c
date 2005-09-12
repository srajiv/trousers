
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Tspi_ChangeAuth(TSS_HOBJECT hObjectToChange,	/* in */
		TSS_HOBJECT hParentObject,	/* in */
		TSS_HPOLICY hNewPolicy		/* in */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	BYTE sharedSecret[20];
	TPM_AUTH auth1;
	TPM_AUTH auth2;
	UINT16 offset;
	BYTE hashBlob[0x1000];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	UINT32 keyHandle;
	TSS_HPOLICY hPolicy;
	TSS_HPOLICY hParentPolicy;
	TCPA_NONCE nonceEvenOSAP;
	UINT32 dataBlobLength;
	BYTE *dataBlob;
	TCPA_STORED_DATA storedData;
	UINT32 keyToChangeHandle;
	UINT32 objectLength;
	TCPA_KEY keyToChange;
	BYTE *keyBlob;
	UINT32 newEncSize;
	BYTE *newEncData;
	TSS_HCONTEXT tspContext;

	/* /////////////////////////////////////////////////////////////////
	 * Perform the initial checks
	 * If the parent Object is Null
	 *      -       Trying to change the TPM Auth
	 *      -       This requires Owner Authorization
	 * If the parent Object is not Null
	 *      -       Trying to change the auth of an entity
	 * If the ObjectToChange is the SRK, then the parent must be the TPM
	 *  Object
	 * */

	if ((result = obj_policy_get_tsp_context(hNewPolicy, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/* if the object to change is the TPM object, then the parent should
	 * be NULL.  If the object to change is not the TPM, then the parent
	 * object must be either an rsakey or the TPM */
	if (obj_is_tpm(hObjectToChange)) {
		if (hParentObject != NULL_HOBJECT)
			return TSPERR(TSS_E_INVALID_HANDLE);
	} else if (!obj_is_rsakey(hParentObject) &&
		   !obj_is_tpm(hParentObject)) {
		return TSPERR(TSS_E_INVALID_HANDLE);
	}

	if (obj_is_tpm(hObjectToChange)) {/*  if TPM Owner Auth change */
		/* get the owner policy */
		if ((result = obj_tpm_get_policy(hObjectToChange, &hPolicy)))
			return result;

		/* //////////////////////////////////////////////////////// */
		/* Now Calculate the authorization */
		if ((result =
		    secret_PerformXOR_OSAP(hPolicy, hNewPolicy, hNewPolicy,
					   hObjectToChange, TCPA_ET_OWNER, 0,
					   &encAuthUsage, &encAuthMig,
					   sharedSecret, &auth1,
					   &nonceEvenOSAP)))
			return result;

		/* calculate auth data */
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner,
				hashBlob);
		Trspi_LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
		Trspi_LoadBlob(&offset, 20, hashBlob, encAuthUsage.authdata);
		Trspi_LoadBlob_UINT16(&offset, TCPA_ET_OWNER, hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result =
		    secret_PerformAuth_OSAP(hPolicy, hNewPolicy, hNewPolicy,
					    hObjectToChange, sharedSecret,
					    &auth1, digest.digest,
					    &nonceEvenOSAP)))
			return result;

		if ((result = TCSP_ChangeAuthOwner(tcsContext,
						  TCPA_PID_ADCP,
						  encAuthUsage, TCPA_ET_OWNER,
						  &auth1)))
			return result;

		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner,
					hashBlob);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result = secret_ValidateAuth_OSAP(hPolicy, hNewPolicy,
						       hNewPolicy,
						       sharedSecret, &auth1,
						       digest.digest,
						       &nonceEvenOSAP)))
			return result;

	} else if (obj_is_rsakey(hObjectToChange)) {
		keyToChangeHandle = getTCSKeyHandle(hObjectToChange);
		if (keyToChangeHandle == NULL_HKEY)
			return TSPERR(TSS_E_KEY_NOT_LOADED);

		if (keyToChangeHandle == TPM_KEYHND_SRK) {
			LogDebug1("SRK Handle");
			/* get the owner policy */
			if ((result = obj_tpm_get_policy(hParentObject,
							 &hParentPolicy)))
				return result;

			/* //////////////////////////////////////////////// */
			/* Now Calculate the authorization */
			if ((result =
			    secret_PerformXOR_OSAP(hParentPolicy, hNewPolicy,
						   hNewPolicy, hParentObject,
						   TCPA_ET_OWNER, 0,
						   &encAuthUsage, &encAuthMig,
						   sharedSecret, &auth1,
						   &nonceEvenOSAP)))
				return result;

			/* calculate auth data */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner,
						hashBlob);
			Trspi_LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
			Trspi_LoadBlob(&offset, 20, hashBlob,
					encAuthUsage.authdata);
			Trspi_LoadBlob_UINT16(&offset, TCPA_ET_SRK, hashBlob);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);

			if ((result =
			    secret_PerformAuth_OSAP(hParentPolicy, hNewPolicy,
						    hNewPolicy, hParentObject,
						    sharedSecret, &auth1,
						    digest.digest,
						    &nonceEvenOSAP)))
				return result;

			if ((result = TCSP_ChangeAuthOwner(tcsContext,
							  TCPA_PID_ADCP,
							  encAuthUsage,
							  TCPA_ET_SRK,
							  &auth1)))
				return result;

			/* ---  Validate the Auth's */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
			Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner,
						hashBlob);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);

			if ((result =
			    secret_ValidateAuth_OSAP(hParentPolicy, hNewPolicy,
						     hNewPolicy, sharedSecret,
						     &auth1, digest.digest,
						     &nonceEvenOSAP)))
				return result;
		} else {
			if ((result = obj_rsakey_get_policy(hObjectToChange,
							TSS_POLICY_USAGE,
							&hPolicy, NULL)))
				return result;

			/*  get the parent secret */
			if ((result = obj_rsakey_get_policy(hParentObject,
							   TSS_POLICY_USAGE,
							   &hParentPolicy, NULL)))
				return result;

			if ((result = obj_rsakey_get_blob(hObjectToChange,
						&objectLength, &keyBlob)))
				return result;

			offset = 0;
			if ((result = Trspi_UnloadBlob_KEY(&offset, keyBlob,
							   &keyToChange))) {
				LogDebug("Trspi_UnloadBlob_KEY failed. "
						"result=0x%x", result);
				return result;
			}

			if ((keyHandle = getTCSKeyHandle(hParentObject)) == NULL_HKEY)
				return TSPERR(TSS_E_KEY_NOT_LOADED);

			if ((result =
			    secret_PerformXOR_OSAP(hParentPolicy,
						   hNewPolicy,
						   hNewPolicy,
						   hParentObject,
						   keyHandle == TPM_KEYHND_SRK ?
						                   TCPA_ET_SRK :
								   TCPA_ET_KEYHANDLE,
						   keyHandle,
						   &encAuthUsage,
						   &encAuthMig,
						   sharedSecret,
						   &auth1,
						   &nonceEvenOSAP)))
				return result;

			/* caluculate auth data */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth,
					hashBlob);
			Trspi_LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
			Trspi_LoadBlob(&offset, 20, hashBlob,
					encAuthUsage.authdata);
			Trspi_LoadBlob_UINT16(&offset, TCPA_ET_KEY, hashBlob);
			Trspi_LoadBlob_UINT32(&offset, keyToChange.encSize,
					hashBlob);
			Trspi_LoadBlob(&offset, keyToChange.encSize, hashBlob,
					keyToChange.encData);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);

			if ((result =
			    secret_PerformAuth_OSAP(hParentPolicy, hNewPolicy,
						    hNewPolicy, hParentObject,
						    sharedSecret, &auth1,
						    digest.digest,
						    &nonceEvenOSAP)))
				return result;

			if ((result = secret_PerformAuth_OIAP(hPolicy, &digest,
								&auth2))) {
				TCSP_TerminateHandle(tcsContext,
							auth1.AuthHandle);
				return result;
			}

			if ((result = TCSP_ChangeAuth(tcsContext, keyHandle,
						      TCPA_PID_ADCP, encAuthUsage,
						      TCPA_ET_KEY,
						      keyToChange.encSize,
						      keyToChange.encData, &auth1,
						      &auth2, &newEncSize,
						      &newEncData)))
				return result;

			/* ---  Validate the Auth's */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
			Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth,
						hashBlob);
			Trspi_LoadBlob_UINT32(&offset, newEncSize, hashBlob);
			Trspi_LoadBlob(&offset, newEncSize, hashBlob,
					newEncData);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);

			if ((result =
			    secret_ValidateAuth_OSAP(hParentPolicy, hNewPolicy,
						     hNewPolicy, sharedSecret,
						     &auth1, digest.digest,
						     &nonceEvenOSAP))) {
				free(newEncData);
				return result;
			}

			if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest,
								&auth2)))
				return result;

			memcpy(keyToChange.encData, newEncData, newEncSize);
			free(newEncData);

			offset = 0;
			Trspi_LoadBlob_KEY(&offset, keyBlob, &keyToChange);
			objectLength = offset;

			if ((result = obj_rsakey_set_tcpakey(hObjectToChange,
					       objectLength, keyBlob)))
				return result;

			/* XXX replace with valid impl if we really want to
			 * touch the PS here */
			//keyreg_replaceEncData_PS(oldEncData,
			//                          keyToChange.encData);
		}
	} else if (obj_is_encdata(hObjectToChange)) {

		/*  get the secret for the parent */
		if ((result = obj_encdata_get_policy(hObjectToChange,
						   TSS_POLICY_USAGE,
						   &hPolicy)))
			return result;

		/*  get the parent secret */
		if ((result = obj_rsakey_get_policy(hParentObject,
						   TSS_POLICY_USAGE,
						   &hParentPolicy, NULL)))
			return result;

		/*  get the data Object  */
		if ((result = obj_encdata_get_data(hObjectToChange,
						 &dataBlobLength, &dataBlob)))
			return result;

		offset = 0;
		if ((result = Trspi_UnloadBlob_STORED_DATA(&offset, dataBlob,
							   &storedData)))
			return result;

		if ((keyHandle = getTCSKeyHandle(hParentObject)) == NULL_HKEY) {
			free(storedData.sealInfo);
			free(storedData.encData);
			return TSPERR(TSS_E_KEY_NOT_LOADED);
		}

		if ((result =
		    secret_PerformXOR_OSAP(hParentPolicy, hNewPolicy,
					   hNewPolicy, hParentObject,
					   TCPA_ET_KEYHANDLE, keyHandle,
					   &encAuthUsage, &encAuthMig,
					   sharedSecret, &auth1,
					   &nonceEvenOSAP))) {
			free(storedData.sealInfo);
			free(storedData.encData);
			return result;
		}

		/* caluculate auth data */
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth, hashBlob);
		Trspi_LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
		Trspi_LoadBlob(&offset, 20, hashBlob, encAuthUsage.authdata);
		Trspi_LoadBlob_UINT16(&offset, TCPA_ET_DATA, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, storedData.encDataSize, hashBlob);
		Trspi_LoadBlob(&offset, storedData.encDataSize, hashBlob,
				storedData.encData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result =
		    secret_PerformAuth_OSAP(hParentPolicy, hNewPolicy,
					    hNewPolicy, hParentObject,
					    sharedSecret, &auth1,
					    digest.digest, &nonceEvenOSAP))) {
			free(storedData.sealInfo);
			free(storedData.encData);
			return result;
		}

		if ((result = secret_PerformAuth_OIAP(hPolicy, &digest,
							&auth2))) {
			TCSP_TerminateHandle(tcsContext, auth1.AuthHandle);
			free(storedData.sealInfo);
			free(storedData.encData);
			return result;
		}

		if ((result = TCSP_ChangeAuth(tcsContext, keyHandle,
					      TCPA_PID_ADCP, encAuthUsage,
					     TCPA_ET_DATA,
					     storedData.encDataSize,
					     storedData.encData, &auth1,
					     &auth2, &newEncSize,
					     &newEncData))) {
			free(storedData.sealInfo);
			free(storedData.encData);
			return result;
		}

		/* ---  Validate the Auth's */
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth, hashBlob);
		Trspi_LoadBlob_UINT32(&offset, newEncSize, hashBlob);
		Trspi_LoadBlob(&offset, newEncSize, hashBlob, newEncData);
		Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result =
		    secret_ValidateAuth_OSAP(hParentPolicy, hNewPolicy,
					     hNewPolicy, sharedSecret, &auth1,
					     digest.digest, &nonceEvenOSAP))) {
			free(storedData.sealInfo);
			free(storedData.encData);
			free(newEncData);
			return result;
		}

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest,
							&auth2))) {
			free(storedData.sealInfo);
			free(storedData.encData);
			return result;
		}

		memcpy(storedData.encData, newEncData, newEncSize);
		free(newEncData);
		storedData.encDataSize = newEncSize;

		offset = 0;
		Trspi_LoadBlob_STORED_DATA(&offset, dataBlob, &storedData);
		free(storedData.sealInfo);
		free(storedData.encData);
		if ((result = obj_encdata_set_data(hObjectToChange,
						 offset, dataBlob)))
			return result;

	} else if (obj_is_policy(hObjectToChange) || obj_is_hash(hObjectToChange) ||
		    obj_is_pcrs(hObjectToChange) || obj_is_context(hObjectToChange)) {
		return TSPERR(TSS_E_BAD_PARAMETER);
	} else {
		return TSPERR(TSS_E_INVALID_HANDLE);
	}

	if ((result = obj_policy_set_type(hNewPolicy, TSS_POLICY_USAGE)))
		return result;

	return Tspi_Policy_AssignToObject(hNewPolicy, hObjectToChange);
}

TSS_RESULT
Tspi_ChangeAuthAsym(TSS_HOBJECT hObjectToChange,	/* in */
		    TSS_HOBJECT hParentObject,		/* in */
		    TSS_HKEY hIdentKey,			/* in */
		    TSS_HPOLICY hNewPolicy		/* in */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TPM_AUTH auth;
	UINT16 offset;
	BYTE hashBlob[0x1000];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	UINT32 keyHandle;
	UINT32 idHandle;
	TSS_HPOLICY hPolicy;
	TSS_HPOLICY hParentPolicy;
	UINT32 keyToChangeHandle;
	TCPA_NONCE antiReplay;
	UINT32 bytesRequested;
	BYTE *randomBytes;
	UINT16 tempSize;
	BYTE tempKey[512];
	TCPA_KEY_PARMS keyParms;
	/* XXX Wow... */
	BYTE ephParms[] = { 0, 0, 0x08, 0, 0, 0, 0, 0x02, 0, 0, 0, 0 };
	UINT32 KeySizeOut;
	BYTE *KeyDataOut;
	UINT32 CertifyInfoSize;
	BYTE *CertifyInfo;
	UINT32 sigSize;
	BYTE *sig;
	UINT32 ephHandle;
	TCPA_CHANGEAUTH_VALIDATE caValidate;
	TCPA_SECRET newSecret, oldSecret;
	BYTE seed[20];
	BYTE a1[256];
	UINT32 a1Size;
	TCPA_KEY ephemeralKey;
	TCPA_DIGEST newAuthLink;
	UINT32 encObjectSize;
	BYTE *encObject = NULL;
	UINT32 encDataSizeOut;
	BYTE *encDataOut;
	TCPA_NONCE saltNonce;
	TCPA_DIGEST changeProof;
	TSS_HPOLICY hOldPolicy;
	UINT32 caValidSize;
	UINT32 keyObjectSize;
	BYTE *keyObject;
	TCPA_KEY keyContainer;
	TCPA_STORED_DATA dataContainer;
	BYTE *dataObject;
	UINT32 dataObjectSize;
	UINT16 entityType;
	TSS_BOOL useAuth = TRUE; // XXX
	TPM_AUTH *pAuth;
	BYTE dataBlob[1024];
	TSS_HCONTEXT tspContext;

	if ((result = obj_policy_get_tsp_context(hNewPolicy, &tspContext)))
		return result;

	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/*  grab all of the needed handles */
	idHandle = getTCSKeyHandle(hIdentKey);
	if (idHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	/*  get the secret for the parent */
	if ((result = obj_rsakey_get_policy(hIdentKey, TSS_POLICY_USAGE,
						&hPolicy, &useAuth)))
		return result;

	/*  get the parent secret */
	if ((result = Tspi_GetPolicyObject(hParentObject, TSS_POLICY_USAGE,
						&hParentPolicy)))
		return result;

	if (!obj_is_rsakey(hParentObject) && !obj_is_tpm(hParentObject))
		return TSPERR(TSS_E_INVALID_HANDLE);

	/*  get the keyObject  */
	keyHandle = getTCSKeyHandle(hParentObject);
	if (keyHandle == NULL_HKEY)
		return TSPERR(TSS_E_KEY_NOT_LOADED);

	if (obj_is_rsakey(hObjectToChange) ||
	    obj_is_encdata(hObjectToChange)) {

		keyToChangeHandle = getTCSKeyHandle(hObjectToChange);

		if (keyToChangeHandle == TPM_KEYHND_SRK) {
			return TSPERR(TSS_E_BAD_PARAMETER);
		} else {
			/*  generate container for ephemeral key */
			keyParms.algorithmID = 1;	/* rsa */
			keyParms.encScheme = 3;
			keyParms.sigScheme = 1;
			keyParms.parmSize = 12;
			keyParms.parms = malloc(12);
			if (keyParms.parms == NULL) {
				LogError("malloc of %d bytes failed.", 12);
				return TSPERR(TSS_E_OUTOFMEMORY);
			}
			memcpy(keyParms.parms, ephParms, 12);

			tempSize = 0;
			Trspi_LoadBlob_KEY_PARMS(&tempSize, tempKey, &keyParms);

			/*  generate antireplay nonce */
			bytesRequested = 20;
			TCSP_GetRandom(tcsContext, bytesRequested,
					&randomBytes);
			memcpy(antiReplay.nonce, randomBytes, bytesRequested);
			free_tspi(tspContext, randomBytes);

			/* caluculate auth data */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset,
					      TPM_ORD_ChangeAuthAsymStart,
					      hashBlob);
			Trspi_LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);
			Trspi_LoadBlob_KEY_PARMS(&offset, hashBlob, &keyParms);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);

			if (useAuth) {
				if ((result = secret_PerformAuth_OIAP(hPolicy,
								      &digest,
								      &auth))) {
					TCSP_TerminateHandle(tcsContext, auth.AuthHandle);
					return result;
				}
				pAuth = &auth;
			} else {
				pAuth = NULL;
			}

			if ((result = TCSP_ChangeAuthAsymStart(tcsContext,
							      idHandle,
							      antiReplay,
							      tempSize,
							      tempKey,
							      pAuth,
							      &KeySizeOut,
							      &KeyDataOut,
							      &CertifyInfoSize,
							      &CertifyInfo,
							      &sigSize,
							      &sig,
							      &ephHandle)))
				return result;

			/* ---  Validate the Auth's */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
			Trspi_LoadBlob_UINT32(&offset,
					      TPM_ORD_ChangeAuthAsymStart,
					      hashBlob);
			Trspi_LoadBlob(&offset, CertifyInfoSize, hashBlob,
					CertifyInfo);
			Trspi_LoadBlob_UINT32(&offset, sigSize, hashBlob);
			Trspi_LoadBlob(&offset, sigSize, hashBlob, sig);
			Trspi_LoadBlob_UINT32(&offset, ephHandle, hashBlob);
			Trspi_LoadBlob(&offset, KeySizeOut, hashBlob,
					KeyDataOut);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);

			if (useAuth) {
				if ((result = obj_policy_validate_auth_oiap(hPolicy,
								       &digest,
								       &auth)))
					return result;
			}

			/*  generate random data for asymfinish */
			bytesRequested = 20;
			TCSP_GetRandom(tcsContext, bytesRequested,
				       &randomBytes);
			memcpy(caValidate.n1.nonce, randomBytes, bytesRequested);
			free_tspi(tspContext, randomBytes);
			bytesRequested = 20;
			TCSP_GetRandom(tcsContext, bytesRequested,
				       &randomBytes);
			memcpy(antiReplay.nonce, randomBytes, bytesRequested);
			free_tspi(tspContext, randomBytes);
			bytesRequested = 20;
			TCSP_GetRandom(tcsContext, bytesRequested,
				       &randomBytes);
			memcpy(seed, randomBytes, 20);
			free_tspi(tspContext, randomBytes);

			if ((result = Tspi_GetPolicyObject(hObjectToChange,
							  TSS_POLICY_USAGE,
							  &hOldPolicy)))
				return result;

			if ((result = obj_policy_get_secret(hNewPolicy, &newSecret)))
				return result;
			if ((result = obj_policy_get_secret(hOldPolicy, &oldSecret)))
				return result;

			/* //////////////////////////////////////////////// */
			/* Encrypt the ChangeAuthValidate structure with the
			 * ephemeral key */

			memcpy(caValidate.newAuthSecret.authdata,
					newSecret.authdata, 20);

			offset = 0;
			Trspi_LoadBlob_CHANGEAUTH_VALIDATE(&offset, hashBlob,
								&caValidate);
			caValidSize = offset;

			offset = 0;
			if ((result = Trspi_UnloadBlob_KEY(&offset, KeyDataOut,
						&ephemeralKey)))
				return result;

			Trspi_RSA_Encrypt(hashBlob, caValidSize, a1, &a1Size,
				       ephemeralKey.pubKey.key,
				       ephemeralKey.pubKey.keyLength);

			free_key_refs(&ephemeralKey);

			Trspi_HMAC(TSS_HASH_SHA1, 20, oldSecret.authdata,
					 20, newSecret.authdata,
					 newAuthLink.digest);

			if (obj_is_rsakey(hObjectToChange)) {
				if ((result = obj_rsakey_get_blob(hObjectToChange,
						   &keyObjectSize, &keyObject)))
					return result;

				memset(&keyContainer, 0, sizeof(TCPA_KEY));

				offset = 0;
				if ((result = Trspi_UnloadBlob_KEY(&offset,
								   keyObject,
								   &keyContainer)))
					return result;

				encObjectSize = keyContainer.encSize;
				encObject = malloc(encObjectSize);
				if (encObject == NULL) {
					LogError("malloc of %d bytes failed.",
							encObjectSize);
					free_key_refs(&keyContainer);
					return TSPERR(TSS_E_OUTOFMEMORY);
				}
				memcpy(encObject, keyContainer.encData,
						encObjectSize);
				entityType = TCPA_ET_KEY;
			} else {
				if ((result = obj_encdata_get_data(hObjectToChange,
						   &dataObjectSize, &dataObject)))
					return result;

				offset = 0;
				if ((result = Trspi_UnloadBlob_STORED_DATA(&offset,
									   dataObject,
									   &dataContainer)))
					return result;

				encObjectSize = dataContainer.encDataSize;
				encObject = malloc(encObjectSize);
				if (encObject == NULL) {
					LogError("malloc of %d bytes failed.",
						 encObjectSize);
					free(dataContainer.sealInfo);
					free(dataContainer.encData);
					return TSPERR(TSS_E_OUTOFMEMORY);
				}
				memcpy(encObject, dataContainer.encData,
						encObjectSize);
				entityType = TCPA_ET_DATA;
			}

			offset = 0;
			Trspi_LoadBlob_UINT32(&offset,
					      TPM_ORD_ChangeAuthAsymFinish,
					      hashBlob);
			Trspi_LoadBlob_UINT16(&offset, entityType, hashBlob);
			Trspi_LoadBlob(&offset, 20, hashBlob,
					newAuthLink.digest);
			Trspi_LoadBlob_UINT32(&offset, a1Size, hashBlob);
			Trspi_LoadBlob(&offset, a1Size, hashBlob, a1);
			Trspi_LoadBlob_UINT32(&offset, encObjectSize, hashBlob);
			Trspi_LoadBlob(&offset, encObjectSize, hashBlob,
					encObject);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob,
					digest.digest);
#if 0
			/* XXX */
			if ((result = policy_UsesAuth(hParentPolicy,
							&useAuth))) {
				free(encObject);
				return result;
			}
#endif
			if (useAuth) {
				if ((result = secret_PerformAuth_OIAP(hParentPolicy,
								&digest, &auth))) {
					TCSP_TerminateHandle(tcsContext,
							     auth.AuthHandle);
					free(encObject);
					free_key_refs(&keyContainer);
					return result;
				}
				pAuth = &auth;
			} else {
				pAuth = NULL;
			}

			if ((result = TCSP_ChangeAuthAsymFinish(tcsContext,
							       keyHandle,
							       ephHandle,
							       entityType,
							       newAuthLink,
							       a1Size,
							       a1,
							       encObjectSize,
							       encObject,
							       pAuth,
							       &encDataSizeOut,
							       &encDataOut,
							       &saltNonce,
							       &changeProof))) {
				free_key_refs(&keyContainer);
				free(encObject);
				return result;
			}

			/* ---  Validate the Auth's */
			offset = 0;
			Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
			Trspi_LoadBlob_UINT32(&offset,
					      TPM_ORD_ChangeAuthAsymFinish,
					      hashBlob);
			Trspi_LoadBlob_UINT32(&offset, encDataSizeOut,
						hashBlob);
			Trspi_LoadBlob(&offset, encDataSizeOut, hashBlob,
					encDataOut);
			Trspi_LoadBlob(&offset, 20, hashBlob, saltNonce.nonce);
			Trspi_LoadBlob(&offset, 20, hashBlob, changeProof.digest);
			Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if (useAuth) {
				if ((result = obj_policy_validate_auth_oiap(hParentPolicy,
									&digest,
									&auth))) {
					free_key_refs(&keyContainer);
					free(encObject);
					return result;
				}
			}

			if (entityType == TCPA_ET_KEY ||
			    entityType == TCPA_ET_KEYHANDLE) {
				/* XXX replace with valid impl */
				//keyreg_replaceEncData_PS(encObject, encDataOut);

				memcpy(keyContainer.encData, encDataOut,
						encDataSizeOut);
				keyContainer.encSize = encDataSizeOut;

				offset = 0;
				Trspi_LoadBlob_KEY(&offset, keyObject,
							&keyContainer);
				free_key_refs(&keyContainer);
				if ((result = obj_rsakey_set_tcpakey(
							hObjectToChange,
							offset, keyObject))) {
					free(encObject);
					return result;
				}
			}

			if (entityType == TCPA_ET_DATA) {
				memcpy(dataContainer.encData, encDataOut,
						encDataSizeOut);
				dataContainer.encDataSize = encDataSizeOut;

				offset = 0;
				Trspi_LoadBlob_STORED_DATA(&offset, dataBlob,
							   &dataContainer);
				free(dataContainer.sealInfo);
				free(dataContainer.encData);
				obj_encdata_set_data(hObjectToChange,
						   offset, dataBlob);
			}
		}
	} else
		return TSPERR(TSS_E_BAD_PARAMETER);

	free(encObject);

	return Tspi_Policy_AssignToObject(hNewPolicy, hObjectToChange);
}

TSS_RESULT
Tspi_SetAttribUint32(TSS_HOBJECT hObject,	/* in */
		     TSS_FLAG attribFlag,	/* in */
		     TSS_FLAG subFlag,		/* in */
		     UINT32 ulAttrib		/* in */
    )
{
	TSS_RESULT result;

	if (obj_is_rsakey(hObject)) {
		if (attribFlag == TSS_TSPATTRIB_KEY_REGISTER) {
			if (subFlag)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_USER)
				result = obj_rsakey_set_pstype(hObject, TSS_PS_TYPE_USER);
			else if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_SYSTEM)
				result = obj_rsakey_set_pstype(hObject, TSS_PS_TYPE_SYSTEM);
			else if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_NO)
				result = obj_rsakey_set_pstype(hObject, TSS_PS_TYPE_NO);
			else
				return TSPERR(TSS_E_INVALID_ATTRIB_DATA);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			switch (subFlag) {
				case TSS_TSPATTRIB_KEYINFO_USAGE:
					if (ulAttrib != TSS_KEYUSAGE_BIND &&
					    ulAttrib != TSS_KEYUSAGE_IDENTITY &&
					    ulAttrib != TSS_KEYUSAGE_LEGACY &&
					    ulAttrib != TSS_KEYUSAGE_SIGN &&
					    ulAttrib != TSS_KEYUSAGE_STORAGE &&
					    ulAttrib != TSS_KEYUSAGE_AUTHCHANGE) {
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);
					}

					result = obj_rsakey_set_usage(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_MIGRATABLE:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_migratable(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_REDIRECTED:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_redirected(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_VOLATILE:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_volatile(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
					if (ulAttrib != TRUE && ulAttrib != FALSE)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_authdata_usage(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_ALGORITHM:
					result = obj_rsakey_set_alg(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_ENCSCHEME:
					if (ulAttrib != TSS_ES_NONE &&
					    ulAttrib != TSS_ES_RSAESPKCSV15 &&
					    ulAttrib != TSS_ES_RSAESOAEP_SHA1_MGF1)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_es(hObject, ulAttrib);
					break;
				case TSS_TSPATTRIB_KEYINFO_SIGSCHEME:
					if (ulAttrib != TSS_SS_NONE &&
					    ulAttrib != TSS_SS_RSASSAPKCS1V15_SHA1 &&
					    ulAttrib != TSS_SS_RSASSAPKCS1V15_DER)
						return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

					result = obj_rsakey_set_ss(hObject, ulAttrib);
					break;
				default:
					return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
				result = obj_rsakey_set_num_primes(hObject, ulAttrib);
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
	} else if (obj_is_policy(hObject)) {
		if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_HMAC) {
			if (ulAttrib == 0)
				return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

			result = obj_policy_set_cb_hmac(hObject, (PVOID)ulAttrib);
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC) {
			if (ulAttrib == 0)
				return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

			result = obj_policy_set_cb_xor(hObject, (PVOID)ulAttrib);
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP) {
			if (ulAttrib == 0)
				return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

			result = obj_policy_set_cb_takeowner(hObject, (PVOID)ulAttrib);
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM) {
			if (ulAttrib == 0)
				return TSPERR(TSS_E_INVALID_ATTRIB_DATA);

			result = obj_policy_set_cb_changeauth(hObject, (PVOID)ulAttrib);
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_SECRET_LIFETIME) {
			if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
				result = obj_policy_set_lifetime(hObject);
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
				result = obj_policy_set_counter(hObject, ulAttrib);
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
				result = obj_policy_set_timer(hObject, ulAttrib);
			} else {
				result = TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
	} else if (obj_is_context(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_SILENT_MODE)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		if (subFlag)
			return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

		if (ulAttrib == TSS_TSPATTRIB_CONTEXT_NOT_SILENT)
			result = obj_context_set_mode(hObject, ulAttrib);
		else if (ulAttrib == TSS_TSPATTRIB_CONTEXT_SILENT) {
			if (obj_context_has_popups(hObject))
				return TSPERR(TSS_E_SILENT_CONTEXT);
			result = obj_context_set_mode(hObject, ulAttrib);
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_DATA);
	} else {
		if (obj_is_tpm(hObject) || obj_is_hash(hObject) ||
		    obj_is_pcrs(hObject) || obj_is_encdata(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_GetAttribUint32(TSS_HOBJECT hObject,	/* in */
		     TSS_FLAG attribFlag,	/* in */
		     TSS_FLAG subFlag,		/* in */
		     UINT32 * pulAttrib		/* out */
    )
{
	UINT32 attrib;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	if (pulAttrib == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (obj_is_rsakey(hObject)) {
		if (attribFlag == TSS_TSPATTRIB_KEY_REGISTER) {
			if (subFlag != 0)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			if ((result = obj_rsakey_get_pstype(hObject, &attrib)))
				return result;

			if (attrib == TSS_PS_TYPE_USER)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_USER;
			else if (attrib == TSS_PS_TYPE_SYSTEM)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_SYSTEM;
			else
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_NO;
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			switch (subFlag) {
			case TSS_TSPATTRIB_KEYINFO_USAGE:
				if ((result = obj_rsakey_get_usage(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_MIGRATABLE:
				*pulAttrib = obj_rsakey_is_migratable(hObject);
				break;
			case TSS_TSPATTRIB_KEYINFO_REDIRECTED:
				*pulAttrib = obj_rsakey_is_redirected(hObject);
				break;
			case TSS_TSPATTRIB_KEYINFO_VOLATILE:
				*pulAttrib = obj_rsakey_is_volatile(hObject);
				break;
			case TSS_TSPATTRIB_KEYINFO_AUTHUSAGE:
				/* fall through */
			case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
				if ((result = obj_rsakey_get_authdata_usage(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_ALGORITHM:
				if ((result = obj_rsakey_get_alg(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_ENCSCHEME:
				if ((result = obj_rsakey_get_es(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_SIGSCHEME:
				if ((result = obj_rsakey_get_ss(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_KEYFLAGS:
				if ((result = obj_rsakey_get_flags(hObject, pulAttrib)))
					return result;
				break;
			case TSS_TSPATTRIB_KEYINFO_SIZE:
				if ((result = obj_rsakey_get_length(hObject, pulAttrib)))
					return result;
				break;
			default:
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE) {
				if ((result = obj_rsakey_get_length(hObject, pulAttrib)))
					return result;
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
				if ((result = obj_rsakey_get_num_primes(hObject, pulAttrib)))
					return result;
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
	} else if (obj_is_policy(hObject)) {
		if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_HMAC) {
			if ((result = obj_policy_get_cb_hmac(hObject, pulAttrib)))
				return result;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC) {
			if ((result = obj_policy_get_cb_xor(hObject, pulAttrib)))
				return result;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP) {
			if ((result = obj_policy_get_cb_takeowner(hObject, pulAttrib)))
				return result;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM) {
			if ((result = obj_policy_get_cb_changeauth(hObject, pulAttrib)))
				return result;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_SECRET_LIFETIME) {
			if ((result = obj_policy_get_lifetime(hObject, &attrib)))
				return result;

			if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
				if (attrib == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS)
					*pulAttrib = TRUE;
				else
					*pulAttrib = FALSE;
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
				if (attrib != TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER)
					return TSPERR(TSS_E_BAD_PARAMETER);
				if ((result = obj_policy_get_counter(hObject, pulAttrib)))
					return result;
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
				if ((result = obj_policy_get_secs_until_expired(hObject, pulAttrib)))
					return result;
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
	} else if (obj_is_context(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_SILENT_MODE)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		if (subFlag)
			return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

		if ((result = obj_context_get_mode(hObject, pulAttrib)))
			return result;
	} else {
		if (obj_is_tpm(hObject) || obj_is_hash(hObject) ||
		    obj_is_pcrs(hObject) || obj_is_encdata(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
	}

	return result;
}

TSS_RESULT
Tspi_SetAttribData(TSS_HOBJECT hObject,		/* in */
		   TSS_FLAG attribFlag,		/* in */
		   TSS_FLAG subFlag,		/* in */
		   UINT32 ulAttribDataSize,	/* in */
		   BYTE * rgbAttribData		/* in */
    )
{
	TSS_RESULT result;
	BYTE *string = NULL;

	if (obj_is_rsakey(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_KEY_BLOB)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);

		if (subFlag == TSS_TSPATTRIB_KEYBLOB_BLOB) {
			result = obj_rsakey_set_tcpakey(hObject, ulAttribDataSize, rgbAttribData);
		} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
			result = obj_rsakey_set_pubkey(hObject, ulAttribDataSize, rgbAttribData);
		} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
			result = obj_rsakey_set_privkey(hObject, ulAttribDataSize, rgbAttribData);
		} else {
			return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	} else if (obj_is_encdata(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_ENCDATA_BLOB)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		if (subFlag != TSS_TSPATTRIB_ENCDATABLOB_BLOB)
			return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

		result = obj_encdata_set_data(hObject, ulAttribDataSize, rgbAttribData);
	} else if (obj_is_policy(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_POLICY_POPUPSTRING)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);

		if ((string = Trspi_UNICODE_To_Native(rgbAttribData, NULL)) == NULL)
			return TSPERR(TSS_E_INTERNAL_ERROR);

		result = obj_policy_set_string(hObject, ulAttribDataSize, string);
	} else {
		if (obj_is_tpm(hObject) || obj_is_hash(hObject) ||
		    obj_is_pcrs(hObject) || obj_is_context(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_GetAttribData(TSS_HOBJECT hObject,		/* in */
		   TSS_FLAG attribFlag,		/* in */
		   TSS_FLAG subFlag,		/* in */
		   UINT32 * pulAttribDataSize,	/* out */
		   BYTE ** prgbAttribData	/* out */
    )
{
	TSS_RESULT result;
	BYTE *string = NULL;

	if (pulAttribDataSize == NULL || prgbAttribData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (obj_is_rsakey(hObject)) {
		if (attribFlag == TSS_TSPATTRIB_KEY_BLOB) {
			if (subFlag == TSS_TSPATTRIB_KEYBLOB_BLOB) {
				result = obj_rsakey_get_blob(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
				result = obj_rsakey_get_priv_blob(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
				result = obj_rsakey_get_pub_blob(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			if (subFlag != TSS_TSPATTRIB_KEYINFO_VERSION)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			result = obj_rsakey_get_version(hObject,
					pulAttribDataSize,
					prgbAttribData);
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) {
				result = obj_rsakey_get_exponent(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) {
				return TSPERR(TSS_E_NOTIMPL);
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_UUID) {
			if (subFlag)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			result = obj_rsakey_get_uuid(hObject,
					pulAttribDataSize,
					prgbAttribData);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_PCR) {
			if (subFlag == TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION) {
				result = obj_rsakey_get_pcr_atcreation(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE) {
				result = obj_rsakey_get_pcr_atrelease(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_KEYPCR_SELECTION) {
				result = obj_rsakey_get_pcr_selection(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
		} else
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
	} else if (obj_is_encdata(hObject)) {
		if (attribFlag == TSS_TSPATTRIB_ENCDATA_BLOB) {
			if (subFlag != TSS_TSPATTRIB_ENCDATABLOB_BLOB)
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);

			result = obj_encdata_get_data(hObject,
					pulAttribDataSize,
					prgbAttribData);
		} else if (attribFlag == TSS_TSPATTRIB_ENCDATA_PCR) {
			if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION) {
				result = obj_encdata_get_pcr_atcreation(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE) {
				result = obj_encdata_get_pcr_atrelease(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_SELECTION) {
				result = obj_encdata_get_pcr_selection(hObject,
						pulAttribDataSize,
						prgbAttribData);
			} else {
				return TSPERR(TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		} else {
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
		}
	} else if (obj_is_context(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_MACHINE_NAME)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);

		if ((result = obj_context_get_machine_name(hObject,
					pulAttribDataSize, &string)))
			return result;

		if ((*prgbAttribData =
		    Trspi_Native_To_UNICODE(string, pulAttribDataSize)) == NULL)
			result = TSPERR(TSS_E_INTERNAL_ERROR);

		free(string);
	} else if (obj_is_policy(hObject)) {
		if (attribFlag != TSS_TSPATTRIB_POLICY_POPUPSTRING)
			return TSPERR(TSS_E_INVALID_ATTRIB_FLAG);

		if ((result = obj_policy_get_string(hObject, pulAttribDataSize,
						    &string)))
			return result;

		if ((*prgbAttribData =
		    Trspi_Native_To_UNICODE(string, pulAttribDataSize)) == NULL)
			result = TSPERR(TSS_E_INTERNAL_ERROR);

		free(string);
	} else {
		if (obj_is_tpm(hObject) || obj_is_hash(hObject) || obj_is_pcrs(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_GetPolicyObject(TSS_HOBJECT hObject,	/* in */
		     TSS_FLAG policyType,	/* in */
		     TSS_HPOLICY * phPolicy	/* out */
    )
{
	TSS_RESULT result;

	if (phPolicy == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (policyType != TSS_POLICY_USAGE &&
	    policyType != TSS_POLICY_MIGRATION)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (obj_is_rsakey(hObject)) {
		result = obj_rsakey_get_policy(hObject, policyType, phPolicy, NULL);
	} else if (obj_is_tpm(hObject)) {
		result = obj_tpm_get_policy(hObject, phPolicy);
	} else if (obj_is_context(hObject)) {
		result = obj_context_get_policy(hObject, phPolicy);
	} else if (obj_is_encdata(hObject)) {
		result = obj_encdata_get_policy(hObject, policyType, phPolicy);
	} else {
		if (obj_is_policy(hObject) || obj_is_hash(hObject) || obj_is_pcrs(hObject))
			result = TSPERR(TSS_E_BAD_PARAMETER);
		else
			result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

