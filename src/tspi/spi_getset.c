
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
#include <time.h>
#include <errno.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "tss_crypto.h"


TSS_RESULT
Tspi_ChangeAuth(TSS_HOBJECT hObjectToChange,	/*  in */
		TSS_HOBJECT hParentObject,	/*  in */
		TSS_HPOLICY hNewPolicy	/*  in */
    )
{
	TCS_CONTEXT_HANDLE hContext;
/* 	TCPA_KEY			*keyObjectToChange; */
	TCPA_ENCAUTH encAuthUsage;
	TCPA_ENCAUTH encAuthMig;
	BYTE sharedSecret[20];
	TCS_AUTH auth1;
	TCS_AUTH auth2;
	UINT16 offset;
	BYTE hashBlob[0x1000];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	UINT32 keyHandle;
	UINT32 objectType;
	TSS_HPOLICY hPolicy;
	TSS_HPOLICY hParentPolicy;
	TCPA_NONCE nonceEvenOSAP;
	AnObject *object;
	UINT32 dataBlobLength;
	BYTE *dataBlob;
	TCPA_STORED_DATA storedData;
	UINT32 keyToChangeHandle;
	BYTE oldEncData[256];
	UINT32 objectLength;
/* 	BYTE				*objectToChange; */
	TCPA_KEY keyToChange;
	BYTE *keyBlob;
	UINT32 newEncSize;
	BYTE *newEncData;

	/* //////////////////////////////////////////////////////////////////////////// */
	/* Perform the initial checks */
	/* If the parent Object is Null */
	/*      -       Trying to change the TPM Auth */
	/*      -       This requires Owner Authorization */
	/* If the parent Object is not Null */
	/*      -       Trying to change the auth of an entity */
	/* If the ObjectToChange is the SRK, then the parent must be the TPM Object */

	LogDebug1("Tspi_ChangeAuth");
	if ((result = internal_CheckObjectType_1(hNewPolicy, TSS_OBJECT_TYPE_POLICY)))
		return result;

/* 	hContext = obj_getContextForObject( hObjectToChange ); */
/* 	if( hContext == 0 ) */
/* 		return TSS_E_INVALID_HANDLE; */
	if (hParentObject == 0) {
		if ((result = internal_CheckContext_2(hObjectToChange, hNewPolicy, &hContext)))
			return result;
	} else {
		if ((result = internal_CheckContext_3(hObjectToChange, hParentObject, hNewPolicy, &hContext)))
			return result;
	}
	/* what is the object type? */
	objectType = getObjectTypeByHandle(hObjectToChange);

	if (objectType == TSS_OBJECT_TYPE_TPM) {	/*  if TPM Owner Auth change */
		LogDebug1("Object Type TPM");
		/* get the owner policy */
		if ((result = Tspi_GetPolicyObject(hObjectToChange, TSS_POLICY_USAGE, &hPolicy)))
			return result;

		/* ////////////////////////////////////////////////////////////////////// */
		/* Now Calculate the authorization */
		if ((result =
		    secret_PerformXOR_OSAP(hPolicy, hNewPolicy, hNewPolicy,
					   hObjectToChange, TCPA_ET_OWNER, 0,
					   &encAuthUsage, &encAuthMig,
					   sharedSecret, &auth1, &nonceEvenOSAP)))
			return result;

		/* calculate auth data HASH(ord, usageauth, migrationauth, keyinfo) */
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner, hashBlob);
		LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
		LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
		LoadBlob_UINT16(&offset, TCPA_ET_OWNER, hashBlob);
		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result =
		    secret_PerformAuth_OSAP(hPolicy, hNewPolicy, hNewPolicy,
					    hObjectToChange, sharedSecret,
					    &auth1, digest.digest, nonceEvenOSAP)))
			return result;

		if ((result = TCSP_ChangeAuthOwner(hContext,
						  TCPA_PID_ADCP,
						  encAuthUsage, TCPA_ET_OWNER, &auth1)))
			return result;

		offset = 0;
		LoadBlob_UINT32(&offset, result, hashBlob);
		LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner, hashBlob);
		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result = secret_ValidateAuth_OSAP(hPolicy, hNewPolicy, hNewPolicy,
					     sharedSecret, &auth1, digest.digest, nonceEvenOSAP)))
			return result;

	}

	else if (objectType == TSS_OBJECT_TYPE_RSAKEY) {
		LogDebug1("Object Type RSAKEY");

		keyToChangeHandle = getTCSKeyHandle(hObjectToChange);
		if (keyToChangeHandle == 0)
			return TSS_E_KEY_NOT_LOADED;

		if (keyToChangeHandle == FIXED_SRK_KEY_HANDLE) {
			LogDebug1("SRK Handle");
			/* get the owner policy */
			if ((result = Tspi_GetPolicyObject(hParentObject, TSS_POLICY_USAGE, &hParentPolicy)))
				return result;

			/* ////////////////////////////////////////////////////////////////////// */
			/* Now Calculate the authorization */
			if ((result =
			    secret_PerformXOR_OSAP(hParentPolicy, hNewPolicy,
						   hNewPolicy, hParentObject,
						   TCPA_ET_OWNER, 0,
						   &encAuthUsage, &encAuthMig,
						   sharedSecret, &auth1, &nonceEvenOSAP)))
				return result;

			/* calculate auth data HASH(ord, usageauth, migrationauth, keyinfo) */
			offset = 0;
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner, hashBlob);
			LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
			LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
			LoadBlob_UINT16(&offset, TCPA_ET_SRK, hashBlob);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if ((result =
			    secret_PerformAuth_OSAP(hParentPolicy, hNewPolicy,
						    hNewPolicy, hParentObject,
						    sharedSecret, &auth1,
						    digest.digest, nonceEvenOSAP)))
				return result;

			if ((result = TCSP_ChangeAuthOwner(hContext,
							  TCPA_PID_ADCP,
							  encAuthUsage, TCPA_ET_SRK, &auth1)))
				return result;

			/* ---  Validate the Auth's */
			offset = 0;
			LoadBlob_UINT32(&offset, result, hashBlob);
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthOwner, hashBlob);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if ((result =
			    secret_ValidateAuth_OSAP(hParentPolicy, hNewPolicy,
						     hNewPolicy, sharedSecret,
						     &auth1, digest.digest, nonceEvenOSAP)))
				return result;

		} else {	/* if( != FIXED_SRK_KEY_HANDLE */

			LogDebug1("Regular key");

			/*  get the secret for the parent */
			if ((result = Tspi_GetPolicyObject(hObjectToChange, TSS_POLICY_USAGE, &hPolicy)))
				return result;

			/*  get the parent secret */
			if ((result = Tspi_GetPolicyObject(hParentObject, TSS_POLICY_USAGE, &hParentPolicy)))
				return result;

			/*  get the keyObject  */
			/* object = getAnObjectByHandle( hObjectToChange ); */
			/* if( object == NULL ) */
			/*              return TSS_E_INVALID_HANDLE; */
			/*      if(( keyObjectToChange = object->memPointer ) == NULL ) */
			/*              return  TSS_E_INTERNAL_ERROR ; */

			result = Tspi_GetAttribData(hObjectToChange, TSS_TSPATTRIB_KEY_BLOB,
					       TSS_TSPATTRIB_KEYBLOB_BLOB, &objectLength, &keyBlob);
			if (result)
				return result;

			offset = 0;
			UnloadBlob_KEY(hContext, &offset, keyBlob, &keyToChange);

			keyHandle = getTCSKeyHandle(hParentObject);
			if (keyHandle == 0)
				return TSS_E_KEY_NOT_LOADED;

			if (keyHandle == 0x40000000) {
				if ((result =
				    secret_PerformXOR_OSAP(hParentPolicy,
							   hNewPolicy,
							   hNewPolicy,
							   hParentObject,
							   TCPA_ET_SRK,
							   keyHandle,
							   &encAuthUsage,
							   &encAuthMig,
							   sharedSecret, &auth1, &nonceEvenOSAP)))
					return result;
			} else {
				if ((result =
				    secret_PerformXOR_OSAP(hParentPolicy,
							   hNewPolicy,
							   hNewPolicy,
							   hParentObject,
							   TCPA_ET_KEYHANDLE,
							   keyHandle,
							   &encAuthUsage,
							   &encAuthMig,
							   sharedSecret, &auth1, &nonceEvenOSAP)))
					return result;
			}

			/* caluculate auth data HASH(ord, usageauth, migrationauth, keyinfo) */
			offset = 0;
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth, hashBlob);
			LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
			LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
			LoadBlob_UINT16(&offset, TCPA_ET_KEY, hashBlob);
			LoadBlob_UINT32(&offset, keyToChange.encSize, hashBlob);
			LoadBlob(&offset, keyToChange.encSize, hashBlob, keyToChange.encData);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if ((result =
			    secret_PerformAuth_OSAP(hParentPolicy, hNewPolicy,
						    hNewPolicy, hParentObject,
						    sharedSecret, &auth1,
						    digest.digest, nonceEvenOSAP)))
				return result;

			if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth2))) {
				TCSP_TerminateHandle(hContext, auth1.AuthHandle);
				return result;
			}

			/* ---  for replacing PS */
			memcpy(oldEncData, keyToChange.encData, 0x100);

			if ((result = TCSP_ChangeAuth(hContext, keyHandle, TCPA_PID_ADCP, encAuthUsage,	/*  in */
						     TCPA_ET_KEY,	/*  in */
						     keyToChange.encSize,	/*  in */
						     keyToChange.encData, &auth1,	/*  in, out */
						     &auth2,	/*  in, out     // in */
						     &newEncSize,	/* keyToChange.encSize,      // out */
						     &newEncData	/* keyToChange.encData       // out */
						)))
				return result;

			/* ---  Validate the Auth's */
			offset = 0;
			LoadBlob_UINT32(&offset, result, hashBlob);
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth, hashBlob);
			LoadBlob_UINT32(&offset, newEncSize, hashBlob);
			LoadBlob(&offset, newEncSize, hashBlob, newEncData);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if ((result =
			    secret_ValidateAuth_OSAP(hParentPolicy, hNewPolicy,
						     hNewPolicy, sharedSecret,
						     &auth1, digest.digest, nonceEvenOSAP)))
				return result;

			if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth2)))
				return result;

			memcpy(keyToChange.encData, newEncData, newEncSize);

			offset = 0;
			LoadBlob_KEY(&offset, keyBlob, &keyToChange);
			objectLength = offset;

			result =
			    Tspi_SetAttribData(hObjectToChange,
					       TSS_TSPATTRIB_KEY_BLOB,
					       TSS_TSPATTRIB_KEYBLOB_BLOB, objectLength, keyBlob);
			if (result)
				return result;

			/* XXX replace with valid impl */
			//keyreg_replaceEncData_PS(oldEncData, keyToChange.encData);
		}
	}

	else if (objectType == TSS_OBJECT_TYPE_ENCDATA) {

		/*  get the secret for the parent */
		if ((result = Tspi_GetPolicyObject(hObjectToChange, TSS_POLICY_USAGE, &hPolicy)))
			return result;

		/*  get the parent secret */
		if ((result = Tspi_GetPolicyObject(hParentObject, TSS_POLICY_USAGE, &hParentPolicy)))
			return result;

		/*  get the data Object  */
		if ((result = Tspi_GetAttribData(hObjectToChange, TSS_TSPATTRIB_ENCDATA_BLOB,
				   TSS_TSPATTRIB_ENCDATABLOB_BLOB, &dataBlobLength, &dataBlob)))
			return result;

		offset = 0;
		if ((result = UnloadBlob_STORED_DATA(hContext, &offset, dataBlob, &storedData)))
			return result;

		keyHandle = getTCSKeyHandle(hParentObject);
		if (keyHandle == 0)
			return TSS_E_KEY_NOT_LOADED;

		if ((result =
		    secret_PerformXOR_OSAP(hParentPolicy, hNewPolicy,
					   hNewPolicy, hParentObject,
					   TCPA_ET_KEYHANDLE, keyHandle,
					   &encAuthUsage, &encAuthMig,
					   sharedSecret, &auth1, &nonceEvenOSAP)))
			return result;

		/* caluculate auth data HASH(ord, usageauth, migrationauth, keyinfo) */
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth, hashBlob);
		LoadBlob_UINT16(&offset, TCPA_PID_ADCP, hashBlob);
		LoadBlob(&offset, 20, hashBlob, encAuthUsage.encauth);
		LoadBlob_UINT16(&offset, TCPA_ET_DATA, hashBlob);
		LoadBlob_UINT32(&offset, storedData.encDataSize, hashBlob);
		LoadBlob(&offset, storedData.encDataSize, hashBlob, storedData.encData);
		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result =
		    secret_PerformAuth_OSAP(hParentPolicy, hNewPolicy,
					    hNewPolicy, hParentObject,
					    sharedSecret, &auth1, digest.digest, nonceEvenOSAP)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth2))) {
			TCSP_TerminateHandle(hContext, auth1.AuthHandle);
			return result;
		}

		if ((result = TCSP_ChangeAuth(hContext, keyHandle, TCPA_PID_ADCP, encAuthUsage,	/*  in */
					     TCPA_ET_DATA,	/*  in */
					     storedData.encDataSize,	/*  in */
					     storedData.encData, &auth1,	/*  in, out */
					     &auth2,	/*  in, out     // in */
					     &newEncSize,	/*  out */
					     &newEncData	/*  out */
					)))
			return result;

		/* ---  Validate the Auth's */
		offset = 0;
		LoadBlob_UINT32(&offset, result, hashBlob);
		LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuth, hashBlob);
		LoadBlob_UINT32(&offset, newEncSize, hashBlob);
		LoadBlob(&offset, newEncSize, hashBlob, newEncData);
		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result =
		    secret_ValidateAuth_OSAP(hParentPolicy, hNewPolicy,
					     hNewPolicy, sharedSecret, &auth1,
					     digest.digest, nonceEvenOSAP)))
			return result;

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth2)))
			return result;

		memcpy(storedData.encData, newEncData, newEncSize);
		storedData.encDataSize = newEncSize;

		offset = 0;
		LoadBlob_STORED_DATA(&offset, dataBlob, &storedData);
		Tspi_SetAttribData(hObjectToChange, TSS_TSPATTRIB_ENCDATA_BLOB,
				   TSS_TSPATTRIB_ENCDATABLOB_BLOB, offset, dataBlob);

	} else
		return TSS_E_BAD_PARAMETER;

	object = getAnObjectByHandle(hNewPolicy);
	if (object == NULL || object->memPointer == NULL) {
		LogError("Couldn't find an internal object with handle 0x%x", hNewPolicy);
		return TSS_E_INTERNAL_ERROR;
	}
	((TSP_INTERNAL_POLICY_OBJECT *)object->memPointer)->p.PolicyType = TSS_POLICY_USAGE;

	Tspi_Policy_AssignToObject(hNewPolicy, hObjectToChange);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_ChangeAuthAsym(TSS_HOBJECT hObjectToChange,	/*  in */
		    TSS_HOBJECT hParentObject,	/*  in */
		    TSS_HKEY hIdentKey,	/*  in */
		    TSS_HPOLICY hNewPolicy	/*  in */
    )
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_KEY *keyObjectToChange;
	TCS_AUTH auth;
	UINT16 offset;
	BYTE hashBlob[0x1000];
	TCPA_DIGEST digest;
	TCPA_RESULT result;
	UINT32 keyHandle;
	UINT32 idHandle;
	UINT32 objectType;
	TSS_HPOLICY hPolicy;
	TSS_HPOLICY hParentPolicy;
	AnObject *object;
	UINT32 keyToChangeHandle;
	TCPA_NONCE antiReplay;
	UINT32 bytesRequested;
	BYTE *randomBytes;
	UINT16 tempSize;
	BYTE tempKey[512];
	TCPA_KEY_PARMS keyParms;
	BYTE ephParms[] = { 00, 00, 0x08, 00, 00, 00, 00, 0x02, 00, 00, 00, 00 };
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
	BYTE *encObject;
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
	BOOL useAuth;
	TCS_AUTH *pAuth;
	BYTE dataBlob[1024];

	if ((result = internal_CheckObjectType_1(hNewPolicy, TSS_OBJECT_TYPE_POLICY)))
		return result;

	if (hParentObject == 0) {
		return TSS_E_BAD_PARAMETER;
	} else {
		if ((result = internal_CheckContext_3(hObjectToChange, hParentObject, hNewPolicy, &hContext)))
			return result;
	}

	/* /////////////////////////////////////////////////////////////////// */
	/*  grab all of the needed handles */

	idHandle = getTCSKeyHandle(hIdentKey);
	if (idHandle == 0)
		return TSS_E_KEY_NOT_LOADED;

	/*  get the secret for the parent */
	if ((result = Tspi_GetPolicyObject(hIdentKey, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	/*  get the parent secret */
	if ((result = Tspi_GetPolicyObject(hParentObject, TSS_POLICY_USAGE, &hParentPolicy)))
		return result;

	/*  get the keyObject  */
	object = getAnObjectByHandle(hObjectToChange);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;
	if ((keyObjectToChange = object->memPointer) == NULL) {
		LogError1("internal object pointer for object to change not found!");
		return TSS_E_INTERNAL_ERROR;
	}

	keyHandle = getTCSKeyHandle(hParentObject);
	if (keyHandle == 0)
		return TSS_E_KEY_NOT_LOADED;

	/* ////////////////////////////////////////////////////////////////////// */

	/* what is the object type? */
	objectType = getObjectTypeByHandle(hObjectToChange);

	if ((objectType == TSS_OBJECT_TYPE_RSAKEY) || objectType == TSS_OBJECT_TYPE_ENCDATA) {

		keyToChangeHandle = getTCSKeyHandle(hObjectToChange);

		if (keyToChangeHandle == FIXED_SRK_KEY_HANDLE) {

			return TSS_E_BAD_PARAMETER;
		} else {

			/*  generate container for ephemeral key */
			keyParms.algorithmID = 1;	/* rsa */
			keyParms.encScheme = 3;
			keyParms.sigScheme = 1;
			keyParms.parmSize = 12;
			keyParms.parms = malloc(12);
			if (keyParms.parms == NULL) {
				LogError("malloc of %d bytes failed.", 12);
				return TSS_E_OUTOFMEMORY;
			}
			memcpy(keyParms.parms, ephParms, 12);

			tempSize = 0;
			LoadBlob_KEY_PARMS(&tempSize, tempKey, &keyParms);

			/*  generate antireplay nonce */
			bytesRequested = 20;
			TCSP_GetRandom(hContext,	/*  in */
				       &bytesRequested,	/*  in, out */
				       &randomBytes	/*  out */
			    );
			memcpy(antiReplay.nonce, randomBytes, bytesRequested);

			/* caluculate auth data HASH(ord, usageauth, migrationauth, keyinfo) */
			offset = 0;
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthAsymStart, hashBlob);
			LoadBlob(&offset, 20, hashBlob, antiReplay.nonce);
			LoadBlob_KEY_PARMS(&offset, hashBlob, &keyParms);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if ((result = policy_UsesAuth(hPolicy, &useAuth)))
				return result;

			if (useAuth) {
				if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth))) {
					TCSP_TerminateHandle(hContext, auth.AuthHandle);
					return result;
				}
				pAuth = &auth;
			} else {
				pAuth = NULL;
			}

			if ((result = TCSP_ChangeAuthAsymStart(hContext,	/*  in */
							      idHandle,	/*  in */
							      antiReplay,	/*  in */
							      tempSize,	/*  in */
							      tempKey,	/*  in */
							      pAuth,	/*  in, out */
							      &KeySizeOut,	/*  out */
							      &KeyDataOut,	/*  out */
							      &CertifyInfoSize,	/*  out */
							      &CertifyInfo,	/*  out */
							      &sigSize,	/*  out */
							      &sig,	/*  out */
							      &ephHandle	/*  out */
			    )))
				return result;

			/* ---  Validate the Auth's */
			offset = 0;
			LoadBlob_UINT32(&offset, result, hashBlob);
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthAsymStart, hashBlob);
			LoadBlob(&offset, CertifyInfoSize, hashBlob, CertifyInfo);
			LoadBlob_UINT32(&offset, sigSize, hashBlob);
			LoadBlob(&offset, sigSize, hashBlob, sig);
			LoadBlob_UINT32(&offset, ephHandle, hashBlob);
			LoadBlob(&offset, KeySizeOut, hashBlob, KeyDataOut);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if (useAuth) {
				if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth)))
					return result;
			}

			/*  generate random data for asymfinish */
			bytesRequested = 20;
			TCSP_GetRandom(hContext,	/*  in */
				       &bytesRequested,	/*  in, out */
				       &randomBytes	/*  out */
			    );
			memcpy(caValidate.n1.nonce, randomBytes, bytesRequested);
			bytesRequested = 20;
			TCSP_GetRandom(hContext,	/*  in */
				       &bytesRequested,	/*  in, out */
				       &randomBytes	/*  out */
			    );
			memcpy(antiReplay.nonce, randomBytes, bytesRequested);
			bytesRequested = 20;
			TCSP_GetRandom(hContext,	/*  in */
				       &bytesRequested,	/*  in, out */
				       &randomBytes	/*  out */
			    );
			memcpy(seed, randomBytes, 20);

			if ((result = Tspi_GetPolicyObject(hObjectToChange,
							  TSS_POLICY_USAGE, &hOldPolicy)))
				return result;

			if ((result = internal_GetSecret(hNewPolicy, &newSecret, 0)))
				return result;
			if ((result = internal_GetSecret(hOldPolicy, &oldSecret, 0)))
				return result;

			/* ////////////////////////////////////////////////////////////////////////// */
			/* Encrypt the ChangeAuthValidate structure with the ephemeral key */

			memcpy(caValidate.newAuthSecret.secret, newSecret.secret, 20);

			offset = 0;
			LoadBlob_CHANGEAUTH_VALIDATE(&offset, hashBlob, &caValidate);
			caValidSize = offset;

			offset = 0;
			UnloadBlob_KEY(hContext, &offset, KeyDataOut, &ephemeralKey);

			TSS_RSA_Encrypt(hashBlob,	/* in */
				       caValidSize,	/* in */
				       a1,	/* out */
				       &a1Size,	/* out */
				       ephemeralKey.pubKey.key,
				       ephemeralKey.pubKey.keyLength);

			TSS_HMAC(TSS_HASH_SHA1, 20, oldSecret.secret,	/* old secret */
				 20, newSecret.secret, newAuthLink.digest);

			if (objectType == TSS_OBJECT_TYPE_RSAKEY) {
				if ((result = Tspi_GetAttribData(hObjectToChange,
						   TSS_TSPATTRIB_KEY_BLOB,
						   TSS_TSPATTRIB_KEYBLOB_BLOB,
						   &keyObjectSize, &keyObject)))
					return result;

				offset = 0;
				UnloadBlob_KEY(hContext, &offset, keyObject, &keyContainer);

				encObjectSize = keyContainer.encSize;
				encObject = malloc(encObjectSize);
				if (encObject == NULL) {
					LogError("malloc of %d bytes failed.", encObjectSize);
					return TSS_E_OUTOFMEMORY;
				}
				memcpy(encObject, keyContainer.encData, encObjectSize);
				entityType = TCPA_ET_KEY;
			} else {
				if ((result = Tspi_GetAttribData(hObjectToChange,
						   TSS_TSPATTRIB_ENCDATA_BLOB,
						   TSS_TSPATTRIB_ENCDATABLOB_BLOB,
						   &dataObjectSize, &dataObject)))
					return result;

				offset = 0;
				if ((result = UnloadBlob_STORED_DATA(hContext, &offset,
						       dataObject, &dataContainer)))
					return result;

				encObjectSize = dataContainer.encDataSize;
				encObject = malloc(encObjectSize);
				if (encObject == NULL) {
					LogError("malloc of %d bytes failed.", encObjectSize);
					return TSS_E_OUTOFMEMORY;
				}
				memcpy(encObject, dataContainer.encData, encObjectSize);
				entityType = TCPA_ET_DATA;
			}

			offset = 0;
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthAsymFinish, hashBlob);
			LoadBlob_UINT16(&offset, entityType, hashBlob);
			LoadBlob(&offset, 20, hashBlob, newAuthLink.digest);
			LoadBlob_UINT32(&offset, a1Size, hashBlob);
			LoadBlob(&offset, a1Size, hashBlob, a1);
			LoadBlob_UINT32(&offset, encObjectSize, hashBlob);
			LoadBlob(&offset, encObjectSize, hashBlob, encObject);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if ((result = policy_UsesAuth(hParentPolicy, &useAuth))) {
				free(encObject);
				return result;
			}

			if (useAuth) {
				if ((result = secret_PerformAuth_OIAP(hParentPolicy, digest, &auth))) {
					TCSP_TerminateHandle(hContext, auth.AuthHandle);
					free(encObject);
					return result;
				}
				pAuth = &auth;
			} else {
				pAuth = NULL;
			}

			if ((result = TCSP_ChangeAuthAsymFinish(hContext,	/*  in */
							       keyHandle,	/*  in */
							       ephHandle,	/*  in */
							       entityType,	/*  in */
							       newAuthLink,	/*  in */
							       a1Size,	/*  in */
							       a1,	/*  in */
							       encObjectSize,	/*  in */
							       encObject,	/*  in */
							       pAuth,	/*  in, out */
							       &encDataSizeOut,	/*  out */
							       &encDataOut,	/*  out */
							       &saltNonce,	/*  out */
							       &changeProof	/*  out */
			    ))) {
				if (useAuth)
					TCSP_TerminateHandle(hContext, pAuth->AuthHandle);
				free(encObject);
				return result;
			}

			/* ---  Validate the Auth's */
			offset = 0;
			LoadBlob_UINT32(&offset, result, hashBlob);
			LoadBlob_UINT32(&offset, TPM_ORD_ChangeAuthAsymFinish, hashBlob);
			LoadBlob_UINT32(&offset, encDataSizeOut, hashBlob);
			LoadBlob(&offset, encDataSizeOut, hashBlob, encDataOut);
			LoadBlob(&offset, 20, hashBlob, saltNonce.nonce);
			LoadBlob(&offset, 20, hashBlob, changeProof.digest);
			TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

			if (useAuth) {
				if ((result = secret_ValidateAuth_OIAP(hParentPolicy, digest, &auth))) {
					TCSP_TerminateHandle(hContext, pAuth->AuthHandle);
					return result;
				}
			}

			if (entityType == TCPA_ET_KEY || entityType == TCPA_ET_KEYHANDLE) {
				/* XXX replace with valid impl */
				//keyreg_replaceEncData_PS(encObject, encDataOut);

				memcpy(keyContainer.encData, encDataOut, encDataSizeOut);
				keyContainer.encSize = encDataSizeOut;

				offset = 0;
				LoadBlob_KEY(&offset, keyObject, &keyContainer);
				Tspi_SetAttribData(hObjectToChange,
						   TSS_TSPATTRIB_KEY_BLOB,
						   TSS_TSPATTRIB_KEYBLOB_BLOB, offset, keyObject);
			}
			if (entityType == TCPA_ET_DATA) {
				memcpy(dataContainer.encData, encDataOut, encDataSizeOut);
				dataContainer.encDataSize = encDataSizeOut;

				offset = 0;
				LoadBlob_STORED_DATA(&offset, dataBlob, &dataContainer);
				Tspi_SetAttribData(hObjectToChange,
						   TSS_TSPATTRIB_ENCDATA_BLOB,
						   TSS_TSPATTRIB_ENCDATABLOB_BLOB,
						   offset, dataBlob);

			}
		}
	}

	else
		return TSS_E_BAD_PARAMETER;

	Tspi_Policy_AssignToObject(hNewPolicy, hObjectToChange);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_SetAttribUint32(TSS_HOBJECT hObject,	/*  in */
		     TSS_FLAG attribFlag,	/*  in */
		     TSS_FLAG subFlag,	/*  in */
		     UINT32 ulAttrib	/*  in */
    )
{
	AnObject *object = NULL;
	TCPA_CONTEXT_OBJECT *ctxObj;
	TCPA_RSAKEY_OBJECT *rsaObj;
	TSP_INTERNAL_POLICY_OBJECT *pObj;

	switch (getObjectTypeByHandle(hObject)) {
	case 0:
		return TSS_E_INVALID_HANDLE;
	case TSS_OBJECT_TYPE_RSAKEY:
		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		rsaObj = object->memPointer;

		if (attribFlag == TSS_TSPATTRIB_KEY_REGISTER) {
			if (subFlag != 0)
				return TSS_E_INVALID_ATTRIB_SUBFLAG;

			if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_USER)
				rsaObj->persStorageType = TSS_PS_TYPE_USER;
			else if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_SYSTEM)
				rsaObj->persStorageType = TSS_PS_TYPE_SYSTEM;
			else if (ulAttrib == TSS_TSPATTRIB_KEYREGISTER_NO)
				rsaObj->persStorageType = TSS_PS_TYPE_NO;
			else
				return TSS_E_INVALID_ATTRIB_DATA;

			break;
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {

			switch (subFlag) {
				case TSS_TSPATTRIB_KEYINFO_USAGE:
					if ((UINT16)ulAttrib != TSS_KEYUSAGE_BIND &&
						(UINT16)ulAttrib != TSS_KEYUSAGE_IDENTITY &&
						(UINT16)ulAttrib != TSS_KEYUSAGE_LEGACY &&
						(UINT16)ulAttrib != TSS_KEYUSAGE_SIGN &&
						(UINT16)ulAttrib != TSS_KEYUSAGE_STORAGE &&
						(UINT16)ulAttrib != TSS_KEYUSAGE_AUTHCHANGE) {
						return TSS_E_INVALID_ATTRIB_DATA;
					}
					rsaObj->tcpaKey.keyUsage = (UINT16) ulAttrib;
					break;
				case TSS_TSPATTRIB_KEYINFO_MIGRATABLE:
					if (ulAttrib)
						rsaObj->tcpaKey.keyFlags |= migratable;
					else
						rsaObj->tcpaKey.keyFlags &= (~migratable);
					break;
				case TSS_TSPATTRIB_KEYINFO_REDIRECTED:
					if (ulAttrib)
						rsaObj->tcpaKey.keyFlags |= redirection;
					else
						rsaObj->tcpaKey.keyFlags &= (~redirection);
					break;
				case TSS_TSPATTRIB_KEYINFO_VOLATILE:
					if (ulAttrib)
						rsaObj->tcpaKey.keyFlags |= volatileKey;
					else
						rsaObj->tcpaKey.keyFlags &= (~volatileKey);
					break;
				case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
					rsaObj->tcpaKey.authDataUsage = (BYTE) ulAttrib;
					rsaObj->usesAuth = (BOOL) ulAttrib;
					break;
				case TSS_TSPATTRIB_KEYINFO_ALGORITHM:
					rsaObj->tcpaKey.algorithmParms.algorithmID = ulAttrib;
					break;
				case TSS_TSPATTRIB_KEYINFO_ENCSCHEME:
					rsaObj->tcpaKey.algorithmParms.encScheme = (UINT16) ulAttrib;
					break;
				case TSS_TSPATTRIB_KEYINFO_SIGSCHEME:
					rsaObj->tcpaKey.algorithmParms.sigScheme = (UINT16) ulAttrib;
					break;

				default:
					return TSS_E_INVALID_ATTRIB_SUBFLAG;
			}

		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			/*if( subFlag == TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE )
			  {
			  UINT32ToArray( ulAttrib, rsaObj->tcpaKey.algorithmParms.parms );
			  }
			  else */ if (subFlag ==
					  TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
				  UINT32ToArray(ulAttrib, &rsaObj->tcpaKey.algorithmParms.parms[4]);
			  } else
				  return TSS_E_INVALID_ATTRIB_SUBFLAG;

		} else
			return TSS_E_INVALID_ATTRIB_FLAG;

		break;
	case TSS_OBJECT_TYPE_POLICY:
		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

		if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_HMAC) {
			if (ulAttrib == 0)
				return TSS_E_INVALID_ATTRIB_DATA;
			pObj->cb.Tspicb_CallbackHMACAuth = (TSS_RESULT (*)(
						PVOID,TSS_HOBJECT,
						TSS_BOOL,UINT32,
						TSS_BOOL,UINT32,
						BYTE *,BYTE *,
						BYTE *,BYTE *,
						UINT32,BYTE *,
						BYTE *))ulAttrib;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC) {
			if (ulAttrib == 0)
				return TSS_E_INVALID_ATTRIB_DATA;
			pObj->cb.Tspicb_CallbackXorEnc = (TSS_RESULT (*)(
						PVOID,TSS_HOBJECT,
						TSS_HOBJECT,TSS_FLAG,
						UINT32,BYTE *,
						BYTE *,BYTE *,
						BYTE *,UINT32,
						BYTE *,BYTE *))ulAttrib;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP) {
			if (ulAttrib == 0)
				return TSS_E_INVALID_ATTRIB_DATA;
			pObj->cb.Tspicb_CallbackTakeOwnership = (TSS_RESULT (*)(
						PVOID,TSS_HOBJECT,
						TSS_HKEY,UINT32,
						BYTE *))ulAttrib;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM) {
			if (ulAttrib == 0)
				return TSS_E_INVALID_ATTRIB_DATA;
			pObj->cb.Tspicb_CallbackChangeAuthAsym = (TSS_RESULT (*)(
						PVOID,TSS_HOBJECT,
						TSS_HKEY,UINT32,
						UINT32,BYTE *,
						BYTE *))ulAttrib;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_SECRET_LIFETIME) {
			if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
				pObj->p.SecretCounter = 0;
				pObj->p.SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS;
				pObj->p.SecretTimer = 0;
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
				pObj->p.SecretCounter = ulAttrib;
				pObj->p.SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER;
				pObj->p.SecretTimer = 0;
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
				time_t t = time(NULL);

				if (t == ((time_t)-1)) {
					LogError("time failed: %s", strerror(errno));
					return TSS_E_INTERNAL_ERROR;
				}
				/* for mode time, we'll use the SecretCounter variable to hold
				 * the number of seconds we're valid and the SecretTimer var to
				 * record the current timestamp. This should protect against
				 * overflows.
				 */
				pObj->p.SecretCounter = ulAttrib;
				pObj->p.SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER;
				pObj->p.SecretTimer = t;
			}
		} else
			return TSS_E_INVALID_ATTRIB_FLAG;

		break;
	case TSS_OBJECT_TYPE_CONTEXT:
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_SILENT_MODE)
			return TSS_E_INVALID_ATTRIB_FLAG;
		if (subFlag != 0)
			return TSS_E_INVALID_ATTRIB_SUBFLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		ctxObj = object->memPointer;

		if (ulAttrib == TSS_TSPATTRIB_CONTEXT_NOT_SILENT)
			ctxObj->silentMode = ulAttrib;
		else if (ulAttrib == TSS_TSPATTRIB_CONTEXT_SILENT) {
			if (anyPopupPolicies(hObject))
				return TSS_E_SILENT_CONTEXT;
			ctxObj->silentMode = ulAttrib;
		} else
			return TSS_E_INVALID_ATTRIB_DATA;

		break;
	default:
		return TSS_E_BAD_PARAMETER;
		break;
	}
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_GetAttribUint32(TSS_HOBJECT hObject,	/*  in */
		     TSS_FLAG attribFlag,	/*  in */
		     TSS_FLAG subFlag,	/*  in */
		     UINT32 * pulAttrib	/*  out */
    )
{
	AnObject *object = NULL;
	TCPA_CONTEXT_OBJECT *ctxObj;
	TCPA_RSAKEY_OBJECT *rsaObj;
	TSP_INTERNAL_POLICY_OBJECT *pObj;
	UINT32 attrib;

	if (pulAttrib == NULL)
		return TSS_E_BAD_PARAMETER;

	switch (getObjectTypeByHandle(hObject)) {
	case 0:
		return TSS_E_INVALID_HANDLE;
	case TSS_OBJECT_TYPE_RSAKEY:
		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INTERNAL_ERROR;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		rsaObj = object->memPointer;

		if (attribFlag == TSS_TSPATTRIB_KEY_REGISTER) {
			if (subFlag != 0)
				return TSS_E_INVALID_ATTRIB_SUBFLAG;

			if (rsaObj->persStorageType == TSS_PS_TYPE_USER)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_USER;
			else if (rsaObj->persStorageType == TSS_PS_TYPE_SYSTEM)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_SYSTEM;
			else if (rsaObj->persStorageType == TSS_PS_TYPE_NO)
				*pulAttrib = TSS_TSPATTRIB_KEYREGISTER_NO;
			else
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
			break;
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			switch (subFlag) {
				case TSS_TSPATTRIB_KEYINFO_USAGE:
					*pulAttrib = rsaObj->tcpaKey.keyUsage;
					break;
				case TSS_TSPATTRIB_KEYINFO_MIGRATABLE:
					*pulAttrib = rsaObj->tcpaKey.keyFlags & migratable ? TRUE : FALSE;
					break;
				case TSS_TSPATTRIB_KEYINFO_REDIRECTED:
					*pulAttrib = rsaObj->tcpaKey.keyFlags & redirection ? TRUE : FALSE;
					break;
				case TSS_TSPATTRIB_KEYINFO_VOLATILE:
					*pulAttrib = rsaObj->tcpaKey.keyFlags & volatileKey ? TRUE : FALSE;
					break;
				case TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE:
					*pulAttrib = rsaObj->tcpaKey.authDataUsage ? TRUE : FALSE;
					break;
				case TSS_TSPATTRIB_KEYINFO_ALGORITHM:
					*pulAttrib = rsaObj->tcpaKey.algorithmParms.algorithmID;
					break;
				case TSS_TSPATTRIB_KEYINFO_ENCSCHEME:
					*pulAttrib = rsaObj->tcpaKey.algorithmParms.encScheme;
					break;
				case TSS_TSPATTRIB_KEYINFO_SIGSCHEME:
					*pulAttrib = rsaObj->tcpaKey.algorithmParms.sigScheme;
					break;
				case TSS_TSPATTRIB_KEYINFO_KEYFLAGS:
					*pulAttrib = rsaObj->tcpaKey.keyFlags;
					break;
				case TSS_TSPATTRIB_KEYINFO_AUTHUSAGE:
					*pulAttrib = rsaObj->tcpaKey.authDataUsage;
					break;
				case TSS_TSPATTRIB_KEYINFO_SIZE:
					*pulAttrib = rsaObj->tcpaKey.pubKey.keyLength;
					break;

				default:
					return TSS_E_INVALID_ATTRIB_SUBFLAG;
			}

		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE) {
				attrib = (*(TCPA_RSA_KEY_PARMS *)(rsaObj->tcpaKey.algorithmParms.parms)).keyLength;
				*pulAttrib = endian32(attrib);
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
				attrib = (*(TCPA_RSA_KEY_PARMS *)(rsaObj->tcpaKey.algorithmParms.parms)).numPrimes;
				*pulAttrib = endian32(attrib);
			} else
				return TSS_E_INVALID_ATTRIB_SUBFLAG;

		} else
			return TSS_E_INVALID_ATTRIB_FLAG;

		break;
	case TSS_OBJECT_TYPE_POLICY:
		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}
		if (object->objectType != TSS_OBJECT_TYPE_POLICY)
			return TSS_E_BAD_PARAMETER;

		pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

		if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_HMAC) {
			*pulAttrib = (UINT32)pObj->cb.Tspicb_CallbackHMACAuth;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC) {
			*pulAttrib = (UINT32)pObj->cb.Tspicb_CallbackXorEnc;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP) {
			*pulAttrib = (UINT32)pObj->cb.Tspicb_CallbackTakeOwnership;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM) {
			*pulAttrib = (UINT32)pObj->cb.Tspicb_CallbackChangeAuthAsym;
		} else if (attribFlag == TSS_TSPATTRIB_POLICY_SECRET_LIFETIME) {
			if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
				if (pObj->p.SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS)
					*pulAttrib = TRUE;
				else
					*pulAttrib = FALSE;
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
				if (pObj->p.SecretLifetime != TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER)
					return TSS_E_BAD_PARAMETER;
				*pulAttrib = pObj->p.SecretCounter;
			} else if (subFlag == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
				int seconds_elapsed;
				time_t t = time(NULL);

				if (pObj->p.SecretLifetime != TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER)
					return TSS_E_BAD_PARAMETER;

				if (t == ((time_t)-1)) {
					LogError("time failed: %s", strerror(errno));
					return TSS_E_INTERNAL_ERROR;
				}
				/* curtime - SecretTimer is the number of seconds elapsed since we
				 * started the timer. SecretCounter is the number of seconds the
				 * secret is valid.  If seconds_elspased > SecretCounter, we've
				 * expired.
				 */
				seconds_elapsed = t - pObj->p.SecretTimer;
				if (seconds_elapsed >= pObj->p.SecretCounter) {
					*pulAttrib = 0;
				} else {
					*pulAttrib = pObj->p.SecretCounter - seconds_elapsed;
				}
			} else
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
		} else
			return TSS_E_INVALID_ATTRIB_FLAG;

		break;
	case TSS_OBJECT_TYPE_CONTEXT:
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_SILENT_MODE)
			return TSS_E_INVALID_ATTRIB_FLAG;
		if (subFlag != 0)
			return TSS_E_INVALID_ATTRIB_SUBFLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		ctxObj = (TCPA_CONTEXT_OBJECT *)object->memPointer;

		*pulAttrib = ctxObj->silentMode;

		break;
	default:
		return TSS_E_BAD_PARAMETER;
		break;
	}
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_SetAttribData(TSS_HOBJECT hObject,	/*  in */
		   TSS_FLAG attribFlag,	/*  in */
		   TSS_FLAG subFlag,	/*  in */
		   UINT32 ulAttribDataSize,	/*  in */
		   BYTE * rgbAttribData	/*  in */
    )
{
	AnObject *object = NULL;
	TCPA_RSAKEY_OBJECT *rsaObj = NULL;
	TCPA_ENCDATA_OBJECT *encDataObject = NULL;
	TCPA_POLICY_OBJECT *policyObject = NULL;
	UINT16 offset;
	UINT32 type;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	LogDebug1("Tspi_SetAttribData");

	type = getObjectTypeByHandle(hObject);
	switch (type) {
	case 0:
		LogDebug1("object type not found");
		return TSS_E_INVALID_HANDLE;
		break;
		/* -------------------------------       */
	case TSS_OBJECT_TYPE_RSAKEY:
		LogDebug1("TSS_OBJECT_TYPE_RSAKEY");
		if (attribFlag != TSS_TSPATTRIB_KEY_BLOB)
			return TSS_E_INVALID_ATTRIB_FLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		rsaObj = object->memPointer;
		if (rsaObj == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		if (subFlag == TSS_TSPATTRIB_KEYBLOB_BLOB) {
			LogDebug1("TSS_TSPATTRIB_KEYBLOB_BLOB");

			/* free any pointers held by the old key */
			destroy_key_refs(&rsaObj->tcpaKey);

			offset = 0;
			UnloadBlob_KEY(0, &offset, rgbAttribData, &rsaObj->tcpaKey);
#if 0
			/* don't do this, since the key object would already be hosed anyway */
			if (offset != ulAttribDataSize)	/* just checking */
				return TSS_E_BAD_PARAMETER;
#endif

			rsaObj->usesAuth = rsaObj->tcpaKey.authDataUsage;
		} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
			LogDebug1("TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY");
			offset = 0;
			if ((result = UnloadBlob_KEY_PARMS(0, &offset, rgbAttribData, &rsaObj->tcpaKey.algorithmParms)))
				return result;
			if ((result = UnloadBlob_STORE_PUBKEY(0, &offset, rgbAttribData, &rsaObj->tcpaKey.pubKey)))
				return result;
			if (offset != ulAttribDataSize) {
				LogError("Attribute data size doesn't match public key size (%d)", offset);
				return TSS_E_INTERNAL_ERROR;
			}
			/* ---  Need to add stuff to free old key components */
		} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
			LogDebug1("TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY");
			if ((result = internal_CheckContext_1(hObject, &tcsContext)))
				return result;
#if 0
			/* why was this Decode_UINT32() in here? -KEY */
			rsaObj->privateKey.Privlen = Decode_UINT32(rgbAttribData);
#else
			rsaObj->privateKey.Privlen = ulAttribDataSize;
#endif
			if (rsaObj->privateKey.Privkey != NULL)
				free_tspi(tcsContext, rsaObj->privateKey.Privkey);

			rsaObj->privateKey.Privkey = calloc_tspi(tcsContext, rsaObj->privateKey.Privlen);
			if (rsaObj->privateKey.Privkey == NULL) {
				LogError("malloc of %d bytes failed.", rsaObj->privateKey.Privlen);
				return TSS_E_OUTOFMEMORY;
			}
			memcpy(rsaObj->privateKey.Privkey, rgbAttribData, rsaObj->privateKey.Privlen);
		} else {
			LogDebug1("TSS_E_INVALID_ATTRIB_SUBFLAG");
			return TSS_E_INVALID_ATTRIB_SUBFLAG;
		}
		break;
	case TSS_OBJECT_TYPE_ENCDATA:
		LogDebug1("TSS_OBJECT_TYPE_ENCDATA");

		if (attribFlag != TSS_TSPATTRIB_ENCDATA_BLOB)
			return TSS_E_INVALID_ATTRIB_FLAG;
		if (subFlag != TSS_TSPATTRIB_ENCDATABLOB_BLOB)
			return TSS_E_INVALID_ATTRIB_SUBFLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		encDataObject = object->memPointer;
		if (encDataObject == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		encDataObject->encryptedDataLength = ulAttribDataSize;
		memcpy(encDataObject->encryptedData, rgbAttribData, ulAttribDataSize);

		break;
	case TSS_OBJECT_TYPE_POLICY:
		LogDebug1("TSS_OBJECT_TYPE_POLICY");

		if (attribFlag != TSS_TSPATTRIB_POLICY_POPUPSTRING)
			return TSS_E_INVALID_ATTRIB_FLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		policyObject = object->memPointer;
		if (policyObject == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		/* check to see if the passed in data can fit in our UNICODE array */
		if ((ulAttribDataSize/sizeof(UNICODE)) >= UI_MAX_POPUP_STRING_LENGTH)
			return TSS_E_BAD_PARAMETER;

		policyObject->popupStringLength = ulAttribDataSize / sizeof(UNICODE);
		wcsncpy(policyObject->popupString, (UNICODE *)rgbAttribData, policyObject->popupStringLength);
		break;
	default:
		return TSS_E_BAD_PARAMETER;
		break;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_GetAttribData(TSS_HOBJECT hObject,	/*  in */
		   TSS_FLAG attribFlag,	/*  in */
		   TSS_FLAG subFlag,	/*  in */
		   UINT32 * pulAttribDataSize,	/*  out  */
		   BYTE ** prgbAttribData	/*  out */
    )
{
	UINT16 offset = 0xffff;
	AnObject *object = NULL;
	TCPA_RSAKEY_OBJECT *rsaObj;
	TCPA_ENCDATA_OBJECT *encDataObj;
	TCPA_CONTEXT_OBJECT *ctxObj;
	TSP_INTERNAL_POLICY_OBJECT *pObj;
	BYTE tempBuf[1024];
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size;

	if (pulAttribDataSize == NULL || prgbAttribData == NULL)
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_GetAttribData");

	if ((result = internal_CheckContext_1(hObject, &hContext)))
		return result;

	switch (getObjectTypeByHandle(hObject)) {
	case 0:
		LogDebug1("Invalid object");
		return TSS_E_INVALID_HANDLE;
	case TSS_OBJECT_TYPE_RSAKEY:
		LogDebug1("Object type RSAKEY");

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}
		rsaObj = object->memPointer;

		if (attribFlag == TSS_TSPATTRIB_KEY_BLOB) {
			LogDebug1("TSS_TSPATTRIB_KEY_BLOB");
			if (subFlag == TSS_TSPATTRIB_KEYBLOB_BLOB) {
				LogDebug1("TSS_TSPATTRIB_KEYBLOB_BLOB");
				offset = 0;
				LoadBlob_KEY(&offset, tempBuf, &rsaObj->tcpaKey);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
				offset = rsaObj->privateKey.Privlen;
				memcpy(tempBuf, rsaObj->privateKey.Privkey, offset);
			} else if (subFlag == TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
				offset = rsaObj->tcpaKey.pubKey.keyLength;
				memcpy(tempBuf, rsaObj->tcpaKey.pubKey.key, offset);
			} else {
				LogDebug1("invalid subflag");
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
			}
		} else if (attribFlag == TSS_TSPATTRIB_KEY_INFO) {
			LogDebug1("TSS_TSPATTRIB_KEY_INFO");
			if (subFlag != TSS_TSPATTRIB_KEYINFO_VERSION)
				return TSS_E_INVALID_ATTRIB_SUBFLAG;

			offset = 0;
			LoadBlob_TCPA_VERSION(&offset, tempBuf, rsaObj->tcpaKey.ver);
		} else if (attribFlag == TSS_TSPATTRIB_RSAKEY_INFO) {
			LogDebug1("TSS_TSPATTRIB_RSAKEY_INFO");
			if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) {
				offset = (*(TCPA_RSA_KEY_PARMS *)
						(rsaObj->tcpaKey.algorithmParms.parms)).exponentSize;
			} else if (subFlag == TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) {
				offset = rsaObj->tcpaKey.pubKey.keyLength;
			} else
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
		} else if (attribFlag == TSS_TSPATTRIB_KEY_UUID) {
			LogDebug1("TSS_TSPATTRIB_KEY_UUID");
			if (subFlag != 0)
				return TSS_E_INVALID_ATTRIB_SUBFLAG;

			offset = 0;
			LoadBlob_UUID(&offset, tempBuf, rsaObj->uuid);
		} else if (attribFlag == TSS_TSPATTRIB_KEY_PCR) {
			LogDebug1("TSS_TSPATTRIB_KEY_PCR");
			if (subFlag == TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION) {
				return TSS_E_NOTIMPL;
			} else if (subFlag == TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE) {
				return TSS_E_NOTIMPL;
			} else if (subFlag == TSS_TSPATTRIB_KEYPCR_SELECTION) {
				return TSS_E_NOTIMPL;
			} else
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
		} else
			return TSS_E_INVALID_ATTRIB_FLAG;

		if (offset == 0)
			return TSS_E_INVALID_ATTRIB_DATA;

		*pulAttribDataSize = offset;
		*prgbAttribData = calloc_tspi(hContext, offset);
		if (*prgbAttribData == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			return TSS_E_OUTOFMEMORY;
		}
		memcpy(*prgbAttribData, tempBuf, offset);

		break;
		/* ---------------------------------------------------------------------------- */
	case TSS_OBJECT_TYPE_ENCDATA:
		LogDebug1("TSS_OBJECT_TYPE_ENCDATA");
		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}
		encDataObj = (TCPA_ENCDATA_OBJECT *)object->memPointer;
		/* ------------------------------------ */
		if (attribFlag == TSS_TSPATTRIB_ENCDATA_BLOB) {
			LogDebug1("TSS_TSPATTRIB_ENCDATA_BLOB");
			if (subFlag != TSS_TSPATTRIB_ENCDATABLOB_BLOB)
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
			*pulAttribDataSize = encDataObj->encryptedDataLength;
			*prgbAttribData = calloc_tspi(hContext, *pulAttribDataSize);
			if (*prgbAttribData == NULL) {
				LogError("malloc of %d bytes failed.", *pulAttribDataSize);
				return TSS_E_OUTOFMEMORY;
			}
			memcpy(*prgbAttribData, encDataObj->encryptedData, *pulAttribDataSize);

		} else if (attribFlag == TSS_TSPATTRIB_ENCDATA_PCR) {
			LogDebug1("TSS_TSPATTRIB_ENCDATA_PCR");
			if (encDataObj->usePCRs == 0)
				return TSS_E_BAD_PARAMETER;
			if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION) {
				*pulAttribDataSize = 20;
				*prgbAttribData = calloc_tspi(hContext, *pulAttribDataSize);
				if (*prgbAttribData == NULL) {
					LogError("malloc of %d bytes failed.", *pulAttribDataSize);
					return TSS_E_OUTOFMEMORY;
				}
				memcpy(*prgbAttribData, encDataObj->pcrInfo.digestAtCreation.digest, 20);
			}
#if 0
			else if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATRELEASE) {
				*pulAttribDataSize = 20;
				*prgbAttribData = calloc_tspi(hContext, *pulAttribDataSize);
				if (*prgbAttribData == NULL) {
					LogError("malloc of %d bytes failed.", *pulAttribDataSize);
					return TSS_E_OUTOFMEMORY;
				}
				memcpy(*prgbAttribData,	encDataObj->pcrInfo.digestAtRelease.digest, 20);
			} else if (subFlag == TSS_TSPATTRIB_ENCDATAPCR_SELECTION) {
				offset = 0;
				LoadBlob_PCR_SELECTION(&offset, tempBuf, encDataObj->pcrInfo.pcrSelection);
				*pulAttribDataSize = offset;
				*prgbAttribData = calloc_tspi(hContext, *pulAttribDataSize);
				if (*prgbAttribData == NULL) {
					LogError("malloc of %d bytes failed.", *pulAttribDataSize);
					return TSS_E_OUTOFMEMORY;
				}
				memcpy(*prgbAttribData, tempBuf, *pulAttribDataSize);
			}
#endif
			else
				return TSS_E_INVALID_ATTRIB_SUBFLAG;
		} else
			return TSS_E_INVALID_ATTRIB_FLAG;

		break;
		/* ---------------------------------------------------------------------------- */
	case TSS_OBJECT_TYPE_CONTEXT:
		LogDebug1("TSS_OBJECT_TYPE_CONTEXT");
		if (attribFlag != TSS_TSPATTRIB_CONTEXT_MACHINE_NAME)
			return TSS_E_INVALID_ATTRIB_FLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;

		if (object->memPointer == NULL) {
			LogError("internal context object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}
		ctxObj = object->memPointer;

		/* allocate the number of bytes, not UNICODE characters */
		*pulAttribDataSize = (ctxObj->machineNameLength + 1) * sizeof(UNICODE);
		*prgbAttribData = calloc_tspi(hContext, *pulAttribDataSize);
		if (*prgbAttribData == NULL) {
			LogError("malloc of %d bytes failed.", *pulAttribDataSize);
			return TSS_E_OUTOFMEMORY;
		}
		/* return the UNICODE string and the number of _bytes_ in it, not the
		 * number of UNICODE characters in it.
		 */
		wcsncpy((UNICODE *)*prgbAttribData, ctxObj->machineName, ctxObj->machineNameLength);
		break;
	case TSS_OBJECT_TYPE_POLICY:
		if (attribFlag != TSS_TSPATTRIB_POLICY_POPUPSTRING)
			return TSS_E_INVALID_ATTRIB_FLAG;

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;

		if (object->memPointer == NULL) {
			LogError("internal policy object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}
		pObj = object->memPointer;

		size = MIN(UI_MAX_POPUP_STRING_LENGTH, (pObj->p.popupStringLength + 1)) * sizeof(UNICODE);

		if (pObj->p.popupStringLength > 0) {
			*prgbAttribData = calloc_tspi(hContext, size);
			if (*prgbAttribData == NULL) {
				LogError("malloc of %d bytes failed.", size);
				return TSS_E_OUTOFMEMORY;
			}

			memcpy(*prgbAttribData, pObj->p.popupString, size);
			*pulAttribDataSize = size;
		} else {
			*prgbAttribData = NULL;
			*pulAttribDataSize = 0;
		}
		break;
	default:
		return TSS_E_BAD_PARAMETER;
		break;
	}
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_GetPolicyObject(TSS_HOBJECT hObject,	/*  in */
		     TSS_FLAG policyType,	/*  in */
		     TSS_HPOLICY * phPolicy	/*  out */
    )
{
	AnObject *object = NULL;
	TCPA_RSAKEY_OBJECT *rsaObj;
	TCPA_TPM_OBJECT *tpmObj;
	TCPA_CONTEXT_OBJECT *ctxObj;
	TCPA_ENCDATA_OBJECT *encDataObj;

	if (phPolicy == NULL)
		return TSS_E_BAD_PARAMETER;

	switch (getObjectTypeByHandle(hObject)) {
	case 0:
		return TSS_E_INVALID_HANDLE;
		break;
	case TSS_OBJECT_TYPE_RSAKEY:
		object = getAnObjectByHandle(hObject);
		if (object == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		rsaObj = object->memPointer;
		if (policyType == TSS_POLICY_USAGE)
			*phPolicy = rsaObj->usagePolicy;
		else if (policyType == TSS_POLICY_MIGRATION)
			*phPolicy = rsaObj->migPolicy;
		else
			return TSS_E_BAD_PARAMETER;
		break;
	case TSS_OBJECT_TYPE_TPM:
		object = getAnObjectByHandle(hObject);
		if (object == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		tpmObj = object->memPointer;
		*phPolicy = tpmObj->policy;
		break;
	case TSS_OBJECT_TYPE_CONTEXT:
		object = getAnObjectByHandle(hObject);
		if (object == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		ctxObj = object->memPointer;
		*phPolicy = ctxObj->policy;
		break;
	case TSS_OBJECT_TYPE_ENCDATA:
		object = getAnObjectByHandle(hObject);
		if (object == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		encDataObj = object->memPointer;
		if (policyType == TSS_POLICY_USAGE)
			*phPolicy = encDataObj->usagePolicy;
		else if (policyType == TSS_POLICY_MIGRATION)
			*phPolicy = encDataObj->migPolicy;
		else
			return TSS_E_BAD_PARAMETER;
		break;
	default:
		return TSS_E_BAD_PARAMETER;
		break;
	}
	return TSS_SUCCESS;
}

