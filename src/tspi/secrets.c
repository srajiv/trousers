
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
#include "obj.h"

extern AnObject *objectList;

/*
 *  popup_GetSecret()
 *
 *    newPIN - non-zero to popup the dialog to enter a new PIN, zero to popup a dialog
 *      to enter an existing PIN
 *    popup_str - string to appear in the title bar of the popup dialog
 *    auth_hash - the 20+ byte buffer that receives the SHA1 hash of the auth data
 *      entered into the dialog box
 *
 */
TSS_RESULT
popup_GetSecret(UINT32 new_pin, UNICODE *popup_str, void *auth_hash)
{
	char secret[UI_MAX_SECRET_STRING_LENGTH] = "\0";
	UNICODE w_popup[UI_MAX_POPUP_STRING_LENGTH];
	const char *dflt = "TSS Authentication Dialog";
	mbstate_t ps;

	memset(&ps, 0, sizeof(mbstate_t));

	if (popup_str == NULL)
		mbsrtowcs(w_popup, &dflt, UI_MAX_POPUP_STRING_LENGTH, &ps);
	else
		wcsncpy(w_popup, popup_str, wcslen(popup_str));

	/* pin the area where the secret will be put in memory */
	if (pin_mem(&secret, UI_MAX_SECRET_STRING_LENGTH)) {
		LogError1("Failed to pin secret in memory.");
		return TSS_E_INTERNAL_ERROR;
	}

	if (new_pin) {
		if (DisplayNewPINWindow(secret, w_popup))
			return TSS_E_INTERNAL_ERROR;
	} else if (DisplayPINWindow(secret, w_popup))
		return TSS_E_INTERNAL_ERROR;

	/* allow a 0 length password here, as spec'd by the TSSWG */
	TSS_Hash(TSS_HASH_SHA1, strlen(secret), secret, (char *)auth_hash);

	/* zero, then unpin the memory */
	memset(&secret, 0, UI_MAX_SECRET_STRING_LENGTH);
	unpin_mem(&secret, UI_MAX_SECRET_STRING_LENGTH);

	return TSS_SUCCESS;
}

TSS_RESULT
policy_UsesAuth(TSS_HPOLICY hPolicy, BOOL * ret)
{
	/******************
	 *	An important thing to remember is that although a
	 *	storage key might say authDataUsage = 0, it may have a
	 *	usage policy with it.  We have found this to be the case
	 *	for things like createKey.  For this reason, if it is a keyObject,
	 *	we must check the bit in the object rather than the policy itself.
	 *
	 *	This is really only useful for Key Objects and only for the usage auth
	 *	so that limits both our usage in the TSP including this function.
	 *
	 *	A weird case to condider is if secret_TakeOwnership calls this funct..
	 *	must return TRUE for the owner auth;
	 ***********************/

	/*
	 * This function should only be called on objects that it makes sense
	 * to use auth on (TPM, Key, Encrypted Data), since the default is TRUE.
	 */

	AnObject *index;

	LogDebug1("Checking if policy uses auth");
	for (index = (AnObject *) objectList; index; next(index)) {
		if (index->objectType == TSS_OBJECT_TYPE_RSAKEY && index->memPointer != NULL) {
			if (((TCPA_RSAKEY_OBJECT *) index->memPointer)->usagePolicy == hPolicy) {
				LogDebug1("Found policy object");
				*ret = ((TCPA_RSAKEY_OBJECT *) index->memPointer)->usesAuth;
				LogDebug("Policy uses auth = 0x%.2X", *ret);
				return TSS_SUCCESS;
			}
		} else if (index->objectType == TSS_OBJECT_TYPE_TPM &&
				((TCPA_TPM_OBJECT *)index->memPointer)->policy == hPolicy) {
			break;
		}
	}
	*ret = TRUE;
	return TSS_SUCCESS;
}

TSS_RESULT
secret_HasSecretExpired(TCPA_POLICY_OBJECT *policyObject, BOOL *answer)
{
	LogDebug1("Has Secret Expired");
	if (policyObject->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
		*answer = FALSE;
	} else if (policyObject->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
		if (policyObject->SecretCounter == 0)
			*answer = TRUE;
		else
			*answer = FALSE;
	} else if (policyObject->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
		int seconds_elapsed;
		time_t t = time(NULL);

		if (t == ((time_t)-1)) {
			LogError("time failed: %s", strerror(errno));
			return TSS_E_INTERNAL_ERROR;
		}
		/* curtime - SecretTimer is the number of seconds elapsed since we
		 * started the timer. SecretCounter is the number of seconds the
		 * secret is valid.  If seconds_elspased > SecretCounter, we've
		 * expired.
		 */
		seconds_elapsed = t - policyObject->SecretTimer;
		if (seconds_elapsed >= policyObject->SecretCounter) {
			*answer = TRUE;
		} else {
			*answer = FALSE;
		}
	} else {
		LogError1("Policy's Secret mode is not set!");
		return TSS_E_INVALID_OBJ_ACCESS;
	}

	LogDebug("has expired = 0x%.2X", *answer);
	return TSS_SUCCESS;
}

void
secret_DecSecretCounter(TCPA_POLICY_OBJECT * policy)
{
	if (policy->SecretLifetime != TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER)
		return;
	--policy->SecretCounter;
}

TSS_RESULT
secret_PerformAuth_OIAP(TSS_HPOLICY hPolicy, TCPA_DIGEST hashDigest, TCS_AUTH * auth)
{
	TSS_RESULT result;
	TCPA_SECRET secret;

	TCS_CONTEXT_HANDLE tcsContext;
	TSP_INTERNAL_POLICY_OBJECT *policyObject;
	AnObject *object;
	BOOL bExpired;
	BOOL useAuth;

	LogDebug1("PerformAuth OIAP");

	object = getAnObjectByHandle(hPolicy);
	if (object == NULL || object->memPointer == NULL) {
		LogDebug1("problem with policy object");
		return TSS_E_INVALID_HANDLE;
	}
	if (object->objectType != TSS_OBJECT_TYPE_POLICY) {
		LogDebug1("Not a policy Object");
		return TSS_E_INVALID_HANDLE;
	}

	policyObject = object->memPointer;

	if ((result = policy_UsesAuth(hPolicy, &useAuth)))
		return result;

	if (useAuth == FALSE) {
		LogDebug1("nothing to do, doesn't use auth");
		return TSS_SUCCESS;
	}

	tcsContext = obj_getTcsContext(hPolicy);
	if (tcsContext == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	/* ---  This validates that the secret can be used */
	if ((result = secret_HasSecretExpired(&policyObject->p, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSS_E_INVALID_OBJ_ACCESS;

	/* ---  OIAP */
	if ((result = Init_AuthNonce(tcsContext, auth)))
		return result;

	/* added retry logic */
	if ((result = TCSP_OIAP(tcsContext, &auth->AuthHandle, &auth->NonceEven))) {
		if (result == TCPA_RESOURCES) {
			int retry = 0;
			do {
				/* POSIX sleep time, { secs, nanosecs } */
				struct timespec t = { 0, AUTH_RETRY_NANOSECS };

				nanosleep(&t, NULL);

				result = TCSP_OIAP(tcsContext, &auth->AuthHandle, &auth->NonceEven);
			} while (result == TCPA_RESOURCES && ++retry < AUTH_RETRY_COUNT);
		}

		if (result)
			return result;
	}

	switch (policyObject->p.SecretMode) {
	case TSS_SECRET_MODE_CALLBACK:
		result = policyObject->cb.Tspicb_CallbackHMACAuth(NULL, hPolicy,	/* for now */
					  1,
					  auth->fContinueAuthSession,
					  FALSE,
					  20,
					  auth->NonceEven.nonce,
					  auth->NonceOdd.nonce,
					  NULL, NULL, 20, hashDigest.digest, auth->HMAC);
		break;
	case TSS_SECRET_MODE_SHA1:
	case TSS_SECRET_MODE_PLAIN:
		LogDebug1("TSP has secret");
		if ((result = internal_GetSecret(hPolicy, &secret, TRUE)))
			break;

		HMAC_Auth(secret.secret,	/* policyObject->Secret,  */
			  hashDigest.digest, auth);
		break;

	case TSS_SECRET_MODE_POPUP:
		LogDebug1("Popup policy");
		if ((result = popup_GetSecret(FALSE, policyObject->p.popupString, &secret)))
			break;

		HMAC_Auth(secret.secret,	/* policyObject->Secret,  */
			  hashDigest.digest, auth);
		break;

	default:
		result = TSS_E_POLICY_NO_SECRET;
		break;
	}

	if (result) {
		TCSP_TerminateHandle(tcsContext, auth->AuthHandle);
		return result;
	}

	secret_DecSecretCounter(&policyObject->p);
	return TSS_SUCCESS;
}

TSS_RESULT
secret_ValidateAuth_OIAP(TSS_HPOLICY hPolicy, TCPA_DIGEST hashDigest, TCS_AUTH * auth)
{
	TSS_RESULT result;
	TCPA_SECRET secret;
	TSP_INTERNAL_POLICY_OBJECT *policyObject;
	AnObject *object;
	BOOL useAuth;

	object = getAnObjectByHandle(hPolicy);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->memPointer == NULL) {
		LogError("mem pointer for policy object 0x%x is NULL", hPolicy);
		return TSS_E_INTERNAL_ERROR;
	}
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	policyObject = object->memPointer;

	if ((result = policy_UsesAuth(hPolicy, &useAuth)))
		return result;

	if (useAuth == FALSE)
		return 0;

	switch (policyObject->p.SecretMode) {
	case TSS_SECRET_MODE_CALLBACK:
		if ((result = policyObject->cb.Tspicb_CallbackHMACAuth(NULL, hPolicy,	/* for now */
					      0,
					      auth->fContinueAuthSession,
					      FALSE,
					      20,
					      auth->NonceEven.nonce,
					      auth->NonceOdd.nonce,
					      NULL, NULL, 20, hashDigest.digest, auth->HMAC)))
			return result;
		break;
	case TSS_SECRET_MODE_SHA1:
	case TSS_SECRET_MODE_PLAIN:
		if ((result = internal_GetSecret(hPolicy, &secret, FALSE)))
			return result;

		if (validateReturnAuth(secret.secret, hashDigest.digest, auth))
			return TSS_E_TSP_AUTHFAIL;
		break;
	case TSS_SECRET_MODE_POPUP:
		if ((result = popup_GetSecret(FALSE, policyObject->p.popupString, &secret)))
			return result;

		if (validateReturnAuth(secret.secret, hashDigest.digest, auth))
			return TSS_E_TSP_AUTHFAIL;
		break;
	default:
		return TSS_E_POLICY_NO_SECRET;
		break;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
secret_PerformXOR_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
		       TSS_HPOLICY hMigrationPolicy, TSS_HOBJECT hKey,
		       UINT16 osapType, UINT32 osapData,
		       TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig,
		       BYTE sharedSecret[20], TCS_AUTH * auth, TCPA_NONCE * nonceEvenOSAP)
{
	TSP_INTERNAL_POLICY_OBJECT *keyPolicyObject;
/* 	TCPA_POLICY_OBJECT* encPolicyObject; */
	TSP_INTERNAL_POLICY_OBJECT *usagePolicyObject;
	TSP_INTERNAL_POLICY_OBJECT *migPolicyObject;
	AnObject *object;
	BOOL bExpired;
/* 	BOOL usesUsageAuth; */

	TSS_RESULT result;
	TCPA_SECRET keySecret;
/* 	TCPA_SECRET encSecret; */
	TCPA_SECRET usageSecret;
	TCPA_SECRET migSecret;
	TCS_CONTEXT_HANDLE tcsContext = obj_getTcsContext(hPolicy);

	if (tcsContext == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	object = getAnObjectByHandle(hPolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	keyPolicyObject = object->memPointer;

	object = getAnObjectByHandle(hUsagePolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	usagePolicyObject = object->memPointer;

/* 	if( result = policy_UsesAuth( hUsagePolicy, &usesUsageAuth )) */
/* 		return result; */

	object = getAnObjectByHandle(hMigrationPolicy);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	migPolicyObject = object->memPointer;

	/* This validates that the secret can be used */
	if ((result = secret_HasSecretExpired(&keyPolicyObject->p, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSS_E_INVALID_OBJ_ACCESS;

	/* check the usage policy secret */
	if ((result = secret_HasSecretExpired(&usagePolicyObject->p, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSS_E_INVALID_OBJ_ACCESS;

	/* check the migration policy secret */
	if ((result = secret_HasSecretExpired(&migPolicyObject->p, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSS_E_INVALID_OBJ_ACCESS;

	/* ---   */

	/* ---  If any of them is a callback */
	if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK ||
	    usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK ||
	    migPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK) {
		/* ---  And they're not all callback */
		if (keyPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK ||
		    usagePolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK ||
		    migPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK)
			return TSS_E_BAD_PARAMETER;	/* error...they should all be callback if one is callback */

	}
/* 		encPolicyObject->SecretMode != TSS_SECRET_MODE_CALLBACK ) */

	if (keyPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK) {

		if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_PLAIN ||
		    keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_SHA1 ||
		    keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_NONE) {
			if ((result = internal_GetSecret(hPolicy, &keySecret, 1)))
				return result;
		} else if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_POPUP) {
			if ((result = popup_GetSecret(hPolicy, keyPolicyObject->p.popupString, &keySecret.secret)))
				return result;
		} else {
			LogError1("Key Policy's Secret mode is not set.");
			return TSS_E_POLICY_NO_SECRET;
		}

		if (usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_PLAIN ||
		    usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_SHA1 ||
		    usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_NONE) {
			if ((result = internal_GetSecret(hUsagePolicy, &usageSecret, 1)))
				return result;
		} else if (usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_POPUP) {
			if ((result = popup_GetSecret(hUsagePolicy, usagePolicyObject->p.popupString,
						&usageSecret.secret)))
				return result;
		} else {
			LogError1("Key Policy's Secret mode is not set.");
			return TSS_E_POLICY_NO_SECRET;
		}

		if (migPolicyObject->p.SecretMode == TSS_SECRET_MODE_PLAIN ||
		    migPolicyObject->p.SecretMode == TSS_SECRET_MODE_SHA1 ||
		    migPolicyObject->p.SecretMode == TSS_SECRET_MODE_NONE) {
			if ((result = internal_GetSecret(hMigrationPolicy, &migSecret, 1)))
				return result;
		} else if (migPolicyObject->p.SecretMode == TSS_SECRET_MODE_POPUP) {
			if ((result = popup_GetSecret(hMigrationPolicy, migPolicyObject->p.popupString,
						&migSecret.secret)))
				return result;
		} else {
			LogError1("Key Policy's Secret mode is not set.");
			return TSS_E_POLICY_NO_SECRET;
		}

		if ((result = OSAP_Calc(tcsContext, osapType, osapData, keySecret.secret,	/* wrap policy- usage */
				       usageSecret.secret,	/* encSecret.secret,    //key policy - usage */
				       migSecret.secret,	/* encSecret.secret,    //key policy - migration */
				       encAuthUsage, encAuthMig, sharedSecret, auth)))
			return result;
	} else if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK) {
		/* call osap here */
		if ((result = TCSP_OSAP(tcsContext, osapType, osapData, auth->NonceOdd,
				  &auth->AuthHandle, &auth->NonceEven, nonceEvenOSAP)))
			return result;

		if ((result = keyPolicyObject->cb.Tspicb_CallbackXorEnc(NULL, 0,	/* hEncPolicy,       //????? */
					    hKey,	/* object ????? */
					    0,	/* pupose secret ???? */
					    20,
					    auth->NonceEven.nonce,
					    NULL,
					    nonceEvenOSAP->nonce,
					    auth->NonceOdd.nonce,
					    20, encAuthUsage->encauth, encAuthMig->encauth)))
			return result;
	} else
		return TSS_E_POLICY_NO_SECRET;

	return 0;
}

TSS_RESULT
secret_PerformAuth_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
			TSS_HPOLICY hMigPolicy, TSS_HOBJECT hKey,
			BYTE sharedSecret[20], TCS_AUTH * auth,
			BYTE * hashDigest, TCPA_NONCE nonceEvenOSAP)
{
	TSP_INTERNAL_POLICY_OBJECT *keyPolicyObject;
	TSP_INTERNAL_POLICY_OBJECT *usagePolicyObject;
	TSP_INTERNAL_POLICY_OBJECT *migPolicyObject;

	AnObject *object;

	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext = obj_getTcsContext(hPolicy);

	if (tcsContext == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	object = getAnObjectByHandle(hPolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	keyPolicyObject = object->memPointer;

	object = getAnObjectByHandle(hUsagePolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	usagePolicyObject = object->memPointer;

	object = getAnObjectByHandle(hMigPolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	migPolicyObject = object->memPointer;

	/* ---  If any of them is a callback */
	if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK ||
	    usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK ||
	    migPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK) {
		/* ---  And they're not all callback */
		if (keyPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK ||
		    usagePolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK ||
		    migPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK)
			return TSS_E_BAD_PARAMETER;	/* error...they should all be callback if one is callback */

	}
/* 	if( keyPolicyObject->SecretMode == TSS_SECRET_MODE_CALLBACK && */
/* 		encPolicyObject->SecretMode != TSS_SECRET_MODE_CALLBACK ) */
/* 		return  TSS_E_BAD_PARAMETER ;		//error...they should both be callback if one is callback */

	if (keyPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK) {
#if 0
		if (keyPolicyObject->SecretMode == TSS_SECRET_MODE_PLAIN ||
		    keyPolicyObject->SecretMode == TSS_SECRET_MODE_SHA1) {
			if (result = internal_GetSecret(hPolicy, &keySecret, 1))
				return result;
		} else if (keyPolicyObject->SecretMode == TSS_SECRET_MODE_POPUP) {
			if (result = popup_GetSecret(hPolicy, &keySecret.secret))
				return result;
		} else
			return 0x99;	/* not yet */

		if (encPolicyObject->SecretMode == TSS_SECRET_MODE_PLAIN ||
		    encPolicyObject->SecretMode == TSS_SECRET_MODE_SHA1) {
			if (result = internal_GetSecret(hEncPolicy, &encSecret, 1))
				return result;
		} else if (encPolicyObject->SecretMode == TSS_SECRET_MODE_POPUP) {
			if (result = popup_GetSecret(hEncPolicy, &encSecret.secret))
				return result;
		} else
			return 0x99;	/* not yet */
#endif
		HMAC_Auth(sharedSecret, hashDigest, auth);
	} else if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK) {
		if ((result = keyPolicyObject->cb.Tspicb_CallbackHMACAuth(NULL, hPolicy,	/* for now */
					      1,	/* not verify    */
					      auth->fContinueAuthSession,
					      TRUE,
					      20,
					      auth->NonceEven.nonce,
					      NULL,
					      nonceEvenOSAP.nonce,
					      auth->NonceOdd.nonce, 20, hashDigest, auth->HMAC)))
			return result;
	} else
		return TSS_E_POLICY_NO_SECRET;

	secret_DecSecretCounter(&keyPolicyObject->p);
	secret_DecSecretCounter(&usagePolicyObject->p);
	secret_DecSecretCounter(&migPolicyObject->p);
	return 0;
}

TSS_RESULT
secret_ValidateAuth_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
			 TSS_HPOLICY hMigPolicy, BYTE sharedSecret[20],
			 TCS_AUTH * auth, BYTE * hashDigest, TCPA_NONCE nonceEvenOSAP)
{
	TSP_INTERNAL_POLICY_OBJECT *keyPolicyObject;
	TSP_INTERNAL_POLICY_OBJECT *usagePolicyObject;
	TSP_INTERNAL_POLICY_OBJECT *migPolicyObject;
	AnObject *object;

	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext = obj_getTcsContext(hPolicy);

	if (tcsContext == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	object = getAnObjectByHandle(hPolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	keyPolicyObject = object->memPointer;

	object = getAnObjectByHandle(hUsagePolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	usagePolicyObject = object->memPointer;

	object = getAnObjectByHandle(hMigPolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;
	if (object->objectType != TSS_OBJECT_TYPE_POLICY)
		return TSS_E_INVALID_HANDLE;

	migPolicyObject = object->memPointer;

	/* ---  If any of them is a callback */
	if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK ||
	    usagePolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK ||
	    migPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK) {
		/* ---  And they're not all callback */
		if (keyPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK ||
		    usagePolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK ||
		    migPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK)
			return TSS_E_BAD_PARAMETER;	/* error...they should all be callback if one is callback */

	}
/* 	if( keyPolicyObject->SecretMode == TSS_SECRET_MODE_CALLBACK && */
/* 		encPolicyObject->SecretMode != TSS_SECRET_MODE_CALLBACK ) */
/* 		return  TSS_E_BAD_PARAMETER ;		//error...they should both be callback if one is callback */

	if (keyPolicyObject->p.SecretMode != TSS_SECRET_MODE_CALLBACK) {
		if (validateReturnAuth(sharedSecret, hashDigest, auth))
			return TSS_E_TSP_AUTHFAIL;
	} else if (keyPolicyObject->p.SecretMode == TSS_SECRET_MODE_CALLBACK) {
		if ((result = keyPolicyObject->cb.Tspicb_CallbackHMACAuth(NULL, hPolicy,	/* for now */
					      0,
					      auth->fContinueAuthSession,
					      TRUE,
					      20,
					      auth->NonceEven.nonce,
					      NULL,
					      nonceEvenOSAP.nonce,
					      auth->NonceOdd.nonce, 20, hashDigest, auth->HMAC)))
			return result;
	} else
		return TSS_E_POLICY_NO_SECRET;

	return TSS_SUCCESS;
}

TSS_RESULT
secret_TakeOwnership(TSS_HKEY hEndorsementPubKey,
		     TSS_HTPM hTPM,
		     TSS_HKEY hKeySRK,
		     TCS_AUTH * auth,
		     UINT32 * encOwnerAuthLength,
		     BYTE * encOwnerAuth, UINT32 * encSRKAuthLength, BYTE * encSRKAuth)
{
	TSS_RESULT rc;
	UINT32 endorsementKeySize;
	BYTE *endorsementKey;
	TCPA_KEY dummyKey;
	UINT16 offset;
	BYTE *random;
	BYTE randomSeed[20];
	TCPA_SECRET ownerSecret;
	TCPA_SECRET srkSecret;
	BYTE hashblob[1024];
	TCPA_DIGEST digest;
	TSS_HPOLICY hSrkPolicy;
	TSS_HPOLICY hOwnerPolicy;
	UINT32 srkKeyBlobLength;
	BYTE *srkKeyBlob;
	AnObject *anObject;
	TSP_INTERNAL_POLICY_OBJECT *ownerPolicy;
	TSP_INTERNAL_POLICY_OBJECT *srkPolicy;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_HCONTEXT tspContext;

	tcsContext = obj_getTcsContext(hTPM);
	tspContext = obj_getTspContext(hTPM);
	if (tcsContext == NULL_HCONTEXT || tspContext == NULL_HCONTEXT)
		return TSS_E_INVALID_HANDLE;

	/*************************************************
	 *	First, get the policy objects and check them for how
	 *		to handle the secrets.  If they cannot be found
	 *		or there is an error, then we must fail
	 **************************************************/

	/* ---  First get the Owner Policy */
	if ((rc = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hOwnerPolicy)))
		return rc;

	anObject = getAnObjectByHandle(hOwnerPolicy);
	if (anObject == NULL || anObject->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;

	ownerPolicy = anObject->memPointer;

	/* ---  Now get the SRK Policy */

	if ((rc = Tspi_GetPolicyObject(hKeySRK, TSS_POLICY_USAGE, &hSrkPolicy)))
		return rc;
	anObject = getAnObjectByHandle(hSrkPolicy);
	if (anObject == NULL || anObject->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;

	srkPolicy = anObject->memPointer;

	/* ---  If the policy callback's aren't the same, that's an error if one is callback */
	if (srkPolicy->p.SecretMode == TSS_SECRET_MODE_CALLBACK &&
	    ownerPolicy->p.SecretMode != TSS_SECRET_MODE_CALLBACK) {
		LogError1("Policy callback modes for SRK policy and Owner policy differ");
		return TSS_E_INTERNAL_ERROR;
	}

	if (ownerPolicy->p.SecretMode != TSS_SECRET_MODE_CALLBACK) {
		/* ---  First, get the Endorsement Public Key for Encrypting */
		if ((rc = Tspi_GetAttribData(hEndorsementPubKey,
					    TSS_TSPATTRIB_KEY_BLOB,
					    TSS_TSPATTRIB_KEYBLOB_BLOB,
					    &endorsementKeySize, &endorsementKey)))
			return rc;

		/* ---  now stick it in a Key Structure */
		offset = 0;
		UnloadBlob_KEY(tspContext, &offset, endorsementKey, &dummyKey);

		/* ---  Now get the secrets */
		if (ownerPolicy->p.SecretMode == TSS_SECRET_MODE_PLAIN ||
		    ownerPolicy->p.SecretMode == TSS_SECRET_MODE_SHA1) {
			if ((rc = internal_GetSecret(hOwnerPolicy, &ownerSecret, 1)))
				return rc;
		} else if (ownerPolicy->p.SecretMode == TSS_SECRET_MODE_POPUP) {
			if ((rc = popup_GetSecret(FALSE, ownerPolicy->p.popupString, ownerSecret.secret)))
				return rc;
		} else {
			LogError1("Key Policy's Secret mode is not set.");
			return TSS_E_POLICY_NO_SECRET;	/* not yet */
		}

		if (srkPolicy->p.SecretMode == TSS_SECRET_MODE_PLAIN ||
		    srkPolicy->p.SecretMode == TSS_SECRET_MODE_SHA1) {
			if ((rc = internal_GetSecret(hSrkPolicy, &srkSecret, 1)))
				return rc;
		} else if (srkPolicy->p.SecretMode == TSS_SECRET_MODE_POPUP) {
			if ((rc = popup_GetSecret(FALSE, srkPolicy->p.popupString, srkSecret.secret)))
				return rc;
		} else {
			LogError1("Key Policy's Secret mode is not set.");
			return TSS_E_POLICY_NO_SECRET;
		}

		/* ---   Encrypt the Owner Authorization */
		if ((rc = Tspi_TPM_GetRandom(hTPM, 20, &random)))
			return rc;
		memcpy(randomSeed, random, 20);
		free_tspi(tspContext, random);

		TSS_RSA_Encrypt(ownerSecret.secret,
				       20,	/* sizeof(tpmObject->ownerAuth), //dataToEncryptLen,  //in */
				       encOwnerAuth,	/* out */
				       encOwnerAuthLength,	/* *encryptedDataLen, //out */
				       dummyKey.pubKey.key,	/* endorsementKey, //pubKey.pubKey.key, */
				       dummyKey.pubKey.keyLength);	/* endorsementKeySize, //pubKey.pubKey.keyLength,  //unsigned int keysize,  */

		/* ---  Encrypt the SRK Authorization */
		if ((rc = Tspi_TPM_GetRandom(hTPM, 20, &random)))
			return rc;

		memcpy(randomSeed, random, 20);
		free_tspi(tspContext, random);

		TSS_RSA_Encrypt(srkSecret.secret,
				       20,	/* sizeof(tpmObject->SRKAuth), //dataToEncryptLen,  //in */
				       encSRKAuth,	/* out */
				       encSRKAuthLength,	/* *encryptedDataLen, //out */
				       dummyKey.pubKey.key,	/* endorsementKey, //pubKey.pubKey.key, */
				       dummyKey.pubKey.keyLength);	/* endorsementKeySize, //pubKey.pubKey.keyLength,  //unsigned int keysize,  */
	} else {		/* ---    If the owner Policy isn't provided */

		*encOwnerAuthLength = 256;
		*encSRKAuthLength = 256;
		if ((rc = ownerPolicy->cb.Tspicb_CallbackTakeOwnership(NULL, 0, hEndorsementPubKey,
					       *encOwnerAuthLength, encOwnerAuth)))
			return rc;
	}

	if ((rc = Tspi_GetAttribData(hKeySRK,
				    TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_BLOB,
				    &srkKeyBlobLength,
				    &srkKeyBlob)))
		return rc;
/* ================  Authorizatin Digest Calculation */
/* ===	Hash first the following: */

	offset = 0;
	LoadBlob_UINT32(&offset, TPM_ORD_TakeOwnership, hashblob);
	LoadBlob_UINT16(&offset, TCPA_PID_OWNER, hashblob);
	LoadBlob_UINT32(&offset, *encOwnerAuthLength, hashblob);
	LoadBlob(&offset, *encOwnerAuthLength, hashblob, encOwnerAuth);
	LoadBlob_UINT32(&offset, *encSRKAuthLength, hashblob);
	LoadBlob(&offset, *encSRKAuthLength, hashblob, encSRKAuth);
	LoadBlob(&offset, srkKeyBlobLength, hashblob, srkKeyBlob);

	TSS_Hash(TSS_HASH_SHA1, offset, hashblob, digest.digest);

	/* ===  HMAC for the final digest */

	if ((rc = secret_PerformAuth_OIAP(hOwnerPolicy, digest, auth)))
		return rc;

	return TSS_SUCCESS;
}
