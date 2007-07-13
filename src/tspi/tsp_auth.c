
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
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
secret_PerformAuth_OIAP(TSS_HOBJECT hAuthorizedObject,
			UINT32 ulPendingFn,
			TSS_HPOLICY hPolicy,
			TSS_BOOL cas, /* continue auth session */
			TCPA_DIGEST *hashDigest,
			TPM_AUTH *auth)
{
	TSS_RESULT result;
	TSS_BOOL bExpired;
	UINT32 mode;
	TCPA_SECRET secret;
	TSS_HCONTEXT tspContext;

	/* This validates that the secret can be used */
	if ((result = obj_policy_has_expired(hPolicy, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSPERR(TSS_E_INVALID_OBJ_ACCESS);

	if ((result = obj_policy_get_tsp_context(hPolicy, &tspContext)))
		return result;

	if ((result = obj_policy_get_mode(hPolicy, &mode)))
		return result;

	if ((result = Init_AuthNonce(tspContext, cas, auth)))
		return result;

	/* added retry logic */
	if ((result = TCSP_OIAP(tspContext, &auth->AuthHandle, &auth->NonceEven))) {
		if (result == TCPA_E_RESOURCES) {
			int retry = 0;
			do {
				/* POSIX sleep time, { secs, nanosecs } */
				struct timespec t = { 0, AUTH_RETRY_NANOSECS };

				nanosleep(&t, NULL);

				result = TCSP_OIAP(tspContext, &auth->AuthHandle, &auth->NonceEven);
			} while (result == TCPA_E_RESOURCES && ++retry < AUTH_RETRY_COUNT);
		}

		if (result)
			return result;
	}

	switch (mode) {
		case TSS_SECRET_MODE_CALLBACK:
			result = obj_policy_do_hmac(hPolicy, hAuthorizedObject,
						    TRUE, ulPendingFn,
						    auth->fContinueAuthSession,
						    20,
						    auth->NonceEven.nonce,
						    auth->NonceOdd.nonce,
						    NULL, NULL, 20,
						    hashDigest->digest,
						    (BYTE *)&auth->HMAC);
			break;
		case TSS_SECRET_MODE_SHA1:
		case TSS_SECRET_MODE_PLAIN:
		case TSS_SECRET_MODE_POPUP:
			if ((result = obj_policy_get_secret(hPolicy, TR_SECRET_CTX_NOT_NEW,
							    &secret)))
				break;

			HMAC_Auth(secret.authdata, hashDigest->digest, auth);
			break;
		case TSS_SECRET_MODE_NONE:
			/* fall through */
		default:
			result = TSPERR(TSS_E_POLICY_NO_SECRET);
			break;
	}

	if (result) {
		TCSP_TerminateHandle(tspContext, auth->AuthHandle);
		return result;
	}

	return obj_policy_dec_counter(hPolicy);
}

TSS_RESULT
secret_PerformXOR_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
		       TSS_HPOLICY hMigrationPolicy, TSS_HOBJECT hOSAPObject,
		       UINT16 osapType, UINT32 osapData,
		       TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig,
		       BYTE *sharedSecret, TPM_AUTH * auth, TCPA_NONCE * nonceEvenOSAP)
{
	TSS_BOOL bExpired;
	TCPA_SECRET keySecret;
	TCPA_SECRET usageSecret;
	TCPA_SECRET migSecret = { { 0, } };
	UINT32 keyMode, usageMode, migMode = 0;
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;


	if ((result = obj_policy_has_expired(hPolicy, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSPERR(TSS_E_INVALID_OBJ_ACCESS);

	if ((result = obj_policy_has_expired(hUsagePolicy, &bExpired)))
		return result;

	if (bExpired == TRUE)
		return TSPERR(TSS_E_INVALID_OBJ_ACCESS);

	if (hMigrationPolicy) {
		if ((result = obj_policy_has_expired(hMigrationPolicy, &bExpired)))
			return result;

		if (bExpired == TRUE)
			return TSPERR(TSS_E_INVALID_OBJ_ACCESS);

		if ((result = obj_policy_get_mode(hMigrationPolicy, &migMode)))
			return result;
	}

	if ((result = obj_policy_get_tsp_context(hPolicy, &tspContext)))
		return result;

	if ((result = obj_policy_get_mode(hPolicy, &keyMode)))
		return result;

	if ((result = obj_policy_get_mode(hUsagePolicy, &usageMode)))
		return result;

	if (keyMode == TSS_SECRET_MODE_CALLBACK ||
	    usageMode == TSS_SECRET_MODE_CALLBACK ||
	    (hMigrationPolicy && migMode == TSS_SECRET_MODE_CALLBACK)) {
		if (keyMode != TSS_SECRET_MODE_CALLBACK ||
		    usageMode != TSS_SECRET_MODE_CALLBACK ||
		    (hMigrationPolicy && migMode != TSS_SECRET_MODE_CALLBACK))
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	if (keyMode != TSS_SECRET_MODE_CALLBACK) {
		if ((result = obj_policy_get_secret(hPolicy, TR_SECRET_CTX_NOT_NEW, &keySecret)))
			return result;

		if ((result = obj_policy_get_secret(hUsagePolicy, TR_SECRET_CTX_NEW, &usageSecret)))
			return result;

		if (hMigrationPolicy) {
			if ((result = obj_policy_get_secret(hMigrationPolicy, TR_SECRET_CTX_NEW,
							&migSecret)))
				return result;
		}

		if ((result = OSAP_Calc(tspContext, osapType, osapData,
					keySecret.authdata, usageSecret.authdata,
					migSecret.authdata, encAuthUsage,
					encAuthMig, sharedSecret, auth)))
			return result;
	} else {
		/* If the secret mode is NONE here, we don't return an error. This is
		 * because there are commands such as CreateKey, which require an auth
		 * session even when creating no-auth keys. A secret of all 0's will be
		 * used in this case. */
		if ((result = TCSP_OSAP(tspContext, osapType, osapData,
					auth->NonceOdd,	&auth->AuthHandle,
					&auth->NonceEven, nonceEvenOSAP)))
			return result;

		if ((result = obj_policy_do_xor(hPolicy, hOSAPObject,
						hPolicy, TRUE, 20,
						auth->NonceEven.nonce, NULL,
						nonceEvenOSAP->nonce,
						auth->NonceOdd.nonce, 20,
						encAuthUsage->authdata,
						encAuthMig->authdata))) {
			TCSP_TerminateHandle(tspContext, auth->AuthHandle);
			return result;
		}
	}

	return TSS_SUCCESS;
}

TSS_RESULT
secret_PerformAuth_OSAP(TSS_HOBJECT hAuthorizedObject, UINT32 ulPendingFn,
			TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
			TSS_HPOLICY hMigPolicy, BYTE sharedSecret[20],
			TPM_AUTH *auth, BYTE *hashDigest,
			TCPA_NONCE *nonceEvenOSAP)
{
	TSS_RESULT result;
	UINT32 keyMode, usageMode, migMode = 0;

	if ((result = obj_policy_get_mode(hPolicy, &keyMode)))
		return result;

	if ((result = obj_policy_get_mode(hUsagePolicy, &usageMode)))
		return result;

	if (hMigPolicy) {
		if ((result = obj_policy_get_mode(hMigPolicy, &migMode)))
			return result;
	}

	/* ---  If any of them is a callback */
	if (keyMode == TSS_SECRET_MODE_CALLBACK ||
	    usageMode == TSS_SECRET_MODE_CALLBACK ||
	    (hMigPolicy && migMode == TSS_SECRET_MODE_CALLBACK)) {
		/* ---  And they're not all callback */
		if (keyMode != TSS_SECRET_MODE_CALLBACK ||
		    usageMode != TSS_SECRET_MODE_CALLBACK ||
		    (hMigPolicy && migMode != TSS_SECRET_MODE_CALLBACK))
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	if (keyMode == TSS_SECRET_MODE_CALLBACK) {
		if ((result = obj_policy_do_hmac(hPolicy, hAuthorizedObject,
						 TRUE, ulPendingFn,
						 auth->fContinueAuthSession,
						 20,
						 auth->NonceEven.nonce,
						 NULL,
						 nonceEvenOSAP->nonce,
						 auth->NonceOdd.nonce, 20,
						 hashDigest,
						 (BYTE *)&auth->HMAC)))
			return result;
	} else {
		HMAC_Auth(sharedSecret, hashDigest, auth);
	}

	if ((result = obj_policy_dec_counter(hPolicy)))
		return result;

	if ((result = obj_policy_dec_counter(hUsagePolicy)))
		return result;

	if (hMigPolicy) {
		if ((result = obj_policy_dec_counter(hMigPolicy)))
			return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
secret_ValidateAuth_OSAP(TSS_HOBJECT hAuthorizedObject, UINT32 ulPendingFn,
			 TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
			 TSS_HPOLICY hMigPolicy, BYTE sharedSecret[20],
			 TPM_AUTH *auth, BYTE *hashDigest,
			 TCPA_NONCE *nonceEvenOSAP)
{
	TSS_RESULT result;
	UINT32 keyMode, usageMode, migMode = 0;

	if ((result = obj_policy_get_mode(hPolicy, &keyMode)))
		return result;

	if ((result = obj_policy_get_mode(hUsagePolicy, &usageMode)))
		return result;

	if (hMigPolicy) {
		if ((result = obj_policy_get_mode(hMigPolicy, &migMode)))
			return result;
	}

	/* ---  If any of them is a callback */
	if (keyMode == TSS_SECRET_MODE_CALLBACK ||
	    usageMode == TSS_SECRET_MODE_CALLBACK ||
	    (hMigPolicy && migMode == TSS_SECRET_MODE_CALLBACK)) {
		/* ---  And they're not all callback */
		if (keyMode != TSS_SECRET_MODE_CALLBACK ||
		    usageMode != TSS_SECRET_MODE_CALLBACK ||
		    (hMigPolicy && migMode != TSS_SECRET_MODE_CALLBACK))
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	if (keyMode != TSS_SECRET_MODE_CALLBACK) {
		if (validateReturnAuth(sharedSecret, hashDigest, auth))
			return TSPERR(TSS_E_TSP_AUTHFAIL);
	} else {
		if ((result = obj_policy_do_hmac(hPolicy, hAuthorizedObject,
						 FALSE, ulPendingFn,
						 auth->fContinueAuthSession,
						 20,
						 auth->NonceEven.nonce,
						 NULL,
						 nonceEvenOSAP->nonce,
						 auth->NonceOdd.nonce, 20,
						 hashDigest,
						 (BYTE *)&auth->HMAC)))
			return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Init_AuthNonce(TSS_HCONTEXT tspContext, TSS_BOOL cas, TPM_AUTH * auth)
{
	TSS_RESULT result;

	auth->fContinueAuthSession = cas;
	if ((result = get_local_random(tspContext, FALSE, sizeof(TPM_NONCE),
				       (BYTE **)auth->NonceOdd.nonce))) {
		LogError("Failed creating random nonce");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

TSS_BOOL
validateReturnAuth(BYTE *secret, BYTE *hash, TPM_AUTH *auth)
{
	BYTE digest[20];
	/* auth is expected to have both nonces and the digest from the TPM */
	memcpy(digest, &auth->HMAC, 20);
	HMAC_Auth(secret, hash, auth);

	return (TSS_BOOL) memcmp(digest, &auth->HMAC, 20);
}

void
HMAC_Auth(BYTE * secret, BYTE * Digest, TPM_AUTH * auth)
{
	UINT64 offset;
	BYTE Blob[61];

	offset = 0;
	Trspi_LoadBlob(&offset, 20, Blob, Digest);
	Trspi_LoadBlob(&offset, 20, Blob, auth->NonceEven.nonce);
	Trspi_LoadBlob(&offset, 20, Blob, auth->NonceOdd.nonce);
	Blob[offset++] = auth->fContinueAuthSession;

	Trspi_HMAC(TSS_HASH_SHA1, 20, secret, offset, Blob, (BYTE *)&auth->HMAC);
}

TSS_RESULT
OSAP_Calc(TSS_HCONTEXT tspContext, UINT16 EntityType, UINT32 EntityValue,
	  BYTE * authSecret, BYTE * usageSecret, BYTE * migSecret,
	  TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig,
	  BYTE * sharedSecret, TPM_AUTH * auth)
{

	TSS_RESULT rc;
	TCPA_NONCE nonceEvenOSAP;
	UINT64 offset;
	BYTE hmacBlob[0x200];
	BYTE hashBlob[0x200];
	BYTE xorUsageAuth[20];
	BYTE xorMigAuth[20];
	UINT32 i;

	if ((rc = get_local_random(tspContext, FALSE, sizeof(TPM_NONCE),
				   (BYTE **)auth->NonceOdd.nonce))) {
		LogError("Failed creating random nonce");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	auth->fContinueAuthSession = 0x00;

	if ((rc = TCSP_OSAP(tspContext, EntityType, EntityValue, auth->NonceOdd,
					&auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP))) {
		if (rc == TCPA_E_RESOURCES) {
			int retry = 0;
			do {
				/* POSIX sleep time, { secs, nanosecs } */
				struct timespec t = { 0, AUTH_RETRY_NANOSECS };

				nanosleep(&t, NULL);

				rc = TCSP_OSAP(tspContext, EntityType, EntityValue, auth->NonceOdd,
						&auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP);
			} while (rc == TCPA_E_RESOURCES && ++retry < AUTH_RETRY_COUNT);
		}

		if (rc)
			return rc;
	}

	offset = 0;
	Trspi_LoadBlob(&offset, 20, hmacBlob, nonceEvenOSAP.nonce);
	Trspi_LoadBlob(&offset, 20, hmacBlob, auth->NonceOdd.nonce);

	Trspi_HMAC(TSS_HASH_SHA1, 20, authSecret, offset, hmacBlob, sharedSecret);

	offset = 0;
	Trspi_LoadBlob(&offset, 20, hashBlob, sharedSecret);
	Trspi_LoadBlob(&offset, 20, hashBlob, auth->NonceEven.nonce);

	if ((rc = Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, xorUsageAuth)))
		return rc;

	offset = 0;
	Trspi_LoadBlob(&offset, 20, hashBlob, sharedSecret);
	Trspi_LoadBlob(&offset, 20, hashBlob, auth->NonceOdd.nonce);
	if ((rc = Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, xorMigAuth)))
		return rc;

	for (i = 0; i < sizeof(TCPA_ENCAUTH); i++)
		encAuthUsage->authdata[i] = usageSecret[i] ^ xorUsageAuth[i];
	for (i = 0; i < sizeof(TCPA_ENCAUTH); i++)
		encAuthMig->authdata[i] = migSecret[i] ^ xorMigAuth[i];

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_validate_auth_oiap(TSS_HPOLICY hPolicy, TCPA_DIGEST *hashDigest, TPM_AUTH *auth)
{
	TSS_RESULT result = TSS_SUCCESS;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	BYTE wellKnown[TCPA_SHA1_160_HASH_LEN] = TSS_WELL_KNOWN_SECRET;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	switch (policy->SecretMode) {
		case TSS_SECRET_MODE_CALLBACK:
			result = policy->Tspicb_CallbackHMACAuth(
					policy->hmacAppData,
					hPolicy,
					0,
					auth->fContinueAuthSession,
					FALSE,
					20,
					auth->NonceEven.nonce,
					auth->NonceOdd.nonce,
					NULL, NULL, 20,
					hashDigest->digest,
					(BYTE *)&auth->HMAC);
			break;
		case TSS_SECRET_MODE_SHA1:
		case TSS_SECRET_MODE_PLAIN:
		case TSS_SECRET_MODE_POPUP:
			if (validateReturnAuth(policy->Secret, hashDigest->digest, auth))
				result = TSPERR(TSS_E_TSP_AUTHFAIL);
			break;
		case TSS_SECRET_MODE_NONE:
			if (validateReturnAuth(wellKnown, hashDigest->digest, auth))
				result = TSPERR(TSS_E_TSP_AUTHFAIL);
			break;
		default:
			result = TSPERR(TSS_E_POLICY_NO_SECRET);
			break;
	}

	obj_list_put(&policy_list);

	return result;
}

