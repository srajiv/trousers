
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2005
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
obj_policy_add(TSS_HCONTEXT tsp_context, UINT32 type, TSS_HOBJECT *phObject)
{
	struct tr_policy_obj *policy;
	TSS_RESULT result;

	if ((policy = calloc(1, sizeof(struct tr_policy_obj))) == NULL) {
		LogError("malloc of %d bytes failed",
				sizeof(struct tr_policy_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	policy->type = type;
	policy->SecretMode = TSS_SECRET_MODE_NONE;
	policy->SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS;

	if ((result = obj_list_add(&policy_list, tsp_context, policy,
					phObject))) {
		free(policy);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_remove(TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
	return obj_list_remove(&policy_list, hObject, tspContext);
}

TSS_BOOL
obj_is_policy(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&policy_list, hObject)))
		answer = TRUE;

	obj_list_put(&policy_list);

	return answer;
}

TSS_RESULT
obj_policy_get_type(TSS_HPOLICY hPolicy, UINT32 *type)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*type = policy->type;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_type(TSS_HPOLICY hPolicy, UINT32 type)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->type = type;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_tsp_context(TSS_HPOLICY hPolicy, TSS_HCONTEXT *tspContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tspContext = obj->tspContext;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_tcs_context(TSS_HPOLICY hPolicy,
			   TCS_CONTEXT_HANDLE *tcsContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tcsContext = obj->tcsContext;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_do_hmac(TSS_HPOLICY hPolicy,
		   TSS_BOOL returnOrVerify, UINT32 ulPendingFunction,
		   TSS_BOOL continueUse, UINT32 ulSizeNonces,
		   BYTE *rgbNonceEven, BYTE *rgbNonceOdd,
		   BYTE *rgbNonceEvenOSAP, BYTE *rgbNonceOddOSAP,
		   UINT32 ulSizeDigestHmac, BYTE *rgbParamDigest,
		   BYTE *rgbHmacData)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	result = policy->Tspicb_CallbackHMACAuth(
			policy->hmacAppData, hPolicy,
			returnOrVerify,
			ulPendingFunction,
			continueUse,
			ulSizeNonces,
			rgbNonceEven,
			rgbNonceOdd,
			rgbNonceEvenOSAP, rgbNonceOddOSAP, ulSizeDigestHmac,
			rgbParamDigest,
			rgbHmacData);

	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_get_secret(TSS_HPOLICY hPolicy, TCPA_SECRET *secret)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;
	TCPA_SECRET null_secret;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	memset(&null_secret, 0, sizeof(TCPA_SECRET));

	switch (policy->SecretMode) {
		case TSS_SECRET_MODE_POPUP:
			/* if the secret is still NULL, grab it using the GUI */
			if (!memcmp(policy->Secret, &null_secret,
						TCPA_SHA1_160_HASH_LEN)) {
				if ((result = popup_GetSecret(hPolicy,
							      policy->popupString,
							      policy->Secret)))
					break;
			}
			/* fall through */
		case TSS_SECRET_MODE_PLAIN:
		case TSS_SECRET_MODE_SHA1:
		case TSS_SECRET_MODE_NONE:
			memcpy(secret, policy->Secret, sizeof(TCPA_SECRET));
			break;
		default:
			result = TSPERR(TSS_E_POLICY_NO_SECRET);
			break;
	}

	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_flush_secret(TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	memset(&policy->Secret, 0, policy->SecretSize);

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_secret_object(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size,
				TCPA_DIGEST *digest)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	memcpy(policy->Secret, digest, size);
	policy->SecretMode = mode;
	policy->SecretSize = size;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_copy_secret(TSS_HPOLICY destPolicy, TSS_HPOLICY srcPolicy)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TCPA_DIGEST digest;
	UINT32 secret_size, mode;

	if ((obj = obj_list_get_obj(&policy_list, srcPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	memcpy(&digest.digest, &policy->Secret, policy->SecretSize);
	mode = policy->SecretMode;
	secret_size = policy->SecretSize;

	obj_list_put(&policy_list);

	return obj_policy_set_secret_object(destPolicy, mode, secret_size, &digest);
}

TSS_RESULT
obj_policy_set_secret(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size, BYTE *data)
{
	TCPA_DIGEST digest;
	UINT32 secret_size = 0;

	memset(&digest.digest, 0, sizeof(TCPA_DIGEST));

	switch (mode) {
		case TSS_SECRET_MODE_PLAIN:
			Trspi_Hash(TSS_HASH_SHA1, size, data, (BYTE *)&digest.digest);
			secret_size = TCPA_SHA1_160_HASH_LEN;
			break;
		case TSS_SECRET_MODE_SHA1:
			if (size != TCPA_SHA1_160_HASH_LEN)
				return TSPERR(TSS_E_BAD_PARAMETER);

			memcpy(&digest.digest, data, size);
			secret_size = TCPA_SHA1_160_HASH_LEN;
			break;
		case TSS_SECRET_MODE_POPUP:
		case TSS_SECRET_MODE_NONE:
			break;
		default:
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	return obj_policy_set_secret_object(hPolicy, mode, secret_size, &digest);
}

TSS_RESULT
obj_policy_get_cb_hmac(TSS_HPOLICY hPolicy, UINT32 *cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*cb = (UINT32)policy->Tspicb_CallbackHMACAuth;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_cb_hmac(TSS_HPOLICY hPolicy, PVOID cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->Tspicb_CallbackHMACAuth = (TSS_RESULT (*)(
				PVOID,TSS_HOBJECT,
				TSS_BOOL,UINT32,
				TSS_BOOL,UINT32,
				BYTE *,BYTE *,
				BYTE *,BYTE *,
				UINT32,BYTE *,
				BYTE *))cb;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_cb_xor(TSS_HPOLICY hPolicy, UINT32 *cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*cb = (UINT32)policy->Tspicb_CallbackXorEnc;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_cb_xor(TSS_HPOLICY hPolicy, PVOID cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->Tspicb_CallbackXorEnc = (TSS_RESULT (*)(
				PVOID,TSS_HOBJECT,
				TSS_HOBJECT,TSS_FLAG,
				UINT32,BYTE *,
				BYTE *,BYTE *,
				BYTE *,UINT32,
				BYTE *,BYTE *))cb;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_cb_takeowner(TSS_HPOLICY hPolicy, UINT32 *cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*cb = (UINT32)policy->Tspicb_CallbackTakeOwnership;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_cb_takeowner(TSS_HPOLICY hPolicy, PVOID cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->Tspicb_CallbackTakeOwnership = (TSS_RESULT (*)(
				PVOID,TSS_HOBJECT,
				TSS_HKEY,UINT32,
				BYTE *))cb;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_cb_changeauth(TSS_HPOLICY hPolicy, UINT32 *cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*cb = (UINT32)policy->Tspicb_CallbackChangeAuthAsym;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_cb_changeauth(TSS_HPOLICY hPolicy, PVOID cb)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->Tspicb_CallbackChangeAuthAsym = (TSS_RESULT (*)(
				PVOID,TSS_HOBJECT,
				TSS_HKEY,UINT32,
				UINT32,BYTE *,
				BYTE *))cb;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_lifetime(TSS_HPOLICY hPolicy, UINT32 *lifetime)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*lifetime = policy->SecretLifetime;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_lifetime(TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->SecretCounter = 0;
	policy->SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS;
	policy->SecretTimer = 0;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_mode(TSS_HPOLICY hPolicy, UINT32 *mode)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*mode = policy->SecretMode;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_counter(TSS_HPOLICY hPolicy, UINT32 *counter)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*counter = policy->SecretCounter;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_counter(TSS_HPOLICY hPolicy, UINT32 counter)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->SecretCounter = counter;
	policy->SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER;
	policy->SecretTimer = 0;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_dec_counter(TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	if (policy->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER)
		policy->SecretCounter--;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_timer(TSS_HPOLICY hPolicy, UINT32 timer)
{
	TSS_RESULT result = TSS_SUCCESS;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	time_t t;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	t = time(NULL);
	if (t == ((time_t)-1)) {
		LogError("time failed: %s", strerror(errno));
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	}
	/* for mode time, we'll use the SecretCounter variable to hold
	 * the number of seconds we're valid and the SecretTimer var to
	 * record the current timestamp. This should protect against
	 * overflows.
	 */
	policy->SecretCounter = timer;
	policy->SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER;
	policy->SecretTimer = t;

done:
	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_get_string(TSS_HPOLICY hPolicy, UINT32 *size, BYTE **data)
{
	TSS_RESULT result = TSS_SUCCESS;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	if (policy->popupStringLength == 0) {
		*data = NULL;
		*size = 0;
	} else {
		*data = calloc_tspi(obj->tspContext,
				policy->popupStringLength * sizeof(UNICODE));
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.",
				policy->popupStringLength * sizeof(UNICODE));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		*size = policy->popupStringLength * sizeof(UNICODE);
		memcpy(*data, policy->popupString, *size);
	}

done:
	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_set_string(TSS_HPOLICY hPolicy, UINT32 size, BYTE *data)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	memcpy(policy->popupString, data, size);
	policy->popupStringLength = size / sizeof(UNICODE);

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_get_secs_until_expired(TSS_HPOLICY hPolicy, UINT32 *secs)
{
	TSS_RESULT result = TSS_SUCCESS;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	int seconds_elapsed;
	time_t t;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	if (policy->SecretLifetime != TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
		result = TSPERR(TSS_E_BAD_PARAMETER);
		goto done;
	}

	if ((t = time(NULL)) == ((time_t)-1)) {
		LogError("time failed: %s", strerror(errno));
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	}
	/* curtime - SecretTimer is the number of seconds elapsed since we
	 * started the timer. SecretCounter is the number of seconds the
	 * secret is valid.  If seconds_elspased > SecretCounter, we've
	 * expired.
	 */
	seconds_elapsed = t - policy->SecretTimer;
	if ((UINT32)seconds_elapsed >= policy->SecretCounter) {
		*secs = 0;
	} else {
		*secs = policy->SecretCounter - seconds_elapsed;
	}

done:
	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_has_expired(TSS_HPOLICY hPolicy, TSS_BOOL *answer)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	if (policy->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
		*answer = FALSE;
	} else if (policy->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
		if (policy->SecretCounter == 0)
			*answer = TRUE;
		else
			*answer = FALSE;
	} else if (policy->SecretLifetime == TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
		int seconds_elapsed;
		time_t t = time(NULL);

		if (t == ((time_t)-1)) {
			LogError("time failed: %s", strerror(errno));
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		/* curtime - SecretTimer is the number of seconds elapsed since we
		 * started the timer. SecretCounter is the number of seconds the
		 * secret is valid.  If seconds_elspased > SecretCounter, we've
		 * expired.
		 */
		seconds_elapsed = t - policy->SecretTimer;
		if ((UINT32)seconds_elapsed >= policy->SecretCounter) {
			*answer = TRUE;
		} else {
			*answer = FALSE;
		}
	} else {
		result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
	}

done:
	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_validate_auth_oiap(TSS_HPOLICY hPolicy, TCPA_DIGEST *hashDigest, TPM_AUTH *auth)
{
	TSS_RESULT result = TSS_SUCCESS;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

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
		default:
			result = TSPERR(TSS_E_POLICY_NO_SECRET);
			break;
	}

	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_do_xor(TSS_HPOLICY hPolicy,
		  TSS_HOBJECT hOSAPObject, TSS_HOBJECT hObject,
		  TSS_FLAG PurposeSecret, UINT32 ulSizeNonces,
		  BYTE *rgbNonceEven, BYTE *rgbNonceOdd,
		  BYTE *rgbNonceEvenOSAP, BYTE *rgbNonceOddOSAP,
		  UINT32 ulSizeEncAuth, BYTE *rgbEncAuthUsage,
		  BYTE *rgbEncAuthMigration)
{
	TSS_RESULT result;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	result = policy->Tspicb_CallbackXorEnc(policy->xorAppData,
			hOSAPObject, hObject,
			PurposeSecret, ulSizeNonces,
			rgbNonceEven, rgbNonceOdd,
			rgbNonceEvenOSAP, rgbNonceOddOSAP,
			ulSizeEncAuth,
			rgbEncAuthUsage, rgbEncAuthMigration);

	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_do_takeowner(TSS_HPOLICY hPolicy,
			TSS_HOBJECT hObject, TSS_HKEY hObjectPubKey,
			UINT32 ulSizeEncAuth, BYTE *rgbEncAuth)
{
	TSS_RESULT result;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	result = policy->Tspicb_CallbackTakeOwnership(
			policy->takeownerAppData,
			hObject, hObjectPubKey, ulSizeEncAuth,
			rgbEncAuth);

	obj_list_put(&policy_list);

	return result;
}
