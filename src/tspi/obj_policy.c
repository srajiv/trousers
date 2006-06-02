
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2005, 2006
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
		LogError("malloc of %zd bytes failed",
				sizeof(struct tr_policy_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	policy->type = type;
#ifndef TSS_SPEC_COMPLIANCE
	policy->SecretMode = TSS_SECRET_MODE_NONE;
	/* The policy object will inherit this attribute from the context */
	if ((result = obj_context_get_hash_mode(tsp_context, &policy->hashMode))) {
		free(policy);
		return result;
	}
#else
	policy->SecretMode = TSS_SECRET_MODE_POPUP;
#endif
	policy->SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS;

	if ((result = obj_list_add(&policy_list, tsp_context, 0, policy, phObject))) {
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

	if ((obj_list_get_obj(&policy_list, hObject))) {
		answer = TRUE;
		obj_list_put(&policy_list);
	}

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
obj_policy_do_hmac(TSS_HPOLICY hPolicy, TSS_HOBJECT hAuthorizedObject,
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
			policy->hmacAppData, hAuthorizedObject,
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
			if (policy->SecretSet == FALSE) {
#ifndef TSS_SPEC_COMPLIANCE
				if ((result = popup_GetSecret2(TRUE, policy->hashMode,
							      policy->popupString,
							      policy->Secret)))
#else
				if ((result = popup_GetSecret(TRUE,
							      policy->popupString,
							      policy->Secret)))
#endif
					break;
			}
			policy->SecretSet = TRUE;
			/* fall through */
		case TSS_SECRET_MODE_PLAIN:
		case TSS_SECRET_MODE_SHA1:
			if (policy->SecretSet == FALSE) {
				result = TSPERR(TSS_E_POLICY_NO_SECRET);
				break;
			}

			memcpy(secret, policy->Secret, sizeof(TCPA_SECRET));
			break;
		case TSS_SECRET_MODE_NONE:
			memcpy(secret, &null_secret, sizeof(TCPA_SECRET));
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
	policy->SecretSet = FALSE;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_secret_object(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size,
			     TCPA_DIGEST *digest, TSS_BOOL set)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	/* if this is going to be a callback policy, the
	 * callbacks need to already be set. (See TSS 1.1b
	 * spec pg. 62). */
	if (mode == TSS_SECRET_MODE_CALLBACK) {
		if (policy->Tspicb_CallbackHMACAuth == NULL) {
			result = TSPERR(TSS_E_FAIL);
			goto done;
		}
	}

	memcpy(policy->Secret, digest, size);
	policy->SecretMode = mode;
	policy->SecretSize = size;
	policy->SecretSet = set;
done:
	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_copy_secret(TSS_HPOLICY destPolicy, TSS_HPOLICY srcPolicy)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TCPA_DIGEST digest;
	UINT32 secret_size, mode;
	TSS_BOOL secret_set;

	if ((obj = obj_list_get_obj(&policy_list, srcPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	memcpy(&digest.digest, &policy->Secret, policy->SecretSize);
	mode = policy->SecretMode;
	secret_size = policy->SecretSize;
	secret_set = policy->SecretSet;

	obj_list_put(&policy_list);

	return obj_policy_set_secret_object(destPolicy, mode, secret_size,
					    &digest, secret_set);
}

TSS_RESULT
obj_policy_set_secret(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size, BYTE *data)
{
	TCPA_DIGEST digest;
	UINT32 secret_size = 0;
	TSS_BOOL secret_set = TRUE;

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
			secret_set = FALSE;
		case TSS_SECRET_MODE_CALLBACK:
			break;
		default:
			return TSPERR(TSS_E_BAD_PARAMETER);
	}

	return obj_policy_set_secret_object(hPolicy, mode, secret_size,
					    &digest, secret_set);
}

TSS_RESULT
obj_policy_get_cb11(TSS_HPOLICY hPolicy, TSS_FLAG type, UINT32 *cb)
{
#ifndef __LP64__
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	switch (type) {
		case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			*cb = (UINT32)policy->Tspicb_CallbackHMACAuth;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			*cb = (UINT32)policy->Tspicb_CallbackXorEnc;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			*cb = (UINT32)policy->Tspicb_CallbackTakeOwnership;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
			*cb = (UINT32)policy->Tspicb_CallbackChangeAuthAsym;
			break;
		default:
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}

	obj_list_put(&policy_list);

	return result;
#else
	return TSPERR(TSS_E_FAIL);
#endif
}

TSS_RESULT
obj_policy_set_cb11(TSS_HPOLICY hPolicy, TSS_FLAG type, TSS_FLAG app_data, UINT32 cb)
{
#ifndef __LP64__
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	switch (type) {
		case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			policy->Tspicb_CallbackHMACAuth = (PVOID)cb;
			policy->hmacAppData = (PVOID)app_data;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			policy->Tspicb_CallbackXorEnc = (PVOID)cb;
			policy->xorAppData = (PVOID)app_data;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			policy->Tspicb_CallbackTakeOwnership = (PVOID)cb;
			policy->takeownerAppData = (PVOID)app_data;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
			policy->Tspicb_CallbackChangeAuthAsym = (PVOID)cb;
			policy->changeauthAppData = (PVOID)app_data;
			break;
		default:
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}

	obj_list_put(&policy_list);

	return result;
#else
	return TSPERR(TSS_E_FAIL);
#endif
}

#ifndef TSS_SPEC_COMPLIANCE
TSS_RESULT
obj_policy_set_cb12(TSS_HPOLICY hPolicy, TSS_FLAG flag, BYTE *in)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;
	TSS_CALLBACK *cb = (TSS_CALLBACK *)in;

	if (!cb)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	switch (flag) {
		case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			policy->Tspicb_CallbackHMACAuth =
				(TSS_RESULT (*)(PVOID, TSS_HOBJECT, TSS_BOOL,
				UINT32, TSS_BOOL, UINT32, BYTE *, BYTE *,
				BYTE *, BYTE *, UINT32, BYTE *, BYTE *))
				cb->callback;
			policy->hmacAppData = cb->appData;
			policy->hmacAlg = cb->alg;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			policy->Tspicb_CallbackXorEnc =
				(TSS_RESULT (*)(PVOID, TSS_HOBJECT,
				TSS_HOBJECT, TSS_FLAG, UINT32, BYTE *, BYTE *,
				BYTE *, BYTE *, UINT32, BYTE *, BYTE *))
				cb->callback;
			policy->xorAppData = cb->appData;
			policy->xorAlg = cb->alg;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			policy->Tspicb_CallbackTakeOwnership =
				(TSS_RESULT (*)(PVOID, TSS_HOBJECT, TSS_HKEY,
				UINT32, BYTE *))cb->callback;
			policy->takeownerAppData = cb->appData;
			policy->takeownerAlg = cb->alg;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
			policy->Tspicb_CallbackChangeAuthAsym =
				(TSS_RESULT (*)(PVOID, TSS_HOBJECT, TSS_HKEY,
				UINT32, UINT32, BYTE *, BYTE *))cb->callback;
			policy->changeauthAppData = cb->appData;
			policy->changeauthAlg = cb->alg;
			break;
		default:
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}

	obj_list_put(&policy_list);

	return result;
}

TSS_RESULT
obj_policy_get_cb12(TSS_HPOLICY hPolicy, TSS_FLAG flag, UINT32 *size, BYTE **out)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	TSS_RESULT result = TSS_SUCCESS;
	TSS_CALLBACK *cb;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	if ((cb = calloc_tspi(obj->tspContext, sizeof(TSS_CALLBACK))) == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TSS_CALLBACK));
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}

	switch (flag) {
		case TSS_TSPATTRIB_POLICY_CALLBACK_HMAC:
			cb->callback = policy->Tspicb_CallbackHMACAuth;
			cb->appData = policy->hmacAppData;
			cb->alg = policy->hmacAlg;
			*size = sizeof(TSS_CALLBACK);
			*out = (BYTE *)cb;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC:
			cb->callback = policy->Tspicb_CallbackXorEnc;
			cb->appData = policy->xorAppData;
			cb->alg = policy->xorAlg;
			*size = sizeof(TSS_CALLBACK);
			*out = (BYTE *)cb;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP:
			cb->callback = policy->Tspicb_CallbackTakeOwnership;
			cb->appData = policy->takeownerAppData;
			cb->alg = policy->takeownerAlg;
			*size = sizeof(TSS_CALLBACK);
			*out = (BYTE *)cb;
			break;
		case TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM:
			cb->callback = policy->Tspicb_CallbackChangeAuthAsym;
			cb->appData = policy->changeauthAppData;
			cb->alg = policy->changeauthAlg;
			*size = sizeof(TSS_CALLBACK);
			*out = (BYTE *)cb;
			break;
		default:
			free_tspi(obj->tspContext, cb);
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}
done:
	obj_list_put(&policy_list);

	return result;
}
#endif

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

/* return a unicode string to the Tspi_GetAttribData function */
TSS_RESULT
obj_policy_get_string(TSS_HPOLICY hPolicy, UINT32 *size, BYTE **data)
{
	TSS_RESULT result = TSS_SUCCESS;
	BYTE *utf_string;
	UINT32 utf_size;
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;

	*size = policy->popupStringLength;
	if (policy->popupStringLength == 0) {
		*data = NULL;
	} else {
		utf_size = policy->popupStringLength;
		utf_string = Trspi_Native_To_UNICODE(policy->popupString,
						     &utf_size);
		if (utf_string == NULL) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*data = calloc_tspi(obj->tspContext, utf_size);
		if (*data == NULL) {
			free(utf_string);
			LogError("malloc of %d bytes failed.", utf_size);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		*size = utf_size;
		memcpy(*data, utf_string, utf_size);
		free(utf_string);
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

	free(policy->popupString);
	policy->popupString = data;
	policy->popupStringLength = size;

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

#ifndef TSS_SPEC_COMPLIANCE
TSS_RESULT
obj_policy_get_hash_mode(TSS_HPOLICY hPolicy, UINT32 *mode)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	*mode = policy->hashMode;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_policy_set_hash_mode(TSS_HPOLICY hPolicy, UINT32 mode)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;

	switch (mode) {
		case TSS_TSPATTRIB_HASH_MODE_NULL:
		case TSS_TSPATTRIB_HASH_MODE_NOT_NULL:
			break;
		default:
			return TSPERR(TSS_E_INVALID_ATTRIB_DATA);
	}

	if ((obj = obj_list_get_obj(&policy_list, hPolicy)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	policy = (struct tr_policy_obj *)obj->data;
	policy->hashMode = mode;

	obj_list_put(&policy_list);

	return TSS_SUCCESS;
}
#endif
