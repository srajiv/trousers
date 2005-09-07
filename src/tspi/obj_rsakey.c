
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
obj_rsakey_add(TSS_HCONTEXT tspContext, TSS_FLAG initFlags, TSS_HOBJECT *phObject)
{
	UINT16 offset;
	TSS_RESULT result;
	TCPA_RSA_KEY_PARMS rsaKeyParms;
	struct tr_rsakey_obj *rsakey = calloc(1, sizeof(struct tr_rsakey_obj));

	if (rsakey == NULL) {
		LogError("malloc of %d bytes failed.",
				sizeof(struct tr_rsakey_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	memset(&rsaKeyParms, 0, sizeof(TCPA_RSA_KEY_PARMS));

	/* add usage policy */
	if ((result = obj_policy_add(tspContext, TSS_POLICY_USAGE,
					&rsakey->usagePolicy))) {
		free(rsakey);
		return result;
	}

	/* add migration policy */
	if ((result = obj_policy_add(tspContext, TSS_POLICY_MIGRATION,
					&rsakey->migPolicy))) {
		obj_policy_remove(rsakey->usagePolicy, tspContext);
		free(rsakey);
		return result;
	}

	if (initFlags & TSS_KEY_EMPTY_KEY)
		goto add_key;

	memcpy(&rsakey->tcpaKey.ver, &VERSION_1_1, sizeof(TCPA_VERSION));

	rsakey->tcpaKey.algorithmParms.algorithmID = TCPA_ALG_RSA;
	rsakey->tcpaKey.algorithmParms.parmSize = sizeof(TCPA_RSA_KEY_PARMS);
	rsakey->tcpaKey.algorithmParms.parms =
					calloc(1, sizeof(TCPA_RSA_KEY_PARMS));

	if (rsakey->tcpaKey.algorithmParms.parms == NULL) {
		LogError("calloc of %d bytes failed.",
				rsakey->tcpaKey.algorithmParms.parmSize);
		obj_policy_remove(rsakey->usagePolicy, tspContext);
		obj_policy_remove(rsakey->migPolicy, tspContext);
		free(rsakey);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	rsaKeyParms.exponentSize = 0;
	rsaKeyParms.numPrimes = 2;
	memset(&rsakey->tcpaKey.keyFlags, 0, sizeof(TCPA_KEY_FLAGS));

	rsakey->tcpaKey.pubKey.keyLength = 0;
	rsakey->tcpaKey.encSize = 0;
	rsakey->privateKey.Privlen = 0;
	rsakey->tcpaKey.PCRInfoSize = 0;
	rsakey->persStorageType = TSS_PS_TYPE_NO;

	/* End of all the default stuff */

	if (initFlags & TSS_KEY_VOLATILE)
		rsakey->tcpaKey.keyFlags |= volatileKey;
	if (initFlags & TSS_KEY_MIGRATABLE)
		rsakey->tcpaKey.keyFlags |= migratable;
	if (initFlags & TSS_KEY_AUTHORIZATION) {
		rsakey->usesAuth = TRUE;
		rsakey->tcpaKey.authDataUsage = TPM_AUTH_ALWAYS;
	} else {
		rsakey->usesAuth = FALSE;
	}

	/* set the key length */
	if ((initFlags & TSS_KEY_SIZE_MASK) == TSS_KEY_SIZE_512) {
		rsaKeyParms.keyLength = 512;
	} else if ((initFlags & TSS_KEY_SIZE_MASK) == TSS_KEY_SIZE_1024) {
		rsaKeyParms.keyLength = 1024;
	} else if ((initFlags & TSS_KEY_SIZE_MASK) == TSS_KEY_SIZE_2048) {
		rsaKeyParms.keyLength = 2048;
	} else if ((initFlags & TSS_KEY_SIZE_MASK) == TSS_KEY_SIZE_4096) {
		rsaKeyParms.keyLength = 4096;
	} else if ((initFlags & TSS_KEY_SIZE_MASK) == TSS_KEY_SIZE_8192) {
		rsaKeyParms.keyLength = 8192;
	} else if ((initFlags & TSS_KEY_SIZE_MASK) == TSS_KEY_SIZE_16384) {
		rsaKeyParms.keyLength = 16384;
	}

	/* assign encryption and signature schemes */
	if ((initFlags & TSS_KEY_TYPE_MASK) == TSS_KEY_TYPE_SIGNING) {
		rsakey->tcpaKey.keyUsage = TPM_KEY_SIGNING;
		rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_NONE;
		rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_RSASSAPKCS1v15_SHA1;
	} else if ((initFlags & TSS_KEY_TYPE_MASK) == TSS_KEY_TYPE_BIND) {
		rsakey->tcpaKey.keyUsage = TPM_KEY_BIND;
		rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;
		rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_NONE;
	} else if ((initFlags & TSS_KEY_TYPE_MASK) == TSS_KEY_TYPE_LEGACY) {
		rsakey->tcpaKey.keyUsage = TPM_KEY_LEGACY;
		rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;
		rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_RSASSAPKCS1v15_SHA1;
	} else if ((initFlags & TSS_KEY_TYPE_MASK) == TSS_KEY_TYPE_STORAGE) {
		rsakey->tcpaKey.keyUsage = TPM_KEY_STORAGE;
		rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;
		rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_NONE;
	} else if ((initFlags & TSS_KEY_TYPE_MASK) == TSS_KEY_TYPE_IDENTITY) {
		rsakey->tcpaKey.keyUsage = TPM_KEY_IDENTITY;
		rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_NONE;
		rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_RSASSAPKCS1v15_SHA1;
	} else if ((initFlags & TSS_KEY_TYPE_MASK) == TSS_KEY_TYPE_AUTHCHANGE) {
		rsakey->tcpaKey.keyUsage = TPM_KEY_AUTHCHANGE;
		rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;
		rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_NONE;
	}

	/* Load the RSA key parms into the blob in the TCPA_KEY_PARMS pointer.
	 * If the exponent is left NULL, the parmSize variable will change
	 * here */
	offset = 0;
	Trspi_LoadBlob_RSA_KEY_PARMS(&offset,
			rsakey->tcpaKey.algorithmParms.parms,
			&rsaKeyParms);
	rsakey->tcpaKey.algorithmParms.parmSize = offset;

add_key:
	if ((result = obj_list_add(&rsakey_list, tspContext, rsakey,
					phObject))) {
		obj_policy_remove(rsakey->usagePolicy, tspContext);
		obj_policy_remove(rsakey->migPolicy, tspContext);
		free(rsakey->tcpaKey.algorithmParms.parms);
		free(rsakey);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_BOOL
obj_is_rsakey(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&rsakey_list, hObject)))
		answer = TRUE;

	obj_list_put(&rsakey_list);

	return answer;
}

TSS_RESULT
obj_rsakey_set_key_parms(TSS_HKEY hKey, TCPA_KEY_PARMS *parms)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	free(rsakey->tcpaKey.algorithmParms.parms);

	memcpy(&rsakey->tcpaKey.algorithmParms, parms, sizeof(TCPA_KEY_PARMS));

	if (parms->parmSize > 0) {
		if ((rsakey->tcpaKey.algorithmParms.parms =
					malloc(parms->parmSize)) == NULL) {
			LogError("calloc of %d bytes failed.", parms->parmSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		memcpy(rsakey->tcpaKey.algorithmParms.parms, parms->parms,
		       parms->parmSize);
	} else {
		rsakey->tcpaKey.algorithmParms.parms = NULL;
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_set_policy(TSS_HKEY hKey, UINT32 type, TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	if (type == TSS_POLICY_USAGE)
		rsakey->usagePolicy = hPolicy;
	else
		rsakey->migPolicy = hPolicy;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_pstype(TSS_HKEY hKey, UINT32 type)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	rsakey->persStorageType = type;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_usage(TSS_HKEY hKey, UINT32 *usage)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	*usage = rsakey->tcpaKey.keyUsage;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_usage(TSS_HKEY hKey, UINT32 usage)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	rsakey->tcpaKey.keyUsage = usage;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_migratable(TSS_HKEY hKey, UINT32 mig)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	if (mig)
		rsakey->tcpaKey.keyFlags |= migratable;
	else
		rsakey->tcpaKey.keyFlags &= (~migratable);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_redirected(TSS_HKEY hKey, UINT32 redir)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	if (redir)
		rsakey->tcpaKey.keyFlags |= redirection;
	else
		rsakey->tcpaKey.keyFlags &= (~redirection);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_volatile(TSS_HKEY hKey, UINT32 vol)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	if (vol)
		rsakey->tcpaKey.keyFlags |= volatileKey;
	else
		rsakey->tcpaKey.keyFlags &= (~volatileKey);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_authdata_usage(TSS_HKEY hKey, UINT32 *usage)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	*usage = (UINT32)rsakey->tcpaKey.authDataUsage;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_authdata_usage(TSS_HKEY hKey, UINT32 usage)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	rsakey->tcpaKey.authDataUsage = (BYTE)usage;
	rsakey->usesAuth = (TSS_BOOL)usage;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_alg(TSS_HKEY hKey, UINT32 *alg)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	*alg = rsakey->tcpaKey.algorithmParms.algorithmID;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_alg(TSS_HKEY hKey, UINT32 alg)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	rsakey->tcpaKey.algorithmParms.algorithmID = alg;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_es(TSS_HKEY hKey, UINT32 *es)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	/* translate TPM numbers to TSS numbers */
	switch (rsakey->tcpaKey.algorithmParms.encScheme) {
		case TCPA_ES_NONE:
			*es = TSS_ES_NONE;
			break;
		case TCPA_ES_RSAESPKCSv15:
			*es = TSS_ES_RSAESPKCSV15;
			break;
		case TCPA_ES_RSAESOAEP_SHA1_MGF1:
			*es = TSS_ES_RSAESOAEP_SHA1_MGF1;
			break;
		default:
			*es = rsakey->tcpaKey.algorithmParms.encScheme;
			break;
	}

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_es(TSS_HKEY hKey, UINT32 es)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	/* translate TSS numbers to TPM numbers */
	switch (es) {
		case TSS_ES_NONE:
			rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_NONE;
			break;
		case TSS_ES_RSAESPKCSV15:
			rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_RSAESPKCSv15;
			break;
		case TSS_ES_RSAESOAEP_SHA1_MGF1:
			rsakey->tcpaKey.algorithmParms.encScheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;
			break;
		default:
			rsakey->tcpaKey.algorithmParms.encScheme = es;
			break;
	}

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_ss(TSS_HKEY hKey, UINT32 *ss)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	/* translate TPM numbers to TSS numbers */
	switch (rsakey->tcpaKey.algorithmParms.sigScheme) {
		case TCPA_SS_NONE:
			*ss = TSS_SS_NONE;
			break;
		case TCPA_SS_RSASSAPKCS1v15_SHA1:
			*ss = TSS_SS_RSASSAPKCS1V15_SHA1;
			break;
		case TCPA_SS_RSASSAPKCS1v15_DER:
			*ss = TSS_SS_RSASSAPKCS1V15_DER;
			break;
		default:
			*ss = rsakey->tcpaKey.algorithmParms.sigScheme;
			break;
	}


	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_ss(TSS_HKEY hKey, UINT32 ss)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	/* translate TSS numbers to TPM numbers */
	switch (ss) {
		case TSS_SS_NONE:
			rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_NONE;
			break;
		case TSS_SS_RSASSAPKCS1V15_SHA1:
			rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_RSASSAPKCS1v15_SHA1;
			break;
		case TSS_SS_RSASSAPKCS1V15_DER:
			rsakey->tcpaKey.algorithmParms.sigScheme = TCPA_SS_RSASSAPKCS1v15_DER;
			break;
		default:
			rsakey->tcpaKey.algorithmParms.sigScheme = ss;
			break;
	}

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_num_primes(TSS_HKEY hKey, UINT32 num)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	UINT32ToArray(num, &rsakey->tcpaKey.algorithmParms.parms[4]);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_num_primes(TSS_HKEY hKey, UINT32 *num)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TCPA_RSA_KEY_PARMS *parms;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	parms = (TCPA_RSA_KEY_PARMS *)rsakey->tcpaKey.algorithmParms.parms;
	*num = endian32(parms->numPrimes);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_flags(TSS_HKEY hKey, UINT32 *flags)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	*flags = rsakey->tcpaKey.keyFlags;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_length(TSS_HKEY hKey, UINT32 *len)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	*len = rsakey->tcpaKey.pubKey.keyLength;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_pstype(TSS_HKEY hKey, UINT32 *type)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	*type = rsakey->persStorageType;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_BOOL
obj_rsakey_is_migratable(TSS_HKEY hKey)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_BOOL answer = FALSE;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return answer;

	rsakey = (struct tr_rsakey_obj *)obj->data;
	if (rsakey->tcpaKey.keyFlags & migratable)
		answer = TRUE;

	obj_list_put(&rsakey_list);

	return answer;
}

TSS_BOOL
obj_rsakey_is_redirected(TSS_HKEY hKey)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_BOOL answer = FALSE;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return answer;

	rsakey = (struct tr_rsakey_obj *)obj->data;
	if (rsakey->tcpaKey.keyFlags & redirection)
		answer = TRUE;

	obj_list_put(&rsakey_list);

	return answer;
}

TSS_BOOL
obj_rsakey_is_volatile(TSS_HKEY hKey)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_BOOL answer = FALSE;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return answer;

	rsakey = (struct tr_rsakey_obj *)obj->data;
	if (rsakey->tcpaKey.keyFlags & volatileKey)
		answer = TRUE;

	obj_list_put(&rsakey_list);

	return answer;
}

TSS_RESULT
obj_rsakey_is_connected(TSS_HKEY hKey, TCS_CONTEXT_HANDLE *tcsContext)
{
	struct tsp_object *obj;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (obj->tcsContext == NULL_HCONTEXT)
		result = TSPERR(TSS_E_NO_CONNECTION);

	*tcsContext = obj->tcsContext;

	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_tsp_context(TSS_HKEY hKey, TSS_HCONTEXT *tspContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tspContext = obj->tspContext;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_policy(TSS_HKEY hKey, TSS_FLAG policyType,
		      TSS_HPOLICY *phPolicy, TSS_BOOL *auth)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	if (policyType == TSS_POLICY_USAGE)
		*phPolicy = rsakey->usagePolicy;
	else
		*phPolicy = rsakey->migPolicy;

	if (auth != NULL)
		*auth = rsakey->usesAuth;

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_get_blob(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;
	BYTE temp[2048];

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	offset = 0;
	Trspi_LoadBlob_KEY(&offset, temp, &rsakey->tcpaKey);

	if (offset > 2048) {
		LogError1("memory corruption");
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	} else {
		*data = calloc_tspi(obj->tspContext, offset);
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = offset;
		memcpy(*data, temp, offset);
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_priv_blob(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	offset = rsakey->tcpaKey.encSize;

	*data = calloc_tspi(obj->tspContext, offset);
	if (*data == NULL) {
		LogError("malloc of %d bytes failed.", offset);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	*size = offset;
	memcpy(*data, rsakey->tcpaKey.encData, offset);

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_pub_blob(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	offset = rsakey->tcpaKey.pubKey.keyLength;

	/* if this key object represents the SRK and the public key
	 * data here is all 0's, then we shouldn't return it, we
	 * should return TSS_E_BAD_PARAMETER. This is part of protecting
	 * the SRK public key. */
	if (getTCSKeyHandle(hKey) == TPM_KEYHND_SRK) {
		BYTE zeroBlob[2048] = { 0, };

		if (!memcmp(rsakey->tcpaKey.pubKey.key, zeroBlob, offset)) {
			result = TSPERR(TSS_E_BAD_PARAMETER);
			goto done;
		}
	}

	*data = calloc_tspi(obj->tspContext, offset);
	if (*data == NULL) {
		LogError("malloc of %d bytes failed.", offset);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	*size = offset;
	memcpy(*data, rsakey->tcpaKey.pubKey.key, offset);

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_version(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;
	BYTE temp[128];

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	offset = 0;
	Trspi_LoadBlob_TCPA_VERSION(&offset, temp, rsakey->tcpaKey.ver);

	if (offset > 128) {
		LogError("memory corruption");
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	} else {
		*data = calloc_tspi(obj->tspContext, offset);
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = offset;
		memcpy(*data, temp, offset);
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_exponent(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	TCPA_RSA_KEY_PARMS *parms;
	BYTE default_exp[3] = { 0x1, 0x0, 0x1 };
	UINT16 offset;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	parms = (TCPA_RSA_KEY_PARMS *)rsakey->tcpaKey.algorithmParms.parms;
	offset = parms->exponentSize;

	/* see TPM 1.1b spec pg. 51. If exponentSize is 0, we're using the
	 * default exponent of 2^16 + 1. */
	if (offset == 0) {
		offset = 3;
		*data = calloc_tspi(obj->tspContext, offset);
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = offset;
		memcpy(*data, default_exp, offset);
	} else {
		*data = calloc_tspi(obj->tspContext, offset);
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = offset;
		memcpy(*data, parms->exponent, offset);
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_uuid(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	BYTE temp[128];
	UINT16 offset;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	offset = 0;
	Trspi_LoadBlob_UUID(&offset, temp, rsakey->uuid);

	if (offset > 128) {
		LogError("memory corruption");
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	}

	*data = calloc_tspi(obj->tspContext, offset);
	if (*data == NULL) {
		LogError("malloc of %d bytes failed.", offset);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	*size = offset;
	memcpy(*data, temp, offset);

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_set_uuid(TSS_HKEY hKey, TSS_UUID *uuid)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;
	memcpy(uuid, &rsakey->uuid, sizeof(TSS_UUID));

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_tcpakey(TSS_HKEY hKey, UINT32 size, BYTE *data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	UINT16 offset;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	offset = 0;
	if ((result = Spi_UnloadBlob_KEY(&offset, data, &rsakey->tcpaKey)))
		goto done;

	rsakey->usesAuth = rsakey->tcpaKey.authDataUsage;

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_pcr_atcreation(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;
	TCPA_PCR_INFO *info;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	if (rsakey->tcpaKey.PCRInfo == NULL) {
		*data = NULL;
		*size = 0;
	} else {
		*data = calloc_tspi(obj->tspContext, sizeof(TCPA_DIGEST));
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", sizeof(TCPA_DIGEST));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = sizeof(TCPA_DIGEST);
		info = (TCPA_PCR_INFO *)rsakey->tcpaKey.PCRInfo;
		offset = 0;
		Trspi_LoadBlob(&offset, sizeof(TCPA_DIGEST), *data,
				(BYTE *)&info->digestAtCreation);
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_pcr_atrelease(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;
	TCPA_PCR_INFO *info;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	if (rsakey->tcpaKey.PCRInfo == NULL) {
		*data = NULL;
		*size = 0;
	} else {
		*data = calloc_tspi(obj->tspContext, sizeof(TCPA_DIGEST));
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", sizeof(TCPA_DIGEST));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = sizeof(TCPA_DIGEST);
		info = (TCPA_PCR_INFO *)rsakey->tcpaKey.PCRInfo;
		offset = 0;
		Trspi_LoadBlob(&offset, sizeof(TCPA_DIGEST), *data,
				(BYTE *)&info->digestAtRelease);
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}

TSS_RESULT
obj_rsakey_get_pcr_selection(TSS_HKEY hKey, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	UINT16 offset;
	TCPA_PCR_INFO *info;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	if (rsakey->tcpaKey.PCRInfo == NULL) {
		*data = NULL;
		*size = 0;
	} else {
		info = (TCPA_PCR_INFO *)rsakey->tcpaKey.PCRInfo;
		offset = info->pcrSelection.sizeOfSelect;
		*data = calloc_tspi(obj->tspContext, offset);
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.", offset);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = offset;
		memcpy(*data, &info->pcrSelection.pcrSelect, *size);
	}

done:
	obj_list_put(&rsakey_list);

	return result;
}


TSS_RESULT
obj_rsakey_set_pubkey(TSS_HKEY hKey, UINT32 size, BYTE *data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	free(rsakey->tcpaKey.pubKey.key);
	rsakey->tcpaKey.pubKey.keyLength = size;

	rsakey->tcpaKey.pubKey.key = calloc(1, size);
	if (rsakey->tcpaKey.pubKey.key == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(rsakey->tcpaKey.pubKey.key, data, size);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_privkey(TSS_HKEY hKey, UINT32 size, BYTE *data)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	free(rsakey->tcpaKey.encData);
	rsakey->tcpaKey.encSize = size;

	rsakey->tcpaKey.encData = calloc(1, size);
	if (rsakey->tcpaKey.encData == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(rsakey->tcpaKey.encData, data, size);

	obj_list_put(&rsakey_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_rsakey_set_pcr_data(TSS_HKEY hKey, TSS_HPCRS hPcrComposite)
{
	struct tsp_object *obj;
	struct tr_rsakey_obj *rsakey;
	TSS_RESULT result = TSS_SUCCESS;
	TCPA_PCR_SELECTION pcrSelect;
	TCPA_PCRVALUE pcrComposite;
	BYTE pcrBlob[1024];
	UINT16 offset;

	memset(pcrBlob, 0, sizeof(pcrBlob));

	if ((obj = obj_list_get_obj(&rsakey_list, hKey)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	rsakey = (struct tr_rsakey_obj *)obj->data;

	/* free the info that may already be set */
	free(rsakey->tcpaKey.PCRInfo);

	if ((result = obj_pcrs_get_composite(hPcrComposite, &pcrComposite)))
		return result;

	if ((result = obj_pcrs_get_selection(hPcrComposite, &pcrSelect)))
		return result;

	offset = 0;
	Trspi_LoadBlob_PCR_SELECTION(&offset, pcrBlob, &pcrSelect);
	memcpy(&pcrBlob[offset], &pcrComposite.digest, TCPA_SHA1_160_HASH_LEN);
	offset += TCPA_SHA1_160_HASH_LEN * 2; // skip over digestAtRelease

	/* ---  Stuff it into the key container */
	rsakey->tcpaKey.PCRInfoSize = offset;
	rsakey->tcpaKey.PCRInfo = calloc(1, offset);
	if (rsakey->tcpaKey.PCRInfo == NULL) {
		LogError("malloc of %d bytes failed.", offset);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	memcpy(rsakey->tcpaKey.PCRInfo, pcrBlob, offset);

done:
	obj_list_put(&rsakey_list);

	return result;
}

void
rsakey_free(struct tr_rsakey_obj *rsakey)
{
	free(rsakey->tcpaKey.algorithmParms.parms);
	free(rsakey->tcpaKey.encData);
	free(rsakey->tcpaKey.PCRInfo);
	free(rsakey->tcpaKey.pubKey.key);
	free(rsakey->privateKey.Privkey);
	free(rsakey);
}

/* remove an individual rsakey object from the rsakey list with handle
 * equal to hObject */
TSS_RESULT
obj_rsakey_remove(TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
	struct tsp_object *obj, *prev = NULL;
	struct obj_list *list = &rsakey_list;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; prev = obj, obj = obj->next) {
		if (obj->handle == hObject) {
			/* validate tspContext */
			if (obj->tspContext != tspContext)
				break;

			rsakey_free(obj->data);
			if (prev)
				prev->next = obj->next;
			else
				list->head = obj->next;
			free(obj);
			result = TSS_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&list->lock);

	return result;
}

void
obj_list_rsakey_close(struct obj_list *list, TSS_HCONTEXT tspContext)
{
	struct tsp_object *index;
	struct tsp_object *next = NULL;
	struct tsp_object *toKill;
	struct tsp_object *prev = NULL;

	pthread_mutex_lock(&list->lock);

	for (index = list->head; index; ) {
		next = index->next;
		if (index->tspContext == tspContext) {
			toKill = index;
			if (prev == NULL) {
				list->head = toKill->next;
			} else {
				prev->next = toKill->next;
			}

			rsakey_free(toKill->data);
			free(toKill);

			index = next;
		} else {
			prev = index;
			index = next;
		}
	}

	pthread_mutex_unlock(&list->lock);
}

