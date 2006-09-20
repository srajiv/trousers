
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
obj_tpm_add(TSS_HCONTEXT tspContext, TSS_HOBJECT *phObject)
{
	TSS_RESULT result;
	struct tr_tpm_obj *tpm = calloc(1, sizeof(struct tr_tpm_obj));

	if (tpm == NULL) {
		LogError("malloc of %zd bytes failed.",
				sizeof(struct tr_tpm_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	/* add usage policy */
	if ((result = obj_policy_add(tspContext, TSS_POLICY_USAGE,
					&tpm->policy))) {
		free(tpm);
		return result;
	}

	if ((result = obj_list_add(&tpm_list, tspContext, 0, tpm, phObject))) {
		free(tpm);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_BOOL
obj_is_tpm(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&tpm_list, hObject))) {
		answer = TRUE;
		obj_list_put(&tpm_list);
	}

	return answer;
}

TSS_RESULT
obj_tpm_set_policy(TSS_HTPM hTpm, TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_tpm_obj *tpm;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	tpm = (struct tr_tpm_obj *)obj->data;
	tpm->policy = hPolicy;

	obj_list_put(&tpm_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_tpm_get_policy(TSS_HTPM hTpm, TSS_HPOLICY *phPolicy)
{
	struct tsp_object *obj;
	struct tr_tpm_obj *tpm;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	tpm = (struct tr_tpm_obj *)obj->data;
	*phPolicy = tpm->policy;

	obj_list_put(&tpm_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_tpm_is_connected(TSS_HTPM hTpm, TSS_HCONTEXT *tcsContext)
{
	struct tsp_object *obj;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (obj->tcsContext == NULL_HCONTEXT)
		result = TSPERR(TSS_E_NO_CONNECTION);

	*tcsContext = obj->tcsContext;

	obj_list_put(&tpm_list);

	return result;
}

TSS_RESULT
obj_tpm_get_tsp_context(TSS_HTPM hTpm, TSS_HCONTEXT *tspContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tspContext = obj->tspContext;

	obj_list_put(&tpm_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_tpm_get_tcs_context(TSS_HTPM hTpm,
			TCS_CONTEXT_HANDLE *tcsContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tcsContext = obj->tcsContext;

	obj_list_put(&tpm_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_tpm_get(TSS_HCONTEXT tspContext, TSS_HTPM *phTpm)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_tspcontext(&tpm_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*phTpm = obj->handle;

	obj_list_put(&tpm_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_tpm_get_cb11(TSS_HTPM hTpm, TSS_FLAG type, UINT32 *cb)
{
#ifndef __LP64__
	struct tsp_object *obj;
	struct tr_tpm_obj *tpm;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	tpm = (struct tr_tpm_obj *)obj->data;

	switch (type) {
		case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			*cb = (UINT32)tpm->Tspicb_CollateIdentity;
			break;
		case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
			*cb = (UINT32)tpm->Tspicb_ActivateIdentity;
			break;
		default:
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}

	obj_list_put(&tpm_list);

	return result;
#else
	return TSPERR(TSS_E_FAIL);
#endif
}

TSS_RESULT
obj_tpm_set_cb11(TSS_HTPM hTpm, TSS_FLAG type, TSS_FLAG app_data, UINT32 cb)
{
#ifndef __LP64__
	struct tsp_object *obj;
	struct tr_tpm_obj *tpm;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	tpm = (struct tr_tpm_obj *)obj->data;

	switch (type) {
		case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			tpm->Tspicb_CollateIdentity = (PVOID)cb;
			tpm->collateAppData = (PVOID)app_data;
			break;
		case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
			tpm->Tspicb_ActivateIdentity = (PVOID)cb;
			tpm->activateAppData = (PVOID)app_data;
			break;
		default:
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}

	obj_list_put(&tpm_list);

	return result;
#else
	return TSPERR(TSS_E_FAIL);
#endif
}

#ifndef TSS_SPEC_COMPLIANCE
TSS_RESULT
obj_tpm_set_cb12(TSS_HTPM hTpm, TSS_FLAG flag, BYTE *in)
{
	struct tsp_object *obj;
	struct tr_tpm_obj *tpm;
	TSS_RESULT result = TSS_SUCCESS;
	TSS_CALLBACK *cb = (TSS_CALLBACK *)in;

	if (!cb)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	tpm = (struct tr_tpm_obj *)obj->data;

	switch (flag) {
		case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			tpm->Tspicb_CollateIdentity = (TSS_RESULT (*)(PVOID,
				UINT32, BYTE *, TSS_ALGORITHM_ID, UINT32 *,
				BYTE *, UINT32 *, BYTE *))cb->callback;
			tpm->collateAppData = cb->appData;
			tpm->collateAlg = cb->alg;
			break;
		case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
			tpm->Tspicb_ActivateIdentity = (TSS_RESULT (*)(PVOID,
				UINT32, BYTE *, UINT32, BYTE *, UINT32 *,
				BYTE *))cb->callback;
			tpm->activateAppData = cb->appData;
			tpm->activateAlg = cb->alg;
			break;
		default:
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}

	obj_list_put(&tpm_list);

	return result;
}

TSS_RESULT
obj_tpm_get_cb12(TSS_HTPM hTpm, TSS_FLAG flag, UINT32 *size, BYTE **out)
{
	struct tsp_object *obj;
	struct tr_tpm_obj *tpm;
	TSS_RESULT result = TSS_SUCCESS;
	TSS_CALLBACK *cb;

	if ((obj = obj_list_get_obj(&tpm_list, hTpm)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	tpm = (struct tr_tpm_obj *)obj->data;

	if ((cb = calloc_tspi(obj->tspContext, sizeof(TSS_CALLBACK))) == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TSS_CALLBACK));
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}

	switch (flag) {
		case TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY:
			cb->callback = tpm->Tspicb_CollateIdentity;
			cb->appData = tpm->collateAppData;
			cb->alg = tpm->collateAlg;
			*size = sizeof(TSS_CALLBACK);
			*out = (BYTE *)cb;
			break;
		case TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY:
			cb->callback = tpm->Tspicb_ActivateIdentity;
			cb->appData = tpm->activateAppData;
			cb->alg = tpm->activateAlg;
			*size = sizeof(TSS_CALLBACK);
			*out = (BYTE *)cb;
			break;
		default:
			free_tspi(obj->tspContext, cb);
			result = TSPERR(TSS_E_INVALID_ATTRIB_FLAG);
			break;
	}
done:
	obj_list_put(&tpm_list);

	return result;
}
#endif
