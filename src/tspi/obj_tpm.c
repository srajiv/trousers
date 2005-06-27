
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
		LogError("malloc of %d bytes failed.",
				sizeof(struct tr_tpm_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	/* add usage policy */
	if ((result = obj_policy_add(tspContext, TSS_POLICY_USAGE,
					&tpm->policy))) {
		free(tpm);
		return result;
	}

	if ((result = obj_list_add(&tpm_list, tspContext, tpm,
					phObject))) {
		free(tpm);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_BOOL
obj_is_tpm(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&tpm_list, hObject)))
		answer = TRUE;

	obj_list_put(&tpm_list);

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
