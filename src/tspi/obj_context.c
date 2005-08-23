
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
#include <wchar.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
obj_context_get_tcs_context(TSS_HCONTEXT hContext,
			    TCS_CONTEXT_HANDLE *tcsContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&context_list, hContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tcsContext = obj->tcsContext;

	obj_list_put(&context_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_context_add(TSS_HOBJECT *phObject)
{
	TSS_RESULT result;
	struct tr_context_obj *context = calloc(1, sizeof(struct tr_context_obj));
	unsigned len = strlen(TSS_LOCALHOST_STRING) + 1;

	if (context == NULL) {
		LogError("malloc of %d bytes failed.",
				sizeof(struct tr_context_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	context->silentMode = TSS_TSPATTRIB_CONTEXT_NOT_SILENT;
	if ((context->machineName = calloc(1, len)) == NULL) {
		LogError("malloc of %d bytes failed", len);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(context->machineName, TSS_LOCALHOST_STRING, len);
	context->machineNameLength = len;

	if ((result = obj_list_add(&context_list, NULL_HCONTEXT, context,
					phObject))) {
		free(context);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_BOOL
obj_is_context(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&context_list, hObject)))
		answer = TRUE;

	obj_list_put(&context_list);

	return answer;
}

TSS_RESULT
obj_context_is_connected(TSS_HCONTEXT tspContext, TCS_CONTEXT_HANDLE *tcsContext)
{
	struct tsp_object *obj;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (obj->tcsContext == NULL_HCONTEXT)
		result = TSPERR(TSS_E_NO_CONNECTION);

	*tcsContext = obj->tcsContext;

	obj_list_put(&context_list);

	return result;
}

TSS_RESULT
obj_context_get_policy(TSS_HCONTEXT tspContext, TSS_HPOLICY *phPolicy)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	context = (struct tr_context_obj *)obj->data;
	*phPolicy = context->policy;

	obj_list_put(&context_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_context_get_machine_name(TSS_HCONTEXT tspContext, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	context = (struct tr_context_obj *)obj->data;

	if (context->machineNameLength == 0) {
		*data = NULL;
		*size = 0;
	} else {
		/* allocate the number of bytes, not UNICODE characters */
		*data = calloc_tspi(obj->tspContext,
				context->machineNameLength * sizeof(UNICODE));
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.",
					context->machineNameLength * sizeof(UNICODE));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		/* return the UNICODE string and the number of _bytes_ in it, not the
		 * number of UNICODE characters in it.
		 */
		*size = context->machineNameLength * sizeof(UNICODE);
		memcpy(*data, context->machineName, *size);
	}

	result = TSS_SUCCESS;

done:
	obj_list_put(&context_list);

	return result;
}

TSS_RESULT
obj_context_set_machine_name(TSS_HCONTEXT tspContext, BYTE *name, UINT32 len)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	context = (struct tr_context_obj *)obj->data;

	free(context->machineName);
	context->machineName = name;
	context->machineNameLength = len;

	obj_list_put(&context_list);

	return TSS_SUCCESS;
}

TSS_BOOL
obj_context_is_silent(TSS_HCONTEXT tspContext)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;
	TSS_BOOL silent = FALSE;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return FALSE;

	context = (struct tr_context_obj *)obj->data;
	if (context->silentMode == TSS_TSPATTRIB_CONTEXT_SILENT)
		silent = TRUE;

	obj_list_put(&context_list);

	return silent;
}

TSS_RESULT
obj_context_set_policy(TSS_HCONTEXT tspContext, TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	context = (struct tr_context_obj *)obj->data;
	context->policy = hPolicy;

	obj_list_put(&context_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_context_get_mode(TSS_HCONTEXT tspContext, UINT32 *mode)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	context = (struct tr_context_obj *)obj->data;
	*mode = context->silentMode;

	obj_list_put(&context_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_context_set_mode(TSS_HCONTEXT tspContext, UINT32 mode)
{
	struct tsp_object *obj;
	struct tr_context_obj *context;

	if ((obj = obj_list_get_obj(&context_list, tspContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	context = (struct tr_context_obj *)obj->data;
	context->silentMode = mode;

	obj_list_put(&context_list);

	return TSS_SUCCESS;
}

/* search the list of all policies bound to context @tspContext. If
 * one is found of type popup, return TRUE, else return FALSE. */
TSS_BOOL
obj_context_has_popups(TSS_HCONTEXT tspContext)
{
	struct tsp_object *obj;
	struct tr_policy_obj *policy;
	struct obj_list *list = &policy_list;
	TSS_BOOL ret = FALSE;

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; obj = obj->next) {
		if (obj->tspContext == tspContext) {
			policy = (struct tr_policy_obj *)obj->data;
			if (policy->SecretMode == TSS_SECRET_MODE_POPUP)
				ret = TRUE;
			break;
		}
	}

	pthread_mutex_unlock(&list->lock);

	return ret;
}

