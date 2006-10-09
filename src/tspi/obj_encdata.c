
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
obj_encdata_add(TSS_HCONTEXT tspContext, UINT32 type, TSS_HOBJECT *phObject)
{
	TSS_RESULT result;
	struct tr_encdata_obj *encdata = calloc(1, sizeof(struct tr_encdata_obj));

	if (encdata == NULL) {
		LogError("malloc of %zd bytes failed.",
				sizeof(struct tr_encdata_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	/* add usage policy */
	if ((result = obj_policy_add(tspContext, TSS_POLICY_USAGE,
					&encdata->usagePolicy))) {
		free(encdata);
		return result;
	}

	/* add migration policy */
	if ((result = obj_policy_add(tspContext, TSS_POLICY_MIGRATION,
					&encdata->migPolicy))) {
		free(encdata);
		return result;
	}

	encdata->type = type;

	if ((result = obj_list_add(&encdata_list, tspContext, 0, encdata, phObject))) {
		free(encdata);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_BOOL
obj_is_encdata(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&encdata_list, hObject))) {
		answer = TRUE;
		obj_list_put(&encdata_list);
	}

	return answer;
}

TSS_RESULT
obj_encdata_get_tsp_context(TSS_HENCDATA hEncdata, TSS_HCONTEXT *tspContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&encdata_list, hEncdata)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tspContext = obj->tspContext;

	obj_list_put(&encdata_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_encdata_is_connected(TSS_HENCDATA hEncdata, TCS_CONTEXT_HANDLE *tcsContext)
{
	struct tsp_object *obj;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&encdata_list, hEncdata)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (obj->tcsContext == NULL_HCONTEXT)
		result = TSPERR(TSS_E_NO_CONNECTION);

	*tcsContext = obj->tcsContext;

	obj_list_put(&encdata_list);

	return result;
}

TSS_RESULT
obj_encdata_get_policy(TSS_HENCDATA hEncData, UINT32 type, TSS_HPOLICY *phPolicy)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	if (type == TSS_POLICY_USAGE)
		*phPolicy = encdata->usagePolicy;
	else
		*phPolicy = encdata->migPolicy;

	obj_list_put(&encdata_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_encdata_set_policy(TSS_HENCDATA hEncData, UINT32 type, TSS_HPOLICY hPolicy)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	if (type == TSS_POLICY_USAGE)
		encdata->usagePolicy = hPolicy;
	else
		encdata->migPolicy = hPolicy;

	obj_list_put(&encdata_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_encdata_get_data(TSS_HENCDATA hEncData, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	if (encdata->encryptedDataLength == 0) {
		result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
		goto done;
	} else {
		*data = calloc_tspi(obj->tspContext, encdata->encryptedDataLength);
		if (*data == NULL) {
			LogError("malloc of %d bytes failed.",
					encdata->encryptedDataLength);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = encdata->encryptedDataLength;
		memcpy(*data, encdata->encryptedData, *size);
	}

done:
	obj_list_put(&encdata_list);

	return result;
}

TSS_RESULT
obj_encdata_get_pcr_atcreation(TSS_HENCDATA hEncData, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	if ((obj->flags & TSS_OBJ_FLAG_PCRS) == FALSE) {
		*data = NULL;
		*size = 0;
	} else {
		*data = calloc_tspi(obj->tspContext, sizeof(TCPA_DIGEST));
		if (*data == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(TCPA_DIGEST));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = sizeof(TCPA_DIGEST);
		memcpy(*data, &encdata->pcrInfo.digestAtCreation,
				sizeof(TCPA_DIGEST));
	}

done:
	obj_list_put(&encdata_list);

	return result;
}

TSS_RESULT
obj_encdata_get_pcr_atrelease(TSS_HENCDATA hEncData, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	if ((obj->flags & TSS_OBJ_FLAG_PCRS) == FALSE) {
		*data = NULL;
		*size = 0;
	} else {
		*data = calloc_tspi(obj->tspContext, sizeof(TCPA_DIGEST));
		if (*data == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(TCPA_DIGEST));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*size = sizeof(TCPA_DIGEST);
		memcpy(*data, &encdata->pcrInfo.digestAtRelease,
				sizeof(TCPA_DIGEST));
	}

done:
	obj_list_put(&encdata_list);

	return result;
}

TSS_RESULT
obj_encdata_get_pcr_selection(TSS_HENCDATA hEncData, UINT32 *size, BYTE **data)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	if ((obj->flags & TSS_OBJ_FLAG_PCRS) == FALSE) {
		*data = NULL;
		*size = 0;
	} else {
		if (encdata->pcrInfo.pcrSelection.sizeOfSelect == 0) {
			*data = NULL;
			*size = 0;
		} else {
			*data = calloc_tspi(obj->tspContext,
					encdata->pcrInfo.pcrSelection.sizeOfSelect);
			if (*data == NULL) {
				LogError("malloc of %d bytes failed.",
					 encdata->pcrInfo.pcrSelection.sizeOfSelect);
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto done;
			}
			*size = encdata->pcrInfo.pcrSelection.sizeOfSelect;
			memcpy(*data, encdata->pcrInfo.pcrSelection.pcrSelect, *size);
		}
	}

done:
	obj_list_put(&encdata_list);

	return result;
}

TSS_RESULT
obj_encdata_set_pcr_info(TSS_HENCDATA hEncData, BYTE *info_blob)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;
	TSS_RESULT result;
	UINT16 offset;

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	free(encdata->pcrInfo.pcrSelection.pcrSelect);

	offset = 0;
	result = Trspi_UnloadBlob_PCR_INFO(&offset, info_blob, &encdata->pcrInfo);
	obj->flags |= TSS_OBJ_FLAG_PCRS;

	obj_list_put(&encdata_list);

	return result;
}

TSS_RESULT
obj_encdata_set_data(TSS_HENCDATA hEncData, UINT32 size, BYTE *data)
{
	struct tsp_object *obj;
	struct tr_encdata_obj *encdata;

	/* XXX hard-coded */
	if (size > 512)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((obj = obj_list_get_obj(&encdata_list, hEncData)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	encdata = (struct tr_encdata_obj *)obj->data;

	encdata->encryptedDataLength = size;
	memcpy(encdata->encryptedData, data, size);

	obj_list_put(&encdata_list);

	return TSS_SUCCESS;
}

void
encdata_free(struct tr_encdata_obj *encdata)
{
	free(encdata->pcrInfo.pcrSelection.pcrSelect);
	free(encdata);
}

/* remove an individual encdata object from the encdata list with handle
 * equal to hObject */
TSS_RESULT
obj_encdata_remove(TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
	struct tsp_object *obj, *prev = NULL;
	struct obj_list *list = &encdata_list;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; prev = obj, obj = obj->next) {
		if (obj->handle == hObject) {
			/* validate tspContext */
			if (obj->tspContext != tspContext)
				break;

			encdata_free(obj->data);
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
obj_list_encdata_close(struct obj_list *list, TSS_HCONTEXT tspContext)
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

			encdata_free(toKill->data);
			free(toKill);

			index = next;
		} else {
			prev = index;
			index = next;
		}
	}

	pthread_mutex_unlock(&list->lock);
}
