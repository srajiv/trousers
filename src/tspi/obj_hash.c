
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
obj_hash_add(TSS_HCONTEXT tspContext, UINT32 type, TSS_HOBJECT *phObject)
{
	TSS_RESULT result;
	struct tr_hash_obj *hash = calloc(1, sizeof(struct tr_hash_obj));

	if (hash == NULL) {
		LogError("malloc of %zd bytes failed.",
				sizeof(struct tr_hash_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if ((type == TSS_HASH_SHA1) ||
	    (type == TSS_HASH_DEFAULT)) {
		hash->type = TSS_HASH_SHA1;
		hash->hashSize = 20;
	} else if (type == TSS_HASH_OTHER) {
		hash->type = TSS_HASH_OTHER;
		hash->hashSize = 0;
	}

	if ((result = obj_list_add(&hash_list, tspContext, 0, hash, phObject))) {
		free(hash);
		return result;
	}

	return TSS_SUCCESS;
}

TSS_BOOL
obj_is_hash(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&hash_list, hObject))) {
		answer = TRUE;
		obj_list_put(&hash_list);
	}

	return answer;
}

TSS_RESULT
obj_hash_get_tsp_context(TSS_HHASH hHash, TSS_HCONTEXT *tspContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&hash_list, hHash)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tspContext = obj->tspContext;

	obj_list_put(&hash_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_hash_set_value(TSS_HHASH hHash, UINT32 size, BYTE *value)
{
	struct tsp_object *obj;
	struct tr_hash_obj *hash;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&hash_list, hHash)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	hash = (struct tr_hash_obj *)obj->data;

	if (hash->type != TSS_HASH_OTHER &&
	    size != TCPA_SHA1_160_HASH_LEN) {
		result = TSPERR(TSS_E_HASH_INVALID_LENGTH);
		goto done;
	}

	free(hash->hashData);

	if ((hash->hashData = calloc(1, size)) == NULL) {
		LogError("malloc of %d bytes failed.", size);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	hash->hashSize = size;
	memcpy(hash->hashData, value, size);

done:
	obj_list_put(&hash_list);

	return result;
}

TSS_RESULT
obj_hash_get_value(TSS_HHASH hHash, UINT32 *size, BYTE **value)
{
	struct tsp_object *obj;
	struct tr_hash_obj *hash;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&hash_list, hHash)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	hash = (struct tr_hash_obj *)obj->data;

	if (hash->hashData == NULL) {
		result = TSPERR(TSS_E_HASH_NO_DATA);
		goto done;
	}

	if ((*value = calloc_tspi(obj->tspContext, hash->hashSize)) == NULL) {
		LogError("malloc of %d bytes failed.", hash->hashSize);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	*size = hash->hashSize;
	memcpy(*value, hash->hashData, *size);

done:
	obj_list_put(&hash_list);

	return result;
}

TSS_RESULT
obj_hash_update_value(TSS_HHASH hHash, UINT32 size, BYTE *data)
{
	struct tsp_object *obj;
	struct tr_hash_obj *hash;
	TSS_RESULT result = TSS_SUCCESS;

	if ((obj = obj_list_get_obj(&hash_list, hHash)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	hash = (struct tr_hash_obj *)obj->data;

	if (hash->type != TSS_HASH_SHA1 &&
	    hash->type != TSS_HASH_DEFAULT) {
		result = TSPERR(TSS_E_FAIL);
		goto done;
	}

	if (hash->hashUpdateBuffer == NULL) {
		hash->hashUpdateBuffer = calloc(1, size);
		if (hash->hashUpdateBuffer == NULL) {
			LogError("malloc of %u bytes failed.", size);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	} else {
		hash->hashUpdateBuffer = realloc(hash->hashUpdateBuffer,
				size + hash->hashUpdateSize);

		if (hash->hashUpdateBuffer == NULL) {
			LogError("malloc of %u bytes failed.", size + hash->hashUpdateSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	}

	memcpy(&hash->hashUpdateBuffer[hash->hashUpdateSize], data, size);
	hash->hashUpdateSize += size;

	if (hash->hashData == NULL) {
		hash->hashData = calloc(1, TCPA_SHA1_160_HASH_LEN);
		if (hash->hashData == NULL) {
			LogError("malloc of %d bytes failed.", TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	}

	result = Trspi_Hash(TSS_HASH_SHA1, hash->hashUpdateSize, hash->hashUpdateBuffer,
			    hash->hashData);

done:
	obj_list_put(&hash_list);

	return result;
}

void
hash_free(struct tr_hash_obj *hash)
{
	free(hash->hashData);
	free(hash->hashUpdateBuffer);
	free(hash);
}

/*
 * remove hash object hObject from the list
 */
TSS_RESULT
obj_hash_remove(TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
	struct tsp_object *obj, *prev = NULL;
	struct obj_list *list = &hash_list;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; prev = obj, obj = obj->next) {
		if (obj->handle == hObject) {
			/* validate tspContext */
			if (obj->tspContext != tspContext)
				break;

			hash_free(obj->data);
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

/*
 * remove all objects in the list with a TSP context matching tspContext
 */
void
obj_list_hash_close(struct obj_list *list, TSS_HCONTEXT tspContext)
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

			hash_free(toKill->data);
			free(toKill);

			index = next;
		} else {
			prev = index;
			index = next;
		}
	}

	pthread_mutex_unlock(&list->lock);
}
