
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
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
obj_regdkey_add(TSS_UUID *uuid, TSS_UUID *parent_uuid, UINT32 parent_ps_type,
		BYTE *blob, TSS_HOBJECT *phObject)
{
	TSS_RESULT result;
	UINT16 offset = 0;
	struct tr_regdkey_obj *regdkey;

	if ((regdkey = calloc(1, sizeof(struct tr_regdkey_obj))) == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct tr_regdkey_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if ((result = Trspi_UnloadBlob_KEY(&offset, blob, &regdkey->tcpaKey))) {
		free(regdkey);
		return result;
	}

	memcpy(&regdkey->uuid, uuid, sizeof(TSS_UUID));
	memcpy(&regdkey->parent_uuid, parent_uuid, sizeof(TSS_UUID));

	/* 0 here is the TSP context, there is none associated with a registered key. Since
	 * no flags are needed for the object, the parent_ps_type is kept there. */
	if ((result = obj_list_add(&regdkey_list, 0, parent_ps_type, regdkey, phObject))) {
		free(regdkey);
		return result;
	}

	return TSS_SUCCESS;
}

void
regdkey_free(struct tr_regdkey_obj *regdkey)
{
	free(regdkey->tcpaKey.algorithmParms.parms);
	free(regdkey->tcpaKey.encData);
	free(regdkey->tcpaKey.PCRInfo);
	free(regdkey->tcpaKey.pubKey.key);
	free(regdkey);
}

TSS_RESULT
obj_regdkey_remove(TSS_UUID *uuid)
{
	struct tsp_object *obj, *prev = NULL;
	struct obj_list *list = &regdkey_list;
	struct tr_regdkey_obj *regdkey;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; prev = obj, obj = obj->next) {
		regdkey = (struct tr_regdkey_obj *)obj->data;
		if (!memcmp(uuid, &regdkey->uuid, sizeof(TSS_UUID))) {

			regdkey_free(obj->data);
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

TSS_RESULT
obj_regdkey_get_by_pub(TSS_HCONTEXT tspContext, UINT32 pub_size, BYTE *pub, TSS_HKEY *phKey)
{
	struct obj_list *list = &regdkey_list;
	struct tsp_object *obj;
	struct tr_regdkey_obj *regdkey;
	TSS_RESULT result = TSS_SUCCESS;

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; obj = obj->next) {
		regdkey = (struct tr_regdkey_obj *)obj->data;

		if (regdkey->tcpaKey.pubKey.keyLength == pub_size &&
		    !memcmp(&regdkey->tcpaKey.pubKey.key, pub, pub_size)) {
			result = obj_rsakey_add_by_key(tspContext, &regdkey->uuid,
						       &regdkey->tcpaKey, phKey);
			goto done;
		}
	}

	*phKey = 0;
done:
	pthread_mutex_unlock(&list->lock);

	return result;
}

TSS_RESULT
obj_regdkey_get_parent_uuid(TSS_UUID *uuid, TSS_FLAG *ps_type, TSS_UUID *parent_uuid)
{
	struct tsp_object *obj, *prev = NULL;
	struct obj_list *list = &regdkey_list;
	struct tr_regdkey_obj *regdkey;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; prev = obj, obj = obj->next) {
		regdkey = (struct tr_regdkey_obj *)obj->data;
		if (!memcmp(uuid, &regdkey->uuid, sizeof(TSS_UUID))) {
			*ps_type = obj->flags;
			memcpy(parent_uuid, &regdkey->parent_uuid, sizeof(TSS_UUID));
			goto done;
		}
	}

	result = TSPERR(TSS_E_PS_KEY_NOTFOUND);
done:
	pthread_mutex_unlock(&list->lock);

	return result;
}

/*
 * obj_rsakey_get_registered_keys is the Tspi_Context_GetRegisteredKeysByUUID interface for User
 * PS.
 */
TSS_RESULT
obj_regdkey_get_registered_keys(TSS_UUID *uuid, UINT32 *hier_size, TSS_KM_KEYINFO **key_hier)
{
	struct tsp_object *obj;
	struct obj_list *list = &regdkey_list;
	struct tr_regdkey_obj *regdkey;
	TSS_UUID *search_uuid = uuid, srk_uuid = TSS_UUID_SRK;
	TSS_KM_KEYINFO *kh = NULL;
	UINT32 hs = 0;

	pthread_mutex_lock(&list->lock);

	if (uuid) {
		/* Look for the provided UUID, then its parent and so on up to the SRK */
		for (obj = list->head; obj; obj = obj->next) {
			regdkey = (struct tr_regdkey_obj *)obj->data;

			if (!memcmp(search_uuid, &regdkey->uuid, sizeof(TSS_UUID))) {
				if ((kh = realloc(kh, (hs + 1) * sizeof(TSS_KM_KEYINFO)))
						== NULL) {
					LogDebug("malloc of %zu bytes failed.", (hs + 1) *
						 sizeof(TSS_KM_KEYINFO));
					return TSPERR(TSS_E_OUTOFMEMORY);
				}

				memcpy(&kh[hs].versionInfo, &regdkey->tcpaKey.ver,
				       sizeof(TSS_VERSION));
				memcpy(&kh[hs].keyUUID, &regdkey->uuid, sizeof(TSS_UUID));
				memcpy(&kh[hs].parentKeyUUID, &regdkey->parent_uuid,
				       sizeof(TSS_UUID));
				kh[hs].bAuthDataUsage = regdkey->tcpaKey.authDataUsage;
				kh[hs].fIsLoaded = 0;
				kh[hs].ulVendorDataLength = 0;
				kh[hs].rgbVendorData = NULL;

				/* If this is the SRK we just found, we're done */
				if (!memcmp(search_uuid, &srk_uuid, sizeof(TSS_UUID)))
					break;
				/* Start the search over, this time for the parent uuid
				 * of the key we just searched for */
				search_uuid = &kh[hs].parentKeyUUID;
				obj = list->head;

				hs++;
			}
		}
	} else {
		/* uuid is NULL, so return every key registered */
		for (obj = list->head; obj; obj = obj->next) {
			regdkey = (struct tr_regdkey_obj *)obj->data;

			if ((kh = realloc(kh, (hs + 1) * sizeof(TSS_KM_KEYINFO))) == NULL) {
				LogDebug("malloc of %zu bytes failed.", (hs + 1) *
						sizeof(TSS_KM_KEYINFO));
				return TSPERR(TSS_E_OUTOFMEMORY);
			}

			memcpy(&kh[hs].versionInfo, &regdkey->tcpaKey.ver, sizeof(TSS_VERSION));
			memcpy(&kh[hs].keyUUID, &regdkey->uuid, sizeof(TSS_UUID));
			memcpy(&kh[hs].parentKeyUUID, &regdkey->parent_uuid, sizeof(TSS_UUID));
			kh[hs].bAuthDataUsage = regdkey->tcpaKey.authDataUsage;
			kh[hs].fIsLoaded = 0;
			kh[hs].ulVendorDataLength = 0;
			kh[hs].rgbVendorData = NULL;

			hs++;
		}
	}

	*hier_size = hs;
	*key_hier = kh;

	pthread_mutex_unlock(&list->lock);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_regdkey_get_by_uuid(TSS_HCONTEXT tspContext, TSS_UUID *uuid, TSS_HKEY *hKey)
{
	struct obj_list *list = &regdkey_list;
	struct tsp_object *obj;
	struct tr_regdkey_obj *regdkey;
	TSS_RESULT result = TSS_SUCCESS;

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; obj = obj->next) {
		regdkey = (struct tr_regdkey_obj *)obj->data;

		if (!memcmp(&regdkey->uuid, uuid, sizeof(TSS_UUID))) {
			result = obj_rsakey_add_by_key(tspContext, uuid, &regdkey->tcpaKey, hKey);
			goto done;
		}
	}

	result = TSPERR(TSS_E_PS_KEY_NOTFOUND);
done:
	pthread_mutex_unlock(&list->lock);

	return result;
}

