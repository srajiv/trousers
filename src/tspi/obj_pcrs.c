
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

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
obj_pcrs_add(TSS_HCONTEXT tspContext, UINT32 type, TSS_HOBJECT *phObject)
{
	TSS_RESULT result;
	UINT32 ver;
	struct tr_pcrs_obj *pcrs;

	if ((pcrs = calloc(1, sizeof(struct tr_pcrs_obj))) == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct tr_pcrs_obj));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if (type == TSS_PCRS_STRUCT_DEFAULT) {
		if ((result = obj_context_get_connection_version(tspContext, &ver))) {
			free(pcrs);
			return result;
		}

		switch (ver) {
			case TSS_TSPATTRIB_CONTEXT_VERSION_V1_2:
				pcrs->type = TSS_PCRS_STRUCT_INFO_LONG;
				break;
			case TSS_TSPATTRIB_CONTEXT_VERSION_V1_1:
				/* fall through */
			default:
				pcrs->type = TSS_PCRS_STRUCT_INFO;
				break;
		}
	} else
		pcrs->type = type;

	if ((result = obj_list_add(&pcrs_list, tspContext, 0, pcrs, phObject))) {
		free(pcrs);
		return result;
	}

	return TSS_SUCCESS;
}

void
free_pcrs(struct tr_pcrs_obj *pcrs)
{
	switch (pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			free(pcrs->info.info11.pcrSelection.pcrSelect);
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			free(pcrs->info.infoshort.pcrSelection.pcrSelect);
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			free(pcrs->info.infolong.creationPCRSelection.pcrSelect);
			free(pcrs->info.infolong.releasePCRSelection.pcrSelect);
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			break;
	}

	free(pcrs);
}

TSS_RESULT
obj_pcrs_remove(TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
        struct tsp_object *obj, *prev = NULL;
	struct obj_list *list = &pcrs_list;
        TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

        MUTEX_LOCK(list->lock);

        for (obj = list->head; obj; prev = obj, obj = obj->next) {
                if (obj->handle == hObject) {
			/* validate tspContext */
			if (obj->tspContext != tspContext)
				break;

                        free_pcrs(obj->data);
                        if (prev)
                                prev->next = obj->next;
                        else
                                list->head = obj->next;
                        free(obj);
                        result = TSS_SUCCESS;
                        break;
                }
        }

        MUTEX_UNLOCK(list->lock);

        return result;

}

TSS_BOOL
obj_is_pcrs(TSS_HOBJECT hObject)
{
	TSS_BOOL answer = FALSE;

	if ((obj_list_get_obj(&pcrs_list, hObject))) {
		answer = TRUE;
		obj_list_put(&pcrs_list);
	}

	return answer;
}

TSS_RESULT
obj_pcrs_get_tsp_context(TSS_HTPM hPcrs, TSS_HCONTEXT *tspContext)
{
	struct tsp_object *obj;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	*tspContext = obj->tspContext;

	obj_list_put(&pcrs_list);

	return TSS_SUCCESS;
}

TSS_RESULT
obj_pcrs_get_selection(TSS_HPCRS hPcrs, UINT32 *size, BYTE *out)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *tmp;
	UINT64 offset = 0;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch (pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			tmp = &pcrs->info.info11.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			tmp = &pcrs->info.infoshort.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			tmp = &pcrs->info.infolong.creationPCRSelection;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
	}

	Trspi_LoadBlob_PCR_SELECTION(&offset, out, tmp);
	*size = offset;
done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_set_values(TSS_HPCRS hPcrs, TPM_PCR_COMPOSITE *pcrComp)
{
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *select = &(pcrComp->select);
	UINT16 i, val_idx = 0;

	for (i = 0; i < select->sizeOfSelect * 8; i++) {
		if (select->pcrSelect[i / 8] & (1 << (i % 8))) {
			if ((result = obj_pcrs_set_value(hPcrs, i, TCPA_SHA1_160_HASH_LEN,
							 (BYTE *)&pcrComp->pcrValue[val_idx])))
				break;

			val_idx++;
		}
	}

	return result;
}

TSS_RESULT
obj_pcrs_set_value(TSS_HPCRS hPcrs, UINT32 idx, UINT32 size, BYTE *value)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *select;
	UINT16 bytes_to_hold = (idx / 8) + 1;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			select = &pcrs->info.info11.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			select = &pcrs->info.infoshort.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			select = &pcrs->info.infolong.creationPCRSelection;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	/* allocate the selection structure */
	if (select->pcrSelect == NULL) {
		if ((select->pcrSelect = malloc(bytes_to_hold)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		select->sizeOfSelect = bytes_to_hold;
		memset(select->pcrSelect, 0, bytes_to_hold);

		/* allocate the pcr array */
		if ((pcrs->pcrs = malloc(bytes_to_hold * 8 *
					 TCPA_SHA1_160_HASH_LEN)) == NULL) {
			LogError("malloc of %d bytes failed.",
				bytes_to_hold * 8 * TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	} else if (select->sizeOfSelect < bytes_to_hold) {
		if ((select->pcrSelect = realloc(select->pcrSelect, bytes_to_hold)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		/* set the newly allocated bytes to 0 */
		memset(&select->pcrSelect[select->sizeOfSelect], 0,
				bytes_to_hold - select->sizeOfSelect);
		select->sizeOfSelect = bytes_to_hold;

		/* realloc the pcrs array */
		if ((pcrs->pcrs = realloc(pcrs->pcrs, bytes_to_hold * 8 *
					  sizeof(TPM_PCRVALUE))) == NULL) {
			LogError("malloc of %d bytes failed.",
					bytes_to_hold * 8 * TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	}

	/* set the bit in the selection structure */
	select->pcrSelect[idx / 8] |= (1 << (idx % 8));

	/* set the value in the pcrs array */
	memcpy(&(pcrs->pcrs[idx]), value, size);
done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_get_value(TSS_HPCRS hPcrs, UINT32 idx, UINT32 *size, BYTE **value)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *select;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			select = &pcrs->info.info11.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			select = &pcrs->info.infoshort.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			select = &pcrs->info.infolong.creationPCRSelection;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	if (select->sizeOfSelect < (idx / 8) + 1) {
		result = TSPERR(TSS_E_BAD_PARAMETER);
		goto done;
	}

	if ((*value = calloc_tspi(obj->tspContext, TCPA_SHA1_160_HASH_LEN)) == NULL) {
		LogError("malloc of %d bytes failed.", TCPA_SHA1_160_HASH_LEN);
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}

	*size = TCPA_SHA1_160_HASH_LEN;
	memcpy(*value, &pcrs->pcrs[idx], TCPA_SHA1_160_HASH_LEN);

done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_get_digest_at_creation(TSS_HPCRS hPcrs, TCPA_PCRVALUE *comp)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *select;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			select = &pcrs->info.info11.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			select = &pcrs->info.infoshort.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			select = &pcrs->info.infolong.creationPCRSelection;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	if ((result = pcrs_sanity_check_selection(obj->tspContext, pcrs, select)))
		goto done;

	result = pcrs_calc_composite(select, pcrs->pcrs, comp);

done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_get_digest_at_release(TSS_HPCRS hPcrs, UINT32 *size, BYTE **out)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	BYTE *digest;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
			goto done;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			digest = (BYTE *)&pcrs->info.infoshort.digestAtRelease;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			digest = (BYTE *)&pcrs->info.infolong.digestAtRelease;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	if ((*out = calloc_tspi(obj->tspContext, sizeof(TPM_COMPOSITE_HASH))) == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TPM_COMPOSITE_HASH));
		result = TSPERR(TSS_E_OUTOFMEMORY);
		goto done;
	}
	memcpy(*out, digest, sizeof(TPM_COMPOSITE_HASH));
	*size = sizeof(TPM_COMPOSITE_HASH);

done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_select_index(TSS_HPCRS hPcrs, UINT32 idx)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *select;
	UINT16 bytes_to_hold = (idx / 8) + 1;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			select = &pcrs->info.info11.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
		case TSS_PCRS_STRUCT_INFO_LONG:
			result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
			goto done;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	/* allocate the selection structure */
	if (select->pcrSelect == NULL) {
		if ((select->pcrSelect = malloc(bytes_to_hold)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		select->sizeOfSelect = bytes_to_hold;
		memset(select->pcrSelect, 0, bytes_to_hold);

		/* alloc the pcrs array */
		if ((pcrs->pcrs = malloc(bytes_to_hold * 8 * TCPA_SHA1_160_HASH_LEN)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold * 8 *
				 TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	} else if (select->sizeOfSelect < bytes_to_hold) {
		if ((select->pcrSelect = realloc(select->pcrSelect, bytes_to_hold)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		/* set the newly allocated bytes to 0 */
		memset(&select->pcrSelect[select->sizeOfSelect], 0,
		       bytes_to_hold - select->sizeOfSelect);
		select->sizeOfSelect = bytes_to_hold;

		/* realloc the pcrs array */
		if ((pcrs->pcrs = realloc(pcrs->pcrs,
					  bytes_to_hold * 8 * TCPA_SHA1_160_HASH_LEN)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold * 8 *
				 TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	}

	/* set the bit in the selection structure */
	select->pcrSelect[idx / 8] |= (1 << (idx % 8));

done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_select_index_ex(TSS_HPCRS hPcrs, UINT32 dir, UINT32 idx)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	TPM_PCR_SELECTION *select;
	UINT16 bytes_to_hold = (idx / 8) + 1;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
			goto done;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			if (dir == TSS_PCRS_DIRECTION_CREATION) {
				result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
				goto done;
			}
			select = &pcrs->info.infoshort.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			if (dir == TSS_PCRS_DIRECTION_CREATION)
				select = &pcrs->info.infolong.creationPCRSelection;
			else
				select = &pcrs->info.infolong.releasePCRSelection;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	/* allocate the selection structure */
	if (select->pcrSelect == NULL) {
		if ((select->pcrSelect = malloc(bytes_to_hold)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		select->sizeOfSelect = bytes_to_hold;
		memset(select->pcrSelect, 0, bytes_to_hold);

		/* alloc the pcrs array */
		if ((pcrs->pcrs = malloc(bytes_to_hold * 8 * TCPA_SHA1_160_HASH_LEN)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold * 8 *
				 TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	} else if (select->sizeOfSelect < bytes_to_hold) {
		if ((select->pcrSelect = realloc(select->pcrSelect, bytes_to_hold)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		/* set the newly allocated bytes to 0 */
		memset(&select->pcrSelect[select->sizeOfSelect], 0,
		       bytes_to_hold - select->sizeOfSelect);
		select->sizeOfSelect = bytes_to_hold;

		/* realloc the pcrs array */
		if ((pcrs->pcrs = realloc(pcrs->pcrs,
					  bytes_to_hold * 8 * TCPA_SHA1_160_HASH_LEN)) == NULL) {
			LogError("malloc of %d bytes failed.", bytes_to_hold * 8 *
				 TCPA_SHA1_160_HASH_LEN);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
	}

	/* set the bit in the selection structure */
	select->pcrSelect[idx / 8] |= (1 << (idx % 8));

done:
	obj_list_put(&pcrs_list);

	return result;
}

/* Create a PCR info struct based on the hPcrs object */
TSS_RESULT
obj_pcrs_create_info(TSS_HPCRS hPcrs, UINT32 *size, BYTE **info)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	UINT64 offset;
	UINT32 ret_size = 0;
	BYTE *ret;
	TPM_PCR_SELECTION *select;
	BYTE *creation_digest = NULL, release_digest[TPM_SHA1_160_HASH_LEN] = { 0, };

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch (pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			ret_size = (UINT32)sizeof(TPM_PCR_INFO);
			select = &pcrs->info.info11.pcrSelection;
			creation_digest = (BYTE *)&pcrs->info.info11.digestAtCreation;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			ret_size = (UINT32)sizeof(TPM_PCR_INFO_LONG);
			select = &pcrs->info.infolong.creationPCRSelection;
			creation_digest = (BYTE *)&pcrs->info.infolong.digestAtCreation;
			break;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			ret_size = (UINT32)sizeof(TPM_PCR_INFO_SHORT);
			select = &pcrs->info.infoshort.pcrSelection;
			break;
		case TSS_PCRS_STRUCT_DEFAULT:
			/* fall through */
		default:
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
			break;
	}

	if ((result = pcrs_calc_composite(select, pcrs->pcrs, (TPM_DIGEST *)creation_digest)))
		goto done;

	if ((ret = calloc(1, ret_size)) == NULL) {
		result = TSPERR(TSS_E_OUTOFMEMORY);
		LogDebug("malloc of %u bytes failed.", ret_size);
		goto done;
	}

	offset = 0;
	if (pcrs->type == TSS_PCRS_STRUCT_INFO) {
		Trspi_LoadBlob_PCR_SELECTION(&offset, ret, select);
		Trspi_LoadBlob(&offset, TPM_SHA1_160_HASH_LEN, ret, creation_digest);
		Trspi_LoadBlob(&offset, TPM_SHA1_160_HASH_LEN, ret, release_digest);
		ret_size = offset;
	} else if (pcrs->type == TSS_PCRS_STRUCT_INFO_LONG) {
		Trspi_LoadBlob_UINT16(&offset, TPM_TAG_PCR_INFO_LONG, ret);
		Trspi_LoadBlob_BYTE(&offset, TPM_LOC_ZERO, ret);
		Trspi_LoadBlob_BYTE(&offset, TPM_LOC_ZERO, ret);
		Trspi_LoadBlob_PCR_SELECTION(&offset, ret, select);
		Trspi_LoadBlob_PCR_SELECTION(&offset, ret, select);
		Trspi_LoadBlob(&offset, TPM_SHA1_160_HASH_LEN, ret, creation_digest);
		Trspi_LoadBlob(&offset, TPM_SHA1_160_HASH_LEN, ret, release_digest);
		ret_size = offset;
	} else if (pcrs->type == TSS_PCRS_STRUCT_INFO_SHORT) {
		Trspi_LoadBlob_PCR_SELECTION(&offset, ret, select);
		Trspi_LoadBlob_BYTE(&offset, TPM_LOC_ZERO, ret);
		Trspi_LoadBlob(&offset, TPM_SHA1_160_HASH_LEN, ret, release_digest);
		ret_size = offset;
	}

	*info = ret;
	*size = ret_size;

done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_get_locality(TSS_HPCRS hPcrs, UINT32 *out)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	BYTE *locality;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
			goto done;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			locality = &pcrs->info.infoshort.localityAtRelease;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			locality = &pcrs->info.infolong.localityAtRelease;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
	}

	*out = (UINT32)*locality;

done:
	obj_list_put(&pcrs_list);

	return result;
}

TSS_RESULT
obj_pcrs_set_locality(TSS_HPCRS hPcrs, UINT32 locality)
{
	struct tsp_object *obj;
	struct tr_pcrs_obj *pcrs;
	TSS_RESULT result = TSS_SUCCESS;
	BYTE *loc;

	if ((obj = obj_list_get_obj(&pcrs_list, hPcrs)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	pcrs = (struct tr_pcrs_obj *)obj->data;

	switch(pcrs->type) {
		case TSS_PCRS_STRUCT_INFO:
			result = TSPERR(TSS_E_INVALID_OBJ_ACCESS);
			goto done;
		case TSS_PCRS_STRUCT_INFO_SHORT:
			loc = &pcrs->info.infoshort.localityAtRelease;
			break;
		case TSS_PCRS_STRUCT_INFO_LONG:
			loc = &pcrs->info.infolong.localityAtRelease;
			break;
		default:
			LogDebugFn("Undefined type of PCRs object");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
	}

	*loc = locality;

done:
	obj_list_put(&pcrs_list);

	return result;
}

