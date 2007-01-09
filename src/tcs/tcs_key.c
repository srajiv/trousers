
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <string.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "req_mgr.h"
#include "tcs_tsp.h"
#include "tcslog.h"
#include "tcs_utils.h"

struct key_mem_cache *key_mem_cache_head = NULL;

TSS_UUID NULL_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };


TSS_RESULT
canILoadThisKey(TCPA_KEY_PARMS *parms, TSS_BOOL *b)
{
	UINT16 subCapLength;
	UINT64 offset;
	BYTE subCap[100];
	TCPA_RESULT result;
	UINT32 respDataLength;
	BYTE *respData;

	offset = 0;
	LoadBlob_KEY_PARMS(&offset, subCap, parms);
	subCapLength = offset;

	if ((result = TCSP_GetCapability_Internal(InternalContext, TCPA_CAP_CHECK_LOADED,
						  subCapLength, subCap, &respDataLength,
						  &respData))) {
		*b = FALSE;
		LogDebugFn("NO");
		return result;
	}

	*b = respData[0];
	free(respData);
	LogDebugFn("%s", *b ? "YES" : "NO");

	return TSS_SUCCESS;
}

TCPA_RESULT
internal_EvictByKeySlot(TCPA_KEY_HANDLE slot)
{
	TCPA_RESULT result;
	UINT32 paramSize;
	UINT64 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Evict Key");

	offset = 10;
	LoadBlob_UINT32(&offset, slot, txBlob);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_EvictKey, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	LogResult("Evict Key", result);
	return result;
}

TSS_RESULT
clearUnknownKeys(TCS_CONTEXT_HANDLE hContext, UINT32 *cleared)
{
	TSS_RESULT result = TSS_SUCCESS;
	TCPA_KEY_HANDLE_LIST keyList = { 0, NULL };
	int i;
	BYTE *respData = NULL;
	UINT32 respDataSize = 0, count = 0;
	TCPA_CAPABILITY_AREA capArea = -1;
	UINT64 offset = 0;
	TSS_BOOL found = FALSE;
	struct key_mem_cache *tmp;

	capArea = TCPA_CAP_KEY_HANDLE;

	if ((result = TCSP_GetCapability_Internal(hContext, capArea, 0, NULL, &respDataSize,
						  &respData)))
		return result;

	if ((result = UnloadBlob_KEY_HANDLE_LIST(&offset, respData, &keyList)))
		goto done;

#ifdef TSS_DEBUG
	LogDebug("Loaded TPM key handles:");
	for (i = 0; i < keyList.loaded; i++) {
		LogDebugFn("%d: %x", i, keyList.handle[i]);
	}

	LogDebug("Loaded TCSD key handles:");
	i=0;
	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("%d: 0x%x -> 0x%x", i++, tmp->tpm_handle,
			    tmp->tcs_handle);
	}
#endif

	for (i = 0; i < keyList.loaded; i++) {
		/* as long as we're only called from evictFirstKey(), we don't
		 * need to lock here */
		for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
			if (tmp->tpm_handle == keyList.handle[i]) {
				found = TRUE;
				break;
			}
		}
		if (found)
			found = FALSE;
		else {
			if ((result = internal_EvictByKeySlot(keyList.handle[i])))
				goto done;
			else
				count++;
		}
	}

	*cleared = count;
done:
	free(keyList.handle);
	free(respData);

	return TSS_SUCCESS;
}

#if 0
TCPA_RESULT
clearKeysFromChip(TCS_CONTEXT_HANDLE hContext)
{
	TCPA_RESULT result;
	TCPA_KEY_HANDLE_LIST keyList;
	UINT32 i;
	BYTE *respData = 0;
	UINT32 respDataSize = 0;
	TCPA_CAPABILITY_AREA capArea = -1;
	UINT64 offset = 0;

	capArea = TCPA_CAP_KEY_HANDLE;

	if ((result = TCSP_GetCapability_Internal(hContext, capArea, 0, NULL,
					&respDataSize, &respData)))
		return result;

	if ((result = UnloadBlob_KEY_HANDLE_LIST(&offset, respData, &keyList)))
		return result;
	for (i = 0; i < keyList.loaded; i++) {
		if (keyList.handle[i] == SRK_TPM_HANDLE ||	/*can't evict SRK */
		    keyList.handle[i] == EK_TPM_HANDLE)	/*can't evict EK */
			continue;
		if ((result = internal_EvictByKeySlot(keyList.handle[i])))
			return result;
	}
	return TSS_SUCCESS;
}
#endif

void
LoadBlob_KEY_PARMS(UINT64 *offset, BYTE *blob, TCPA_KEY_PARMS *keyInfo)
{
	LoadBlob_UINT32(offset, keyInfo->algorithmID, blob);
	LoadBlob_UINT16(offset, keyInfo->encScheme, blob);
	LoadBlob_UINT16(offset, keyInfo->sigScheme, blob);
	LoadBlob_UINT32(offset, keyInfo->parmSize, blob);
	LoadBlob(offset, keyInfo->parmSize, blob, keyInfo->parms);
}

TSS_RESULT
UnloadBlob_STORE_PUBKEY(UINT64 *offset, BYTE *blob, TCPA_STORE_PUBKEY *store)
{
	if (!store) {
		UINT32 keyLength;

		UnloadBlob_UINT32(offset, &keyLength, blob);

		if (keyLength > 0)
			UnloadBlob(offset, keyLength, blob, NULL);

		return TSS_SUCCESS;
	}

	UnloadBlob_UINT32(offset, &store->keyLength, blob);

	if (store->keyLength == 0) {
		store->key = NULL;
		LogWarn("Unloading a public key of size 0!");
	} else {
		store->key = (BYTE *)malloc(store->keyLength);
		if (store->key == NULL) {
			LogError("malloc of %u bytes failed.", store->keyLength);
			store->keyLength = 0;
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		UnloadBlob(offset, store->keyLength, blob, store->key);
	}

	return TSS_SUCCESS;
}

void
LoadBlob_STORE_PUBKEY(UINT64 *offset, BYTE * blob, TCPA_STORE_PUBKEY * store)
{
	LoadBlob_UINT32(offset, store->keyLength, blob);
	LoadBlob(offset, store->keyLength, blob, store->key);
}

TSS_RESULT
UnloadBlob_KEY(UINT64 *offset, BYTE *blob, TCPA_KEY *key)
{
	TSS_RESULT rc;

	if (!key) {
		UINT32 size;

		UnloadBlob_VERSION(offset, blob, NULL);
		UnloadBlob_UINT16(offset, NULL, blob);
		UnloadBlob_KEY_FLAGS(offset, blob, NULL);
		UnloadBlob_BOOL(offset, NULL, blob);
		if ((rc = UnloadBlob_KEY_PARMS(offset, blob, NULL)))
			return rc;
		UnloadBlob_UINT32(offset, &size, blob);

		if (size > 0)
			UnloadBlob(offset, size, blob, NULL);

		if ((rc = UnloadBlob_STORE_PUBKEY(offset, blob, NULL)))
			return rc;

		UnloadBlob_UINT32(offset, &size, blob);

		if (size > 0)
			UnloadBlob(offset, size, blob, NULL);

		return TSS_SUCCESS;
	}

	UnloadBlob_VERSION(offset, blob, &key->ver);
	UnloadBlob_UINT16(offset, &key->keyUsage, blob);
	UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	UnloadBlob_BOOL(offset, (TSS_BOOL *)&key->authDataUsage, blob);
	if ((rc = UnloadBlob_KEY_PARMS(offset, blob, &key->algorithmParms)))
		return rc;
	UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob);

	if (key->PCRInfoSize == 0)
		key->PCRInfo = NULL;
	else {
		key->PCRInfo = malloc(key->PCRInfoSize);
		if (key->PCRInfo == NULL) {
			LogError("malloc of %u bytes failed.", key->PCRInfoSize);
			key->PCRInfoSize = 0;
			free(key->algorithmParms.parms);
			key->algorithmParms.parms = NULL;
			key->algorithmParms.parmSize = 0;
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	}

	if ((rc = UnloadBlob_STORE_PUBKEY(offset, blob, &key->pubKey))) {
		free(key->PCRInfo);
		key->PCRInfo = NULL;
		key->PCRInfoSize = 0;
		free(key->algorithmParms.parms);
		key->algorithmParms.parms = NULL;
		key->algorithmParms.parmSize = 0;
		return rc;
	}
	UnloadBlob_UINT32(offset, &key->encSize, blob);

	if (key->encSize == 0)
		key->encData = NULL;
	else {
		key->encData = (BYTE *)malloc(key->encSize);
		if (key->encData == NULL) {
			LogError("malloc of %d bytes failed.", key->encSize);
			key->encSize = 0;
			free(key->algorithmParms.parms);
			key->algorithmParms.parms = NULL;
			key->algorithmParms.parmSize = 0;
			free(key->PCRInfo);
			key->PCRInfo = NULL;
			key->PCRInfoSize = 0;
			free(key->pubKey.key);
			key->pubKey.key = NULL;
			key->pubKey.keyLength = 0;
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->encSize, blob, key->encData);
	}

	return TSS_SUCCESS;
}

void
LoadBlob_KEY(UINT64 *offset, BYTE * blob, TCPA_KEY * key)
{
	LoadBlob_VERSION(offset, blob, &key->ver);
	LoadBlob_UINT16(offset, key->keyUsage, blob);
	LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	LoadBlob_BOOL(offset, key->authDataUsage, blob);
	LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);
	LoadBlob_UINT32(offset, key->PCRInfoSize, blob);
	LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	LoadBlob_UINT32(offset, key->encSize, blob);
	LoadBlob(offset, key->encSize, blob, key->encData);
}

void
LoadBlob_PUBKEY(UINT64 *offset, BYTE * blob, TCPA_PUBKEY * key)
{
	LoadBlob_KEY_PARMS(offset, blob, &(key->algorithmParms));
	LoadBlob_STORE_PUBKEY(offset, blob, &(key->pubKey));
}

TSS_RESULT
UnloadBlob_PUBKEY(UINT64 *offset, BYTE *blob, TCPA_PUBKEY *key)
{
	TSS_RESULT rc;

	if (!key) {
		if ((rc = UnloadBlob_KEY_PARMS(offset, blob, NULL)))
			return rc;
		return UnloadBlob_STORE_PUBKEY(offset, blob, NULL);
	}

	if ((rc = UnloadBlob_KEY_PARMS(offset, blob, &key->algorithmParms)))
		return rc;
	if ((rc = UnloadBlob_STORE_PUBKEY(offset, blob, &key->pubKey))) {
		free(key->algorithmParms.parms);
		key->algorithmParms.parms = NULL;
		key->algorithmParms.parmSize = 0;
	}

	return rc;
}

void
LoadBlob_KEY_FLAGS(UINT64 *offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;

	if ((*flags) & migratable)
		tempFlag |= TSS_FLAG_MIGRATABLE;
	if ((*flags) & redirection)
		tempFlag |= TSS_FLAG_REDIRECTION;
	if ((*flags) & volatileKey)
		tempFlag |= TSS_FLAG_VOLATILE;
	LoadBlob_UINT32(offset, tempFlag, blob);
}

void
destroy_key_refs(TCPA_KEY *key)
{
	free(key->algorithmParms.parms);
	key->algorithmParms.parms = NULL;
	key->algorithmParms.parmSize = 0;

	free(key->pubKey.key);
	key->pubKey.key = NULL;
	key->pubKey.keyLength = 0;

	free(key->encData);
	key->encData = NULL;
	key->encSize = 0;

	free(key->PCRInfo);
	key->PCRInfo = NULL;
	key->PCRInfoSize = 0;
}
