
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsps.h"
#include "req_mgr.h"

/*
 * mem_cache_lock will be responsible for protecting the key_mem_cache_head list. This is a
 * TCSD global linked list of all keys which have been loaded into the TPM at some time.
 */
pthread_mutex_t mem_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * tcs_keyhandle_lock is only used to make TCS keyhandle generation atomic for all TCSD
 * threads.
 */
static pthread_mutex_t tcs_keyhandle_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * timestamp_lock is only used to make TCS key timestamp generation atomic for all TCSD
 * threads.
 */
static pthread_mutex_t timestamp_lock = PTHREAD_MUTEX_INITIALIZER;

TSS_UUID SRK_UUID = TSS_UUID_SRK;

TCS_KEY_HANDLE
getNextTcsKeyHandle()
{
	static TCS_KEY_HANDLE NextTcsKeyHandle = 0x22330000;
	TCS_KEY_HANDLE ret;

	pthread_mutex_lock(&tcs_keyhandle_lock);

	do {
		ret = NextTcsKeyHandle++;
	} while (NextTcsKeyHandle == SRK_TPM_HANDLE);

	pthread_mutex_unlock(&tcs_keyhandle_lock);

	return ret;
}

UINT32
getNextTimeStamp()
{
	static UINT32 time_stamp = 1;
	UINT32 ret;

	pthread_mutex_lock(&timestamp_lock);
	ret = time_stamp++;
	pthread_mutex_unlock(&timestamp_lock);

	return ret;
}

TSS_RESULT
initDiskCache(void)
{
	int fd;
	TSS_RESULT rc;

	pthread_mutex_init(&disk_cache_lock, NULL);

	if ((fd = get_file()) < 0)
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if ((rc = init_disk_cache(fd)))
		return rc;

	/* this is temporary, to clear out a PS file from trousers
	 * versions before 0.2.1 */
	if ((rc = clean_disk_cache(fd)))
		return rc;

	put_file(fd);
	return TSS_SUCCESS;
}

void
closeDiskCache(void)
{
	int fd;

	if ((fd = get_file()) < 0) {
		LogError1("get_file() failed while trying to close disk cache.");
		return;
	}

	close_disk_cache(fd);

	put_file(fd);
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getPubBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret;

	if (tpm_handle == NULL_TPM_HANDLE)
		return NULL;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x",
			   tmp->tcs_handle);
		if (tmp->tpm_handle == tpm_handle) {
			ret = &tmp->blob->pubKey;
			return ret;
		}
	}
	LogDebugFn1("returning NULL TCPA_STORE_PUBKEY");
	return NULL;
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getPubByHandle(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret;

	LogDebugFn("looking for 0x%x", tcs_handle);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x",
			 tmp->tcs_handle);
		if (tmp->tcs_handle == tcs_handle) {
			ret = &tmp->blob->pubKey;
			return ret;
		}
	}

	LogDebugFn1("returning NULL TCPA_STORE_PUBKEY");
	return NULL;
}

/* only called from load key paths, so no locking */
TSS_RESULT
setParentByHandle(TCS_KEY_HANDLE tcs_handle, TCS_KEY_HANDLE p_tcs_handle)
{
	struct key_mem_cache *tmp, *parent;

	/* find parent */
	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebug("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tcs_handle == p_tcs_handle) {
			parent = tmp;
			break;
		}
	}

	/* didn't find parent */
	if (tmp == NULL)
		goto done;

	/* set parent blob in child */
	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tcs_handle == tcs_handle) {
			tmp->parent = parent;
			return TSS_SUCCESS;
		}
	}
done:
	return TCSERR(TSS_E_FAIL);
}

TCPA_RESULT
ensureKeyIsLoaded(TCS_CONTEXT_HANDLE hContext, TCS_KEY_HANDLE keyHandle,
		TCPA_KEY_HANDLE * keySlot)
{
	TCPA_RESULT result = TSS_SUCCESS;
	TCPA_STORE_PUBKEY *myPub;

	LogDebugFn("0x%x", keyHandle);

	pthread_mutex_lock(&mem_cache_lock);

	*keySlot = getSlotByHandle(keyHandle);
	LogDebug("keySlot is %08X", *keySlot);
	if (*keySlot == NULL_TPM_HANDLE || isKeyLoaded(*keySlot) == FALSE) {
		LogDebug1("calling getPubByHandle");
		if ((myPub = getPubByHandle(keyHandle)) == NULL) {
			LogDebug1("Failed to find pub by handle");
			result = TCSERR(TCS_E_KM_LOADFAILED);
			goto done;
		}

		LogDebugFn1("calling LoadKeyShim");
		if ((result = LoadKeyShim(hContext, myPub, NULL, keySlot))) {
			LogDebug1("Failed shim");
			goto done;
		}

		if (*keySlot == NULL_TPM_HANDLE) {
			LogDebug1("Key slot is still invalid after ensureKeyIsLoaded");
			result = TCSERR(TCS_E_KM_LOADFAILED);
			goto done;
		}
	}
	refreshTimeStampBySlot(*keySlot);

done:
	pthread_mutex_unlock(&mem_cache_lock);
	LogDebugFn1("Exit");
	return result;
}


/* only called from load key paths, so no locking */
TSS_UUID *
getUuidByPub(TCPA_STORE_PUBKEY *pub)
{
	TSS_UUID *ret;
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->blob->pubKey.keyLength == pub->keyLength &&
		    !memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = &tmp->uuid;
			return ret;
		}
	}

	return NULL;
}

TSS_RESULT
getHandlesByUUID(TSS_UUID *uuid, TCS_KEY_HANDLE *tcsHandle, TCPA_KEY_HANDLE *slot)
{
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(&tmp->uuid, uuid, sizeof(TSS_UUID))) {
			*tcsHandle = tmp->tcs_handle;
			*slot = tmp->tpm_handle;
			return TSS_SUCCESS;
		}
	}

	return TCSERR(TSS_E_FAIL);
}

TSS_UUID *
getUUIDByEncData(BYTE *encData)
{
	struct key_mem_cache *tmp;
	TSS_UUID *ret;

	LogDebug1("getUUIDByEncData");

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->blob->encSize == 0)
			continue;
		if (!memcmp(tmp->blob->encData, encData, tmp->blob->encSize)) {
			LogDebug1("Found it in knowledge by encData");
			ret = &tmp->uuid;
			pthread_mutex_unlock(&mem_cache_lock);
			return ret;
		}
	}
	LogDebug1("Never found UUID in mem cache by encData");
	pthread_mutex_unlock(&mem_cache_lock);
	return NULL;
}

TCS_KEY_HANDLE
getTCSKeyHandleByEncData(BYTE *encData)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->blob->encSize == 0)
			continue;
		if (!memcmp(tmp->blob->encData, encData, tmp->blob->encSize)) {
			ret = tmp->tcs_handle;
			pthread_mutex_unlock(&mem_cache_lock);
			return ret;
		}
	}
	pthread_mutex_unlock(&mem_cache_lock);
	return 0;
}

TSS_RESULT
replaceEncData_knowledge(BYTE *encData, BYTE *newEncData)
{
	struct key_mem_cache *tmp;
	BYTE *tmp_enc_data;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->blob->encSize == 0)
			continue;
		if (!memcmp(tmp->blob->encData, encData, tmp->blob->encSize)) {
			tmp_enc_data = (BYTE *)malloc(tmp->blob->encSize);
			if (tmp_enc_data == NULL) {
				LogError("malloc of %u bytes failed.", tmp->blob->encSize);
				pthread_mutex_unlock(&mem_cache_lock);
				return TCSERR(TSS_E_OUTOFMEMORY);
			}

			memcpy(tmp_enc_data, newEncData, tmp->blob->encSize);
			free(tmp->blob->encData);
			tmp->blob->encData = tmp_enc_data;
			pthread_mutex_unlock(&mem_cache_lock);
			return TSS_SUCCESS;
		}
	}
	pthread_mutex_unlock(&mem_cache_lock);
	LogError1("Couldn't find requested encdata in mem cache");
	return TCSERR(TSS_E_INTERNAL_ERROR);
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getPubByUuid(TSS_UUID *uuid)
{
	TCPA_STORE_PUBKEY *ret;
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (!memcmp(&tmp->uuid, uuid, sizeof(TSS_UUID))) {
			ret = &tmp->blob->pubKey;
			return ret;
		}
	}

	LogDebugFn1("returning NULL");
	return NULL;
}

/*
 * only called from load key paths and the init (single thread time) path,
 * so no locking
 */
TSS_RESULT
add_mem_cache_entry(TCS_KEY_HANDLE tcs_handle,
			TCPA_KEY_HANDLE tpm_handle,
			TCPA_KEY *key_blob)
{
	struct key_mem_cache *entry, *tmp;

	/* Make sure the cache doesn't already have an entry for this key */
	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tcs_handle == tmp->tcs_handle) {
			return TSS_SUCCESS;
		}
	}

	/* Not found - we need to create a new entry */
	entry = (struct key_mem_cache *)calloc(1, sizeof(struct key_mem_cache));
	if (entry == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct key_mem_cache));
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	entry->tcs_handle = tcs_handle;
	if (tpm_handle != NULL_TPM_HANDLE)
		entry->time_stamp = getNextTimeStamp();

	entry->tpm_handle = tpm_handle;

	/* allocate space for the blob */
	entry->blob = malloc(sizeof(TCPA_KEY));
	if (entry->blob == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TCPA_KEY));
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob, key_blob, sizeof(TCPA_KEY));

	/* allocate space for the key parameters if necessary */
	if (key_blob->algorithmParms.parmSize) {
		BYTE *tmp_parms = (BYTE *)malloc(key_blob->algorithmParms.parmSize);
		if (tmp_parms == NULL) {
			LogError("malloc of %u bytes failed.", key_blob->algorithmParms.parmSize);
			free(entry->blob);
			free(entry);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(tmp_parms, key_blob->algorithmParms.parms, key_blob->algorithmParms.parmSize);
		entry->blob->algorithmParms.parms = tmp_parms;
	}

	/* allocate space for the public key */
	entry->blob->pubKey.key = (BYTE *)malloc(key_blob->pubKey.keyLength);
	if (entry->blob->pubKey.key == NULL) {
		LogError("malloc of %u bytes failed.", key_blob->pubKey.keyLength);
		free(entry->blob->algorithmParms.parms);
		free(entry->blob);
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob->pubKey.key, key_blob->pubKey.key, key_blob->pubKey.keyLength);

	/* allocate space for the encData if necessary */
	if (key_blob->encSize != 0) {
		entry->blob->encData = (BYTE *)malloc(key_blob->encSize);
		if (entry->blob->encData == NULL) {
			LogError("malloc of %u bytes failed.", key_blob->encSize);
			free(entry->blob->pubKey.key);
			free(entry->blob->algorithmParms.parms);
			free(entry->blob);
			free(entry);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(entry->blob->encData, key_blob->encData, key_blob->encSize);
	}
	entry->blob->encSize = key_blob->encSize;

	/* add to the front of the list */
	entry->next = key_mem_cache_head;
	if (key_mem_cache_head) {
		/* set the reference count to 0 initially for all keys not being the SRK. Up
		 * the call chain, a reference to this mem cache entry will be set in the
		 * context object of the calling context and this reference count will be
		 * incremented there. */
		entry->ref_cnt = 0;

		key_mem_cache_head->prev = entry;
	} else {
		/* if we are the SRK, initially set the reference count to 1, so that it is
		 * never unregistered. */
		entry->ref_cnt = 1;
	}
	key_mem_cache_head = entry;

	return TSS_SUCCESS;
}

/* caller must lock the mem cache before calling! */
TSS_RESULT
remove_mem_cache_entry(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *cur;

	for (cur = key_mem_cache_head; cur; cur = cur->next) {
		if (cur->tcs_handle == tcs_handle) {
			free(cur->blob->pubKey.key);
			free(cur->blob->algorithmParms.parms);
			free(cur->blob);
			if (cur->prev != NULL)
				cur->prev->next = cur->next;
			if (cur->next != NULL)
				cur->next->prev = cur->prev;

			if (cur == key_mem_cache_head)
				key_mem_cache_head = cur->next;
			free(cur);

			return TSS_SUCCESS;
		}
	}

	return TCSERR(TSS_E_FAIL);
}

/*
 * custom add mem cache entry function called only at take ownership time, since
 * that's the only non init-time instance where we need to create a mem cache
 * entry from outside a load key path
 */
TSS_RESULT
add_mem_cache_entry_srk(TCS_KEY_HANDLE tcs_handle,
			TCPA_KEY_HANDLE tpm_handle,
			TCPA_KEY *key_blob)
{
	struct key_mem_cache *entry, *tmp;

	/* Make sure the cache doesn't already have an entry for this key */
	pthread_mutex_lock(&mem_cache_lock);
	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tcs_handle == tmp->tcs_handle) {
			remove_mem_cache_entry(tcs_handle);
		}
	}
	pthread_mutex_unlock(&mem_cache_lock);

	/* Not found - we need to create a new entry */
	entry = (struct key_mem_cache *)calloc(1, sizeof(struct key_mem_cache));
	if (entry == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct key_mem_cache));
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	entry->tcs_handle = tcs_handle;
	if (tpm_handle != NULL_TPM_HANDLE)
		entry->time_stamp = getNextTimeStamp();

	entry->tpm_handle = tpm_handle;

	/* allocate space for the blob */
	entry->blob = malloc(sizeof(TCPA_KEY));
	if (entry->blob == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(TCPA_KEY));
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob, key_blob, sizeof(TCPA_KEY));

	/* allocate space for the key parameters if necessary */
	if (key_blob->algorithmParms.parmSize) {
		BYTE *tmp_parms = (BYTE *)malloc(key_blob->algorithmParms.parmSize);
		if (tmp_parms == NULL) {
			LogError("malloc of %u bytes failed.", key_blob->algorithmParms.parmSize);
			free(entry->blob);
			free(entry);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(tmp_parms, key_blob->algorithmParms.parms, key_blob->algorithmParms.parmSize);
		entry->blob->algorithmParms.parms = tmp_parms;
	}

	/* allocate space for the public key */
	entry->blob->pubKey.key = (BYTE *)malloc(key_blob->pubKey.keyLength);
	if (entry->blob->pubKey.key == NULL) {
		LogError("malloc of %u bytes failed.", key_blob->pubKey.keyLength);
		free(entry->blob);
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob->pubKey.key, key_blob->pubKey.key, key_blob->pubKey.keyLength);

	/* allocate space for the encData if necessary */
	if (key_blob->encSize != 0) {
		entry->blob->encData = (BYTE *)malloc(key_blob->encSize);
		if (entry->blob->encData == NULL) {
			LogError("malloc of %u bytes failed.", key_blob->encSize);
			free(entry->blob->pubKey.key);
			free(entry->blob);
			free(entry);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(entry->blob->encData, key_blob->encData, key_blob->encSize);
	}
	entry->blob->encSize = key_blob->encSize;

	memcpy(&entry->uuid, &SRK_UUID, sizeof(TSS_UUID));

	pthread_mutex_lock(&mem_cache_lock);

	entry->next = key_mem_cache_head;
	if (key_mem_cache_head)
		key_mem_cache_head->prev = entry;

	entry->ref_cnt = 1;
	key_mem_cache_head = entry;
	pthread_mutex_unlock(&mem_cache_lock);

	return TSS_SUCCESS;
}

/* only called from evict key paths, so no locking */
TSS_RESULT
setSlotBySlot(TCPA_KEY_HANDLE old_handle, TCPA_KEY_HANDLE new_handle)
{
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle == old_handle) {
			LogDebugFn("Set TCS key 0x%x, old TPM handle: 0x%x "
				   "new TPM handle: 0x%x", tmp->tcs_handle,
				   old_handle, new_handle);
			if (new_handle == NULL_TPM_HANDLE)
				tmp->time_stamp = 0;
			else
				tmp->time_stamp = getNextTimeStamp();
			tmp->tpm_handle = new_handle;
			return TSS_SUCCESS;
		}
	}

	return TCSERR(TSS_E_FAIL);
}

/* only called from load key paths, so no locking */
TSS_RESULT
setSlotByHandle(TCS_KEY_HANDLE tcs_handle, TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebug("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tcs_handle == tcs_handle) {
			if (tpm_handle == NULL_TPM_HANDLE)
				tmp->time_stamp = 0;
			else
				tmp->time_stamp = getNextTimeStamp();
			tmp->tpm_handle = tpm_handle;
			return TSS_SUCCESS;
		}
	}

	return TCSERR(TSS_E_FAIL);
}

/* the beginnings of a key manager start here ;-) */

TSS_RESULT
key_mgr_evict(TCS_CONTEXT_HANDLE hContext, TCS_KEY_HANDLE hKey)
{
	TSS_RESULT result;

	pthread_mutex_lock(&mem_cache_lock);

	result = TCSP_EvictKey_Internal(hContext, hKey);

	pthread_mutex_unlock(&mem_cache_lock);

	return result;
}


TSS_RESULT
key_mgr_load_by_uuid(TCS_CONTEXT_HANDLE hContext,
		     TSS_UUID *uuid,
		     TCS_LOADKEY_INFO *pInfo,
		     TCS_KEY_HANDLE *phKeyTCSI)
{
	TSS_RESULT result;

	pthread_mutex_lock(&mem_cache_lock);

	result = TCSP_LoadKeyByUUID_Internal(hContext, uuid, pInfo, phKeyTCSI);

	LogDebug("Key %s loaded by UUID w/ TCS handle: 0x%x",
		result ? "NOT" : "successfully", result ? 0 : *phKeyTCSI);

	pthread_mutex_unlock(&mem_cache_lock);

	return result;
}

TSS_RESULT
key_mgr_load_by_blob(TCS_CONTEXT_HANDLE hContext, TCS_KEY_HANDLE hUnwrappingKey,
		     UINT32 cWrappedKeyBlob, BYTE *rgbWrappedKeyBlob,
		     TPM_AUTH *pAuth, TCS_KEY_HANDLE *phKeyTCSI, TCS_KEY_HANDLE *phKeyHMAC)
{
	TSS_RESULT result;

	pthread_mutex_lock(&mem_cache_lock);

	result = TCSP_LoadKeyByBlob_Internal(hContext, hUnwrappingKey,
			cWrappedKeyBlob, rgbWrappedKeyBlob,
			pAuth, phKeyTCSI, phKeyHMAC);

	pthread_mutex_unlock(&mem_cache_lock);

	return result;
}

/* create a reference to one key. This is called from the key_mgr_load_*
 * functions only, so no locking is done.
 */
TSS_RESULT
key_mgr_inc_ref_count(TCS_KEY_HANDLE key_handle)
{
	struct key_mem_cache *cur;

	for (cur = key_mem_cache_head; cur; cur = cur->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", cur->tcs_handle);
		if (cur->tcs_handle == key_handle) {
			cur->ref_cnt++;
			return TSS_SUCCESS;
		}
	}

	return TCSERR(TSS_E_FAIL);
}

/* de-reference one key.  This is called by the context routines, so
 * locking is necessary.
 */
TSS_RESULT
key_mgr_dec_ref_count(TCS_KEY_HANDLE key_handle)
{
	struct key_mem_cache *cur;

	pthread_mutex_lock(&mem_cache_lock);

	for (cur = key_mem_cache_head; cur; cur = cur->next) {
		if (cur->tcs_handle == key_handle) {
			cur->ref_cnt--;
			LogDebugFn("decrementing ref cnt for key 0x%x",
				   key_handle);
			pthread_mutex_unlock(&mem_cache_lock);
			return TSS_SUCCESS;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
	return TCSERR(TSS_E_FAIL);
}

/* run through the global list and free any keys with reference counts of 0 */
void
key_mgr_ref_count()
{
	struct key_mem_cache *tmp, *cur;

	pthread_mutex_lock(&mem_cache_lock);

	for (cur = key_mem_cache_head; cur;) {
		if (cur->ref_cnt == 0) {
			LogDebugFn("Key 0x%x being freed", cur->tcs_handle);
			free(cur->blob->pubKey.key);
			free(cur->blob->algorithmParms.parms);
			free(cur->blob);
			if (cur->prev != NULL)
				cur->prev->next = cur->next;
			if (cur->next != NULL)
				cur->next->prev = cur->prev;

			tmp = cur;
			if (cur == key_mem_cache_head)
				key_mem_cache_head = cur->next;
			cur = cur->next;
			free(tmp);
		} else {
			cur = cur->next;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
}

/* only called from load key paths, so no locking */
TCPA_KEY_HANDLE
getSlotByHandle(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tcs_handle == tcs_handle) {
			ret = tmp->tpm_handle;
			return ret;
		}
	}

	LogDebugFn1("returning NULL_TPM_HANDLE");
	return NULL_TPM_HANDLE;
}

/* called from functions outside the load key path */
TCPA_KEY_HANDLE
getSlotByHandle_lock(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tcs_handle == tcs_handle) {
			ret = tmp->tpm_handle;
			pthread_mutex_unlock(&mem_cache_lock);
			return ret;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
	LogDebugFn1("returning NULL_TPM_HANDLE");
	return NULL_TPM_HANDLE;
}

/* only called from load key paths, so no locking */
TCPA_KEY_HANDLE
getSlotByPub(TCPA_STORE_PUBKEY *pub)
{
	struct key_mem_cache *tmp;
	TCPA_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = tmp->tpm_handle;
			return ret;
		}
	}

	LogDebugFn1("returning NULL_TPM_HANDLE");
	return NULL_TPM_HANDLE;
}

/* only called from load key paths, so no locking */
TCS_KEY_HANDLE
getTCSKeyHandleByPub(TCPA_STORE_PUBKEY *pub)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = tmp->tcs_handle;
			return ret;
		}
	}

	LogDebugFn1("returning NULL_TPM_HANDLE");
	return NULL_TPM_HANDLE;
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getParentPubByPub(TCPA_STORE_PUBKEY *pub)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret = NULL;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tcs_handle == TPM_KEYHND_SRK) {
			LogDebugFn1("skipping the SRK");
			continue;
		}
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			if (tmp->parent && tmp->parent->blob) {
				ret = &tmp->parent->blob->pubKey;
				LogDebugFn1("Success");
			} else {
				LogError("parent pointer not set in key mem "
					 "cache object w/ TCS handle: 0x%x",
					 tmp->tcs_handle);
			}
			return ret;
		}
	}

	LogDebugFn1("returning NULL TCPA_STORE_PUBKEY");
	return NULL;
}

TSS_BOOL
isKeyRegistered(TCPA_STORE_PUBKEY *pub)
{
	TSS_UUID *uuid;
	int fd;
	TSS_RESULT rc;
	TSS_BOOL is_reg = FALSE;

	if ((fd = get_file()) < 0)
		return FALSE;

	if ((rc = ps_get_uuid_by_pub(fd, pub, &uuid))) {
		put_file(fd);
		return FALSE;
	}

	put_file(fd);

	if ((isUUIDRegistered(uuid, &is_reg)))
		is_reg = FALSE;

	free(uuid);
	return is_reg;
}

/* only called from load key paths, so no locking */
TSS_RESULT
getBlobByPub(TCPA_STORE_PUBKEY *pub, TCPA_KEY **ret_key)
{
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			*ret_key = tmp->blob;
			return TSS_SUCCESS;
		}
	}

	LogDebugFn1("returning TSS_E_FAIL");
	return TCSERR(TSS_E_FAIL);
}

/* only called from load key paths, so no locking */
TCS_KEY_HANDLE
getAnyHandleBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tpm_handle == tpm_handle) {
			ret = tmp->tcs_handle;
			return ret;
		}
	}

	return NULL_TCS_HANDLE;
}

/* only called from load key paths, so no locking */
TSS_RESULT
refreshTimeStampBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TSS_RESULT ret = TCSERR(TSS_E_FAIL);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		LogDebugFn("TCSD mem_cached handle: 0x%x", tmp->tcs_handle);
		if (tmp->tpm_handle == tpm_handle) {
			tmp->time_stamp = getNextTimeStamp();
			ret = TSS_SUCCESS;
			break;
		}
	}

	return ret;
}

/* Right now this evicts the LRU key assuming it's not the parent */
TSS_RESULT
evictFirstKey(TCS_KEY_HANDLE parent_tcs_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE tpm_handle_to_evict = NULL_TPM_HANDLE;
	UINT32 smallestTimeStamp = ~(0U);	/* largest */
	TSS_RESULT result;

	/* First, see if there are any known keys worth evicting */
	if ((result = clearUnknownKeys(InternalContext)))
		return result;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle != NULL_TPM_HANDLE &&	/* not already evicted */
		    tmp->tpm_handle != SRK_TPM_HANDLE &&	/* not the srk */
		    tmp->tcs_handle != parent_tcs_handle &&	/* not my parent */
		    tmp->time_stamp < smallestTimeStamp) {	/* is the smallest time
								   stamp so far */
			tpm_handle_to_evict = tmp->tpm_handle;
			smallestTimeStamp = tmp->time_stamp;
		}
	}

	if (tpm_handle_to_evict != NULL_TCS_HANDLE) {
		if ((result = internal_EvictByKeySlot(tpm_handle_to_evict)))
			return result;

		LogDebugFn("Evicted key w/ TPM handle 0x%x", tpm_handle_to_evict);
		result = setSlotBySlot(tpm_handle_to_evict, NULL_TPM_HANDLE);
	} else
		return TSS_SUCCESS;

	return result;
}

TSS_RESULT
getParentUUIDByUUID(TSS_UUID *uuid, TSS_UUID *ret_uuid)
{
	struct key_disk_cache *disk_tmp;

	/* check the registered key disk cache */
	pthread_mutex_lock(&disk_cache_lock);

	for (disk_tmp = key_disk_cache_head; disk_tmp; disk_tmp = disk_tmp->next) {
		if ((disk_tmp->flags & CACHE_FLAG_VALID) &&
		    !memcmp(&disk_tmp->uuid, uuid, sizeof(TSS_UUID))) {
			memcpy(ret_uuid, &disk_tmp->parent_uuid, sizeof(TSS_UUID));
			pthread_mutex_unlock(&disk_cache_lock);
			return TSS_SUCCESS;
		}
	}
	pthread_mutex_unlock(&disk_cache_lock);

	return TCSERR(TSS_E_FAIL);
}

TSS_RESULT
isUUIDRegistered(TSS_UUID *uuid, TSS_BOOL *is_reg)
{
	struct key_disk_cache *disk_tmp;

	/* check the registered key disk cache */
	pthread_mutex_lock(&disk_cache_lock);

	for (disk_tmp = key_disk_cache_head; disk_tmp; disk_tmp = disk_tmp->next) {
		if ((disk_tmp->flags & CACHE_FLAG_VALID) &&
		    !memcmp(&disk_tmp->uuid, uuid, sizeof(TSS_UUID))) {
			*is_reg = TRUE;
			pthread_mutex_unlock(&disk_cache_lock);
			return TSS_SUCCESS;
		}
	}
	pthread_mutex_unlock(&disk_cache_lock);
	*is_reg = FALSE;

	return TSS_SUCCESS;
}

void
disk_cache_shift(struct key_disk_cache *c)
{
	UINT32 offset = VENDOR_DATA_OFFSET(c) + c->vendor_data_size
			- UUID_OFFSET(c);
	struct key_disk_cache *tmp = key_disk_cache_head;

	/* for each disk cache entry, if the data for that entry is at an
	 * offset greater than the key beign removed, then the entry needs to
	 * be decremented by the size of key's disk footprint (the offset
	 * variable) */
	while (tmp) {
		if (tmp->offset > offset) {
			tmp->offset -= offset;
		}

		tmp = tmp->next;
	}
}

TSS_RESULT
removeRegisteredKey(TSS_UUID *uuid)
{
	struct key_disk_cache *tmp, *prev = NULL;
	TSS_RESULT rc;
        int fd = -1;

	pthread_mutex_lock(&disk_cache_lock);
	tmp = key_disk_cache_head;

	for (; tmp; prev = tmp, tmp = tmp->next) {
		if ((tmp->flags & CACHE_FLAG_VALID) &&
		    !memcmp(uuid, &tmp->uuid, sizeof(TSS_UUID))) {
			if ((fd = get_file()) < 0) {
				rc = TCSERR(TSS_E_INTERNAL_ERROR);
				break;
			}

			rc = ps_remove_key(fd, tmp);

			put_file(fd);

			/* if moving the file contents around succeeded, then
			 * change the offsets of the keys in the cache in
			 * mem_cache_shift() and remove the key from the
			 * cache. */
			if (!rc) {
				disk_cache_shift(tmp);
				if (prev) {
					prev->next = tmp->next;
				} else {
					key_disk_cache_head = tmp->next;
				}
				free(tmp);
			} else {
				LogError1("Error removing registered key.");
			}

			pthread_mutex_unlock(&disk_cache_lock);
			return rc;
		}
	}

	pthread_mutex_unlock(&disk_cache_lock);

	return TCSERR(TCSERR(TSS_E_PS_KEY_NOTFOUND));
}

/*
 * temporary function to clean out blanked keys from a PS file from
 * trousers 0.2.0 and before
 */
TSS_RESULT
clean_disk_cache(int fd)
{
	struct key_disk_cache *tmp, *prev = NULL;
	TSS_RESULT rc;

	pthread_mutex_lock(&disk_cache_lock);
	tmp = key_disk_cache_head;

	for (; tmp; prev = tmp, tmp = tmp->next) {
		if (!(tmp->flags & CACHE_FLAG_VALID)) {
			rc = ps_remove_key(fd, tmp);

			/* if moving the file contents around succeeded, then
			 * change the offsets of the keys in the cache in
			 * mem_cache_shift() and remove the key from the
			 * cache. */
			if (!rc) {
				disk_cache_shift(tmp);
				if (prev) {
					prev->next = tmp->next;
				}
				free(tmp);
			} else {
				LogError1("Error removing blank key.");
			}

			pthread_mutex_unlock(&disk_cache_lock);
			return rc;
		}
	}

	pthread_mutex_unlock(&disk_cache_lock);
	return TSS_SUCCESS;
}

TSS_RESULT
getRegisteredKeyByUUID(TSS_UUID *uuid, BYTE *blob, UINT16 *blob_size)
{
        int fd = -1;
        TSS_RESULT rc = TSS_SUCCESS;

        if ((fd = get_file()) < 0)
                return TCSERR(TSS_E_INTERNAL_ERROR);

        rc = ps_get_key_by_uuid(fd, uuid, blob, blob_size);

        put_file(fd);
        return rc;
}

TSS_RESULT
getKeyByCacheEntry(struct key_disk_cache *c, BYTE *blob, UINT16 *blob_size)
{
        int fd = -1;
        TSS_RESULT rc = TSS_SUCCESS;

        if ((fd = get_file()) < 0)
                return TCSERR(TSS_E_INTERNAL_ERROR);

        rc = ps_get_key_by_cache_entry(fd, c, blob, blob_size);

        put_file(fd);
        return rc;
}

TCPA_RESULT
isPubRegistered(TCPA_STORE_PUBKEY *key)
{
        int fd = -1;
        TSS_BOOL answer;

        if ((fd = get_file()) < 0)
                return FALSE;

        if (ps_is_pub_registered(fd, key, &answer)) {
                put_file(fd);
                return FALSE;
        }

        put_file(fd);
        return answer;
}

TSS_RESULT
getRegisteredUuidByPub(TCPA_STORE_PUBKEY *pub, TSS_UUID **uuid)
{
        int fd = -1;
	TSS_RESULT ret;

        if ((fd = get_file()) < 0)
                return TCSERR(TSS_E_INTERNAL_ERROR);

        ret = ps_get_uuid_by_pub(fd, pub, uuid);

        put_file(fd);
        return ret;
}

TSS_RESULT
getRegisteredKeyByPub(TCPA_STORE_PUBKEY *pub, UINT32 *size, BYTE **key)
{
        int fd = -1;
	TSS_RESULT ret;

        if ((fd = get_file()) < 0)
                return TCSERR(TSS_E_INTERNAL_ERROR);

        ret = ps_get_key_by_pub(fd, pub, size, key);

        put_file(fd);
        return ret;
}

TSS_BOOL
isKeyLoaded(TCPA_KEY_HANDLE keySlot)
{
	UINT16 offset;
	UINT32 i;
	TCPA_KEY_HANDLE_LIST keyList;
	UINT32 respSize;
	BYTE *resp;
	TSS_RESULT result;

	if (keySlot == SRK_TPM_HANDLE) {
		return TRUE;
	}

	if ((result = TCSP_GetCapability_Internal(InternalContext,
				    TCPA_CAP_KEY_HANDLE,
				    0, NULL, &respSize, &resp)))
		goto not_loaded;

	offset = 0;
	UnloadBlob_KEY_HANDLE_LIST(&offset, resp, &keyList);
	free(resp);
	for (i = 0; i < keyList.loaded; i++) {
		LogDebugFn("loaded TPM key handle: 0x%x", keyList.handle[i]);
		if (keyList.handle[i] == keySlot) {
			free(keyList.handle);
			return TRUE;
		}
	}

	free(keyList.handle);

not_loaded:
	LogDebugFn1("Key is not loaded, changing slot");
	setSlotBySlot(keySlot, NULL_TPM_HANDLE);
	return FALSE;
}

/* all calls to LoadKeyShim are inside locks */
TCPA_RESULT
LoadKeyShim(TCS_CONTEXT_HANDLE hContext, TCPA_STORE_PUBKEY *pubKey,
	    TSS_UUID * parentUuid, TCPA_KEY_HANDLE * slotOut)
{

	TCPA_STORE_PUBKEY *parentPub;
	UINT32 result;
	TCPA_KEY_HANDLE keySlot;
	TCPA_KEY_HANDLE parentSlot;
	TSS_UUID *KeyUUID;
	TCS_KEY_HANDLE tcsKeyHandle;
	TCPA_KEY *myKey;
	UINT16 offset;
	TCS_KEY_HANDLE parentHandle;
	BYTE keyBlob[1024];

	LogDebugFn1("calling getSlotByPub");

	/* If I'm loaded, then no point being here.  Get the slot and return */
	keySlot = getSlotByPub(pubKey);
	if (keySlot != NULL_TPM_HANDLE && isKeyLoaded(keySlot)) {
		*slotOut = keySlot;
		return TCPA_SUCCESS;
	}

	/*
	 * Before proceeding, the parent must be loaded.
	 * If the parent is registered, then it can be loaded by UUID.
	 * If not, then the shim will be called to load it's parent and then try
	 * to load it based on the persistent store.
	 */

	LogDebugFn1("calling getParentPubByPub");
	/* Check if the Key is in the memory cache */
	if ((parentPub = getParentPubByPub(pubKey)) == NULL) {
		LogDebugFn1("parentPub is NULL");
		/* If parentUUID is not handed in, then this key was never
		 * loaded and isn't reg'd */
		if (parentUuid == NULL) {
			return TCSERR(TCS_E_KM_LOADFAILED);
		}

		LogDebugFn1("calling TCSP_LoadKeyByUUID_Internal");
		/* This will try to load my parent by UUID */
		if ((result = TCSP_LoadKeyByUUID_Internal(hContext, parentUuid, NULL, &parentSlot)))
			return result;
	} else {
		LogDebugFn1("calling LoadKeyShim");
		if ((result = LoadKeyShim(hContext, parentPub, NULL, &parentSlot)))
			return result;
	}

	/*
	 * Now that the parent is loaded, I can load myself.
	 * If I'm registered, that's by UUID.  If I'm not,
	 * that's by blob.  If there is no persistent storage data, then I cannot be
	 * loaded by blob. The user must have some point loaded this key manually.
	 */

	/* check the mem cache */
	if (getBlobByPub(pubKey, &myKey) == 0) {
		parentPub = getPubBySlot(parentSlot);
		if (parentPub == NULL)
			return TCSERR(TCS_E_KM_LOADFAILED);
		parentHandle = getTCSKeyHandleByPub(parentPub);
		if (parentHandle == 0)
			return TCSERR(TCS_E_KM_LOADFAILED);

		offset = 0;
		LoadBlob_KEY(&offset, keyBlob, myKey);
		if ((result = TCSP_LoadKeyByBlob_Internal(hContext,
							parentHandle,
							offset,
							keyBlob,
							NULL,
							&tcsKeyHandle,
							slotOut)))
			return result;
	} else {
		/* check registered */
		if (isPubRegistered(pubKey) == FALSE)
			return TCSERR(TCS_E_KM_LOADFAILED);
		KeyUUID = getUuidByPub(pubKey);
		if ((result = TCSP_LoadKeyByUUID_Internal
					(hContext,	/* in */
					 KeyUUID,	/* in */
					 NULL,
					 &tcsKeyHandle))) {
			free(KeyUUID);
			return result;
		}
		free(KeyUUID);
		*slotOut = getSlotByHandle(tcsKeyHandle);
	}

	return ctx_mark_key_loaded(hContext, tcsKeyHandle);
}

TSS_RESULT
writeRegisteredKeyToFile(TSS_UUID *uuid, TSS_UUID *parent_uuid,
			 BYTE *vendor_data, UINT32 vendor_size,
			 BYTE *blob, UINT32 blob_size)
{
        int fd = -1;
        TSS_RESULT rc;
	UINT32 parent_ps;
	UINT16 short_blob_size = (UINT16)blob_size;

        if ((fd = get_file()) < 0)
                return TCSERR(TSS_E_INTERNAL_ERROR);

	/* this case needed for PS file init. if the key file doesn't yet exist, the
	 * ps_get_parent_ps_type_by_uuid() call would fail. */
	if (!memcmp(parent_uuid, &NULL_UUID, sizeof(TSS_UUID))) {
		parent_ps = TSS_PS_TYPE_SYSTEM;
	} else {
		if ((rc = ps_get_parent_ps_type_by_uuid(fd, parent_uuid, &parent_ps)))
			return rc;
	}

        rc = ps_write_key(fd, uuid, parent_uuid, &parent_ps, vendor_data,
			  vendor_size, blob, short_blob_size);

        put_file(fd);
        return TSS_SUCCESS;
}
