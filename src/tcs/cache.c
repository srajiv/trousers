
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
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

/* This lock will be responsible for protecting the key_mem_cache_head list */
pthread_mutex_t mem_cache_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t tcs_keyhandle_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t timestamp_lock = PTHREAD_MUTEX_INITIALIZER;

TSS_UUID SRK_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 1 } };

/*================================= */
/*	proto's for just this file */
UINT32 getNextTimeStamp();

TCS_KEY_HANDLE NextTcsKeyHandle = 0x22330000;
TCS_KEY_HANDLE
getNextTcsKeyHandle()
{
	TCS_KEY_HANDLE ret;

	pthread_mutex_lock(&tcs_keyhandle_lock);

	do {
		ret = NextTcsKeyHandle++;
	} while (NextTcsKeyHandle == SRK_TPM_HANDLE);

	pthread_mutex_unlock(&tcs_keyhandle_lock);

	return ret;
}

UINT32 NextTimeStamp = 1;
UINT32
getNextTimeStamp()
{
	UINT32 ret;

	pthread_mutex_lock(&timestamp_lock);
	ret = NextTimeStamp++;
	pthread_mutex_unlock(&timestamp_lock);

	return ret;
}

/*-------------------------------------------------------------------------------------------- */

TCPA_RESULT
internal_BSOSAP(void)
{
	UINT16 offset;
	UINT32 paramSize;
	TCPA_RESULT result;
/*	TCPA_PUBKEY pubContainer; */
/*	TCPA_KEY_HANDLE keySlot; */
	TCPA_NONCE nonce;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	offset = 10;
	LoadBlob_UINT16(&offset, TCPA_ET_KEYHANDLE, txBlob, NULL);
	LoadBlob_UINT32(&offset, SRK_TPM_HANDLE, txBlob, NULL);
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonce.nonce, NULL);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_OSAP, txBlob);

	result = req_mgr_submit_req(txBlob);

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result)
		internal_TerminateHandle(Decode_UINT32(&txBlob[10]));
	return result;
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

#if 0
void
initKeyFile(TCS_CONTEXT_HANDLE hContext)
{
	TCPA_RESULT result;
	TSS_BOOL hasOwner;
	BYTE key[1024];
	UINT16 keySize = sizeof (key);
	int vendor;
	static TSS_BOOL KeyFileInit = FALSE;

	/*******************************
	 *	If there is no owner inthe chip, but a keyfile exists,
	 *		clear it.  The TCS will not worry about
	 *		the case that there is an owner and no key file.
	 *		Right now the TSP will take care of that.
	 ***********************************/

	LogDebug1("Init Key File");
	if (KeyFileInit) {
		LogDebug1("Key file is already init'd");
		return;
	}

	LogDebug1("Key file is not init'd");
	/*---	See if the chip has an owner and if the keyfile should be adjusted */
	vendor = getVendor(InternalContext);
	if (vendor == TPM_VENDOR_ATMEL) {
		result = internal_BSOSAP();

		/*---	Atmel is fixed at 0 and 1...can't hurt to have this for debug */
		internal_TerminateHandle(0);
		internal_TerminateHandle(1);

		if (result == 0 || result == 0x15)
			hasOwner = TRUE;
		else if (result == 0x0D)	/*bs SRK */
			hasOwner = FALSE;
		else
			return;
	} else if (vendor == TPM_VENDOR_NATL) {
		/*---	find out how they respond to fake OSAP */
		result = internal_BSOSAP();

		/*---	For giggles. */
		internal_TerminateHandle(0);
		internal_TerminateHandle(1);

		if (result == 0 || result == 0x15)
			hasOwner = TRUE;
		else if (result == 0x12)
			hasOwner = FALSE;
		else
			return;
	} else
		return;

	/*      This stuff relies on the file */
	LogDebug1("Checking if keyfile should be wacked");
	result = getRegisteredKeyByUUID(&SRK_UUID, key, &keySize);
	if (result == 0 && hasOwner == FALSE) {
		LogDebug1("Clearing keyfile since chip detected to not have owner");
		/*---	Clear out the file */
		destroyKeyFile();
	}

	LogDebug1("Leaving initKeyFile");
	KeyFileInit = TRUE;
}
#endif

#if 0
TCPA_STORE_PUBKEY *
getParentPubBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret;

	if (tpm_handle == NULL_TPM_HANDLE)
		return NULL;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle == tpm_handle) {
			ret = &tmp->parent->blob->pubKey;
			pthread_mutex_unlock(&mem_cache_lock);
			return ret;
		}
	}
	pthread_mutex_unlock(&mem_cache_lock);
	return NULL;
}
#endif


/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getPubBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret;

	if (tpm_handle == NULL_TPM_HANDLE)
		return NULL;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle == tpm_handle) {
			ret = &tmp->blob->pubKey;
			return ret;
		}
	}
	return NULL;
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getPubByHandle(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tcs_handle == tcs_handle) {
			ret = &tmp->blob->pubKey;
			return ret;
		}
	}

	return NULL;
}

/* only called from load key paths, so no locking */
TSS_RESULT
setParentByHandle(TCS_KEY_HANDLE tcs_handle, TCS_KEY_HANDLE p_tcs_handle)
{
	struct key_mem_cache *tmp, *parent;

	/* find parent */
	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
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

/* XXX take a look at this function */
TCPA_RESULT
ensureKeyIsLoaded(TCS_CONTEXT_HANDLE hContext, TCS_KEY_HANDLE keyHandle,
		TCPA_KEY_HANDLE * keySlot)
{
	TCPA_RESULT result = TSS_SUCCESS;
	TCPA_STORE_PUBKEY *myPub;

	LogDebug1("ensureKeyIsLoaded");

	pthread_mutex_lock(&mem_cache_lock);

	*keySlot = getSlotByHandle(keyHandle);
	LogDebug("keySlot is %08X", *keySlot);
	if (*keySlot == NULL_TPM_HANDLE || isKeyLoaded(*keySlot) == FALSE) {
		/*---   May have been evicted */
		myPub = getPubByHandle(keyHandle);
		if (myPub == NULL) {
			LogDebug1("Failed to find pub by handle");
			result = TCSERR(TCS_E_KM_LOADFAILED);
			goto done;
		}

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
	/*---   Now verify using get Cap */

done:
	pthread_mutex_unlock(&mem_cache_lock);
	/*todo */
	/*      isKeyLoaded( TCPA_KEY_HANDLE keySlot ) */
	LogDebug1("Passed ensure key is loaded");
	return result;
}


/* only called from load key paths, so no locking */
TSS_UUID *
getUuidByPub(TCPA_STORE_PUBKEY *pub)
{
	TSS_UUID *ret;
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->blob->pubKey.keyLength == pub->keyLength &&
				/* could this memcmp be less than pub->keyLength and still be ok? */
				!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = &tmp->uuid;
			return ret;
		}
	}

	return NULL;
}

TSS_UUID *
getUUIDByEncData(BYTE *encData)
{
	struct key_mem_cache *tmp;
	TSS_UUID *ret;

	LogDebug1("getUUIDByEncData");

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
#if 0
		if (entry->cacheStruct.blobSize == 0
				|| entry->cacheStruct.blob == NULL)
			continue;

		offset = 0;
		UnloadBlob_KEY(&offset,
				entry->cacheStruct.blob, &keyContainer);
#endif
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
		if (tmp->blob->encSize == 0)
			continue;
		if (!memcmp(tmp->blob->encData, encData, tmp->blob->encSize)) {
			tmp_enc_data = (BYTE *)malloc(tmp->blob->encSize);
			if (tmp_enc_data == NULL) {
				LogError("malloc of %d bytes failed.", tmp->blob->encSize);
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

void
replaceEncData_PS(TSS_UUID uuid, BYTE * encData, BYTE * newEncData)
{
	LogError("Passed through unfinished function: %s", __FUNCTION__);
#if 0
	TCPAPS_ReplaceEncdata(TCS_KEY_STORAGE_FILE, encData, newEncData);
#endif
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getPubByUuid(TSS_UUID *uuid)
{
	TCPA_STORE_PUBKEY *ret;
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(&tmp->uuid, uuid, sizeof(TSS_UUID))) {
			ret = &tmp->blob->pubKey;
			return ret;
		}
	}

	return NULL;
}

/* only called from load key paths and the init (single thread time) path,
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
		if (tcs_handle == tmp->tcs_handle) {
			return TSS_SUCCESS;
		}
	}

	/* Not found - we need to create a new entry */
	entry = (struct key_mem_cache *)calloc(1, sizeof(struct key_mem_cache));
	if (entry == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(struct key_mem_cache));
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	entry->tcs_handle = tcs_handle;
	if (tpm_handle != NULL_TPM_HANDLE)
		entry->time_stamp = getNextTimeStamp();

	entry->tpm_handle = tpm_handle;

	/* allocate space for the blob */
	entry->blob = malloc(sizeof(TCPA_KEY));
	if (entry->blob == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(TCPA_KEY));
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob, key_blob, sizeof(TCPA_KEY));

	/* allocate space for the key parameters if necessary */
	if (key_blob->algorithmParms.parmSize) {
		BYTE *tmp_parms = (BYTE *)malloc(key_blob->algorithmParms.parmSize);
		if (tmp_parms == NULL) {
			LogError("malloc of %d bytes failed.", key_blob->algorithmParms.parmSize);
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
		LogError("malloc of %d bytes failed.", key_blob->pubKey.keyLength);
		free(entry->blob);
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob->pubKey.key, key_blob->pubKey.key, key_blob->pubKey.keyLength);

	/* allocate space for the encData if necessary */
	if (key_blob->encSize != 0) {
		entry->blob->encData = (BYTE *)malloc(key_blob->encSize);
		if (entry->blob->encData == NULL) {
			LogError("malloc of %d bytes failed.", key_blob->encSize);
			free(entry->blob->pubKey.key);
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
		 * incremented there.
		 */
		entry->ref_cnt = 0;

		key_mem_cache_head->prev = entry;
	} else {
		/* if we are the SRK, initially set the reference count to 1, so that it is
		 * never unregistered.
		 */
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

/* custom add mem cache entry function called only at take ownership time, since
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
		LogError("malloc of %d bytes failed.", sizeof(struct key_mem_cache));
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	entry->tcs_handle = tcs_handle;
	if (tpm_handle != NULL_TPM_HANDLE)
		entry->time_stamp = getNextTimeStamp();

	entry->tpm_handle = tpm_handle;

	/* allocate space for the blob */
	entry->blob = malloc(sizeof(TCPA_KEY));
	if (entry->blob == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(TCPA_KEY));
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob, key_blob, sizeof(TCPA_KEY));

	/* allocate space for the key parameters if necessary */
	if (key_blob->algorithmParms.parmSize) {
		BYTE *tmp_parms = (BYTE *)malloc(key_blob->algorithmParms.parmSize);
		if (tmp_parms == NULL) {
			LogError("malloc of %d bytes failed.", key_blob->algorithmParms.parmSize);
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
		LogError("malloc of %d bytes failed.", key_blob->pubKey.keyLength);
		free(entry->blob);
		free(entry);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(entry->blob->pubKey.key, key_blob->pubKey.key, key_blob->pubKey.keyLength);

	/* allocate space for the encData if necessary */
	if (key_blob->encSize != 0) {
		entry->blob->encData = (BYTE *)malloc(key_blob->encSize);
		if (entry->blob->encData == NULL) {
			LogError("malloc of %d bytes failed.", key_blob->encSize);
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
	/* add to the front of the list */
	entry->next = key_mem_cache_head;
	if (key_mem_cache_head) {
		key_mem_cache_head->prev = entry;
	}
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

#if 0
TSS_RESULT
setUuidsByPub(TCPA_STORE_PUBKEY *pub, TSS_UUID *uuid, TSS_UUID *p_uuid)
{
	struct key_mem_cache *tmp;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			memcpy(&tmp->uuid, uuid, sizeof(TSS_UUID));
			memcpy(&tmp->parent->uuid, p_uuid, sizeof(TSS_UUID));
			pthread_mutex_unlock(&mem_cache_lock);
			return TSS_SUCCESS;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
	return TCSERR(TSS_E_FAIL);
}
#endif

/* only called from load key paths, so no locking */
TCPA_KEY_HANDLE
getSlotByHandle(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tcs_handle == tcs_handle) {
			ret = tmp->tpm_handle;
			return ret;
		}
	}

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
		if (tmp->tcs_handle == tcs_handle) {
			ret = tmp->tpm_handle;
			pthread_mutex_unlock(&mem_cache_lock);
			return ret;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
	return NULL_TPM_HANDLE;
}

/* only called from load key paths, so no locking */
TCPA_KEY_HANDLE
getSlotByPub(TCPA_STORE_PUBKEY *pub)
{
	struct key_mem_cache *tmp;
	TCPA_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = tmp->tpm_handle;
			return ret;
		}
	}

	return NULL_TPM_HANDLE;
}

/* only called from load key paths, so no locking */
TCS_KEY_HANDLE
getTCSKeyHandleByPub(TCPA_STORE_PUBKEY *pub)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = tmp->tcs_handle;
			return ret;
		}
	}

	return NULL_TPM_HANDLE;
}

/* only called from load key paths, so no locking */
TCPA_STORE_PUBKEY *
getParentPubByPub(TCPA_STORE_PUBKEY *pub)
{
	struct key_mem_cache *tmp;
	TCPA_STORE_PUBKEY *ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			ret = &tmp->parent->blob->pubKey;
			return ret;
		}
	}

	return NULL;
}

#if 0
TSS_BOOL
isKeyInMemCache(TCS_KEY_HANDLE tcs_handle)
{
	struct key_mem_cache *tmp;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tcs_handle == tcs_handle) {
			pthread_mutex_unlock(&mem_cache_lock);
			return TRUE;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
	return FALSE;
}
#endif

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
		return FALSE;

	return is_reg;
}

/* only called from load key paths, so no locking */
TSS_RESULT
getBlobByPub(TCPA_STORE_PUBKEY *pub, TCPA_KEY **ret_key)
{
	struct key_mem_cache *tmp;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(tmp->blob->pubKey.key, pub->key, pub->keyLength)) {
			*ret_key = tmp->blob;
			return TSS_SUCCESS;
		}
	}

	return TCSERR(TSS_E_FAIL);
}

#if 0
TSS_RESULT
getBlobBySlot(TCPA_KEY_HANDLE tpm_handle, TCPA_KEY **ret_key)
{
	struct key_mem_cache *tmp;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle == tpm_handle) {
			*ret_key = tmp->blob;
			pthread_mutex_unlock(&mem_cache_lock);
			return TSS_SUCCESS;
		}
	}

	pthread_mutex_unlock(&mem_cache_lock);
	return TCSERR(TSS_E_FAIL);
}
#endif

/* only called from load key paths, so no locking */
TCS_KEY_HANDLE
getAnyHandleBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE ret;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle == tpm_handle) {
			ret = tmp->tcs_handle;
			return ret;
		}
	}

	return NULL_TCS_HANDLE;
}

#if 0
TCS_KEY_HANDLE
getKeyHandleByUuid(TSS_UUID *uuid)
{
	TCS_KEY_HANDLE ret;
	struct key_mem_cache *tmp;

	pthread_mutex_lock(&mem_cache_lock);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (!memcmp(&tmp->uuid, uuid, sizeof(TSS_UUID))) {
			ret = tmp->tcs_handle;
			pthread_mutex_unlock(&mem_cache_lock);
			return ret;
		}
	}
	pthread_mutex_unlock(&mem_cache_lock);
	return NULL_TCS_HANDLE;
}
#endif

/* only called from load key paths, so no locking */
TSS_RESULT
refreshTimeStampBySlot(TCPA_KEY_HANDLE tpm_handle)
{
	struct key_mem_cache *tmp;
	TSS_RESULT ret = TCSERR(TSS_E_FAIL);

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle == tpm_handle) {
			tmp->time_stamp = getNextTimeStamp();
			ret = TSS_SUCCESS;
			break;
		}
	}

	return ret;
}

/*---	Right now this evicts the LRU key assuming it's not the parent */
/* XXX locking trouble if TCSP_ChangeAuthAsymStart_Internal is called */
TSS_RESULT
evictFirstKey(TCS_KEY_HANDLE parent_tcs_handle)
{
	struct key_mem_cache *tmp;
	TCS_KEY_HANDLE tpm_handle_to_evict = NULL_TPM_HANDLE;
	UINT32 smallestTimeStamp = ~(0U);	/*largest */
	TSS_RESULT result;

	/*---	First, see if there are any known keys worth evicting */
	if ((result = clearUnknownKeys(InternalContext)))
		return result;

	for (tmp = key_mem_cache_head; tmp; tmp = tmp->next) {
		if (tmp->tpm_handle != NULL_TPM_HANDLE &&	/* not already evicted */
		    tmp->tpm_handle != SRK_TPM_HANDLE &&	/* not the srk */
		    tmp->tcs_handle != parent_tcs_handle &&	/* not my parent */
		    tmp->time_stamp < smallestTimeStamp) {	/* is the smallest time stamp so far */
			tpm_handle_to_evict = tmp->tpm_handle;
			smallestTimeStamp = tmp->time_stamp;
		}
	}

	if (tpm_handle_to_evict != NULL_TCS_HANDLE) {
		if ((result = internal_EvictByKeySlot(tpm_handle_to_evict)))
			return result;

		result = setSlotBySlot(tpm_handle_to_evict, NULL_TPM_HANDLE);
	} else {
		/* success if the key is already evicted */
		return TSS_SUCCESS;
	}

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

/*
 * run through the key cache and invalidate the key with the given uuid. If a new
 * key is then added to the cache with the same size, it will overwrite the
 * invalidated key. If PS is closed before a key overwrites it, the bytes in the
 * file for the invalid key are written with 0's.
 */
TSS_RESULT
removeRegisteredKey(TSS_UUID *uuid)
{
	struct key_disk_cache *tmp;

	pthread_mutex_lock(&disk_cache_lock);
	tmp = key_disk_cache_head;

	for (; tmp; tmp = tmp->next) {
		if ((tmp->flags & CACHE_FLAG_VALID) &&
				!memcmp(uuid, &tmp->uuid, sizeof(TSS_UUID))) {
			/* just invalidate the key in the cache. The next time a key of the same
			 * size needs to be written to disk, this key will be overwritten. This is
			 * fine for the TSP, but the TCS will have to zero out invalid entries on
			 * disk before exiting or sth. */
			tmp->flags &= ~CACHE_FLAG_VALID;
			pthread_mutex_unlock(&disk_cache_lock);
			return TSS_SUCCESS;
		}
	}

	pthread_mutex_unlock(&disk_cache_lock);

	return TCSERR(TCSERR(TSS_E_PS_KEY_NOTFOUND));
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
		if (keyList.handle[i] == keySlot) {
			free(keyList.handle);
			return TRUE;	/* key is already loaded */
		}
	}

	free(keyList.handle);

not_loaded:
	LogDebug1("Key is not loaded, changing slot");
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

	/****************************************
	 *	If I'm loaded, then no point being here.  Get the
	 *	slot and return
	 **************************************/

	keySlot = getSlotByPub(pubKey);

	if (keySlot != NULL_TPM_HANDLE && isKeyLoaded(keySlot)) {
		*slotOut = keySlot;
		return TCPA_SUCCESS;
	}

	/****************************************
	 *	Before proceeding, the parent must be loaded.
	 *	If the parent is registered, then it can be loaded by UUID.
	 *	If not, then the shim will be called to load it's parent and then try
	 *	to load it based on the persistent store.
	 **************************************/

	/*---	Check if the Key is in the memory cache */
	parentPub = getParentPubByPub(pubKey);
	if (parentPub == NULL) {
		/*---	If parentUUID is not handed in, then this key was never loaded and isn't reg'd */
		if (parentUuid == NULL) {
			return TCSERR(TCS_E_KM_LOADFAILED);
		}

		/*---	This will try to load my parent by UUID */
		if ((result = TCSP_LoadKeyByUUID_Internal(hContext, parentUuid, NULL, &parentSlot)))
			return result;
	}
	/*---	The parent key is in the mem cache */
	else if ((result = LoadKeyShim(hContext, parentPub, NULL, &parentSlot)))
		return result;

	/****************************************
	 *	Now that the parent is loaded, I can loaded myself.
	 *	If I'm registered, that's by UUID.  If I'm not,
	 *	that's by blob.  If there is no persistent storage data, then I cannot be
	 *	loaded by blob. The user must have some point loaded this key manually.
	 **************************************/

	/*--- check the mem cache */
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
	}
	/*---	check registered */
	else {
		if (isPubRegistered(pubKey) == FALSE)
			return TCSERR(TCS_E_KM_LOADFAILED);
		KeyUUID = getUuidByPub(pubKey);
		if ((result = TCSP_LoadKeyByUUID_Internal
					(hContext,	/* in */
					 KeyUUID,	/* in */
					 NULL,	/*key info...for now */
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
writeRegisteredKeyToFile(TSS_UUID *uuid, TSS_UUID *parent_uuid, BYTE *blob, UINT32 blob_size)
{
        int fd = -1;
        TSS_RESULT rc;
	UINT32 parent_ps;

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

        rc = ps_write_key(fd, uuid, parent_uuid, &parent_ps, blob, blob_size);

        put_file(fd);
        return TSS_SUCCESS;
}

/*---------------------------------------------------------------------- */
/*	KM_KEYINFO stuff */

#if 0
typedef struct tdKMList
{
	TSS_KM_KEYINFO* kmInfo;
	struct tdKMList* next;
	struct tdKMList* parent;
	TSS_BOOL freekmInfo;
}KMList;

KMNode *
createNewKMNode()
{
	KMNode *ret;
	ret = malloc(sizeof(KMNode));
	if (ret != NULL)
		memset(ret, 0x00, sizeof(KMNode));
	return ret;
}

KMNode *
concatKMNode(KMNode ** first, KMNode * second)
{
	KMNode *index;
	if (*first == NULL) {
		*first = second;
		return *first;
	}
	for (index = *first; index->next; next(index)) {
		;
	}
	index->next = second;
	return *first;
}

KMList *
createNewKMList()
{
	KMList *ret;
	ret = malloc(sizeof(KMList));
	if (ret != NULL) {
		memset(ret, 0x00, sizeof(KMList));
		ret->kmInfo = malloc(sizeof(TSS_KM_KEYINFO));
		if (ret->kmInfo == NULL) {
			free(ret);
			return(NULL);
		}
		ret->freekmInfo = TRUE;
	}
	return ret;
}

KMList *
concatKMList(KMList ** first, KMList * second)
{
	KMList *index;
	if (*first == NULL) {
		*first = second;
		return *first;
	}
	for (index = *first; index->next; next(index)) {
		;
	}
	index->next = second;
	return *first;
}

TSS_RESULT
KM_AddKeyToList(KMList ** list, TSS_UUID myUUID, TSS_UUID parentUUID,
		BYTE * keyBlob, UINT32 vDataLength, BYTE * vData)
{
	TCPA_KEY key;
	UINT16 offset;
	KMList *currentKMList = createNewKMList();
	if (currentKMList == NULL) {
		LogError1("Malloc Failure.");
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(&(currentKMList->kmInfo->keyUUID), &myUUID, sizeof (TSS_UUID));
	memcpy(&(currentKMList->kmInfo->parentKeyUUID), &parentUUID,
	       sizeof (TSS_UUID));

	offset = 0;
	UnloadBlob_KEY(&offset, keyBlob, &key);

	currentKMList->kmInfo->bAuthDataUsage = key.authDataUsage;
	currentKMList->kmInfo->fIsLoaded = 0;	/*update this */
	memcpy(&(currentKMList->kmInfo->versionInfo), &key.ver,
	       sizeof (TCPA_VERSION));

	if (vDataLength) {
		currentKMList->kmInfo->rgbVendorData =  malloc(vDataLength);
		if (currentKMList->kmInfo->rgbVendorData == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(currentKMList->kmInfo->rgbVendorData, vData, vDataLength);
	}

	concatKMList(list, currentKMList);

	return TSS_SUCCESS;
}

int
KM_LinkParents(KMList * list)
{
	KMList *currentIndex;
	KMList *parentIndex;

	for (currentIndex = list; currentIndex; next(currentIndex)) {
		if (!memcmp
		    (&currentIndex->kmInfo->keyUUID,
		     &currentIndex->kmInfo->parentKeyUUID, sizeof (TSS_UUID))) {
			/*it's the SRK */
			currentIndex->parent = NULL;
			continue;
		}
		for (parentIndex = list; parentIndex; next(parentIndex)) {
			if (!memcmp(&parentIndex->kmInfo->keyUUID, &currentIndex->kmInfo->parentKeyUUID, sizeof (TSS_UUID))) {
				currentIndex->parent = parentIndex;
/*				concatKMNode( &parentIndex->children, currentIndex ); */
			}
		}
		if (parentIndex == NULL)
			return 1;
	}
	return 0;
}

int
KM_AddChildren(KMList * list, KMList * startPoint, KMNode ** graphPoint)
{
	KMList *listIndex;
	KMNode *tempNode;

	for (listIndex = list; listIndex; next(listIndex)) {
		if (listIndex->parent == startPoint) {
			tempNode = createNewKMNode();
			if (tempNode == NULL) {
				LogError1("Malloc Failure.");
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			tempNode->kmInfo = listIndex->kmInfo;
			listIndex->freekmInfo = FALSE;
/*			tempNode->parent = listIndex->parent; */
			KM_AddChildren(list, listIndex, &(tempNode->children));
			concatKMNode(graphPoint, tempNode);
		}
	}

	return 0;
}

int
KM_BuildGraph(TSS_UUID * uuid, KMList * list, KMNode ** newGraph)
{
/*	KMNode* graphIndex; */
	KMNode *graphStart;
	KMList *listIndex;
	KMList *firstNode;

	firstNode = NULL;
	for (listIndex = list; listIndex; next(listIndex)) {
		if (uuid == NULL) {
			if (listIndex->parent == NULL) {
				firstNode = listIndex;
				break;
			}
			continue;
		}
		if (!memcmp(&listIndex->kmInfo->keyUUID, uuid, sizeof(TSS_UUID))) {
			firstNode = listIndex;
			break;
		}
	}
	if (firstNode == NULL)
		return 1;

	graphStart = createNewKMNode();
	if (graphStart == NULL) {
		LogError1("Malloc Failure.");
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	graphStart->kmInfo = firstNode->kmInfo;
	firstNode->freekmInfo = FALSE;
	KM_AddChildren(list, firstNode, &(graphStart->children));

	*newGraph = graphStart;
	KM_DestroyKMList(list);
	return 0;
}

int
KM_GetHierarchy(TSS_UUID * startUUID, KMNode ** parmGraph)
{
	/*
	   //   KMNode* list = NULL;
	   TSS_UUID myUUID, parentUUID;
	   UINT16 keyBlobSize;
	   BYTE keyBlob[1024];
	   KMList* list = NULL;
	   KMNode* graph = NULL;

	   UINT16       iResult, i;
	   CHAR achSection[128], achKeyValue[128];
	   BYTE currentUUID[16], buffer[1024];
	   //   BOOL    bKeyFound;
	   //   UINT16 keySize;
	   UINT16 offset;
	   int ret;

	   LogDebug1("Get Key Hierarchy" );
	   i =  0;
	   memset( buffer, 0x00, sizeof( buffer ));
	   WriteStringToFile( NULL, NULL, NULL, TCS_KEY_STORAGE_FILE ); 

	   iResult = GetIntFromFile("NumKeys", "current", 0, TCS_KEY_STORAGE_FILE);
	   if(!iResult)
	   return 0;            //passing scenerio

	   for( i = 0 ; i < iResult ; i++ )
	   {
	   #ifdef WIN32
	   sprintf(achSection, "key %d", i+1);
	   #else
	   sprintf(achSection, "key_%d", i+1);
	   #endif
	   for(;;)
	   {
	   ret = 0;
	   if( 0 == GetStructFromFile(achSection, "KeyUUID", currentUUID, 16, TCS_KEY_STORAGE_FILE))
	   {
	   LogDebug1("Failed to get myUUID" );
	   ret = -1;
	   break;
	   }
	   offset = 0;
	   UnloadBlob_UUID( &offset, currentUUID, &myUUID );

	   if( 0 == GetStructFromFile(achSection, "ParentUUID", currentUUID, 16, TCS_KEY_STORAGE_FILE))
	   {
	   LogDebug1("Failed to get ParentUUID" );
	   ret = -1;
	   break;
	   }
	   offset = 0;
	   UnloadBlob_UUID( &offset, currentUUID, &parentUUID );

	   if( 0 == GetStringFromFile(achSection, "TCPAKeySize", "", achKeyValue,  sizeof(achKeyValue), TCS_KEY_STORAGE_FILE))
	   {
	   LogDebug1("Failed to get KeySize" );
	   ret = -1;
	   break;
	   }
	   keyBlobSize = wrapper_atoi(achKeyValue);
	   if( 0 == GetStructFromFile(achSection, "TCPAKey", keyBlob, keyBlobSize, TCS_KEY_STORAGE_FILE))
	   {
	   LogDebug1("Failed to get Key" );
	   ret = -1;
	   break;
	   }

	   if( KM_AddKeyToList( &list, myUUID, parentUUID, keyBlob, 0, NULL ))
	   {
	   LogDebug1("Failed to add key to list" );
	   ret = -1;
	   break;
	   }

	   break;
	   }
	   if( ret )
	   {
	   return 1;
	   }
	   }
	   if( KM_LinkParents( list ))
	   {
	   return -2;
	   }
	   if( KM_BuildGraph( startUUID, list, &graph ))
	   {
	   return -2;
	   }

	   //   *parmList= list;
	   *parmGraph = graph;
	 */
	return 0;
}

void
KM_DestroyKMList(KMList * list)
{
	KMList *index;
	for (index = list; index; next(index)) {
		if (index->freekmInfo == FALSE) ;
	}
}
void
KM_DestroyKMNode(KMNode * list)
{

}
#endif

