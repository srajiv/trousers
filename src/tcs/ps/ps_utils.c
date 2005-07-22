
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_int_literals.h"
#include "tcs_internal_types.h"
#include "tcs_utils.h"
#include "tcsps.h"
#include "tcs_tsp.h"
#include "tcslog.h"

struct key_disk_cache *key_disk_cache_head = NULL;

void
LoadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION version)
{
	blob[(*offset)++] = version.major;
	blob[(*offset)++] = version.minor;
	blob[(*offset)++] = version.revMajor;
	blob[(*offset)++] = version.revMinor;
}

void
UnloadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out)
{
	out->major = blob[(*offset)++];
	out->minor = blob[(*offset)++];
	out->revMajor = blob[(*offset)++];
	out->revMinor = blob[(*offset)++];
}

TSS_RESULT
UnloadBlob_KEY_PARMS_PS(UINT16 *offset, BYTE *blob, TCPA_KEY_PARMS *keyParms)
{
	UnloadBlob_UINT32(offset, &keyParms->algorithmID, blob, NULL);
	UnloadBlob_UINT16(offset, &keyParms->encScheme, blob, NULL);
	UnloadBlob_UINT16(offset, &keyParms->sigScheme, blob, NULL);
	UnloadBlob_UINT32(offset, &keyParms->parmSize, blob, NULL);

	if (keyParms->parmSize == 0)
		keyParms->parms = NULL;
	else {
		keyParms->parms = malloc(keyParms->parmSize);
		if (keyParms->parms == NULL) {
			LogError("malloc of %u bytes failed.", keyParms->parmSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, keyParms->parmSize, blob, keyParms->parms, NULL);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_STORE_PUBKEY_PS(UINT16 *offset, BYTE *blob, TCPA_STORE_PUBKEY *store)
{
	UnloadBlob_UINT32(offset, &store->keyLength, blob, NULL);

	if (store->keyLength == 0) {
		LogWarn1("Unloading public key of size 0!");
		store->key = NULL;
	} else {
		store->key = malloc(store->keyLength);
		if (store->key == NULL) {
			LogError("malloc of %u bytes failed.", store->keyLength);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, store->keyLength, blob, store->key, NULL);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_KEY_PS(UINT16 *offset, BYTE *blob, TCPA_KEY *key)
{
	TSS_RESULT rc = TSS_SUCCESS;

	memset(key, 0, sizeof(TCPA_KEY));
	UnloadBlob_TCPA_VERSION(offset, blob, &key->ver);
	UnloadBlob_UINT16(offset, &key->keyUsage, blob, NULL);
	UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	UnloadBlob_BOOL(offset, &key->authDataUsage, blob, NULL);
	if (UnloadBlob_KEY_PARMS_PS(offset, blob, &key->algorithmParms))
		return rc;

	UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob, NULL);

	if (key->PCRInfoSize == 0)
		key->PCRInfo = NULL;
	else {
		key->PCRInfo = malloc(key->PCRInfoSize);
		if (key->PCRInfo == NULL) {
			LogError("malloc of %u bytes failed.", key->PCRInfoSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo, NULL);
	}

	if ((rc = UnloadBlob_STORE_PUBKEY_PS(offset, blob, &key->pubKey)))
		return rc;

	UnloadBlob_UINT32(offset, &key->encSize, blob, NULL);

	if (key->encSize == 0)
		key->encData = NULL;
	else {
		key->encData = malloc(key->encSize);
		if (key->encData == NULL) {
			LogError("malloc of %u bytes failed.", key->encSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->encSize, blob, key->encData, NULL);
	}

	return TSS_SUCCESS;
}

void
LoadBlob_KEY_PS(UINT16 *offset, BYTE *blob, TCPA_KEY *key)
{
	LoadBlob_TCPA_VERSION(offset, blob, key->ver);
	LoadBlob_UINT16(offset, key->keyUsage, blob, NULL);
	LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	LoadBlob_BOOL(offset, key->authDataUsage, blob, NULL);
	LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);
	LoadBlob_UINT32(offset, key->PCRInfoSize, blob, NULL);
	LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo, NULL);
	LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	LoadBlob_UINT32(offset, key->encSize, blob, NULL);
	LoadBlob(offset, key->encSize, blob, key->encData, NULL);
}

inline TSS_RESULT
read_data(int fd, void *data, UINT32 size)
{
	int rc;

	rc = read(fd, data, size);
	if (rc == -1) {
		LogError("read of %d bytes: %s", size, strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	} else if ((unsigned)rc != size) {
		LogError("read of %d bytes (only %d read)", size, rc);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}


inline TSS_RESULT
write_data(int fd, void *data, UINT32 size)
{
	int rc;

	rc = write(fd, data, size);
	if (rc == -1) {
		LogError("write of %d bytes: %s", size, strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	} else if ((unsigned)rc != size) {
		LogError("write of %d bytes (only %d written)", size, rc);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

/*
 * called by write_key_init to find the next available location in the PS file to
 * write a new key to.
 */
int
find_write_offset(UINT32 pub_data_size, UINT32 blob_size, UINT32 vendor_data_size)
{
	struct key_disk_cache *tmp;
	unsigned int offset;

	pthread_mutex_lock(&disk_cache_lock);

	tmp = key_disk_cache_head;
	while (tmp) {
		/* if we find a deleted key of the right size, return its offset */
		if (!(tmp->flags & CACHE_FLAG_VALID) &&
		    tmp->pub_data_size == pub_data_size &&
		    tmp->blob_size == blob_size &&
		    tmp->vendor_data_size == vendor_data_size) {
			offset = tmp->offset;
			pthread_mutex_unlock(&disk_cache_lock);
			return offset;
		}
		tmp = tmp->next;
	}

	pthread_mutex_unlock(&disk_cache_lock);

	/* no correctly sized holes */
	return -1;
}

/*
 * move the file pointer to the point where the next key can be written and return
 * that offset
 */
int
write_key_init(int fd, UINT32 pub_data_size, UINT32 blob_size, UINT32 vendor_data_size)
{
	UINT32 num_keys;
	int rc, offset;

	/* seek to the PS version */
	rc = lseek(fd, VERSION_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* go to NUM_KEYS */
	rc = lseek(fd, NUM_KEYS_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* read the number of keys */
	rc = read(fd, &num_keys, sizeof(UINT32));
	if (rc == -1) {
		LogError("read of %d bytes: %s", sizeof(UINT32), strerror(errno));
		return -1;
	} else if (rc == 0) {
		/* This is the first key being written */
		num_keys = 1;

		rc = lseek(fd, NUM_KEYS_OFFSET, SEEK_SET);
		if (rc == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			return -1;
		}

		if ((rc = write_data(fd, &num_keys, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			return rc;
		}

		/* return the offset */
		return sizeof(UINT32);
	}

	/* if there is a hole in the file we can write to, find it */
	offset = find_write_offset(pub_data_size, blob_size, vendor_data_size);

	if (offset != -1) {
		/* we found a hole, seek to it and don't increment the # of keys on disk */
		rc = lseek(fd, offset, SEEK_SET);
	} else {
		/* we didn't find a hole, increment the number of keys on disk and seek
		 * to the end of the file
		 */
		num_keys++;

		/* go to the beginning */
		rc = lseek(fd, NUM_KEYS_OFFSET, SEEK_SET);
		if (rc == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			return -1;
		}

		if ((rc = write_data(fd, &num_keys, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			return rc;
		}

		rc = lseek(fd, 0, SEEK_END);
	}
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* lseek returns the number of bytes of offset from the beginning of the file */
	return rc;
}

/*
 * add a new cache entry for a written key
 */
TSS_RESULT
cache_key(UINT32 offset, UINT16 flags,
		TSS_UUID *uuid, TSS_UUID *parent_uuid,
		UINT16 pub_data_size, UINT32 blob_size,
		UINT32 vendor_data_size)
{
	struct key_disk_cache *tmp;

	pthread_mutex_lock(&disk_cache_lock);

	tmp = key_disk_cache_head;

	for (; tmp; tmp = tmp->next) {
		/* reuse an invalidated key cache entry */
		if (!(tmp->flags & CACHE_FLAG_VALID))
			goto fill_cache_entry;
	}

	tmp = malloc(sizeof(struct key_disk_cache));
	if (tmp == NULL) {
		LogError1("malloc of %d bytes failed.");
		pthread_mutex_unlock(&disk_cache_lock);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	tmp->next = key_disk_cache_head;
	key_disk_cache_head = tmp;

fill_cache_entry:
	tmp->offset = offset;
#ifdef TSS_DEBUG
	if (offset == 0)
		LogDebug1("Storing key with file offset==0!!!");
#endif
	tmp->flags = flags;
	tmp->blob_size = blob_size;
	tmp->pub_data_size = pub_data_size;
	tmp->vendor_data_size = vendor_data_size;
	memcpy(&tmp->uuid, uuid, sizeof(TSS_UUID));
	memcpy(&tmp->parent_uuid, parent_uuid, sizeof(TSS_UUID));

	pthread_mutex_unlock(&disk_cache_lock);
	return TSS_SUCCESS;
}

/*
 * read into the PS file and return the number of keys
 */
int
get_num_keys_in_file(int fd)
{
	UINT32 num_keys;
	int rc;

	/* go to the number of keys */
	rc = lseek(fd, NUM_KEYS_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	rc = read(fd, &num_keys, sizeof(UINT32));
	if (rc == -1) {
		LogError("read of %d bytes: %s", sizeof(UINT32), strerror(errno));
		return -1;
	} else if ((unsigned)rc < sizeof(UINT32)) {
		num_keys = 0;
	}

	return num_keys;
}

/*
 * count the number of valid keys in the cache
 */
int
get_num_keys()
{
	int num_keys = 0;
	struct key_disk_cache *tmp;

	pthread_mutex_lock(&disk_cache_lock);

	tmp = key_disk_cache_head;

	for (; tmp; tmp = tmp->next) {
		if (tmp->flags & CACHE_FLAG_VALID)
			num_keys++;
	}

	pthread_mutex_unlock(&disk_cache_lock);
	return num_keys;
}

/*
 * disk store format:
 *
 * TrouSerS 0.2.0 and before:
 * Version 0:                  cached?
 * [UINT32   num_keys_on_disk]
 * [TSS_UUID uuid0           ] yes
 * [TSS_UUID uuid_parent0    ] yes
 * [UINT16   pub_data_size0  ] yes
 * [UINT16   blob_size0      ] yes
 * [UINT16   cache_flags0    ] yes
 * [BYTE[]   pub_data0       ]
 * [BYTE[]   blob0           ]
 * [...]
 *
 * TrouSerS 0.2.1+
 * Version 1:                  cached?
 * [BYTE     PS version = '\1']
 * [UINT32   num_keys_on_disk ]
 * [TSS_UUID uuid0            ] yes
 * [TSS_UUID uuid_parent0     ] yes
 * [UINT16   pub_data_size0   ] yes
 * [UINT16   blob_size0       ] yes
 * [UINT32   vendor_data_size0] yes
 * [UINT16   cache_flags0     ] yes
 * [BYTE[]   pub_data0        ]
 * [BYTE[]   blob0            ]
 * [BYTE[]   vendor_data0     ]
 * [...]
 *
 */
/*
 * read the PS file pointed to by fd and create a cache based on it
 */
int
init_disk_cache(int fd)
{
	UINT32 num_keys = get_num_keys_in_file(fd);
	UINT16 tmp_offset, i;
	int rc = 0, offset;
	struct key_disk_cache *tmp, *prev = NULL;
	BYTE srk_blob[2048];
	TCPA_KEY srk_key;
#ifdef TSS_DEBUG
	int valid_keys = 0;
#endif

	pthread_mutex_lock(&disk_cache_lock);

	if (num_keys == 0) {
		key_disk_cache_head = NULL;
		pthread_mutex_unlock(&disk_cache_lock);
		return 0;
	} else {
		key_disk_cache_head = tmp = calloc(1, sizeof(struct key_disk_cache));
		if (tmp == NULL) {
			LogError("malloc of %d bytes failed.",
						sizeof(struct key_disk_cache));
			rc = -1;
			goto err_exit;
		}
	}

	/* make sure the file pointer is where we expect, just after the number
	 * of keys on disk at the head of the file
	 */
	offset = lseek(fd, KEYS_OFFSET, SEEK_SET);
	if (offset == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		rc = -1;
		goto err_exit;
	}

	for (i=0; i<num_keys; i++) {
		offset = lseek(fd, 0, SEEK_CUR);
		if (offset == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			rc = -1;
			goto err_exit;
		}
		tmp->offset = offset;
#ifdef TSS_DEBUG
		if (offset == 0)
			LogDebug1("Storing key with file offset==0!!!");
#endif
		/* read UUID */
		if ((rc = read_data(fd, (void *)&tmp->uuid, sizeof(TSS_UUID)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* read parent UUID */
		if ((rc = read_data(fd, (void *)&tmp->parent_uuid, sizeof(TSS_UUID)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* pub data size */
		if ((rc = read_data(fd, &tmp->pub_data_size, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		DBG_ASSERT(tmp->pub_data_size <= 2048 && tmp->pub_data_size > 0);

		/* blob size */
		if ((rc = read_data(fd, &tmp->blob_size, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		DBG_ASSERT(tmp->blob_size <= 4096 && tmp->blob_size > 0);

		/* vendor data size */
		if ((rc = read_data(fd, &tmp->vendor_data_size, sizeof(UINT32)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

		/* cache flags */
		if ((rc = read_data(fd, &tmp->flags, sizeof(UINT16)))) {
			LogError("%s", __FUNCTION__);
			goto err_exit;
		}

#ifdef TSS_DEBUG
		if (tmp->flags & CACHE_FLAG_VALID)
			valid_keys++;
#endif
		/* fast forward over the pub key */
		offset = lseek(fd, tmp->pub_data_size, SEEK_CUR);
		if (offset == ((off_t) - 1)) {
			LogError("lseek: %s", strerror(errno));
			rc = -1;
			goto err_exit;
		}

		/* if this is the SRK, load it into memory, since its already loaded in
		 * the chip */
		if (!memcmp(&SRK_UUID, &tmp->uuid, sizeof(TSS_UUID))) {
			/* read SRK blob from disk */
			if ((rc = read_data(fd, srk_blob, tmp->blob_size))) {
				LogError("%s", __FUNCTION__);
				goto err_exit;
			}

			tmp_offset = 0;
			if ((rc = UnloadBlob_KEY_PS(&tmp_offset, srk_blob, &srk_key)))
				goto err_exit;
			/* add to the mem cache */
			if ((rc = add_mem_cache_entry(SRK_TPM_HANDLE, SRK_TPM_HANDLE,
							&srk_key))) {
				LogError1("Error adding SRK to mem cache.");
				destroy_key_refs(&srk_key);
				goto err_exit;
			}
			destroy_key_refs(&srk_key);
		} else {
			/* fast forward over the blob */
			offset = lseek(fd, tmp->blob_size, SEEK_CUR);
			if (offset == ((off_t) - 1)) {
				LogError("lseek: %s", strerror(errno));
				rc = -1;
				goto err_exit;
			}

			/* fast forward over the vendor data */
			offset = lseek(fd, tmp->vendor_data_size, SEEK_CUR);
			if (offset == ((off_t) - 1)) {
				LogError("lseek: %s", strerror(errno));
				rc = -1;
				goto err_exit;
			}
		}

		tmp->next = calloc(1, sizeof(struct key_disk_cache));
		if (tmp->next == NULL) {
			LogError("malloc of %d bytes failed.",
					sizeof(struct key_disk_cache));
			rc = -1;
			goto err_exit;
		}
		prev = tmp;
		tmp = tmp->next;
	}

	/* delete the dangling, unfilled cache entry */
	free(tmp);
	prev->next = NULL;
	rc = 0;
	LogDebug("%s: found %d valid key(s) on disk.\n", __FUNCTION__, valid_keys);

err_exit:
	pthread_mutex_unlock(&disk_cache_lock);
	return rc;
}

#if 0
/*
 * zero out a key in the persistent store. The key data and blob are zeroed,
 * but the sizes of each remain on disk. Newly created keys will then be inserted
 * in the blank space.  Keys are only blanked on disk before a TCS shutdown,
 * otherwise the TSP will just overwrite the free space.
 */
int
blank_key(int fd, struct key_disk_cache *key)
{
	int rc;
	char blank[1024] = {0,};

	// seek to the key location
#ifdef TSS_DEBUG
	if (key->offset == 0)
		LogDebug1("Storing key with file offset==0!!!");
#endif
	// blank the uuid
	rc = lseek(fd, UUID_OFFSET(key), SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}
	if ((rc = write_data(fd, &blank, sizeof(TSS_UUID)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	// blank the parent's uuid
	rc = lseek(fd, PARENT_UUID_OFFSET(key), SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}
	if ((rc = write_data(fd, &blank, sizeof(TSS_UUID)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	// blank the key's cache flags
	rc = lseek(fd, CACHE_FLAGS_OFFSET(key), SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}
	if ((rc = write_data(fd, &blank, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	// blank the public key
	rc = lseek(fd, PUB_DATA_OFFSET(key), SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}
	if ((rc = write_data(fd, &blank, key->pub_data_size))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	// blank the blob
	rc = lseek(fd, BLOB_DATA_OFFSET(key), SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}
	if ((rc = write_data(fd, &blank, key->blob_size))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	// blank the vendor data
	rc = lseek(fd, VENDOR_DATA_OFFSET(key), SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}
	if ((rc = write_data(fd, &blank, key->vendor_data_size))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	return 0;
}
#endif

int
close_disk_cache(int fd)
{
	struct key_disk_cache *tmp, *tmp_next;

	if (key_disk_cache_head == NULL)
		return 0;

	pthread_mutex_lock(&disk_cache_lock);
	tmp = key_disk_cache_head;

	do {
		tmp_next = tmp->next;
#if 0
		if (!(tmp->flags & CACHE_FLAG_VALID))
			(void)blank_key(fd, tmp);
#endif
		free(tmp);
		tmp = tmp_next;
	} while (tmp);

	pthread_mutex_unlock(&disk_cache_lock);

	return 0;
}
