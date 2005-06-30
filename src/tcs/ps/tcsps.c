
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/file.h>
#include <pthread.h>
#include <assert.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcsps.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

int system_ps_fd = -1;
pthread_mutex_t disk_cache_lock;

int
get_file()
{
	int rc = 0;

	/* check the global file handle first.  If it exists, lock it and return */
	if (system_ps_fd != -1) {
		if ((rc = flock(system_ps_fd, LOCK_EX))) {
			LogError("failed to get system PS lock: %s", strerror(errno));
			return -1;
		}

		return system_ps_fd;
	}

	/* open and lock the file */
	system_ps_fd = open(tcsd_options.system_ps_file, O_CREAT|O_RDWR, 0600);
	if (system_ps_fd < 0) {
		LogError("system PS: open() of %s failed: %s",
				tcsd_options.system_ps_file, strerror(errno));
		return -1;
	}

	if ((rc = flock(system_ps_fd, LOCK_EX))) {
		LogError("failed to get system PS lock of file %s: %s",
				tcsd_options.system_ps_file, strerror(errno));
		return -1;
	}

	return system_ps_fd;
}

int
put_file(int fd)
{
	int rc = 0;

	/* release the file lock */
	if ((rc = flock(fd, LOCK_UN))) {
		LogError("failed to unlock system PS file: %s", strerror(errno));
		return -1;
	}

	return rc;
}

void
close_file(int fd)
{
	close(fd);
	system_ps_fd = -1;
}

TSS_RESULT
ps_get_parent_uuid_by_uuid(int fd, TSS_UUID *uuid, TSS_UUID *ret_uuid)
{
        int rc;
        UINT32 file_offset = 0;
        struct key_disk_cache *tmp;

        pthread_mutex_lock(&disk_cache_lock);
        tmp = key_disk_cache_head;

        while (tmp) {
                if (memcmp(uuid, &tmp->uuid, sizeof(TSS_UUID)) || !(tmp->flags & CACHE_FLAG_VALID)) {
                        tmp = tmp->next;
                        continue;
                }

                /* jump to the location of the parent uuid */
                file_offset = PARENT_UUID_OFFSET(tmp);

                rc = lseek(fd, file_offset, SEEK_SET);
                if (rc == ((off_t) - 1)) {
                        LogError("lseek: %s", strerror(errno));
                        pthread_mutex_unlock(&disk_cache_lock);
                        return -1;
                }

                if ((rc = read_data(fd, ret_uuid, sizeof(TSS_UUID)))) {
			LogError("%s", __FUNCTION__);
                        pthread_mutex_unlock(&disk_cache_lock);
                        return rc;
                }

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return -2;
}

/*
 * return a key blob from PS given a uuid
 */
TSS_RESULT
ps_get_key_by_uuid(int fd, TSS_UUID *uuid, BYTE *ret_buffer, UINT16 *ret_buffer_size)
{
        int rc;
        UINT32 file_offset = 0;
        struct key_disk_cache *tmp;

        pthread_mutex_lock(&disk_cache_lock);
        tmp = key_disk_cache_head;

        while (tmp) {
                if (memcmp(uuid, &tmp->uuid, sizeof(TSS_UUID)) || !(tmp->flags & CACHE_FLAG_VALID)) {
                        tmp = tmp->next;
                        continue;
                }

                /* jump to the location of the key blob */
                file_offset = BLOB_DATA_OFFSET(tmp);

                rc = lseek(fd, file_offset, SEEK_SET);
                if (rc == ((off_t) - 1)) {
                        LogError("lseek: %s", strerror(errno));
                        pthread_mutex_unlock(&disk_cache_lock);
                        return TCSERR(TSS_E_INTERNAL_ERROR);
                }

                /* we found the key; file ptr is pointing at the blob */
                if (*ret_buffer_size < tmp->blob_size) {
                        /* not enough room */
                        pthread_mutex_unlock(&disk_cache_lock);
                        return TCSERR(TSS_E_FAIL);
                }

                if ((rc = read_data(fd, ret_buffer, tmp->blob_size))) {
			LogError("%s", __FUNCTION__);
                        pthread_mutex_unlock(&disk_cache_lock);
                        return rc;
                }
		*ret_buffer_size = tmp->blob_size;

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return TCSERR(TSS_E_FAIL);
}

/*
 * return a key blob from PS given its cache entry. The disk cache must be locked by the caller.
 */
TSS_RESULT
ps_get_key_by_cache_entry(int fd, struct key_disk_cache *c, BYTE *ret_buffer, UINT16 *ret_buffer_size)
{
        int rc;
        UINT32 file_offset = 0;

	/* jump to the location of the key blob */
	file_offset = BLOB_DATA_OFFSET(c);

	rc = lseek(fd, file_offset, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	/* we found the key; file ptr is pointing at the blob */
	if (*ret_buffer_size < c->blob_size) {
		/* not enough room */
		LogError("%s: Buf size too small. Needed %d bytes, passed %d", __FUNCTION__,
				c->blob_size, *ret_buffer_size);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if ((rc = read_data(fd, ret_buffer, c->blob_size))) {
		LogError("%s: error reading %d bytes", __FUNCTION__, c->blob_size);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	*ret_buffer_size = c->blob_size;

	return TSS_SUCCESS;
}

TSS_RESULT
ps_get_parent_ps_type_by_uuid(int fd, TSS_UUID *uuid, UINT32 *ret_ps_type)
{
        struct key_disk_cache *tmp;

        pthread_mutex_lock(&disk_cache_lock);
        tmp = key_disk_cache_head;

        while (tmp) {
                if (memcmp(uuid, &tmp->uuid, sizeof(TSS_UUID)) || !(tmp->flags & CACHE_FLAG_VALID)) {
                        tmp = tmp->next;
                        continue;
                }

		if (tmp->flags & CACHE_FLAG_PARENT_PS_SYSTEM)
			*ret_ps_type = TSS_PS_TYPE_SYSTEM;
		else
			*ret_ps_type = TSS_PS_TYPE_USER;

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return TCSERR(TSS_E_PS_KEY_NOTFOUND);
}

TSS_RESULT
ps_is_pub_registered(int fd, TCPA_STORE_PUBKEY *pub, TSS_BOOL *is_reg)
{
        int rc;
        UINT32 file_offset = 0;
        struct key_disk_cache *tmp;
	char tmp_buffer[2048];

        pthread_mutex_lock(&disk_cache_lock);
        tmp = key_disk_cache_head;

        while (tmp) {
		/* if the key is of the wrong size or is invalid, try the next one */
                if (pub->keyLength != tmp->pub_data_size || !(tmp->flags & CACHE_FLAG_VALID)) {
                        tmp = tmp->next;
                        continue;
                }

		/* we have a valid key with the same key size as the one we're looking for.
		 * grab the pub key data off disk and compare it. */

                /* jump to the location of the public key */
                file_offset = PUB_DATA_OFFSET(tmp);

                rc = lseek(fd, file_offset, SEEK_SET);
                if (rc == ((off_t) - 1)) {
                        LogError("lseek: %s", strerror(errno));
                        pthread_mutex_unlock(&disk_cache_lock);
                        return TCSERR(TSS_E_INTERNAL_ERROR);
                }

		assert(tmp->pub_data_size < 2048);

		/* read in the key */
                if ((rc = read_data(fd, tmp_buffer, tmp->pub_data_size))) {
			LogError("%s", __FUNCTION__);
                        pthread_mutex_unlock(&disk_cache_lock);
                        return rc;
                }

		/* do the compare */
		if (memcmp(tmp_buffer, pub->key, tmp->pub_data_size)) {
			tmp = tmp->next;
			continue;
		}

		/* the key matches, copy the uuid out */
		*is_reg = TRUE;

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
	*is_reg = FALSE;
        return TSS_SUCCESS;
}


TSS_RESULT
ps_get_uuid_by_pub(int fd, TCPA_STORE_PUBKEY *pub, TSS_UUID **ret_uuid)
{
        int rc;
        UINT32 file_offset = 0;
        struct key_disk_cache *tmp;
	char tmp_buffer[2048];

        pthread_mutex_lock(&disk_cache_lock);
        tmp = key_disk_cache_head;

        while (tmp) {
		/* if the key is of the wrong size or is invalid, try the next one */
                if (pub->keyLength != tmp->pub_data_size || !(tmp->flags & CACHE_FLAG_VALID)) {
                        tmp = tmp->next;
                        continue;
                }

		/* we have a valid key with the same key size as the one we're looking for.
		 * grab the pub key data off disk and compare it. */

                /* jump to the location of the public key */
                file_offset = PUB_DATA_OFFSET(tmp);

                rc = lseek(fd, file_offset, SEEK_SET);
                if (rc == ((off_t) - 1)) {
                        LogError("lseek: %s", strerror(errno));
                        pthread_mutex_unlock(&disk_cache_lock);
                        return TCSERR(TSS_E_INTERNAL_ERROR);
                }

		assert(tmp->pub_data_size < 2048);

		/* read in the key */
                if ((rc = read_data(fd, tmp_buffer, tmp->pub_data_size))) {
			LogError("%s", __FUNCTION__);
                        pthread_mutex_unlock(&disk_cache_lock);
                        return rc;
                }

		/* do the compare */
		if (memcmp(tmp_buffer, pub->key, tmp->pub_data_size)) {
			tmp = tmp->next;
			continue;
		}

		*ret_uuid == (TSS_UUID *)malloc(sizeof(TSS_UUID));
		if (*ret_uuid == NULL) {
			LogError1("Malloc Failure.");
                        pthread_mutex_unlock(&disk_cache_lock);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		/* the key matches, copy the uuid out */
		memcpy(*ret_uuid, &tmp->uuid, sizeof(TSS_UUID));

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return TCSERR(TSS_E_PS_KEY_NOTFOUND);
}

TSS_RESULT
ps_get_key_by_pub(int fd, TCPA_STORE_PUBKEY *pub, UINT32 *size, BYTE **ret_key)
{
        int rc;
        UINT32 file_offset = 0;
        struct key_disk_cache *tmp;
	BYTE tmp_buffer[4096];

        pthread_mutex_lock(&disk_cache_lock);
        tmp = key_disk_cache_head;

        while (tmp) {
		/* if the key is of the wrong size or is invalid, try the next one */
                if (pub->keyLength != tmp->pub_data_size || !(tmp->flags & CACHE_FLAG_VALID)) {
                        tmp = tmp->next;
                        continue;
                }

		/* we have a valid key with the same key size as the one we're looking for.
		 * grab the pub key data off disk and compare it. */

                /* jump to the location of the public key */
                file_offset = PUB_DATA_OFFSET(tmp);

                rc = lseek(fd, file_offset, SEEK_SET);
                if (rc == ((off_t) - 1)) {
                        LogError("lseek: %s", strerror(errno));
                        pthread_mutex_unlock(&disk_cache_lock);
                        return TCSERR(TSS_E_INTERNAL_ERROR);
                }

		assert(tmp->pub_data_size < 2048);

		/* read in the key */
                if ((rc = read_data(fd, tmp_buffer, tmp->pub_data_size))) {
			LogError("%s", __FUNCTION__);
                        pthread_mutex_unlock(&disk_cache_lock);
                        return rc;
                }

		/* do the compare */
		if (memcmp(tmp_buffer, pub->key, tmp->pub_data_size)) {
			tmp = tmp->next;
			continue;
		}

                /* jump to the location of the key blob */
                file_offset = BLOB_DATA_OFFSET(tmp);

                rc = lseek(fd, file_offset, SEEK_SET);
                if (rc == ((off_t) - 1)) {
                        LogError("lseek: %s", strerror(errno));
                        pthread_mutex_unlock(&disk_cache_lock);
                        return TCSERR(TSS_E_INTERNAL_ERROR);
                }

		assert(tmp->blob_size < 4096);

		/* read in the key blob */
                if ((rc = read_data(fd, tmp_buffer, tmp->blob_size))) {
			LogError("%s", __FUNCTION__);
                        pthread_mutex_unlock(&disk_cache_lock);
                        return rc;
                }

		*ret_key = malloc(tmp->blob_size);
		if (*ret_key == NULL) {
			LogError("malloc of %d bytes failed.", tmp->blob_size);
                        pthread_mutex_unlock(&disk_cache_lock);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		memcpy(*ret_key, tmp_buffer, tmp->blob_size);
		*size = tmp->blob_size;

                pthread_mutex_unlock(&disk_cache_lock);
                return rc;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return -2;
}

/*
 * disk store format:
 *
 *                             cached?
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
 */
TSS_RESULT
ps_write_key(int fd,
		TSS_UUID *uuid,
		TSS_UUID *parent_uuid,
		UINT32 *parent_ps,
		BYTE *key_blob,
		UINT32 key_blob_size)
{
	//BYTE pub_key[2048];
	TCPA_KEY key;
	UINT16 offset, pub_key_size, cache_flags = CACHE_FLAG_VALID;
	int rc = 0;

	/* leaving the cache flag for parent ps type as 0 implies TSS_PS_TYPE_USER */
	if (*parent_ps == TSS_PS_TYPE_SYSTEM)
		cache_flags |= CACHE_FLAG_PARENT_PS_SYSTEM;

	/* Unload the blob to get the public key */
	offset = 0;
	if ((rc = UnloadBlob_KEY_PS(&offset, key_blob, &key)))
		return rc;
#if 0
	offset = 0;
	LoadBlob_STORE_PUBKEY((UINT16 *)&offset, pub_key, &key.pubKey);
#endif
	pub_key_size = key.pubKey.keyLength;

        if ((rc = write_key_init(fd, pub_key_size, key_blob_size)) < 0)
                return rc;

	/* offset now holds the number of bytes from the beginning of the file
	 * the key will be stored at
	 */
	offset = rc;

#ifdef TSS_DEBUG
	if (offset == 0)
		LogDebug1("ERROR: key being written with offset 0!!");
#endif

	/* [TSS_UUID uuid0           ] yes */
        if ((rc = write_data(fd, (void *)uuid, sizeof(TSS_UUID)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	/* [TSS_UUID uuid_parent0    ] yes */
        if ((rc = write_data(fd, (void *)parent_uuid, sizeof(TSS_UUID)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	/* [UINT16   pub_data_size0  ] yes */
        if ((rc = write_data(fd, &pub_key_size, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	/* [UINT16   blob_size0      ] yes */
        if ((rc = write_data(fd, &key_blob_size, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	/* [UINT16   cache_flags0    ] yes */
        if ((rc = write_data(fd, &cache_flags, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	/* [BYTE[]   pub_data0       ] */
        //if ((rc = write_data(fd, (void *)pub_key, pub_key_size))) {
        if ((rc = write_data(fd, (void *)key.pubKey.key, pub_key_size))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	/* [BYTE[]   blob0           ] */
        if ((rc = write_data(fd, (void *)key_blob, key_blob_size))) {
		LogError("%s", __FUNCTION__);
		return rc;
	}

	if ((rc = cache_key(offset, cache_flags, uuid, parent_uuid, pub_key_size, key_blob_size)))
		return rc;

        return TSS_SUCCESS;
}

