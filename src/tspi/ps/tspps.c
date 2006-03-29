
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
#include <errno.h>
#include <sys/types.h>
#include <sys/file.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "tspps.h"
#include "tcs_tsp.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"

extern pid_t getpgid(pid_t);

int user_ps_fd = -1;
char file_name[256];
pthread_mutex_t disk_cache_lock;

int
get_file()
{
	int rc = 0;
	pid_t pgid;

	/* check the global file handle first.  If it exists, lock it and return */
	if (user_ps_fd != -1) {
		if ((rc = flock(user_ps_fd, LOCK_EX))) {
			LogError("failed to get user PS lock: %s", strerror(errno));
			return -1;
		}
#if 0
		/* set the file pointer back to the beginning */
		if (lseek(user_ps_fd, 0, SEEK_SET) < 0) {
			LogError("failed to set user PS file pointer: %s", strerror(errno));
			/* let this pass for now */
		}
#endif
		return user_ps_fd;
	}

	/* get the process id of this process */
	if ((pgid = getpgid(0)) == -1) {
		LogError("getpgid: %s", strerror(errno));
		return -1;
	} else {
		/* create the key file name */
		snprintf(file_name, 256, "%s%d", TSP_KEY_FILE_NAME, pgid);
	}

	/* open and lock the file */
	user_ps_fd = open(file_name, O_CREAT|O_RDWR, 0600);
	if (user_ps_fd < 0) {
		LogError("user PS: open() of %s failed: %s", file_name, strerror(errno));
		return -1;
	}

	if ((rc = flock(user_ps_fd, LOCK_EX))) {
		LogError("failed to get user PS lock of file %s: %s", file_name, strerror(errno));
		return -1;
	}
#if 0
	/* set the file pointer back to the beginning */
	if (lseek(user_ps_fd, 0, SEEK_SET) < 0) {
		LogError("failed to set user PS file pointer for file %s: %s", file_name, strerror(errno));
		/* let this pass for now */
	}
#endif
	return user_ps_fd;
}

int
put_file(int fd)
{
	int rc = 0;

	/* release the file lock */
	if ((rc = flock(fd, LOCK_UN))) {
		LogError("failed to unlock user PS file: %s", strerror(errno));
		return -1;
	}

	return rc;
}

void
destroy_ps()
{
	int fd = -1;

	/* attempt to get the lock first */
	if ((fd = get_file()) < 0 ) {
		LogError("Could not destroy user ps file.");
	}

	/* remove the PS file */
	if (unlink(file_name)) {
		LogError("Error unlinking user ps file: %s", strerror(errno));
	}

	put_file(fd);
	close(fd);
	user_ps_fd = -1;
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
                        return TSPERR(TSS_E_INTERNAL_ERROR);
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
        return TSPERR(TSS_E_PS_KEY_NOTFOUND);
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
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		/* we found the key; file ptr is pointing at the blob */
		if (*ret_buffer_size < tmp->blob_size) {
			/* not enough room */
			LogError("%s: %d bytes needed but there's only room for %d", __FUNCTION__,
					tmp->blob_size, *ret_buffer_size);
			pthread_mutex_unlock(&disk_cache_lock);
			return TSPERR(TSS_E_INTERNAL_ERROR);
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
	return TSPERR(TSS_E_PS_KEY_NOTFOUND);
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
                        return TSPERR(TSS_E_INTERNAL_ERROR);
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
                        return TSPERR(TSS_E_INTERNAL_ERROR);
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

		*ret_uuid = (TSS_UUID *)malloc(sizeof(TSS_UUID));
		if (*ret_uuid == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(TSS_UUID));
			pthread_mutex_unlock(&disk_cache_lock);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		/* the key matches, copy the uuid out */
		memcpy(ret_uuid, &tmp->uuid, sizeof(TSS_UUID));

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return TSPERR(TSS_E_PS_KEY_NOTFOUND);
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
		UINT16 key_blob_size)
{
	BYTE pub_key[2048];
	TCPA_KEY key;
	UINT16 offset, pub_key_size, cache_flags = CACHE_FLAG_VALID;
	int rc = 0;

	/* leaving the cache flag for parent ps type as 0 implies TSS_PS_TYPE_USER */
	if (*parent_ps == TSS_PS_TYPE_SYSTEM)
		cache_flags |= CACHE_FLAG_PARENT_PS_SYSTEM;

	/* Unload the blob to get the public key */
	offset = 0;
	if ((rc = Trspi_UnloadBlob_KEY(&offset, key_blob, &key)))
		return rc;

	offset = 0;
	Trspi_LoadBlob_STORE_PUBKEY(&offset, pub_key, &key.pubKey);

	/* offset is incremented sizeof(pub_key) bytes by Trspi_LoadBlob_STORE_PUBKEY */
	pub_key_size = offset;
        if ((rc = write_key_init(fd, pub_key_size, key_blob_size)) < 0)
                return rc;

	/* offset now holds the number of bytes from the beginning of the file
	 * the key will be stored at
	 */
        offset = rc;

#ifdef TSS_DEBUG
        if (offset == 0)
                LogDebug("ERROR: key being written with offset 0!!");
#endif

        if ((rc = write_data(fd, (void *)uuid, sizeof(TSS_UUID)))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

        if ((rc = write_data(fd, (void *)parent_uuid, sizeof(TSS_UUID)))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

        if ((rc = write_data(fd, &pub_key_size, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

        if ((rc = write_data(fd, &key_blob_size, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

        if ((rc = write_data(fd, &cache_flags, sizeof(UINT16)))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

        if ((rc = write_data(fd, (void *)pub_key, pub_key_size))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

        if ((rc = write_data(fd, (void *)key_blob, key_blob_size))) {
		LogError("%s", __FUNCTION__);
                return rc;
	}

	if ((rc = cache_key(offset, cache_flags, uuid, parent_uuid, pub_key_size, key_blob_size)))
		return rc;

        return TSS_SUCCESS;
}

