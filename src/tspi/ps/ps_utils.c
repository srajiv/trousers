
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
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "tspps.h"
#include "tcs_tsp.h"
#include "tsplog.h"

struct key_disk_cache *key_disk_cache_head = NULL;

inline TSS_RESULT
read_data(int fd, void *data, UINT32 size)
{
	int rc;

	rc = read(fd, data, size);
	if (rc == -1) {
		LogError("read of %d bytes: %s", size, strerror(errno));
		return TSPERR(TSS_E_INTERNAL_ERROR);
	} else if ((unsigned)rc != size) {
		LogError("read of %d bytes (only %d read)", size, rc);
		return TSPERR(TSS_E_INTERNAL_ERROR);
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
		return TSPERR(TSS_E_INTERNAL_ERROR);
	} else if ((unsigned)rc != size) {
		LogError("write of %d bytes (only %d written)", size, rc);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

/*
 * called by write_key_init to find the next available location in the PS file to
 * write a new key to.
 */
int
find_write_offset(UINT32 pub_data_size, UINT32 blob_size)
{
	struct key_disk_cache *tmp;
	unsigned int offset;

	pthread_mutex_lock(&disk_cache_lock);

	tmp = key_disk_cache_head;
	while (tmp) {
		/* if we find a deleted key of the right size, return its offset */
		if (!(tmp->flags & CACHE_FLAG_VALID) &&
			tmp->pub_data_size == pub_data_size &&
			tmp->blob_size == blob_size) {

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
write_key_init(int fd, UINT32 pub_data_size, UINT32 blob_size)
{
	UINT32 num_keys;
	int rc, offset;

	/* go to the number of keys offset */
	rc = lseek(fd, NUM_KEYS_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	/* read the number of keys */
	rc = read(fd, &num_keys, sizeof(UINT32));
	if (rc == -1) {
		LogError("read of %zd bytes: %s", sizeof(UINT32), strerror(errno));
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
	offset = find_write_offset(pub_data_size, blob_size);

	if (offset != -1) {
		/* we found a hole, seek to it and don't increment the # of keys on disk */
		rc = lseek(fd, offset, SEEK_SET);
	} else {
		/* we didn't find a hole, increment the number of keys on disk and seek
		 * to the end of the file
		 */
		num_keys++;

		/* go to the number of keys offset */
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
		UINT16 pub_data_size, UINT32 blob_size)
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
		LogError("malloc of %zd bytes failed.", sizeof(struct key_disk_cache));
		pthread_mutex_unlock(&disk_cache_lock);
		return TSPERR(TSS_E_INTERNAL_ERROR);
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

	/* go to the number of keys offset */
	rc = lseek(fd, NUM_KEYS_OFFSET, SEEK_SET);
	if (rc == ((off_t) - 1)) {
		LogError("lseek: %s", strerror(errno));
		return -1;
	}

	rc = read(fd, &num_keys, sizeof(UINT32));
	if (rc == -1) {
		LogError("read of %zd bytes: %s", sizeof(UINT32), strerror(errno));
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
