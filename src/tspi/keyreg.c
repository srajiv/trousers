
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
 *
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "tcs_tsp.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tspps.h"
#include "tsplog.h"

TSS_RESULT
keyreg_IsKeyAlreadyRegistered(UINT32 keyBlobSize, BYTE *keyBlob, TSS_BOOL *answer)
{
	TCPA_KEY key;
	UINT16 offset;
	int fd = -1;
	UINT32 result;

	offset = 0;
	memset(&key, 0, sizeof(TCPA_KEY));
	if ((result = Trspi_UnloadBlob_KEY(&offset, keyBlob, &key)))
		return result;

	if ((fd = get_file()) < 0) {
		free_key_refs(&key);
		return FALSE;
	}

	if (ps_is_pub_registered(fd, &key.pubKey, answer))
		*answer = FALSE;

	free_key_refs(&key);
	put_file(fd);
	return result;
}

TSS_RESULT
keyreg_WriteKeyToFile(TSS_UUID *uuid, TSS_UUID *parent_uuid, UINT32 parent_ps,
		      UINT32 blob_size, BYTE *blob)
{
	int fd = -1;
	TSS_RESULT rc;
	UINT16 short_blob_size = (UINT16)blob_size;

	if (blob_size > USHRT_MAX) {
		LogError("Blob data being written to disk is too large(%u "
			 "bytes)!", blob_size);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if ((fd = get_file()) < 0)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	rc = ps_write_key(fd, uuid, parent_uuid, &parent_ps, blob, short_blob_size);

	put_file(fd);
	return TSS_SUCCESS;
}


TSS_RESULT
keyreg_RemoveKey(TSS_UUID *uuid)
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

        return TSPERR(TSS_E_PS_KEY_NOTFOUND);
}

TSS_RESULT
keyreg_GetKeyByUUID(TSS_UUID *uuid, UINT32 * blobSizeOut, BYTE ** blob)
{
	BYTE tempBlob[2048];
	UINT16 tempBlobSize = sizeof (tempBlob);
	int fd = -1;
	TSS_RESULT rc = TSS_SUCCESS;

	if ((fd = get_file()) < 0)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	/* XXX need the PS funcs to return TSS_RESULTs */
	if ((rc = ps_get_key_by_uuid(fd, uuid, tempBlob, &tempBlobSize))) {
		put_file(fd);
		return rc;
	}

	put_file(fd);

	*blobSizeOut = tempBlobSize;
	*blob = malloc(*blobSizeOut);
	if (*blob == NULL) {
		LogError("malloc of %d bytes failed.", *blobSizeOut);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	memcpy(*blob, tempBlob, tempBlobSize);
	return TSS_SUCCESS;
}

TSS_RESULT
keyreg_GetParentUUIDByUUID(TSS_UUID *uuid, TSS_UUID *parent_uuid)
{
	int fd = -1;
	TSS_RESULT rc = TSS_SUCCESS;

	if ((fd = get_file()) < 0)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	rc = ps_get_parent_uuid_by_uuid(fd, uuid, parent_uuid);

	put_file(fd);
	return rc;
}

TSS_RESULT
keyreg_GetParentPSTypeByUUID(TSS_UUID *uuid, UINT32 *psTypeOut)
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
                        *psTypeOut = TSS_PS_TYPE_SYSTEM;
                else
                        *psTypeOut = TSS_PS_TYPE_USER;

                pthread_mutex_unlock(&disk_cache_lock);
                return TSS_SUCCESS;
        }
        pthread_mutex_unlock(&disk_cache_lock);
        /* key not found */
        return TSPERR(TSS_E_PS_KEY_NOTFOUND);
}

#if 0
TSS_RESULT
keyreg_replaceEncData_PS(BYTE *enc_data, BYTE *new_enc_data)
{
	int fd = -1;
	TSS_RESULT rc = TSS_SUCCESS;

	if ((fd = get_file()) < 0)
		return TSPERR(TSS_E_INTERNAL_ERROR);
	
	rc = ps_replace_enc_data(fd, enc_data, new_enc_data);
	put_file(fd);

	return rc;
}
#endif
