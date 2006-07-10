
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
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
#include "spi_utils.h"
#include "tcs_tsp.h"
#include "tspps.h"
#include "tsplog.h"
#include "obj.h"

/*
 * keyreg.c
 *
 * Functions used to query the user persistent storage file.
 *
 * Since other apps may be altering the file, all operations must be atomic WRT the file and no
 * cache will be kept, since another app could delete keys from the file out from under us.
 *
 * Atomicity is guaranteed for operations inbetween calls to get_file() and put_file().
 *
 * A PS file will have the lifetime of the TSP context. For instance, this code will store hKeyA
 * and hKeyB in the file "a":
 *
 * setenv("TSS_USER_PS_FILE=a");
 * Tspi_Context_Create(&hContext);
 * Tspi_Context_RegisterKey(hKeyA);
 * setenv("TSS_USER_PS_FILE=b");
 * Tspi_Context_RegisterKey(hKeyB);
 *
 * but this code will store hKeyA in file "a" and hKeyB in file "b":
 *
 * setenv("TSS_USER_PS_FILE=a");
 * Tspi_Context_Create(&hContext);
 * Tspi_Context_RegisterKey(hKeyA);
 * Tspi_Context_Close(hContext);
 *
 * setenv("TSS_USER_PS_FILE=b");
 * Tspi_Context_Create(&hContext);
 * Tspi_Context_RegisterKey(hKeyB);
 *
 */

TSS_RESULT
ps_get_registered_keys(TSS_UUID *uuid, UINT32 *size, TSS_KM_KEYINFO **keys)
{
	int fd;
	UINT32 result;

	if ((result = get_file(&fd)))
		return result;

	result = psfile_get_registered_keys(fd, uuid, size, keys);

	put_file(fd);

	return result;
}

TSS_RESULT
ps_is_key_registered(TSS_UUID *uuid, TSS_BOOL *answer)
{
	int fd;
	TSS_RESULT result;

	if ((result = get_file(&fd)))
		return result;

	result = psfile_is_key_registered(fd, uuid, answer);

	put_file(fd);

	return result;
}

TSS_RESULT
ps_write_key(TSS_UUID *uuid, TSS_UUID *parent_uuid, UINT32 parent_ps, UINT32 blob_size, BYTE *blob)
{
	int fd;
	TSS_RESULT result;
	UINT16 short_blob_size = (UINT16)blob_size;

	if (blob_size > USHRT_MAX) {
		LogError("Blob data being written to disk is too large(%u bytes)!", blob_size);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if ((result = get_file(&fd)))
		return result;

	result = psfile_write_key(fd, uuid, parent_uuid, parent_ps, blob, short_blob_size);

	put_file(fd);
	return result;
}


TSS_RESULT
ps_remove_key(TSS_UUID *uuid)
{
	int fd;
	TSS_RESULT result;

	if ((result = get_file(&fd)))
		return result;

	result = psfile_remove_key(fd, uuid);

	put_file(fd);
	return result;
}

TSS_RESULT
ps_get_key_by_pub(TSS_HCONTEXT tspContext, UINT32 pub_size, BYTE *pub, TSS_HKEY *hKey)
{
	int fd;
	TSS_RESULT result = TSS_SUCCESS;
	BYTE key[4096];
	TSS_UUID uuid;

	if ((result = get_file(&fd)))
		return result;

	if ((result = psfile_get_key_by_pub(fd, &uuid, pub_size, pub, key))) {
		put_file(fd);
		return result;
	}

	put_file(fd);

	result = obj_rsakey_add_by_key(tspContext, &uuid, key, TSS_OBJ_FLAG_USER_PS, hKey);

	return result;
}

TSS_RESULT
ps_get_key_by_uuid(TSS_HCONTEXT tspContext, TSS_UUID *uuid, TSS_HKEY *hKey)
{
	int fd;
	TSS_RESULT result = TSS_SUCCESS;
	BYTE key[4096];

	if ((result = get_file(&fd)))
		return result;

	if ((result = psfile_get_key_by_uuid(fd, uuid, key))) {
		put_file(fd);
		return result;
	}

	put_file(fd);

	result = obj_rsakey_add_by_key(tspContext, uuid, key, TSS_OBJ_FLAG_USER_PS, hKey);

	return result;
}

TSS_RESULT
ps_get_parent_uuid_by_uuid(TSS_UUID *uuid, TSS_UUID *parent_uuid)
{
	int fd;
	TSS_RESULT result;

	if ((result = get_file(&fd)))
		return result;

	result = psfile_get_parent_uuid_by_uuid(fd, uuid, parent_uuid);

	put_file(fd);
	return result;
}

TSS_RESULT
ps_get_parent_ps_type_by_uuid(TSS_UUID *uuid, UINT32 *type)
{
	int fd;
	TSS_RESULT result;

	if ((result = get_file(&fd)))
		return result;

	result = psfile_get_parent_ps_type(fd, uuid, type);

	put_file(fd);

        return result;
}

TSS_RESULT
ps_close()
{
	TSS_RESULT result;
	int fd;

	if ((result = get_file(&fd)))
		return result;

	psfile_close(fd);

	/* No need to call put_file() here, the file is closed */

	return TSS_SUCCESS;
}
