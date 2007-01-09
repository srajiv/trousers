
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

#include "trousers/tss.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcsps.h"
#include "tcslog.h"
#include "tddl.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

TSS_RESULT
fill_key_info(struct key_disk_cache *d, struct key_mem_cache *m, TSS_KM_KEYINFO *key_info)
{
	BYTE tmp_blob[2048];
	UINT16 tmp_blob_size = 2048;
	TCPA_KEY tmp_key;
	UINT64 offset;
	TSS_RESULT result;

	if (m == NULL) {
		key_info->fIsLoaded = FALSE;

		/* read key from disk */
		if ((result = ps_get_key_by_cache_entry(d, (BYTE *)&tmp_blob, &tmp_blob_size)))
			return result;

		offset = 0;
		/* XXX add a real context handle here */
		if ((result = UnloadBlob_KEY(&offset, tmp_blob, &tmp_key)))
			return result;

		memcpy(&key_info->versionInfo, &tmp_key.ver, sizeof(TSS_VERSION));
		memcpy(&key_info->bAuthDataUsage, &tmp_key.authDataUsage,
		       sizeof(TCPA_AUTH_DATA_USAGE));
		destroy_key_refs(&tmp_key);
	} else {
		if (m->tpm_handle == NULL_TPM_HANDLE)
			key_info->fIsLoaded = FALSE;
		else
			key_info->fIsLoaded = TRUE;

		memcpy(&key_info->versionInfo, &m->blob->ver, sizeof(TSS_VERSION));
		memcpy(&key_info->bAuthDataUsage, &m->blob->authDataUsage,
		       sizeof(TCPA_AUTH_DATA_USAGE));
	}

	memcpy(&key_info->keyUUID, &d->uuid, sizeof(TSS_UUID));
	memcpy(&key_info->parentKeyUUID, &d->parent_uuid, sizeof(TSS_UUID));

	/* XXX consider filling in something useful here */
	key_info->ulVendorDataLength = 0;
	key_info->rgbVendorData = NULL;

	return TSS_SUCCESS;
}

TSS_RESULT
key_mgr_load_by_uuid(TCS_CONTEXT_HANDLE hContext,
		     TSS_UUID *uuid,
		     TCS_LOADKEY_INFO *pInfo,
		     TCS_KEY_HANDLE *phKeyTCSI)
{
	TSS_RESULT result;

	MUTEX_LOCK(mem_cache_lock);

	result = TCSP_LoadKeyByUUID_Internal(hContext, uuid, pInfo, phKeyTCSI);

	LogDebug("Key %s loaded by UUID w/ TCS handle: 0x%x",
		result ? "NOT" : "successfully", result ? 0 : *phKeyTCSI);

	MUTEX_UNLOCK(mem_cache_lock);

	return result;
}

