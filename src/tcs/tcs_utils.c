
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/evp.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
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

struct key_mem_cache *key_mem_cache_head = NULL;
TSS_UUID NULL_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };

TSS_BOOL firstVendorCheck = 1;

TSS_RESULT
fill_key_info(struct key_disk_cache *d,
		struct key_mem_cache *m,
		TSS_KM_KEYINFO *key_info)
{
	BYTE tmp_blob[2048];
	UINT16 tmp_blob_size = 2048;
	TCPA_KEY tmp_key;
	UINT16 offset;
	TSS_RESULT result;

	if (m == NULL) {
		key_info->fIsLoaded = FALSE;

		/* read key from disk */
		if ((result = ps_get_key_by_cache_entry(d, (BYTE *)&tmp_blob, &tmp_blob_size)))
			return result;

		offset = 0;
		/* XXX add a real context handle here */
		UnloadBlob_KEY(&offset, tmp_blob, &tmp_key);

		memcpy(&key_info->versionInfo, &tmp_key.ver, sizeof(TSS_VERSION));
		memcpy(&key_info->bAuthDataUsage, &tmp_key.authDataUsage, sizeof(TCPA_AUTH_DATA_USAGE));
	} else {
		if (m->tpm_handle == NULL_TPM_HANDLE)
			key_info->fIsLoaded = FALSE;
		else
			key_info->fIsLoaded = TRUE;

		memcpy(&key_info->versionInfo, &m->blob->ver, sizeof(TSS_VERSION));
		memcpy(&key_info->bAuthDataUsage, &m->blob->authDataUsage, sizeof(TCPA_AUTH_DATA_USAGE));
	}

	memcpy(&key_info->keyUUID, &d->uuid, sizeof(TSS_UUID));
	memcpy(&key_info->parentKeyUUID, &d->parent_uuid, sizeof(TSS_UUID));

	/* XXX consider filling in something useful here */
	key_info->ulVendorDataLength = 0;
	key_info->rgbVendorData = NULL;

	return TSS_SUCCESS;
}

TSS_RESULT
get_current_version(TCPA_VERSION *version)
{
	TCPA_CAPABILITY_AREA capArea = TPM_CAP_VERSION_VAL;
	UINT32 respSize;
	BYTE *resp;
	TSS_RESULT result;
	UINT16 offset;

	/* try the 1.2 way first */
	result = TCSP_GetCapability_Internal(InternalContext,
			capArea,
			0,
			NULL,
			&respSize,
			&resp);
	if (result == TSS_SUCCESS) {
		offset = sizeof(UINT16); // XXX hack
		UnloadBlob_VERSION(&offset, resp, version);
		free(resp);
	} else if (result == TCPA_E_BAD_MODE) {
		/* if the TPM doesn't understand VERSION_VAL, try the 1.1 way */
		capArea = TCPA_CAP_VERSION;
		result = TCSP_GetCapability_Internal(InternalContext,
				capArea,
				0,
				NULL,
				&respSize,
				&resp);
		if (result == TSS_SUCCESS) {
			offset = 0;
			UnloadBlob_VERSION(&offset, resp, version);
			free(resp);
		}
	}

	return result;
}

TSS_RESULT
get_cap_uint32(TCPA_CAPABILITY_AREA capArea, BYTE *subCap, UINT32 subCapSize, UINT32 *v)
{
	UINT32 respSize;
	BYTE *resp;
	TSS_RESULT result;
	UINT16 offset;

	result = TCSP_GetCapability_Internal(InternalContext,
			capArea,
			subCapSize,
			subCap,
			&respSize,
			&resp);
	if (!result) {
		offset = 0;
		switch (respSize) {
			case 1:
				UnloadBlob_BYTE(&offset, (BYTE *)v, resp, NULL);
				break;
			case sizeof(UINT16):
				UnloadBlob_UINT16(&offset, (UINT16 *)v, resp, NULL);
				break;
			case sizeof(UINT32):
				UnloadBlob_UINT32(&offset, v, resp, NULL);
				break;
			default:
				LogDebug("TCSP_GetCapability_Internal returned"
					  " %u bytes", respSize);
				result = TCSERR(TSS_E_FAIL);
				break;
		}
		free(resp);
	}

	return result;
}


TSS_RESULT
get_max_auths(UINT32 *auths)
{
	TCS_AUTHHANDLE handles[TSS_MAX_AUTHS_CAP];
	TCPA_NONCE nonce;
	UINT32 subCap;
	TSS_RESULT result;
	int i;

	if (TPM_VERSION(1,2)) {
		UINT32ToArray(TPM_CAP_PROP_MAX_AUTHSESS, (BYTE *)(&subCap));
		result = get_cap_uint32(TPM_CAP_PROPERTY, (BYTE *)&subCap,
					sizeof(subCap), auths);
	} else if (TPM_VERSION(1,1)) {
		/* open auth sessions until we get a failure */
		for (i = 0; i < TSS_MAX_AUTHS_CAP; i++) {
			result = TCSP_OIAP_Internal(InternalContext,
						    &(handles[i]), &nonce);
			if (result != TSS_SUCCESS) {
				/* this is not off by one since we're 0 indexed */
				*auths = i;
				break;
			}
		}

		if (i == TSS_MAX_AUTHS_CAP)
			*auths = TSS_MAX_AUTHS_CAP;

		/* close the auth sessions */
		for (i = 0; (UINT32)i < *auths; i++) {
			internal_TerminateHandle(handles[i]);
		}
	} else {
		result = TCSERR(TSS_E_INTERNAL_ERROR);
		*auths = 0;
	}

	if (*auths < 2) {
		LogError("%s reported only %d auth available!", __FUNCTION__, *auths);
		LogError("Your TPM must be reset before the TCSD can be started.");
	} else {
		LogDebug("get_max_auths reports %u auth contexts found", *auths);
		result = TSS_SUCCESS;
	}

	return result;
}

/* This is only called from init paths, so printing an error message is
 * appropriate if something goes wrong */
TSS_RESULT
get_tpm_metrics(struct tpm_properties *p)
{
	TSS_RESULT result;
	UINT32 subCap, rv = 0;

	if ((result = get_current_version(&p->version)))
		goto err;

	UINT32ToArray(TPM_ORD_SaveKeyContext, (BYTE *)&subCap);
	if ((result = get_cap_uint32(TCPA_CAP_ORD, (BYTE *)&subCap, sizeof(UINT32), &rv)))
		goto err;
	p->keyctx_swap = rv ? TRUE : FALSE;

	rv = 0;
	UINT32ToArray(TPM_ORD_SaveAuthContext, (BYTE *)&subCap);
	if ((result = get_cap_uint32(TCPA_CAP_ORD, (BYTE *)&subCap, sizeof(UINT32), &rv)))
		goto err;
	p->authctx_swap = rv ? TRUE : FALSE;

	UINT32ToArray(TPM_CAP_PROP_PCR, (BYTE *)&subCap);
	if ((result = get_cap_uint32(TCPA_CAP_PROPERTY, (BYTE *)&subCap, sizeof(UINT32),
					&p->num_pcrs)))
		goto err;

	UINT32ToArray(TPM_CAP_PROP_DIR, (BYTE *)&subCap);
	if ((result = get_cap_uint32(TCPA_CAP_PROPERTY, (BYTE *)&subCap, sizeof(UINT32),
					&p->num_dirs)))
		goto err;

	UINT32ToArray(TPM_CAP_PROP_SLOTS, (BYTE *)&subCap);
	if ((result = get_cap_uint32(TCPA_CAP_PROPERTY, (BYTE *)&subCap, sizeof(UINT32),
					&p->num_keys)))
		goto err;

	UINT32ToArray(TPM_CAP_PROP_MANUFACTURER, (BYTE *)&subCap);
	if ((result = get_cap_uint32(TCPA_CAP_PROPERTY, (BYTE *)&subCap, sizeof(UINT32),
					(UINT32 *)&p->manufacturer)))
		goto err;

	result = get_max_auths(&(p->num_auths));

err:
	if (result)
		LogError("TCS GetCapability failed with result = 0x%x", result);

	return result;
}

void
LogData(char *string, UINT32 data)
{
#if 0
	/* commenting out temporarily, logs getting too chatty */
	LogDebug("%s %08x", string, data);
#endif
}

void
LogResult(char *string, TCPA_RESULT result)
{
#if 0
	/* commenting out temporarily, logs getting too chatty */
	LogDebug("Leaving %s with result 0x%08x", string, result);
#endif
}

TSS_RESULT
canILoadThisKey(TCPA_KEY_PARMS *parms, TSS_BOOL *b)
{
	UINT16 subCapLength;
	BYTE subCap[100];
	TCPA_RESULT result;
	UINT32 respDataLength;
	BYTE *respData;

	subCapLength = 0;
	LoadBlob_KEY_PARMS(&subCapLength, subCap, parms);

	if ((result = TCSP_GetCapability_Internal(InternalContext,	/* in */
					    TCPA_CAP_CHECK_LOADED,	/* in */
					    subCapLength,	/* in */
					    subCap,	/* in */
					    &respDataLength,	/* out */
					    &respData))) {	/* out */
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
	UINT16 offset;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Evict Key");

	offset = 10;
	LoadBlob_UINT32(&offset, slot, txBlob, "key handle");
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
	TCPA_KEY_HANDLE_LIST keyList;
	int i;
	BYTE *respData = 0;
	UINT32 respDataSize = 0, count = 0;
	TCPA_CAPABILITY_AREA capArea = -1;
	UINT16 offset = 0;
	TSS_BOOL found = FALSE;
	struct key_mem_cache *tmp;

	capArea = TCPA_CAP_KEY_HANDLE;

	if ((result = TCSP_GetCapability_Internal(hContext, capArea, 0, NULL,
						&respDataSize, &respData)))
		return result;

	if ((result = UnloadBlob_KEY_HANDLE_LIST(&offset, respData, &keyList)))
		return result;

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
				return result;
			else
				count++;
		}
	}

	*cleared = count;

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
	UINT16 offset = 0;

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

UINT16
Decode_UINT16(BYTE * in)
{
	UINT16 temp = 0;
	temp = (in[1] & 0xFF);
	temp |= (in[0] << 8);
	return temp;
}

void
UINT32ToArray(UINT32 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 24) & 0xFF);
	out[1] = (BYTE) ((i >> 16) & 0xFF);
	out[2] = (BYTE) ((i >> 8) & 0xFF);
	out[3] = (BYTE) (i & 0xFF);
}

void
UINT16ToArray(UINT16 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 8) & 0xFF);
	out[1] = (BYTE) (i & 0xFF);
}

UINT32
Decode_UINT32(BYTE * y)
{
	UINT32 x = 0;

	x = y[0];
	x = ((x << 8) | (y[1] & 0xFF));
	x = ((x << 8) | (y[2] & 0xFF));
	x = ((x << 8) | (y[3] & 0xFF));

	return x;
}

void
LoadBlob_UINT32(UINT16 * offset, UINT32 in, BYTE * blob, char *log)
{
	UINT32ToArray(in, &blob[*offset]);
	*offset += 4;
	if (log)
		LogData(log, in);
}

void
LoadBlob_UINT16(UINT16 * offset, UINT16 in, BYTE * blob, char *log)
{
	UINT16ToArray(in, &blob[*offset]);
	*offset += 2;
	if (log)
		LogData(log, in);
}

void
UnloadBlob_UINT32(UINT16 * offset, UINT32 * out, BYTE * blob, char *log)
{
	*out = Decode_UINT32(&blob[*offset]);
	*offset += 4;
	if (log)
		LogData(log, *out);
}

void
UnloadBlob_UINT16(UINT16 * offset, UINT16 * out, BYTE * blob, char *log)
{
	*out = Decode_UINT16(&blob[*offset]);
	*offset += 2;
	if (log)
		LogData(log, *out);
}

void
LoadBlob_BYTE(UINT16 * offset, BYTE data, BYTE * blob, char *log)
{
	blob[*offset] = data;
	(*offset)++;
#ifdef TSS_DEBUG
	if (log)
		LogDebug("%s: %c", log, data);
#endif
}

void
UnloadBlob_BYTE(UINT16 * offset, BYTE * dataOut, BYTE * blob, char *log)
{
	*dataOut = blob[*offset];
	(*offset)++;
#ifdef TSS_DEBUG
	if (log)
		LogDebug("%s: %c", log, *dataOut);
#endif
}

void
LoadBlob_BOOL(UINT16 * offset, TSS_BOOL data, BYTE * blob, char *log)
{
	blob[*offset] = data;
	(*offset)++;
#if 0
	if (log)
		LogDebug("%s: %c", log, data);
#endif
}

void
UnloadBlob_BOOL(UINT16 * offset, TSS_BOOL *dataOut, BYTE * blob, char *log)
{
	*dataOut = blob[*offset];
	(*offset)++;
#if 0
	if (log)
		LogDebug("%s: %c", log, *dataOut);
#endif
}

void
LoadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object,
	 char *log)
{
	memcpy(&container[*offset], object, size);
	(*offset) += (UINT16) size;
}

void
UnloadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object,
	   char *log)
{
	memcpy(object, &container[*offset], size);
	(*offset) += (UINT16) size;
#if 0
	/* commenting out for now, logs getting too chatty */
	if (log && size) {
		LogDebug(log);
		/* XXX Crashes sometimes. Investigate. */
		//LogBlob(size, object);
	}
#endif
}

void
LoadBlob_Header(UINT16 tag, UINT32 paramSize, UINT32 ordinal,
		BYTE * blob)
{

	UINT16ToArray(tag, &blob[0]);
	LogData("Header Tag:", tag);
	UINT32ToArray(paramSize, &blob[2]);
	LogData("Header ParamSize:", paramSize);
	UINT32ToArray(ordinal, &blob[6]);
	LogData("Header Ordinal:", ordinal);
#if 0
	LogInfo("Blob's TPM Ordinal: 0x%x", ordinal);
#endif
}

TCPA_RESULT
UnloadBlob_Header(BYTE * blob, UINT32 * size)
{
	UINT16 temp = Decode_UINT16(blob);
	LogData("UnloadBlob_Tag:", (temp));
	*size = Decode_UINT32(&blob[2]);
	LogData("UnloadBlob_Header, size:", *size);
	LogData("UnloadBlob_Header, returnCode:", Decode_UINT32(&blob[6]));
	return Decode_UINT32(&blob[6]);
}

void
LoadBlob_MIGRATIONKEYAUTH(UINT16 * offset, BYTE * blob,
			  TCPA_MIGRATIONKEYAUTH * mkAuth)
{
	LoadBlob_PUBKEY(offset, blob, &mkAuth->migrationKey);
	LoadBlob_UINT16(offset, mkAuth->migrationScheme, blob,
			"mkauth migScheme");
	LoadBlob(offset, 20, blob, mkAuth->digest.digest, "mkauth digest");
}

void
UnloadBlob_MIGRATIONKEYAUTH(UINT16 * offset,
			    BYTE * blob, TCPA_MIGRATIONKEYAUTH * mkAuth)
{
	UnloadBlob_PUBKEY(offset, blob, &mkAuth->migrationKey);
	UnloadBlob_UINT16(offset, &mkAuth->migrationScheme, blob,
			  "mkauth migScheme");
	UnloadBlob(offset, 20, blob, mkAuth->digest.digest, "mkauth digest");
}

void
LoadBlob_Auth(UINT16 * offset, BYTE * blob, TPM_AUTH * auth)
{
	LoadBlob_UINT32(offset, auth->AuthHandle, blob, "Auth AuthHandle");
	LoadBlob(offset, TCPA_NONCE_SIZE, blob, auth->NonceOdd.nonce, "Auth: NonceOdd");
	LoadBlob_BOOL(offset, auth->fContinueAuthSession, blob, "CAS");
	LoadBlob(offset, TCPA_AUTHDATA_SIZE, blob, (BYTE *)&auth->HMAC, "auth: HMAC");
}

void
UnloadBlob_Auth(UINT16 * offset, BYTE * blob, TPM_AUTH * auth)
{
	UnloadBlob(offset, TCPA_NONCE_SIZE, blob, auth->NonceEven.nonce, "Nonce Even");
	UnloadBlob_BOOL(offset, &auth->fContinueAuthSession, blob, "CAS");
	UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, (BYTE *)&auth->HMAC, "Auth HMAC");
}

void
LoadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob,
		   TCPA_KEY_PARMS * keyInfo)
{
	LoadBlob_UINT32(offset, keyInfo->algorithmID, blob, "KEY_PARMS: algID");
	LoadBlob_UINT16(offset, keyInfo->encScheme, blob,
			"KEY_PARMS: encScheme");
	LoadBlob_UINT16(offset, keyInfo->sigScheme, blob,
			"KEY_PARMS: sigScheme");
	LoadBlob_UINT32(offset, keyInfo->parmSize, blob, "KEY_PARMS: parmSize");
	LoadBlob(offset, keyInfo->parmSize, blob, keyInfo->parms,
		 "KEY_PARMS: parms");
}

TSS_RESULT
UnloadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob,
		     TCPA_KEY_PARMS * keyParms)
{
	UnloadBlob_UINT32(offset, &keyParms->algorithmID, blob,
			  "KEY_PARMS: algID");
	UnloadBlob_UINT16(offset, &keyParms->encScheme, blob,
			  "KEY_PARMS: encScheme");
	UnloadBlob_UINT16(offset, &keyParms->sigScheme, blob,
			  "KEY_PARMS: sigScheme");
	UnloadBlob_UINT32(offset, &keyParms->parmSize, blob,
			  "KEY_PARMS: parmSize");

	if (keyParms->parmSize == 0)
		keyParms->parms = NULL;
	else {
		keyParms->parms = malloc(keyParms->parmSize);
		if (keyParms->parms == NULL) {
			LogError("malloc of %u bytes failed.", keyParms->parmSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		UnloadBlob(offset, keyParms->parmSize, blob, keyParms->parms,
				"KEY_PARMS: parms");
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob,
			TCPA_STORE_PUBKEY * store)
{
	UnloadBlob_UINT32(offset, &store->keyLength, blob,
			  "STORE_PUBKEY KeyLength");

	if (store->keyLength == 0) {
		store->key = NULL;
		LogWarn("Unloading a public key of size 0!");
	} else {
		store->key = (BYTE *)malloc(store->keyLength);
		if (store->key == NULL) {
			LogError("malloc of %d bytes failed.", store->keyLength);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		UnloadBlob(offset, store->keyLength, blob, store->key,
				"STORE_PUBKEY key");
	}

	return TSS_SUCCESS;
}

void
LoadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob,
		      TCPA_STORE_PUBKEY * store)
{
	LoadBlob_UINT32(offset, store->keyLength, blob,
			"STORE_PUBKEY keyLength");
	LoadBlob(offset, store->keyLength, blob, store->key,
		 "STORE_PUBKEY key");
}

void
UnloadBlob_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out)
{
	UnloadBlob_BYTE(offset, &out->major, blob, NULL);
	UnloadBlob_BYTE(offset, &out->minor, blob, NULL);
	UnloadBlob_BYTE(offset, &out->revMajor, blob, NULL);
	UnloadBlob_BYTE(offset, &out->revMinor, blob, NULL);
}

void
LoadBlob_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * ver)
{
	LoadBlob_BYTE(offset, ver->major, blob, NULL);
	LoadBlob_BYTE(offset, ver->minor, blob, NULL);
	LoadBlob_BYTE(offset, ver->revMajor, blob, NULL);
	LoadBlob_BYTE(offset, ver->revMinor, blob, NULL);
}

TSS_RESULT
UnloadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key)
{
	TSS_RESULT rc;

	UnloadBlob_VERSION(offset, blob, &key->ver);
	UnloadBlob_UINT16(offset, &key->keyUsage, blob, "KEY keyUsage");
	UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	UnloadBlob_BOOL(offset, (TSS_BOOL *)&key->authDataUsage, blob, "KEY AuthDataUsage");
	if ((rc = UnloadBlob_KEY_PARMS(offset, blob, &key->algorithmParms)))
		return rc;
	UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob, "KEY PCRInfoSize");

	if (key->PCRInfoSize == 0)
		key->PCRInfo = NULL;
	else {
		key->PCRInfo = malloc(key->PCRInfoSize);
		if (key->PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", key->PCRInfoSize);
			free(key->algorithmParms.parms);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo, "KEY PCRInfo");
	}

	if ((rc = UnloadBlob_STORE_PUBKEY(offset, blob, &key->pubKey))) {
		free(key->PCRInfo);
		free(key->algorithmParms.parms);
		return rc;
	}
	UnloadBlob_UINT32(offset, &key->encSize, blob, "KEY encSize");

	if (key->encSize == 0)
		key->encData = NULL;
	else {
		key->encData = (BYTE *)malloc(key->encSize);
		if (key->encData == NULL) {
			LogError("malloc of %d bytes failed.", key->encSize);
			free(key->algorithmParms.parms);
			free(key->PCRInfo);
			free(key->pubKey.key);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->encSize, blob, key->encData, "KEY encData");
	}

	return TSS_SUCCESS;
}

void
LoadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key)
{
	LoadBlob_VERSION(offset, blob, &key->ver);
	LoadBlob_UINT16(offset, key->keyUsage, blob, "KEY keyUsage");
	LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	LoadBlob_BOOL(offset, key->authDataUsage, blob, "KEY authDataUsage");
	LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);
	LoadBlob_UINT32(offset, key->PCRInfoSize, blob, "KEY pcrInfosize");
	LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo, "KEY PCRInfo");
	LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	LoadBlob_UINT32(offset, key->encSize, blob, "KEY encSize");
	LoadBlob(offset, key->encSize, blob, key->encData, "KEY encData");
}

void
LoadBlob_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_PUBKEY * key)
{
	LoadBlob_KEY_PARMS(offset, blob, &(key->algorithmParms));
	LoadBlob_STORE_PUBKEY(offset, blob, &(key->pubKey));
}

TSS_RESULT
UnloadBlob_PUBKEY(UINT16 * offset, BYTE * blob,
		  TCPA_PUBKEY * key)
{
	TSS_RESULT rc;

	if ((rc = UnloadBlob_KEY_PARMS(offset, blob, &key->algorithmParms)))
		return rc;
	if ((rc = UnloadBlob_STORE_PUBKEY(offset, blob, &key->pubKey))) {
		free(key->algorithmParms.parms);
	}

	return rc;
}
#if 0
void
LoadBlob_SYMMETRIC_KEY(UINT16 *offset, BYTE *blob, TCPA_SYMMETRIC_KEY *key)
{
	LoadBlob_UINT32(offset, key->algId, blob, NULL);
	LoadBlob_UINT16(offset, key->encScheme, blob, NULL);
	LoadBlob_UINT16(offset, key->size, blob, NULL);

	if (key->size > 0) {
		LoadBlob(offset, key->size, blob, key->data, NULL);
	} else {
		key->data = NULL;
	}
}

TSS_RESULT
UnloadBlob_SYMMETRIC_KEY(UINT16 *offset, BYTE *blob, TCPA_SYMMETRIC_KEY *key)
{
	UnloadBlob_UINT32(offset, &key->algId, blob, NULL);
	UnloadBlob_UINT16(offset, &key->encScheme, blob, NULL);
	UnloadBlob_UINT16(offset, &key->size, blob, NULL);

	if (key->size > 0) {
		key->data = (BYTE *)malloc(key->size);
		if (key->data == NULL) {
			LogError("malloc of %hu bytes failed.", key->size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, key->size, blob, key->data, "SYM KEY data");
	} else {
		key->data = NULL;
	}

	return TSS_SUCCESS;
}
#endif
TSS_RESULT
UnloadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob,
			 TCPA_PCR_SELECTION * pcr)
{
	UnloadBlob_UINT16(offset, &pcr->sizeOfSelect, blob,
			  "PCR SEL sizeOfSel");
	pcr->pcrSelect = malloc(pcr->sizeOfSelect);
        if (pcr->pcrSelect == NULL) {
		LogError("malloc of %d bytes failed.", pcr->sizeOfSelect);
                return TCSERR(TSS_E_OUTOFMEMORY);
        }
	UnloadBlob(offset, pcr->sizeOfSelect, blob, pcr->pcrSelect,
		   "PCR SEL pcrSel");
	return TSS_SUCCESS;
}

void
LoadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob,
		       TCPA_PCR_SELECTION pcr)
{
	LoadBlob_UINT16(offset, pcr.sizeOfSelect, blob, "PCR SEL sizeOfSel");
	LoadBlob(offset, pcr.sizeOfSelect, blob, pcr.pcrSelect,
		 "PCR SEL pcrSel");
}

TSS_RESULT
UnloadBlob_PCR_COMPOSITE(UINT16 *offset, BYTE *blob,
			 TCPA_PCR_COMPOSITE *out)
{
	TSS_RESULT rc;

	if ((rc = UnloadBlob_PCR_SELECTION(offset, blob, &out->select)))
		return rc;

	UnloadBlob_UINT32(offset, &out->valueSize, blob, "PCR COMP valueSize");
	out->pcrValue = malloc(out->valueSize);
        if (out->pcrValue == NULL) {
		LogError("malloc of %d bytes failed.", out->valueSize);
                return TCSERR(TSS_E_OUTOFMEMORY);
        }
	UnloadBlob(offset, out->valueSize, blob, (BYTE *) out->pcrValue,
		   "PCR COMP value");
	return TSS_SUCCESS;
}

void
LoadBlob_PCR_INFO(UINT16 * offset, BYTE * blob, TCPA_PCR_INFO * pcr)
{
	LoadBlob_PCR_SELECTION(offset, blob, pcr->pcrSelection);
	LoadBlob(offset, TCPA_DIGEST_SIZE, blob, pcr->digestAtRelease.digest,
		 "PCR_INFO digAtRel");
	LoadBlob(offset, TCPA_DIGEST_SIZE, blob, pcr->digestAtCreation.digest,
		 "PCR_INFO digAtCreate");
}

TSS_RESULT
UnloadBlob_PCR_INFO(UINT16 * offset, BYTE * blob,
		    TCPA_PCR_INFO * pcr)
{
	TSS_RESULT rc;

	if ((rc = UnloadBlob_PCR_SELECTION(offset, blob, &pcr->pcrSelection)))
		return rc;
	UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, pcr->digestAtRelease.digest, "PCR_INFO digAtRel");
	UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, pcr->digestAtCreation.digest, "PCR_INFO digAtCreate");

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_STORED_DATA(UINT16 * offset, BYTE * blob,
		       TCPA_STORED_DATA * data)
{
	UnloadBlob_VERSION(offset, blob, &data->ver);

	UnloadBlob_UINT32(offset, &data->sealInfoSize, blob, "seal info size");

	if (data->sealInfoSize > 0) {
		data->sealInfo = (BYTE *)calloc(1, data->sealInfoSize);
		if (data->sealInfo == NULL) {
			LogError("malloc of %d bytes failed.", data->sealInfoSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, data->sealInfoSize, blob, data->sealInfo, "seal info");
	} else {
		data->sealInfo = NULL;
	}

	UnloadBlob_UINT32(offset, &data->encDataSize, blob, "encDataSize");

	if (data->encDataSize > 0) {
		data->encData = (BYTE *)calloc(1, data->encDataSize);
		if (data->encData == NULL) {
			LogError("malloc of %d bytes failed.", data->encDataSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, data->encDataSize, blob, data->encData, "encdata");
	} else {
		data->encData = NULL;
	}

	return TSS_SUCCESS;
}

void
LoadBlob_STORED_DATA(UINT16 * offset, BYTE * blob,
		     TCPA_STORED_DATA * data)
{
	LoadBlob_VERSION(offset, blob, &data->ver);

	LoadBlob_UINT32(offset, data->sealInfoSize, blob, "seal info size");
	LoadBlob(offset, data->sealInfoSize, blob, data->sealInfo, "seal info");
	LoadBlob_UINT32(offset, data->encDataSize, blob, "encSize");
	LoadBlob(offset, data->encDataSize, blob, data->encData, "encData");
}

void
LoadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;

	if ((*flags) & migratable)
		tempFlag |= TSS_FLAG_MIGRATABLE;
	if ((*flags) & redirection)
		tempFlag |= TSS_FLAG_REDIRECTION;
	if ((*flags) & volatileKey)
		tempFlag |= TSS_FLAG_VOLATILE;
	LoadBlob_UINT32(offset, tempFlag, blob, "Flags");
}

void
UnloadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;
	memset(flags, 0x00, sizeof (TCPA_KEY_FLAGS));

	UnloadBlob_UINT32(offset, &tempFlag, blob, "Flags");

	if (tempFlag & redirection)
		*flags |= redirection;
	if (tempFlag & migratable)
		*flags |= migratable;
	if (tempFlag & volatileKey)
		*flags |= volatileKey;
}

TSS_RESULT
UnloadBlob_CERTIFY_INFO(UINT16 * offset, BYTE * blob,
			TCPA_CERTIFY_INFO * certify)
{
	TSS_RESULT rc;

	LogDebug("Certify Info");
	UnloadBlob_VERSION(offset, blob, &certify->version);
	UnloadBlob_UINT16(offset, &certify->keyUsage, blob, "usage");
	UnloadBlob_KEY_FLAGS(offset, blob, &certify->keyFlags);
	UnloadBlob_BOOL(offset, (TSS_BOOL *)&certify->authDataUsage, blob, "authDatausage");

	if ((rc = UnloadBlob_KEY_PARMS(offset, blob, &certify->algorithmParms)))
		return rc;

	UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, certify->pubkeyDigest.digest, "pubkey digest");
	UnloadBlob(offset, TCPA_NONCE_SIZE, blob, certify->data.nonce, "data");
	UnloadBlob_BOOL(offset, &certify->parentPCRStatus, blob, "parent pcr status");
	UnloadBlob_UINT32(offset, &certify->PCRInfoSize, blob, "pcr info size");

	if (certify->PCRInfoSize > 0) {
		certify->PCRInfo = (BYTE *)malloc(certify->PCRInfoSize);
		if (certify->PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", certify->PCRInfoSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(offset, certify->PCRInfoSize, blob, certify->PCRInfo, "pcr info");
	} else {
		certify->PCRInfo = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_KEY_HANDLE_LIST(UINT16 * offset,
			   BYTE * blob, TCPA_KEY_HANDLE_LIST * list)
{
	UINT16 i;

	UnloadBlob_UINT16(offset, &list->loaded, blob,
			  "key handle list: loaded");
	if (list->loaded == 0)
		return TSS_SUCCESS;
	list->handle = malloc(list->loaded * sizeof (UINT32));
        if (list->handle == NULL) {
		LogError("malloc of %zd bytes failed.", list->loaded * sizeof (UINT32));
                return TCSERR(TSS_E_OUTOFMEMORY);
        }

	for (i = 0; i < list->loaded; i++) {
		UnloadBlob_UINT32(offset, &list->handle[i], blob,
				  "key handle list: handle");
	}
	return TSS_SUCCESS;
}

void
LoadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID uuid)
{
	LoadBlob_UINT32(offset, uuid.ulTimeLow, blob, NULL);
	LoadBlob_UINT16(offset, uuid.usTimeMid, blob, NULL);
	LoadBlob_UINT16(offset, uuid.usTimeHigh, blob, NULL);
	LoadBlob_BYTE(offset, uuid.bClockSeqHigh, blob, NULL);
	LoadBlob_BYTE(offset, uuid.bClockSeqLow, blob, NULL);
	LoadBlob(offset, 6, blob, uuid.rgbNode, NULL);
}

void
UnloadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID *uuid)
{
	memset(uuid, 0, sizeof(TSS_UUID));
	UnloadBlob_UINT32(offset, &uuid->ulTimeLow, blob, NULL);
	UnloadBlob_UINT16(offset, &uuid->usTimeMid, blob, NULL);
	UnloadBlob_UINT16(offset, &uuid->usTimeHigh, blob, NULL);
	UnloadBlob_BYTE(offset, &uuid->bClockSeqHigh, blob, NULL);
	UnloadBlob_BYTE(offset, &uuid->bClockSeqLow, blob, NULL);
	UnloadBlob(offset, 6, blob, uuid->rgbNode, NULL);
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

/* XXX make this a macro */
UINT32
get_pcr_event_size(TSS_PCR_EVENT *e)
{
	return (sizeof(TSS_PCR_EVENT) + e->ulEventLength + e->ulPcrValueLength);
}

/*
 * Hopefully this will make the code clearer since
 * OpenSSL returns 1 on success
 */
#define EVP_SUCCESS 1

TSS_RESULT
Hash(UINT32 HashType, UINT32 BufSize, BYTE* Buf, BYTE* Digest)
{
	EVP_MD_CTX md_ctx;
	unsigned int result_size;
	int rv;

	switch (HashType) {
		case TSS_HASH_SHA1:
			rv = EVP_DigestInit(&md_ctx, EVP_sha1());
			break;
		default:
			rv = TSPERR(TSS_E_BAD_PARAMETER);
			goto out;
			break;
	}

	if (rv != EVP_SUCCESS) {
		rv = TSPERR(TSS_E_INTERNAL_ERROR);
		goto out;
	}

	rv = EVP_DigestUpdate(&md_ctx, Buf, BufSize);
	if (rv != EVP_SUCCESS) {
		rv = TSPERR(TSS_E_INTERNAL_ERROR);
		goto out;
	}

	result_size = EVP_MD_CTX_size(&md_ctx);
	rv = EVP_DigestFinal(&md_ctx, Digest, &result_size);
	if (rv != EVP_SUCCESS) {
		rv = TSPERR(TSS_E_INTERNAL_ERROR);
	} else
		rv = TSS_SUCCESS;

out:
	return rv;
}

void
get_credential(int type, UINT32 *size, BYTE **cred)
{
	int rc, fd;
	char *path = NULL;
	void *file = NULL;
	struct stat stat_buf;
	size_t file_size;

	switch (type) {
		case PLATFORM:
			path = tcsd_options.platform_cred;
			break;
		case CONFORMANCE:
			path = tcsd_options.conformance_cred;
			break;
		case ENDORSEMENT:
			path = tcsd_options.endorsement_cred;
			break;
		default:
			LogDebugFn("Bad credential type");
			break;
	}

	if (path == NULL)
		goto done;

	if ((fd = open(path, O_RDONLY)) < 0) {
		LogError("open(%s): %s", path, strerror(errno));
		goto done;
	}

	if ((rc = fstat(fd, &stat_buf)) == -1) {
		LogError("Error stating credential: %s: %s", path, strerror(errno));
		goto done;
	}

	file_size = (size_t)stat_buf.st_size;

	LogDebugFn("%s, (%zd bytes)", path, file_size);

	file = mmap(0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		LogError("Error reading credential: %s: %s", path, strerror(errno));
		close(fd);
		goto done;
	}
	close(fd);

	if ((*cred = malloc(file_size)) == NULL) {
		LogError("malloc of %zd bytes failed.", file_size);
		munmap(file, file_size);
		goto done;
	}

	memcpy(*cred, file, file_size);
	*size = file_size;
	munmap(file, file_size);

	return;
done:
	*cred = NULL;
	*size = 0;
}
