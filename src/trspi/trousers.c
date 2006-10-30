
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
#include <sys/mman.h>
#include <langinfo.h>
#include <iconv.h>
#include <wchar.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


void
Trspi_UnloadBlob_DIGEST(UINT64 *offset, BYTE *blob, TCPA_DIGEST digest)
{
	Trspi_UnloadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob, digest.digest);
}

void
Trspi_LoadBlob_PUBKEY(UINT64 *offset, BYTE *blob, TCPA_PUBKEY *pubKey)
{
	Trspi_LoadBlob_KEY_PARMS(offset, blob, &pubKey->algorithmParms);
	Trspi_LoadBlob_STORE_PUBKEY(offset, blob, &pubKey->pubKey);
}

TSS_RESULT
Trspi_UnloadBlob_PUBKEY(UINT64 *offset, BYTE *blob, TCPA_PUBKEY *pubKey)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_KEY_PARMS(offset, blob, &pubKey->algorithmParms)))
		return result;
	if ((result = Trspi_UnloadBlob_STORE_PUBKEY(offset, blob, &pubKey->pubKey))) {
		free(pubKey->pubKey.key);
		free(pubKey->algorithmParms.parms);
		pubKey->pubKey.key = NULL;
		pubKey->pubKey.keyLength = 0;
		pubKey->algorithmParms.parms = NULL;
		pubKey->algorithmParms.parmSize = 0;
		return result;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob(UINT64 *offset, size_t size, BYTE *to, BYTE *from)
{
	if (size == 0)
		return;
	memcpy(&to[(*offset)], from, size);
	*offset += size;
}

void
Trspi_UnloadBlob(UINT64 *offset, size_t size, BYTE *from, BYTE *to)
{
	if (size <= 0)
		return;
	memcpy(to, &from[*offset], size);
	*offset += size;
}

void
Trspi_LoadBlob_BYTE(UINT64 *offset, BYTE data, BYTE *blob)
{
	blob[*offset] = data;
	(*offset)++;
}

void
Trspi_UnloadBlob_BYTE(UINT64 *offset, BYTE *dataOut, BYTE *blob)
{
	*dataOut = blob[*offset];
	(*offset)++;
}

void
Trspi_LoadBlob_BOOL(UINT64 *offset, TSS_BOOL data, BYTE *blob)
{
	blob[*offset] = (BYTE) data;
	(*offset)++;
}

void
Trspi_UnloadBlob_BOOL(UINT64 *offset, TSS_BOOL *dataOut, BYTE *blob)
{
	*dataOut = blob[*offset];
	(*offset)++;
}

void
Trspi_LoadBlob_UINT32(UINT64 *offset, UINT32 in, BYTE *blob)
{
	UINT32ToArray(in, &blob[*offset]);
	*offset += 4;
}

void
Trspi_LoadBlob_UINT16(UINT64 *offset, UINT16 in, BYTE *blob)
{
	UINT16ToArray(in, &blob[*offset]);
	*offset += sizeof(UINT16);
}

void
Trspi_UnloadBlob_UINT32(UINT64 *offset, UINT32 *out, BYTE *blob)
{
	*out = Decode_UINT32(&blob[*offset]);
	*offset += sizeof(UINT32);
}

void
Trspi_UnloadBlob_UINT16(UINT64 *offset, UINT16 *out, BYTE *blob)
{
	*out = Decode_UINT16(&blob[*offset]);
	*offset += sizeof(UINT16);
}

void
Trspi_LoadBlob_RSA_KEY_PARMS(UINT64 *offset, BYTE *blob, TCPA_RSA_KEY_PARMS *parms)
{
	Trspi_LoadBlob_UINT32(offset, parms->keyLength, blob);
	Trspi_LoadBlob_UINT32(offset, parms->numPrimes, blob);
	Trspi_LoadBlob_UINT32(offset, parms->exponentSize, blob);

	if (parms->exponentSize > 0)
		Trspi_LoadBlob(offset, parms->exponentSize, blob, parms->exponent);
}

void
Trspi_UnloadBlob_TSS_VERSION(UINT64 *offset, BYTE *blob, TSS_VERSION *out)
{
	out->bMajor = blob[(*offset)++];
	out->bMinor = blob[(*offset)++];
	out->bRevMajor = blob[(*offset)++];
	out->bRevMinor = blob[(*offset)++];
}

void
Trspi_LoadBlob_TSS_VERSION(UINT64 *offset, BYTE *blob, TSS_VERSION version)
{
	blob[(*offset)++] = version.bMajor;
	blob[(*offset)++] = version.bMinor;
	blob[(*offset)++] = version.bRevMajor;
	blob[(*offset)++] = version.bRevMinor;
}

void
Trspi_UnloadBlob_TCPA_VERSION(UINT64 *offset, BYTE *blob, TCPA_VERSION *out)
{
	out->major = blob[(*offset)++];
	out->minor = blob[(*offset)++];
	out->revMajor = blob[(*offset)++];
	out->revMinor = blob[(*offset)++];
}

void
Trspi_LoadBlob_TCPA_VERSION(UINT64 *offset, BYTE *blob, TCPA_VERSION version)
{
	blob[(*offset)++] = version.major;
	blob[(*offset)++] = version.minor;
	blob[(*offset)++] = version.revMajor;
	blob[(*offset)++] = version.revMinor;
}

TSS_RESULT
Trspi_UnloadBlob_PCR_SELECTION(UINT64 *offset, BYTE *blob, TCPA_PCR_SELECTION *pcr)
{
	UINT16 i;

	pcr->sizeOfSelect = Decode_UINT16(&blob[*offset]);

	if (pcr->sizeOfSelect > 0) {
		*offset += sizeof(UINT16);
		pcr->pcrSelect = calloc(1, pcr->sizeOfSelect);
		if (pcr->pcrSelect == NULL) {
			LogError("malloc of %d bytes failed.", pcr->sizeOfSelect);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		for (i = 0; i < pcr->sizeOfSelect; i++, (*offset)++)
			pcr->pcrSelect[i] = blob[*offset];
	} else {
		pcr->pcrSelect = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob_PCR_SELECTION(UINT64 *offset, BYTE *blob, TCPA_PCR_SELECTION *pcr)
{
	UINT16 i;

	UINT16ToArray(pcr->sizeOfSelect, &blob[*offset]);
	*offset += sizeof(UINT16);
	for (i = 0; i < pcr->sizeOfSelect; i++, (*offset)++)
		blob[*offset] = pcr->pcrSelect[i];
}

void
Trspi_LoadBlob_KEY(UINT64 *offset, BYTE *blob, TCPA_KEY *key)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, key->ver);
	Trspi_LoadBlob_UINT16(offset, key->keyUsage, blob);
	Trspi_LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	blob[(*offset)++] = key->authDataUsage;
	Trspi_LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);
	Trspi_LoadBlob_UINT32(offset, key->PCRInfoSize, blob);
	Trspi_LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	Trspi_LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	Trspi_LoadBlob_UINT32(offset, key->encSize, blob);
	Trspi_LoadBlob(offset, key->encSize, blob, key->encData);
}

void
Trspi_LoadBlob_KEY_FLAGS(UINT64 *offset, BYTE *blob, TCPA_KEY_FLAGS *flags)
{
	UINT32 tempFlag = 0;

	if (*flags & migratable)
		tempFlag |= TSS_FLAG_MIGRATABLE;
	if (*flags & redirection)
		tempFlag |= TSS_FLAG_REDIRECTION;
	if (*flags & volatileKey)
		tempFlag |= TSS_FLAG_VOLATILE;
	Trspi_LoadBlob_UINT32(offset, tempFlag, blob);
}

void
Trspi_UnloadBlob_KEY_FLAGS(UINT64 *offset, BYTE *blob, TCPA_KEY_FLAGS *flags)
{
	UINT32 tempFlag = 0;
	memset(flags, 0x00, sizeof(TCPA_KEY_FLAGS));

	Trspi_UnloadBlob_UINT32(offset, &tempFlag, blob);

	if (tempFlag & TSS_FLAG_REDIRECTION)
		*flags |= redirection;
	if (tempFlag & TSS_FLAG_MIGRATABLE)
		*flags |= migratable;
	if (tempFlag & TSS_FLAG_VOLATILE)
		*flags |= volatileKey;
}

void
Trspi_LoadBlob_KEY_PARMS(UINT64 *offset, BYTE *blob, TCPA_KEY_PARMS *keyInfo)
{
	Trspi_LoadBlob_UINT32(offset, keyInfo->algorithmID, blob);
	Trspi_LoadBlob_UINT16(offset, keyInfo->encScheme, blob);
	Trspi_LoadBlob_UINT16(offset, keyInfo->sigScheme, blob);
	Trspi_LoadBlob_UINT32(offset, keyInfo->parmSize, blob);

	if (keyInfo->parmSize > 0)
		Trspi_LoadBlob(offset, keyInfo->parmSize, blob, keyInfo->parms);
}

void
Trspi_LoadBlob_STORE_PUBKEY(UINT64 *offset, BYTE *blob, TCPA_STORE_PUBKEY *store)
{
	Trspi_LoadBlob_UINT32(offset, store->keyLength, blob);
	Trspi_LoadBlob(offset, store->keyLength, blob, store->key);
}

void
Trspi_LoadBlob_UUID(UINT64 *offset, BYTE *blob, TSS_UUID uuid)
{
	Trspi_LoadBlob_UINT32(offset, uuid.ulTimeLow, blob);
	Trspi_LoadBlob_UINT16(offset, uuid.usTimeMid, blob);
	Trspi_LoadBlob_UINT16(offset, uuid.usTimeHigh, blob);
	Trspi_LoadBlob_BYTE(offset, uuid.bClockSeqHigh, blob);
	Trspi_LoadBlob_BYTE(offset, uuid.bClockSeqLow, blob);
	Trspi_LoadBlob(offset, 6, blob, uuid.rgbNode);
}

void
Trspi_UnloadBlob_UUID(UINT64 *offset, BYTE *blob, TSS_UUID *uuid)
{
	memset(uuid, 0, sizeof(TSS_UUID));
	Trspi_UnloadBlob_UINT32(offset, &uuid->ulTimeLow, blob);
	Trspi_UnloadBlob_UINT16(offset, &uuid->usTimeMid, blob);
	Trspi_UnloadBlob_UINT16(offset, &uuid->usTimeHigh, blob);
	Trspi_UnloadBlob_BYTE(offset, &uuid->bClockSeqHigh, blob);
	Trspi_UnloadBlob_BYTE(offset, &uuid->bClockSeqLow, blob);
	Trspi_UnloadBlob(offset, 6, blob, uuid->rgbNode);
}

TSS_RESULT
Trspi_UnloadBlob_KEY_PARMS(UINT64 *offset, BYTE *blob, TCPA_KEY_PARMS *keyParms)
{
	Trspi_UnloadBlob_UINT32(offset, &keyParms->algorithmID, blob);
	Trspi_UnloadBlob_UINT16(offset, &keyParms->encScheme, blob);
	Trspi_UnloadBlob_UINT16(offset, &keyParms->sigScheme, blob);
	Trspi_UnloadBlob_UINT32(offset, &keyParms->parmSize, blob);

	if (keyParms->parmSize > 0) {
		keyParms->parms = malloc(keyParms->parmSize);
		if (keyParms->parms == NULL) {
			LogError("malloc of %d bytes failed.", keyParms->parmSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, keyParms->parmSize, blob, keyParms->parms);
	} else {
		keyParms->parms = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Trspi_UnloadBlob_KEY(UINT64 *offset, BYTE *blob, TCPA_KEY *key)
{
	TSS_RESULT result;

	Trspi_UnloadBlob_TCPA_VERSION(offset, blob, &key->ver);
	Trspi_UnloadBlob_UINT16(offset, &key->keyUsage, blob);
	Trspi_UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	key->authDataUsage = blob[(*offset)++];
	if ((result = Trspi_UnloadBlob_KEY_PARMS(offset, (BYTE *) blob, &key->algorithmParms)))
		return result;
	Trspi_UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob);

	if (key->PCRInfoSize > 0) {
		key->PCRInfo = malloc(key->PCRInfoSize);
		if (key->PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", key->PCRInfoSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	} else {
		key->PCRInfo = NULL;
	}

	if ((result = Trspi_UnloadBlob_STORE_PUBKEY(offset, blob, &key->pubKey)))
		return result;
	Trspi_UnloadBlob_UINT32(offset, &key->encSize, blob);

	if (key->encSize > 0) {
		key->encData = malloc(key->encSize);
		if (key->encData == NULL) {
			LogError("malloc of %d bytes failed.", key->encSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, key->encSize, blob, key->encData);
	} else {
		key->encData = NULL;
	}

	return result;
}

/*
void UnloadBlob_VERSION( UINT16* offset,  BYTE* blob, TCPA_VERSION* out ){

	out->major = blob[(*offset)++];
	out->minor = blob[(*offset)++];
	out->revMajor = blob[(*offset)++];
	out->revMinor = blob[(*offset)++];

	return;
}
*/

TSS_RESULT
Trspi_UnloadBlob_STORE_PUBKEY(UINT64 *offset, BYTE *blob, TCPA_STORE_PUBKEY *store)
{
	Trspi_UnloadBlob_UINT32(offset, &store->keyLength, blob);

	if (store->keyLength > 0) {
		store->key = malloc(store->keyLength);
		if (store->key == NULL) {
			LogError("malloc of %d bytes failed.", store->keyLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, store->keyLength, blob, store->key);
	} else {
		store->key = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_UnloadBlob_VERSION(UINT64 *offset, BYTE *blob, TCPA_VERSION *out)
{
	Trspi_UnloadBlob_BYTE(offset, &out->major, blob);
	Trspi_UnloadBlob_BYTE(offset, &out->minor, blob);
	Trspi_UnloadBlob_BYTE(offset, &out->revMajor, blob);
	Trspi_UnloadBlob_BYTE(offset, &out->revMinor, blob);
}

void
Trspi_UnloadBlob_KM_KEYINFO(UINT64 *offset, BYTE *blob, TSS_KM_KEYINFO *info)
{
	Trspi_UnloadBlob_TSS_VERSION( offset, blob, &info->versionInfo);
	Trspi_UnloadBlob_UUID( offset, blob, &info->keyUUID);
	Trspi_UnloadBlob_UUID( offset, blob, &info->parentKeyUUID);
	Trspi_UnloadBlob_BYTE( offset, &info->bAuthDataUsage, blob);
	Trspi_UnloadBlob_BOOL( offset, &info->fIsLoaded, blob);
	Trspi_UnloadBlob_UINT32( offset, &info->ulVendorDataLength, blob);
	Trspi_UnloadBlob(offset, info->ulVendorDataLength, info->rgbVendorData, blob);
}

void
Trspi_LoadBlob_PCR_EVENT(UINT64 *offset, BYTE *blob, TSS_PCR_EVENT *event)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, *(TCPA_VERSION *)(&event->versionInfo));
	Trspi_LoadBlob_UINT32(offset, event->ulPcrIndex, blob);
	Trspi_LoadBlob_UINT32(offset, event->eventType, blob);

	Trspi_LoadBlob_UINT32(offset, event->ulPcrValueLength, blob);
	if (event->ulPcrValueLength > 0)
		Trspi_LoadBlob(offset, event->ulPcrValueLength, blob, event->rgbPcrValue);

	Trspi_LoadBlob_UINT32(offset, event->ulEventLength, blob);
	if (event->ulEventLength > 0)
		Trspi_LoadBlob(offset, event->ulEventLength, blob, event->rgbEvent);

}

TSS_RESULT
Trspi_UnloadBlob_PCR_EVENT(UINT64 *offset, BYTE *blob, TSS_PCR_EVENT *event)
{
	Trspi_UnloadBlob_VERSION(offset, blob, (TCPA_VERSION *)&(event->versionInfo));
	Trspi_UnloadBlob_UINT32(offset, &event->ulPcrIndex, blob);
	Trspi_UnloadBlob_UINT32(offset, &event->eventType, blob);

	Trspi_UnloadBlob_UINT32(offset, &event->ulPcrValueLength, blob);
	if (event->ulPcrValueLength > 0) {
		event->rgbPcrValue = malloc(event->ulPcrValueLength);
		if (event->rgbPcrValue == NULL) {
			LogError("malloc of %d bytes failed.", event->ulPcrValueLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		Trspi_UnloadBlob(offset, event->ulPcrValueLength, blob, event->rgbPcrValue);
	} else {
		event->rgbPcrValue = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &event->ulEventLength, blob);
	if (event->ulEventLength > 0) {
		event->rgbEvent = malloc(event->ulEventLength);
		if (event->rgbEvent == NULL) {
			LogError("malloc of %d bytes failed.", event->ulEventLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		Trspi_UnloadBlob(offset, event->ulEventLength, blob, event->rgbEvent);
	} else {
		event->rgbEvent = NULL;
	}

	return TSS_SUCCESS;
}

/* loads a blob with the info needed to hash when creating the private key area
 * of a TCPA_KEY from an external source
 */
void
Trspi_LoadBlob_PRIVKEY_DIGEST(UINT64 *offset, BYTE *blob, TCPA_KEY *key)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, key->ver);
	Trspi_LoadBlob_UINT16(offset, key->keyUsage, blob);
	Trspi_LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	blob[(*offset)++] = key->authDataUsage;
	Trspi_LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);

	Trspi_LoadBlob_UINT32(offset, key->PCRInfoSize, blob);
	/* exclude pcrInfo when PCRInfoSize is 0 as spec'd in TPM 1.1b spec p.71 */
	if (key->PCRInfoSize != 0)
		Trspi_LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);

	Trspi_LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	/* exclude encSize, encData as spec'd in TPM 1.1b spec p.71 */
}

void
Trspi_LoadBlob_SYMMETRIC_KEY(UINT64 *offset, BYTE *blob, TCPA_SYMMETRIC_KEY *key)
{
	Trspi_LoadBlob_UINT32(offset, key->algId, blob);
	Trspi_LoadBlob_UINT16(offset, key->encScheme, blob);
	Trspi_LoadBlob_UINT16(offset, key->size, blob);

	if (key->size > 0)
		Trspi_LoadBlob(offset, key->size, blob, key->data);
}

TSS_RESULT
Trspi_UnloadBlob_SYMMETRIC_KEY(UINT64 *offset, BYTE *blob, TCPA_SYMMETRIC_KEY *key)
{
	Trspi_UnloadBlob_UINT32(offset, &key->algId, blob);
	Trspi_UnloadBlob_UINT16(offset, &key->encScheme, blob);
	Trspi_UnloadBlob_UINT16(offset, &key->size, blob);

	if (key->size > 0) {
		key->data = malloc(key->size);
		if (key->data == NULL) {
			key->size = 0;
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, key->size, blob, key->data);
	} else {
		key->data = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob_IDENTITY_REQ(UINT64 *offset, BYTE *blob, TCPA_IDENTITY_REQ *req)
{
	Trspi_LoadBlob_UINT32(offset, req->asymSize, blob);
	Trspi_LoadBlob_UINT32(offset, req->symSize, blob);
	Trspi_LoadBlob_KEY_PARMS(offset, blob, &req->asymAlgorithm);
	Trspi_LoadBlob_KEY_PARMS(offset, blob, &req->symAlgorithm);
	Trspi_LoadBlob(offset, req->asymSize, blob, req->asymBlob);
	Trspi_LoadBlob(offset, req->symSize, blob, req->symBlob);
}

void
Trspi_LoadBlob_CHANGEAUTH_VALIDATE(UINT64 *offset, BYTE *blob, TPM_CHANGEAUTH_VALIDATE *caValidate)
{
	Trspi_LoadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob, caValidate->newAuthSecret.authdata);
	Trspi_LoadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob, caValidate->n1.nonce);
}

TSS_RESULT
Trspi_UnloadBlob_IDENTITY_REQ(UINT64 *offset, BYTE *blob, TCPA_IDENTITY_REQ *req)
{
	Trspi_UnloadBlob_UINT32(offset, &req->asymSize, blob);
	Trspi_UnloadBlob_UINT32(offset, &req->symSize, blob);
	/* XXX */
	Trspi_UnloadBlob_KEY_PARMS(offset, blob, &req->asymAlgorithm);
	Trspi_UnloadBlob_KEY_PARMS(offset, blob, &req->symAlgorithm);

	if (req->asymSize > 0) {
		req->asymBlob = malloc(req->asymSize);
		if (req->asymBlob == NULL) {
			req->asymSize = 0;
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, req->asymSize, blob, req->asymBlob);
	} else {
		req->asymBlob = NULL;
	}

	if (req->symSize > 0) {
		req->symBlob = malloc(req->symSize);
		if (req->symBlob == NULL) {
			req->symSize = 0;
			req->asymSize = 0;
			free(req->asymBlob);
			req->asymBlob = NULL;
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, req->symSize, blob, req->symBlob);
	} else {
		req->symBlob = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Trspi_UnloadBlob_IDENTITY_PROOF(UINT64 *offset, BYTE *blob, TCPA_IDENTITY_PROOF *proof)
{
	TSS_RESULT result;

	/* helps when an error occurs */
	memset(proof, 0, sizeof(TCPA_IDENTITY_PROOF));

	Trspi_UnloadBlob_VERSION(offset, blob, (TCPA_VERSION *)&proof->ver);
	Trspi_UnloadBlob_UINT32(offset, &proof->labelSize, blob);
	Trspi_UnloadBlob_UINT32(offset, &proof->identityBindingSize, blob);
	Trspi_UnloadBlob_UINT32(offset, &proof->endorsementSize, blob);
	Trspi_UnloadBlob_UINT32(offset, &proof->platformSize, blob);
	Trspi_UnloadBlob_UINT32(offset, &proof->conformanceSize, blob);

	if ((result = Trspi_UnloadBlob_PUBKEY(offset, blob,
					      &proof->identityKey))) {
		proof->labelSize = 0;
		proof->identityBindingSize = 0;
		proof->endorsementSize = 0;
		proof->platformSize = 0;
		proof->conformanceSize = 0;
		return result;
	}

	if (proof->labelSize > 0) {
		proof->labelArea = malloc(proof->labelSize);
		if (proof->labelArea == NULL) {
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto error;
		}
		Trspi_UnloadBlob(offset, proof->labelSize, blob, proof->labelArea);
	} else {
		proof->labelArea = NULL;
	}

	if (proof->identityBindingSize > 0) {
		proof->identityBinding = malloc(proof->identityBindingSize);
		if (proof->identityBinding == NULL) {
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto error;
		}
		Trspi_UnloadBlob(offset, proof->identityBindingSize, blob,
				 proof->identityBinding);
	} else {
		proof->identityBinding = NULL;
	}

	if (proof->endorsementSize > 0) {
		proof->endorsementCredential = malloc(proof->endorsementSize);
		if (proof->endorsementCredential == NULL) {
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto error;
		}
		Trspi_UnloadBlob(offset, proof->endorsementSize, blob,
				 proof->endorsementCredential);
	} else {
		proof->endorsementCredential = NULL;
	}

	if (proof->platformSize > 0) {
		proof->platformCredential = malloc(proof->platformSize);
		if (proof->platformCredential == NULL) {
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto error;
		}
		Trspi_UnloadBlob(offset, proof->platformSize, blob,
				 proof->platformCredential);
	} else {
		proof->platformCredential = NULL;
	}

	if (proof->conformanceSize > 0) {
		proof->conformanceCredential = malloc(proof->conformanceSize);
		if (proof->conformanceCredential == NULL) {
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto error;
		}
		Trspi_UnloadBlob(offset, proof->conformanceSize, blob,
				 proof->conformanceCredential);
	} else {
		proof->conformanceCredential = NULL;
	}

	return TSS_SUCCESS;
error:
	proof->labelSize = 0;
	proof->identityBindingSize = 0;
	proof->endorsementSize = 0;
	proof->platformSize = 0;
	proof->conformanceSize = 0;
	free(proof->labelArea);
	proof->labelArea = NULL;
	free(proof->identityBinding);
	proof->identityBinding = NULL;
	free(proof->endorsementCredential);
	proof->endorsementCredential = NULL;
	free(proof->conformanceCredential);
	proof->conformanceCredential = NULL;
	/* free identityKey */
	free(proof->identityKey.pubKey.key);
	free(proof->identityKey.algorithmParms.parms);
	proof->identityKey.pubKey.key = NULL;
	proof->identityKey.pubKey.keyLength = 0;
	proof->identityKey.algorithmParms.parms = NULL;
	proof->identityKey.algorithmParms.parmSize = 0;

	return result;
}

void
Trspi_LoadBlob_SYM_CA_ATTESTATION(UINT64 *offset, BYTE *blob, TCPA_SYM_CA_ATTESTATION *sym)
{
	Trspi_LoadBlob_UINT32(offset, sym->credSize, blob);
	Trspi_LoadBlob_KEY_PARMS(offset, blob, &sym->algorithm);
	Trspi_LoadBlob(offset, sym->credSize, blob, sym->credential);
}

TSS_RESULT
Trspi_UnloadBlob_SYM_CA_ATTESTATION(UINT64 *offset, BYTE *blob, TCPA_SYM_CA_ATTESTATION *sym)
{
	TSS_RESULT result;

	Trspi_UnloadBlob_UINT32(offset, &sym->credSize, blob);
	if ((result = Trspi_UnloadBlob_KEY_PARMS(offset, blob, &sym->algorithm))) {
		sym->credSize = 0;
		return result;
	}

	if (sym->credSize > 0) {
		if ((sym->credential = malloc(sym->credSize)) == NULL) {
			free(sym->algorithm.parms);
			sym->algorithm.parmSize = 0;
			sym->credSize = 0;
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, sym->credSize, blob, sym->credential);
	} else {
		sym->credential = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob_ASYM_CA_CONTENTS(UINT64 *offset, BYTE *blob, TCPA_ASYM_CA_CONTENTS *asym)
{
	Trspi_LoadBlob_SYMMETRIC_KEY(offset, blob, &asym->sessionKey);
	Trspi_LoadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob,
		       (BYTE *)&asym->idDigest);
}

TSS_RESULT
Trspi_UnloadBlob_ASYM_CA_CONTENTS(UINT64 *offset, BYTE *blob, TCPA_ASYM_CA_CONTENTS *asym)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_SYMMETRIC_KEY(offset, blob, &asym->sessionKey)))
		return result;

	Trspi_UnloadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob, (BYTE *)&asym->idDigest);

	return TSS_SUCCESS;
}

/* function to mimic strerror with TSS error codes */
char *
Trspi_Error_String(TSS_RESULT r)
{
	/* Check the return code to see if it is common to all layers.
	 * If so, return it.
	 */
	switch (TSS_ERROR_CODE(r)) {
		case TSS_SUCCESS:			return "Success";
		default:
			break;
	}

	/* The return code is either unknown, or specific to a layer */
	if (TSS_ERROR_LAYER(r) == TSS_LAYER_TPM) {
		switch (TSS_ERROR_CODE(r)) {
			case TCPA_E_AUTHFAIL:		return "Authentication failed";
			case TCPA_E_BAD_PARAMETER:	return "Bad Parameter";
			case TCPA_E_BADINDEX:		return "Bad index";
			case TCPA_E_AUDITFAILURE:	return "Audit failure";
			case TCPA_E_CLEAR_DISABLED:	return "Clear has been disabled";
			case TCPA_E_DEACTIVATED:	return "TPM is deactivated";
			case TCPA_E_DISABLED:		return "TPM is disabled";
			case TCPA_E_DISABLED_CMD:	return "Disabled command";
			case TCPA_E_FAIL:		return "Operation failed";
			case TCPA_E_INACTIVE:		return "Bad ordinal or unknown command";
			case TCPA_E_INSTALL_DISABLED:	return "Owner install disabled";
			case TCPA_E_INVALID_KEYHANDLE:	return "Invalid keyhandle";
			case TCPA_E_KEYNOTFOUND:	return "Key not found";
			case TCPA_E_NEED_SELFTEST:	return "Bad encryption scheme or need self test";
			case TCPA_E_MIGRATEFAIL:	return "Migration authorization failed";
			case TCPA_E_NO_PCR_INFO:	return "PCR information uninterpretable";
			case TCPA_E_NOSPACE:		return "No space to load key";
			case TCPA_E_NOSRK:		return "No SRK";
			case TCPA_E_NOTSEALED_BLOB:	return "Encrypted blob invalid";
			case TCPA_E_OWNER_SET:		return "Owner already set";
			case TCPA_E_RESOURCES:		return "Insufficient TPM resources";
			case TCPA_E_SHORTRANDOM:	return "Random string too short";
			case TCPA_E_SIZE:		return "TPM out of space";
			case TCPA_E_WRONGPCRVAL:	return "Wrong PCR value";
			case TCPA_E_BAD_PARAM_SIZE:	return "Bad input size";
			case TCPA_E_SHA_THREAD:		return "No existing SHA-1 thread";
			case TCPA_E_SHA_ERROR:		return "SHA-1 error";
			case TCPA_E_FAILEDSELFTEST:	return "Self-test failed, TPM shutdown";
			case TCPA_E_AUTH2FAIL:		return "Second authorization session failed";
			case TCPA_E_BADTAG:		return "Invalid tag";
			case TCPA_E_IOERROR:		return "I/O error";
			case TCPA_E_ENCRYPT_ERROR:	return "Encryption error";
			case TCPA_E_DECRYPT_ERROR:	return "Decryption error";
			case TCPA_E_INVALID_AUTHHANDLE:	return "Invalid authorization handle";
			case TCPA_E_NO_ENDORSEMENT:	return "No EK";
			case TCPA_E_INVALID_KEYUSAGE:	return "Invalid key usage";
			case TCPA_E_WRONG_ENTITYTYPE:	return "Invalid entity type";
			case TCPA_E_INVALID_POSTINIT:	return "Invalid POST init sequence";
			case TCPA_E_INAPPROPRIATE_SIG:	return "Invalid signature format";
			case TCPA_E_BAD_KEY_PROPERTY:	return "Unsupported key parameters";
			case TCPA_E_BAD_MIGRATION:	return "Invalid migration properties";
			case TCPA_E_BAD_SCHEME:		return "Invalid signature or encryption scheme";
			case TCPA_E_BAD_DATASIZE:	return "Invalid data size";
			case TCPA_E_BAD_MODE:		return "Bad mode parameter";
			case TCPA_E_BAD_PRESENCE:	return "Bad physical presence value";
			case TCPA_E_BAD_VERSION:	return "Invalid version";
			case TCPA_E_RETRY:		return "TPM busy: Retry command at a later time";
			default:			return "Unknown error";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TDDL) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "General failure";
			case TSS_E_BAD_PARAMETER:		return "Bad parameter";
			case TSS_E_INTERNAL_ERROR:		return "Internal software error";
			case TSS_E_NOTIMPL:			return "Not implemented";
			case TSS_E_PS_KEY_NOTFOUND:		return "Key not found in persistent storage";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "UUID already registered";
			case TSS_E_CANCELED:			return "The action was cancelled by request";
			case TSS_E_TIMEOUT:			return "The operation has timed out";
			case TSS_E_OUTOFMEMORY:			return "Out of memory";
			case TSS_E_TPM_UNEXPECTED:		return "Unexpected TPM output";
			case TSS_E_COMM_FAILURE:		return "Communication failure";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "Unsupported feature";
			case TDDL_E_COMPONENT_NOT_FOUND:	return "Connection to TPM device failed";
			case TDDL_E_ALREADY_OPENED:		return "Device already opened";
			case TDDL_E_BADTAG:			return "Invalid or unsupported capability";
			case TDDL_E_INSUFFICIENT_BUFFER:	return "Receive buffer too small";
			case TDDL_E_COMMAND_COMPLETED:		return "Command has already completed";
			case TDDL_E_ALREADY_CLOSED:		return "Device driver already closed";
			case TDDL_E_IOERROR:			return "I/O error";
			//case TDDL_E_COMMAND_ABORTED:		return "TPM aborted processing of command";
			default:				return "Unknown";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TCS) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "General failure";
			case TSS_E_BAD_PARAMETER:		return "Bad parameter";
			case TSS_E_INTERNAL_ERROR:		return "Internal software error";
			case TSS_E_NOTIMPL:			return "Not implemented";
			case TSS_E_PS_KEY_NOTFOUND:		return "Key not found in persistent storage";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "UUID already registered";
			case TSS_E_CANCELED:			return "The action was cancelled by request";
			case TSS_E_TIMEOUT:			return "The operation has timed out";
			case TSS_E_OUTOFMEMORY:			return "Out of memory";
			case TSS_E_TPM_UNEXPECTED:		return "Unexpected TPM output";
			case TSS_E_COMM_FAILURE:		return "Communication failure";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "Unsupported feature";
			case TCS_E_KEY_MISMATCH:		return "UUID does not match key handle";
			case TCS_E_KM_LOADFAILED:		return "Key load failed: parent key requires authorization";
			case TCS_E_KEY_CONTEXT_RELOAD:		return "Reload of key context failed";
			case TCS_E_INVALID_CONTEXTHANDLE:	return "Invalid context handle";
			case TCS_E_INVALID_KEYHANDLE:		return "Invalid key handle";
			case TCS_E_INVALID_AUTHHANDLE:		return "Invalid authorization session handle";
			case TCS_E_INVALID_AUTHSESSION:		return "Authorization session has been closed by TPM";
			case TCS_E_INVALID_KEY:			return "Invalid key";
			default:				return "Unknown";
		}
	} else {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "General failure";
			case TSS_E_BAD_PARAMETER:		return "Bad parameter";
			case TSS_E_INTERNAL_ERROR:		return "Internal software error";
			case TSS_E_NOTIMPL:			return "Not implemented";
			case TSS_E_PS_KEY_NOTFOUND:		return "Key not found in persistent storage";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "UUID already registered";
			case TSS_E_CANCELED:			return "The action was cancelled by request";
			case TSS_E_TIMEOUT:			return "The operation has timed out";
			case TSS_E_OUTOFMEMORY:			return "Out of memory";
			case TSS_E_TPM_UNEXPECTED:		return "Unexpected TPM output";
			case TSS_E_COMM_FAILURE:		return "Communication failure";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "Unsupported feature";
			case TSS_E_INVALID_OBJECT_TYPE:		return "Object type not valid for this operation";
			case TSS_E_INVALID_OBJECT_INITFLAG:	return "Wrong flag information for object creation";
			case TSS_E_INVALID_HANDLE:		return "Invalid handle";
			case TSS_E_NO_CONNECTION:		return "Core service connection doesn't exist";
			case TSS_E_CONNECTION_FAILED:		return "Core service connection failed";
			case TSS_E_CONNECTION_BROKEN:		return "Communication with core services failed";
			case TSS_E_HASH_INVALID_ALG:		return "Invalid hash algorithm";
			case TSS_E_HASH_INVALID_LENGTH:		return "Hash length is inconsistent with algorithm";
			case TSS_E_HASH_NO_DATA:		return "Hash object has no internal hash value";
			case TSS_E_SILENT_CONTEXT:		return "A silent context requires user input";
			case TSS_E_INVALID_ATTRIB_FLAG:		return "Flag value for attrib-functions inconsistent";
			case TSS_E_INVALID_ATTRIB_SUBFLAG:	return "Sub-flag value for attrib-functions inconsistent";
			case TSS_E_INVALID_ATTRIB_DATA:		return "Data for attrib-functions invalid";
			case TSS_E_NO_PCRS_SET:			return "No PCR registers are selected or set";
			case TSS_E_KEY_NOT_LOADED:		return "The addressed key is not currently loaded";
			case TSS_E_KEY_NOT_SET:			return "No key informatio is currently available";
			case TSS_E_VALIDATION_FAILED:		return "Internal validation of data failed";
			case TSS_E_TSP_AUTHREQUIRED:		return "Authorization is required";
			case TSS_E_TSP_AUTH2REQUIRED:		return "Multiple authorizations are required";
			case TSS_E_TSP_AUTHFAIL:		return "Authorization failed";
			case TSS_E_TSP_AUTH2FAIL:		return "Multiple authorization failed";
			case TSS_E_KEY_NO_MIGRATION_POLICY:	return "Addressed key has no migration policy";
			case TSS_E_POLICY_NO_SECRET:		return "No secret information available for the address policy";
			case TSS_E_INVALID_OBJ_ACCESS:		return "Accessed object is in an inconsistent state";
			case TSS_E_INVALID_ENCSCHEME:		return "Invalid encryption scheme";
			case TSS_E_INVALID_SIGSCHEME:		return "Invalid signature scheme";
			case TSS_E_ENC_INVALID_LENGTH:		return "Invalid length for encrypted data object";
			case TSS_E_ENC_NO_DATA:			return "Encrypted data object contains no data";
			case TSS_E_ENC_INVALID_TYPE:		return "Invalid type for encrypted data object";
			case TSS_E_INVALID_KEYUSAGE:		return "Invalid usage of key";
			case TSS_E_VERIFICATION_FAILED:		return "Internal validation of data failed";
			case TSS_E_HASH_NO_IDENTIFIER:		return "Hash algorithm identifier not set";
			default:				return "Unknown";
		}
	}
}

char *
Trspi_Error_Layer(TSS_RESULT r)
{
	switch (TSS_ERROR_LAYER(r)) {
		case TSS_LAYER_TPM:	return "tpm";
		case TSS_LAYER_TDDL:	return "tddl";
		case TSS_LAYER_TCS:	return "tcs";
		case TSS_LAYER_TSP:	return "tsp";
		default:		return "unknown";
	}
}

TSS_RESULT
Trspi_Error_Code(TSS_RESULT r)
{
	return TSS_ERROR_CODE(r);
}

static int
hacky_strlen(char *codeset, BYTE *string)
{
	BYTE *ptr = string;
	int len = 0;

	if (strcmp("UTF-16", codeset) == 0) {
		while (!(ptr[0] == '\0' && ptr[1] == '\0')) {
			len += 2;
			ptr += 2;
		}
	} else if (strcmp("UTF-32", codeset) == 0) {
		while (!(ptr[0] == '\0' && ptr[1] == '\0' &&
			 ptr[2] == '\0' && ptr[3] == '\0')) {
			len += 4;
			ptr += 4;
		}
	} else {
		/* default to 8bit chars */
		while (*ptr++ != '\0') {
			len++;
		}
	}

	return len;
}

static inline int
char_width(char *codeset)
{
	if (strcmp("UTF-16", codeset) == 0) {
		return 2;
	} else if (strcmp("UTF-32", codeset) == 0) {
		return 4;
	}

	return 1;
}

#define MAX_BUF_SIZE	4096

BYTE *
Trspi_Native_To_UNICODE(BYTE *string, unsigned *size)
{
	char *ptr, *ret, *outbuf, tmpbuf[MAX_BUF_SIZE] = { 0, };
	unsigned len = 0, tmplen;
	iconv_t cd = 0;
	size_t rc, outbytesleft, inbytesleft;

	if (string == NULL)
		goto alloc_string;

	if ((cd = iconv_open("UTF-16LE", nl_langinfo(CODESET))) == (iconv_t)-1) {
		LogDebug("iconv_open: %s", strerror(errno));
		return NULL;
	}

	if ((tmplen = hacky_strlen(nl_langinfo(CODESET), string)) == 0) {
		LogDebug("hacky_strlen returned 0");
		goto alloc_string;
	}

	do {
		len++;
		outbytesleft = len;
		inbytesleft = tmplen;
		outbuf = tmpbuf;
		ptr = (char *)string;
		errno = 0;

		rc = iconv(cd, &ptr, &inbytesleft, &outbuf, &outbytesleft);
	} while (rc == (size_t)-1 && errno == E2BIG);

	if (len > MAX_BUF_SIZE) {
		LogDebug("string too long.");
		iconv_close(cd);
		return NULL;
	}

alloc_string:
	/* add terminating bytes of the correct width */
	len += char_width("UTF-16");
	if ((ret = calloc(1, len)) == NULL) {
		LogDebug("malloc of %u bytes failed.", len);
		iconv_close(cd);
		return NULL;
	}

	memcpy(ret, &tmpbuf, len);
	if (size)
		*size = len;

	if (cd)
		iconv_close(cd);

	return (BYTE *)ret;

}

BYTE *
Trspi_UNICODE_To_Native(BYTE *string, unsigned *size)
{
	char *ret, *ptr, *outbuf, tmpbuf[MAX_BUF_SIZE] = { 0, };
	unsigned len = 0, tmplen;
	iconv_t cd;
	size_t rc, outbytesleft, inbytesleft;

	if (string == NULL) {
		if (size)
			*size = 0;
		return NULL;
	}

	if ((cd = iconv_open(nl_langinfo(CODESET), "UTF-16LE")) == (iconv_t)-1) {
		LogDebug("iconv_open: %s", strerror(errno));
		return NULL;
	}

	if ((tmplen = hacky_strlen("UTF-16", string)) == 0) {
		LogDebug("hacky_strlen returned 0");
		return 0;
	}

	do {
		len++;
		outbytesleft = len;
		inbytesleft = tmplen;
		outbuf = tmpbuf;
		ptr = (char *)string;
		errno = 0;

		rc = iconv(cd, &ptr, &inbytesleft, &outbuf, &outbytesleft);
	} while (rc == (size_t)-1 && errno == E2BIG);

	/* add terminating bytes of the correct width */
	len += char_width(nl_langinfo(CODESET));
	if (len > MAX_BUF_SIZE) {
		LogDebug("string too long.");
		iconv_close(cd);
		return NULL;
	}

	if ((ret = calloc(1, len)) == NULL) {
		LogDebug("malloc of %d bytes failed.", len);
		iconv_close(cd);
		return NULL;
	}

	memcpy(ret, &tmpbuf, len);
	if (size)
		*size = len;
	iconv_close(cd);

	return (BYTE *)ret;
}

void
Trspi_LoadBlob_BOUND_DATA(UINT64 *offset, TCPA_BOUND_DATA bd, UINT32 payloadLength, BYTE *blob)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, bd.ver);
	Trspi_LoadBlob(offset, 1, blob, &bd.payload);
	Trspi_LoadBlob(offset, payloadLength, blob, bd.payloadData);
}

/* Functions to support incremental hashing */
TSS_RESULT
Trspi_Hash_UINT16(Trspi_HashCtx *c, UINT16 i)
{
	BYTE bytes[sizeof(UINT16)];

	UINT16ToArray(i, bytes);
	return Trspi_HashUpdate(c, sizeof(UINT16), bytes);
}

TSS_RESULT
Trspi_Hash_UINT32(Trspi_HashCtx *c, UINT32 i)
{
	BYTE bytes[sizeof(UINT32)];

	UINT32ToArray(i, bytes);
	return Trspi_HashUpdate(c, sizeof(UINT32), bytes);
}

TSS_RESULT
Trspi_Hash_BYTE(Trspi_HashCtx *c, BYTE data)
{
	return Trspi_HashUpdate(c, sizeof(BYTE), &data);
}

TSS_RESULT
Trspi_Hash_BOOL(Trspi_HashCtx *c, TSS_BOOL data)
{
	return Trspi_HashUpdate(c, sizeof(TSS_BOOL), &data);
}

TSS_RESULT
Trspi_Hash_VERSION(Trspi_HashCtx *c, TSS_VERSION *version)
{
	TSS_RESULT result;

	result = Trspi_Hash_BYTE(c, version->bMajor);
	result |= Trspi_Hash_BYTE(c, version->bMinor);
	result |= Trspi_Hash_BYTE(c, version->bRevMajor);
	result |= Trspi_Hash_BYTE(c, version->bRevMinor);

	return result;
}

TSS_RESULT
Trspi_Hash_DAA_PK(Trspi_HashCtx *c, TSS_DAA_PK *pk)
{
	UINT32 i;
	TSS_RESULT result;

	result = Trspi_Hash_VERSION(c, &pk->versionInfo);

	result |= Trspi_Hash_UINT32(c, pk->modulusLength);
	result |= Trspi_HashUpdate(c, pk->modulusLength, pk->modulus);

	result |= Trspi_Hash_UINT32(c, pk->capitalSLength);
	result |= Trspi_HashUpdate(c, pk->capitalSLength, pk->capitalS);

	result |= Trspi_Hash_UINT32(c, pk->capitalZLength);
	result |= Trspi_HashUpdate(c, pk->capitalZLength, pk->capitalZ);

	result |= Trspi_Hash_UINT32(c, pk->capitalR0Length);
	result |= Trspi_HashUpdate(c, pk->capitalR0Length, pk->capitalR0);

	result |= Trspi_Hash_UINT32(c, pk->capitalR1Length);
	result |= Trspi_HashUpdate(c, pk->capitalR1Length, pk->capitalR1);

	result |= Trspi_Hash_UINT32(c, pk->gammaLength);
	result |= Trspi_HashUpdate(c, pk->gammaLength, pk->gamma);

	result |= Trspi_Hash_UINT32(c, pk->capitalGammaLength);
	result |= Trspi_HashUpdate(c, pk->capitalGammaLength, pk->capitalGamma);

	result |= Trspi_Hash_UINT32(c, pk->rhoLength);
	result |= Trspi_HashUpdate(c, pk->rhoLength, pk->rho);

	for (i = 0; i < pk->capitalYLength; i++)
		result |= Trspi_HashUpdate(c, pk->capitalYLength2, pk->capitalY[i]);

	result |= Trspi_Hash_UINT32(c, pk->capitalYPlatformLength);

	result |= Trspi_Hash_UINT32(c, pk->issuerBaseNameLength);
	result |= Trspi_HashUpdate(c, pk->issuerBaseNameLength, pk->issuerBaseName);

	return result;
}

TSS_RESULT
Trspi_Hash_RSA_KEY_PARMS(Trspi_HashCtx *c, TCPA_RSA_KEY_PARMS *parms)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, parms->keyLength);
	result |= Trspi_Hash_UINT32(c, parms->numPrimes);
	result |= Trspi_Hash_UINT32(c, parms->exponentSize);

	if (parms->exponentSize > 0)
		result |= Trspi_HashUpdate(c, parms->exponentSize, parms->exponent);

	return result;
}

TSS_RESULT
Trspi_Hash_STORE_PUBKEY(Trspi_HashCtx *c, TCPA_STORE_PUBKEY *store)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, store->keyLength);
	result |= Trspi_HashUpdate(c, store->keyLength, store->key);

	return result;
}

TSS_RESULT
Trspi_Hash_KEY_PARMS(Trspi_HashCtx *c, TCPA_KEY_PARMS *keyInfo)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, keyInfo->algorithmID);
	result |= Trspi_Hash_UINT16(c, keyInfo->encScheme);
	result |= Trspi_Hash_UINT16(c, keyInfo->sigScheme);
	result |= Trspi_Hash_UINT32(c, keyInfo->parmSize);

	if (keyInfo->parmSize > 0)
		result |= Trspi_HashUpdate(c, keyInfo->parmSize, keyInfo->parms);

	return result;
}

TSS_RESULT
Trspi_Hash_PUBKEY(Trspi_HashCtx *c, TCPA_PUBKEY *pubKey)
{
	TSS_RESULT result;

	result = Trspi_Hash_KEY_PARMS(c, &pubKey->algorithmParms);
	result |= Trspi_Hash_STORE_PUBKEY(c, &pubKey->pubKey);

	return result;
}

TSS_RESULT
Trspi_Hash_STORED_DATA(Trspi_HashCtx *c, TCPA_STORED_DATA *data)
{
	TSS_RESULT result;

	result = Trspi_Hash_VERSION(c, (TSS_VERSION *)&data->ver);
	result |= Trspi_Hash_UINT32(c, data->sealInfoSize);
	result |= Trspi_HashUpdate(c, data->sealInfoSize, data->sealInfo);
	result |= Trspi_Hash_UINT32(c, data->encDataSize);
	result |= Trspi_HashUpdate(c, data->encDataSize, data->encData);

	return result;
}

TSS_RESULT
Trspi_Hash_PCR_SELECTION(Trspi_HashCtx *c, TCPA_PCR_SELECTION *pcr)
{
	TSS_RESULT result;
	UINT16 i;

	result = Trspi_Hash_UINT16(c, pcr->sizeOfSelect);

	for (i = 0; i < pcr->sizeOfSelect; i++)
		result |= Trspi_Hash_BYTE(c, pcr->pcrSelect[i]);

	return result;
}

TSS_RESULT
Trspi_Hash_KEY_FLAGS(Trspi_HashCtx *c, TCPA_KEY_FLAGS *flags)
{
	UINT32 tempFlag = 0;

	if (*flags & migratable)
		tempFlag |= TSS_FLAG_MIGRATABLE;
	if (*flags & redirection)
		tempFlag |= TSS_FLAG_REDIRECTION;
	if (*flags & volatileKey)
		tempFlag |= TSS_FLAG_VOLATILE;
	return Trspi_Hash_UINT32(c, tempFlag);
}

TSS_RESULT
Trspi_Hash_KEY(Trspi_HashCtx *c, TCPA_KEY *key)
{
	TSS_RESULT result;

	result = Trspi_Hash_VERSION(c, (TSS_VERSION *)&key->ver);
	result |= Trspi_Hash_UINT16(c, key->keyUsage);
	result |= Trspi_Hash_KEY_FLAGS(c, &key->keyFlags);
	result |= Trspi_Hash_BYTE(c, key->authDataUsage);
	result |= Trspi_Hash_KEY_PARMS(c, &key->algorithmParms);
	result |= Trspi_Hash_UINT32(c, key->PCRInfoSize);
	result |= Trspi_HashUpdate(c, key->PCRInfoSize, key->PCRInfo);
	result |= Trspi_Hash_STORE_PUBKEY(c, &key->pubKey);
	result |= Trspi_Hash_UINT32(c, key->encSize);
	result |= Trspi_HashUpdate(c, key->encSize, key->encData);

	return result;
}

TSS_RESULT
Trspi_Hash_UUID(Trspi_HashCtx *c, TSS_UUID uuid)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, uuid.ulTimeLow);
	result |= Trspi_Hash_UINT16(c, uuid.usTimeMid);
	result |= Trspi_Hash_UINT16(c, uuid.usTimeHigh);
	result |= Trspi_Hash_BYTE(c, uuid.bClockSeqHigh);
	result |= Trspi_Hash_BYTE(c, uuid.bClockSeqLow);
	result |= Trspi_HashUpdate(c, sizeof(uuid.rgbNode), uuid.rgbNode);

	return result;
}

TSS_RESULT
Trspi_Hash_PCR_EVENT(Trspi_HashCtx *c, TSS_PCR_EVENT *event)
{
	TSS_RESULT result;

	result = Trspi_Hash_VERSION(c, &event->versionInfo);
	result |= Trspi_Hash_UINT32(c, event->ulPcrIndex);
	result |= Trspi_Hash_UINT32(c, event->eventType);

	Trspi_Hash_UINT32(c, event->ulPcrValueLength);
	if (event->ulPcrValueLength > 0)
		result |= Trspi_HashUpdate(c, event->ulPcrValueLength, event->rgbPcrValue);

	result |= Trspi_Hash_UINT32(c, event->ulEventLength);
	if (event->ulEventLength > 0)
		result |= Trspi_HashUpdate(c, event->ulEventLength, event->rgbEvent);


	return result;
}

TSS_RESULT
Trspi_Hash_PRIVKEY_DIGEST(Trspi_HashCtx *c, TCPA_KEY *key)
{
	TSS_RESULT result;

	result = Trspi_Hash_VERSION(c, (TSS_VERSION *)&key->ver);
	result |= Trspi_Hash_UINT16(c, key->keyUsage);
	result |= Trspi_Hash_KEY_FLAGS(c, &key->keyFlags);
	result |= Trspi_Hash_BYTE(c, key->authDataUsage);
	result |= Trspi_Hash_KEY_PARMS(c, &key->algorithmParms);

	result |= Trspi_Hash_UINT32(c, key->PCRInfoSize);
	/* exclude pcrInfo when PCRInfoSize is 0 as spec'd in TPM 1.1b spec p.71 */
	if (key->PCRInfoSize != 0)
		result |= Trspi_HashUpdate(c, key->PCRInfoSize, key->PCRInfo);

	Trspi_Hash_STORE_PUBKEY(c, &key->pubKey);
	/* exclude encSize, encData as spec'd in TPM 1.1b spec p.71 */

	return result;
}

TSS_RESULT
Trspi_Hash_SYMMETRIC_KEY(Trspi_HashCtx *c, TCPA_SYMMETRIC_KEY *key)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, key->algId);
	result |= Trspi_Hash_UINT16(c, key->encScheme);
	result |= Trspi_Hash_UINT16(c, key->size);

	if (key->size > 0)
		result |= Trspi_HashUpdate(c, key->size, key->data);

	return result;
}

TSS_RESULT
Trspi_Hash_IDENTITY_REQ(Trspi_HashCtx *c, TCPA_IDENTITY_REQ *req)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, req->asymSize);
	result |= Trspi_Hash_UINT32(c, req->symSize);
	result |= Trspi_Hash_KEY_PARMS(c, &req->asymAlgorithm);
	result |= Trspi_Hash_KEY_PARMS(c, &req->symAlgorithm);
	result |= Trspi_HashUpdate(c, req->asymSize, req->asymBlob);
	result |= Trspi_HashUpdate(c, req->symSize, req->symBlob);

	return result;
}

TSS_RESULT
Trspi_Hash_CHANGEAUTH_VALIDATE(Trspi_HashCtx *c, TPM_CHANGEAUTH_VALIDATE *caValidate)
{
	TSS_RESULT result;

	result = Trspi_HashUpdate(c, TCPA_SHA1_160_HASH_LEN, caValidate->newAuthSecret.authdata);
	result |= Trspi_HashUpdate(c, TCPA_SHA1_160_HASH_LEN, caValidate->n1.nonce);

	return result;
}

TSS_RESULT
Trspi_Hash_SYM_CA_ATTESTATION(Trspi_HashCtx *c, TCPA_SYM_CA_ATTESTATION *sym)
{
	TSS_RESULT result;

	result = Trspi_Hash_UINT32(c, sym->credSize);
	result |= Trspi_Hash_KEY_PARMS(c, &sym->algorithm);
	result |= Trspi_HashUpdate(c, sym->credSize, sym->credential);

	return result;
}

TSS_RESULT
Trspi_Hash_ASYM_CA_CONTENTS(Trspi_HashCtx *c, TCPA_ASYM_CA_CONTENTS *asym)
{
	TSS_RESULT result;

	result = Trspi_Hash_SYMMETRIC_KEY(c, &asym->sessionKey);
	result |= Trspi_HashUpdate(c, TCPA_SHA1_160_HASH_LEN, (BYTE *)&asym->idDigest);

	return result;
}

TSS_RESULT
Trspi_Hash_BOUND_DATA(Trspi_HashCtx *c, TCPA_BOUND_DATA *bd, UINT32 payloadLength)
{
	TSS_RESULT result;

	result = Trspi_Hash_VERSION(c, (TSS_VERSION *)&bd->ver);
	result |= Trspi_Hash_BYTE(c, bd->payload);
	result |= Trspi_HashUpdate(c, payloadLength, bd->payloadData);

	return result;
}

