
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
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"
#include "tss/trousers.h"


void
Trspi_UnloadBlob_DIGEST(UINT16 * offset, BYTE * blob, TCPA_DIGEST digest)
{
	Trspi_UnloadBlob(offset, SHA1_HASH_SIZE, blob, digest.digest);
}

TSS_RESULT
Trspi_UnloadBlob_PUBKEY(TSS_HCONTEXT tspContext, UINT16 * offset,
		  BYTE * blob, TCPA_PUBKEY * pubKey)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_KEY_PARMS(tspContext, offset, blob, &pubKey->algorithmParms)))
		return result;
	return Trspi_UnloadBlob_STORE_PUBKEY(tspContext, offset, blob, &pubKey->pubKey);
}

void
Trspi_UnloadBlob_MigrationKeyAuth(TSS_HCONTEXT tspContext,
			    UINT16 * offset, TCPA_MIGRATIONKEYAUTH * migAuth, BYTE * blob)
{
	Trspi_UnloadBlob_PUBKEY(tspContext, offset, blob, &migAuth->migrationKey);
	Trspi_UnloadBlob_UINT16(offset, &migAuth->migrationScheme, blob);
	Trspi_UnloadBlob_DIGEST(offset, blob, migAuth->digest);
}

#if 0
void
LoadBlob_STORE_PRIVKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PRIVKEY * store)
{
	LoadBlob_UINT32(offset, store->keyLength, blob);
	LoadBlob(offset, store->keyLength, blob, store->key);
}

void
LoadBlob_STORE_ASYMKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_ASYMKEY * store)
{
	blob[(*offset)++] = store->payload;
	LoadBlob(offset, SHA1_HASH_SIZE, blob, store->usageAuth.secret);
	LoadBlob(offset, SHA1_HASH_SIZE, blob, store->migrationAuth.secret);
	LoadBlob(offset, SHA1_HASH_SIZE, blob, store->pubDataDigest.digest);
	LoadBlob_STORE_PRIVKEY(offset, blob, &store->privKey);
}
#endif

void
Trspi_LoadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object)
{
	if (size == 0)
		return;
	memcpy(&container[(*offset)], object, size);
	(*offset) += (UINT16) size;
}

void
Trspi_UnloadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object)
{
	if (size == 0)
		return;
	memcpy(object, &container[(*offset)], size);
	(*offset) += (UINT16) size;
}

void
Trspi_LoadBlob_BYTE(UINT16 * offset, BYTE data, BYTE * blob)
{
	blob[*offset] = data;
	(*offset)++;
}

void
Trspi_UnloadBlob_BYTE(UINT16 * offset, BYTE * dataOut, BYTE * blob)
{
	*dataOut = blob[*offset];
	(*offset)++;
}

void
Trspi_LoadBlob_BOOL(UINT16 * offset, BOOL data, BYTE * blob)
{
	blob[*offset] = (BYTE) data;
	(*offset)++;
}

void
Trspi_UnloadBlob_BOOL(UINT16 * offset, BOOL * dataOut, BYTE * blob)
{
	*dataOut = blob[*offset];
	(*offset)++;
}

void
Trspi_LoadBlob_UINT32(UINT16 * offset, UINT32 in, BYTE * blob)
{
	UINT32ToArray(in, &blob[*offset]);
	*offset += 4;
}

void
Trspi_LoadBlob_UINT16(UINT16 * offset, UINT16 in, BYTE * blob)
{
	UINT16ToArray(in, &blob[*offset]);
	*offset += sizeof(UINT16);
}

void
Trspi_UnloadBlob_UINT32(UINT16 * offset, UINT32 * out, BYTE * blob)
{
	*out = Decode_UINT32(&blob[*offset]);
	*offset += sizeof(UINT32);
}

void
Trspi_UnloadBlob_UINT16(UINT16 * offset, UINT16 * out, BYTE * blob)
{
	*out = Decode_UINT16(&blob[*offset]);
	*offset += sizeof(UINT16);
}

void
Trspi_LoadBlob_RSA_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_RSA_KEY_PARMS * parms)
{
	Trspi_LoadBlob_UINT32(offset, parms->keyLength, blob);
	Trspi_LoadBlob_UINT32(offset, parms->numPrimes, blob);
	Trspi_LoadBlob_UINT32(offset, parms->exponentSize, blob);
	Trspi_LoadBlob(offset, parms->exponentSize, blob, parms->exponent);
}

void
Trspi_UnloadBlob_TSS_VERSION(UINT16 * offset, BYTE * blob, TSS_VERSION * out)
{
	out->bMajor = blob[(*offset)++];
	out->bMinor = blob[(*offset)++];
	out->bRevMajor = blob[(*offset)++];
	out->bRevMinor = blob[(*offset)++];
}

void
Trspi_LoadBlob_TSS_VERSION(UINT16 * offset, BYTE * blob, TSS_VERSION version)
{
	blob[(*offset)++] = version.bMajor;
	blob[(*offset)++] = version.bMinor;
	blob[(*offset)++] = version.bRevMajor;
	blob[(*offset)++] = version.bRevMinor;
	return;
}

void
Trspi_UnloadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out)
{
	out->major = blob[(*offset)++];
	out->minor = blob[(*offset)++];
	out->revMajor = blob[(*offset)++];
	out->revMinor = blob[(*offset)++];
	return;
}

void
Trspi_LoadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION version)
{
	blob[(*offset)++] = version.major;
	blob[(*offset)++] = version.minor;
	blob[(*offset)++] = version.revMajor;
	blob[(*offset)++] = version.revMinor;
	return;
}

void
Trspi_LoadBlob_BOUND_DATA(UINT16 * offset, TCPA_BOUND_DATA bd,
		    UINT32 payloadLength, BYTE * blob)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, bd.ver);
	Trspi_LoadBlob(offset, 1, blob, &bd.payload);
	Trspi_LoadBlob(offset, payloadLength, blob, bd.payloadData);
}

#if 0
void
LoadBlob_PCR_INFO(UINT16 * offset, BYTE * blob, TCPA_PCR_INFO * pcr)
{
	LoadBlob_PCR_SELECTION(offset, blob, pcr->pcrSelection);
	LoadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtRelease.digest);
	LoadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtCreation.digest);
	return;
}
#endif

TSS_RESULT
Trspi_UnloadBlob_PCR_INFO(TSS_HCONTEXT tspContext, UINT16 * offset,
		    BYTE * blob, TCPA_PCR_INFO * pcr)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_PCR_SELECTION(tspContext, offset, blob, &pcr->pcrSelection)))
		return result;
	Trspi_UnloadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtRelease.digest);
	Trspi_UnloadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtCreation.digest);
	return TSS_SUCCESS;
}

TSS_RESULT
Trspi_UnloadBlob_STORED_DATA(TSS_HCONTEXT tspContext, UINT16 * offset,
		       BYTE * blob, TCPA_STORED_DATA * data)
{
	Trspi_UnloadBlob_TCPA_VERSION(offset, blob, &data->ver);
	Trspi_UnloadBlob_UINT32(offset, &data->sealInfoSize, blob);

	if (data->sealInfoSize > 0) {
		data->sealInfo = calloc_tspi(tspContext, data->sealInfoSize);
		if (data->sealInfo == NULL) {
			LogError("malloc of %d bytes failed.", data->sealInfoSize);
			return TSS_E_OUTOFMEMORY;
		}
		Trspi_UnloadBlob(offset, data->sealInfoSize, blob, data->sealInfo);
	} else {
		data->sealInfo = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &data->encDataSize, blob);

	if (data->encDataSize > 0) {
		data->encData = calloc_tspi(tspContext, data->encDataSize);
		if (data->encData == NULL) {
			LogError("malloc of %d bytes failed.", data->encDataSize);
			return TSS_E_OUTOFMEMORY;
		}

		Trspi_UnloadBlob(offset, data->encDataSize, blob, data->encData);
	} else {
		data->encData = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob_STORED_DATA(UINT16 * offset, BYTE * blob, TCPA_STORED_DATA * data)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, data->ver);
	Trspi_LoadBlob_UINT32(offset, data->sealInfoSize, blob);
	Trspi_LoadBlob(offset, data->sealInfoSize, blob, data->sealInfo);
	Trspi_LoadBlob_UINT32(offset, data->encDataSize, blob);
	Trspi_LoadBlob(offset, data->encDataSize, blob, data->encData);
}

TSS_RESULT
Trspi_UnloadBlob_PCR_SELECTION(TSS_HCONTEXT tspContext,
			 UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION * pcr)
{
	UINT16 i;

	pcr->sizeOfSelect = Decode_UINT16(&blob[*offset]);

	if (pcr->sizeOfSelect > 0) {
		*offset += 2;
		pcr->pcrSelect = calloc_tspi(tspContext, pcr->sizeOfSelect);
		if (pcr->pcrSelect == NULL) {
			LogError("malloc of %d bytes failed.", pcr->sizeOfSelect);
			return TSS_E_OUTOFMEMORY;
		}

		for (i = 0; i < pcr->sizeOfSelect; i++, (*offset)++)
			pcr->pcrSelect[i] = blob[*offset];
	} else {
		pcr->pcrSelect = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION pcr)
{
	UINT16 i;

	UINT16ToArray(pcr.sizeOfSelect, &blob[*offset]);
	*offset += 2;
	for (i = 0; i < pcr.sizeOfSelect; i++, (*offset)++)
		blob[*offset] = pcr.pcrSelect[i];
	return;

}

void
Trspi_LoadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key)
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
Trspi_LoadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;

	if (*flags & migratable)
		tempFlag |= FLAG_MIGRATABLE;
	if (*flags & redirection)
		tempFlag |= FLAG_REDIRECTION;
	if (*flags & volatileKey)
		tempFlag |= FLAG_VOLATILE;
	Trspi_LoadBlob_UINT32(offset, tempFlag, blob);
}

void
Trspi_UnloadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;
	memset(flags, 0x00, sizeof(TCPA_KEY_FLAGS));

	Trspi_UnloadBlob_UINT32(offset, &tempFlag, blob);

	if (tempFlag & FLAG_REDIRECTION)
		*flags |= redirection;
	if (tempFlag & FLAG_MIGRATABLE)
		*flags |= migratable;
	if (tempFlag & FLAG_VOLATILE)
		*flags |= volatileKey;
}

void
Trspi_LoadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyInfo)
{
	Trspi_LoadBlob_UINT32(offset, keyInfo->algorithmID, blob);
	Trspi_LoadBlob_UINT16(offset, keyInfo->encScheme, blob);
	Trspi_LoadBlob_UINT16(offset, keyInfo->sigScheme, blob);
	Trspi_LoadBlob_UINT32(offset, keyInfo->parmSize, blob);
	Trspi_LoadBlob(offset, keyInfo->parmSize, blob, keyInfo->parms);
}

void
Trspi_LoadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store)
{
	Trspi_LoadBlob_UINT32(offset, store->keyLength, blob);
	Trspi_LoadBlob(offset, store->keyLength, blob, store->key);
}

void
Trspi_LoadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID uuid)
{
	Trspi_LoadBlob_UINT32(offset, uuid.ulTimeLow, blob);
	Trspi_LoadBlob_UINT16(offset, uuid.usTimeMid, blob);
	Trspi_LoadBlob_UINT16(offset, uuid.usTimeHigh, blob);
	Trspi_LoadBlob_BYTE(offset, uuid.bClockSeqHigh, blob);
	Trspi_LoadBlob_BYTE(offset, uuid.bClockSeqLow, blob);
	Trspi_LoadBlob(offset, 6, blob, uuid.rgbNode);
}

void
Trspi_UnloadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID * uuid)
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
Trspi_UnloadBlob_KEY_PARMS(TSS_HCONTEXT tspContext,
		     UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyParms)
{
	Trspi_UnloadBlob_UINT32(offset, &keyParms->algorithmID, blob);
	Trspi_UnloadBlob_UINT16(offset, &keyParms->encScheme, blob);
	Trspi_UnloadBlob_UINT16(offset, &keyParms->sigScheme, blob);
	Trspi_UnloadBlob_UINT32(offset, &keyParms->parmSize, blob);

	if (keyParms->parmSize > 0) {
		keyParms->parms = calloc_tspi(tspContext, keyParms->parmSize);
		if (keyParms->parms == NULL) {
			LogError("malloc of %d bytes failed.", keyParms->parmSize);
			return TSS_E_OUTOFMEMORY;
		}
		Trspi_UnloadBlob(offset, keyParms->parmSize, blob, keyParms->parms);
	} else {
		keyParms->parms = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Trspi_UnloadBlob_KEY(TSS_HCONTEXT tspContext, UINT16 * offset, BYTE * blob, TCPA_KEY * key)
{
	TSS_RESULT result;

	Trspi_UnloadBlob_TCPA_VERSION(offset, blob, &key->ver);
	Trspi_UnloadBlob_UINT16(offset, &key->keyUsage, blob);
	Trspi_UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	key->authDataUsage = blob[(*offset)++];
	if ((result = Trspi_UnloadBlob_KEY_PARMS(tspContext, offset, (BYTE *) blob, &key->algorithmParms)))
		return result;
	Trspi_UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob);

	if (key->PCRInfoSize > 0) {
		key->PCRInfo = calloc_tspi(tspContext, key->PCRInfoSize);
		if (key->PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", key->PCRInfoSize);
			return TSS_E_OUTOFMEMORY;
		}
		Trspi_UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	} else {
		key->PCRInfo = NULL;
	}

	if ((result = Trspi_UnloadBlob_STORE_PUBKEY(tspContext, offset, blob, &key->pubKey)))
		return result;
	Trspi_UnloadBlob_UINT32(offset, &key->encSize, blob);

	if (key->encSize > 0) {
		key->encData = calloc_tspi(tspContext, key->encSize);
		if (key->encData == NULL) {
			LogError("malloc of %d bytes failed.", key->encSize);
			return TSS_E_OUTOFMEMORY;
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
Trspi_UnloadBlob_STORE_PUBKEY(TSS_HCONTEXT tspContext,
			UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store)
{

	Trspi_UnloadBlob_UINT32(offset, &store->keyLength, blob);

	if (store->keyLength > 0) {
		store->key = calloc_tspi(tspContext, store->keyLength);
		if (store->key == NULL) {
			LogError("malloc of %d bytes failed.", store->keyLength);
			return TSS_E_OUTOFMEMORY;
		}
		Trspi_UnloadBlob(offset, store->keyLength, blob, store->key);
	} else {
		store->key = NULL;
	}

	return TSS_SUCCESS;
}

#if 0
void
LoadBlob_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_PUBKEY pubKey)
{

	LoadBlob_KEY_PARMS(offset, blob, &pubKey.algorithmParms);
	LoadBlob_UINT32(offset, pubKey.pubKey.keyLength, blob);
	LoadBlob(offset, pubKey.pubKey.keyLength, blob, pubKey.pubKey.key);

	return;
}

void
LoadBlob_CERTIFY_INFO(UINT16 * offset, BYTE * blob, TCPA_CERTIFY_INFO * certify)
{

	LoadBlob_TCPA_VERSION(offset, blob, certify->version);
	LoadBlob_UINT16(offset, certify->keyUsage, blob);
	LoadBlob_KEY_FLAGS(offset, blob, &certify->keyFlags);
	LoadBlob_BYTE(offset, (BYTE) certify->authDataUsage, blob);
	LoadBlob_KEY_PARMS(offset, blob, &certify->algorithmParms);
	LoadBlob(offset, SHA1_HASH_SIZE, blob, certify->pubkeyDigest.digest);
	LoadBlob(offset, SHA1_HASH_SIZE, blob, certify->data.nonce);
	LoadBlob_BYTE(offset, (BYTE) certify->parentPCRStatus, blob);
	LoadBlob_UINT32(offset, certify->PCRInfoSize, blob);
	LoadBlob(offset, certify->PCRInfoSize, blob, certify->PCRInfo);
	return;
}
#endif

void
Trspi_UnloadBlob_TCPA_EVENT_CERT(UINT16 * offset, BYTE * blob, TCPA_EVENT_CERT * cert)
{
	Trspi_UnloadBlob(offset, SHA1_HASH_SIZE, blob, cert->certificateHash.digest);
	Trspi_UnloadBlob(offset, SHA1_HASH_SIZE, blob, cert->entityDigest.digest);
	cert->digestChecked = blob[(*offset)++];
	cert->digestVerified = blob[(*offset)++];
	Trspi_UnloadBlob_UINT32(offset, &cert->issuerSize, blob);
	Trspi_UnloadBlob(offset, cert->issuerSize, blob, cert->issuer);
}

void
Trspi_LoadBlob_CHANGEAUTH_VALIDATE(UINT16 * offset, BYTE * blob,
			     TCPA_CHANGEAUTH_VALIDATE * caValidate)
{
	Trspi_LoadBlob(offset, SHA1_HASH_SIZE, blob, caValidate->newAuthSecret.secret);
	Trspi_LoadBlob(offset, SHA1_HASH_SIZE, blob, caValidate->n1.nonce);
}

void
Trspi_UnloadBlob_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out)
{
	Trspi_UnloadBlob_BYTE(offset, &out->major, blob);
	Trspi_UnloadBlob_BYTE(offset, &out->minor, blob);
	Trspi_UnloadBlob_BYTE(offset, &out->revMajor, blob);
	Trspi_UnloadBlob_BYTE(offset, &out->revMinor, blob);
}

void
Trspi_UnloadBlob_KM_KEYINFO(UINT16 *offset, BYTE *blob, TSS_KM_KEYINFO *info)
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
Trspi_LoadBlob_PCR_EVENT(UINT16 *offset, BYTE *blob, TSS_PCR_EVENT *event)
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
Trspi_UnloadBlob_PCR_EVENT(UINT16 *offset, BYTE *blob, TSS_PCR_EVENT *event)
{
	Trspi_UnloadBlob_VERSION(offset, blob, (TCPA_VERSION *)&(event->versionInfo));
	Trspi_UnloadBlob_UINT32(offset, &event->ulPcrIndex, blob);
	Trspi_UnloadBlob_UINT32(offset, &event->eventType, blob);

	Trspi_UnloadBlob_UINT32(offset, &event->ulPcrValueLength, blob);
	if (event->ulPcrValueLength > 0) {
		event->rgbPcrValue = malloc(event->ulPcrValueLength);
		if (event->rgbPcrValue == NULL) {
			LogError("malloc of %d bytes failed.", event->ulPcrValueLength);
			return TSS_E_OUTOFMEMORY;
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
			return TSS_E_OUTOFMEMORY;
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
Trspi_LoadBlob_PRIVKEY_DIGEST(UINT16 * offset, BYTE * blob, TCPA_KEY *key)
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

/* function to mimic strerror with TSS error codes */
char *
Trspi_Error(TSS_RESULT r)
{
	switch (r) {
	case TSS_SUCCESS:			return "Success";

	case TDDL_E_BAD_PARAMETER:		return "Bad parameter";
	case TDDL_E_COMPONENT_NOT_FOUND:	return "Connection to TPM device failed";
	case TDDL_E_ALREADY_OPENED:		return "Device already opened";
	case TDDL_E_BADTAG:			return "Invalid or unsupported capability";
	case TDDL_E_TIMEOUT:			return "Operation timed out";
	case TDDL_E_INSUFFICIENT_BUFFER:	return "Receive buffer too small";
	case TDDL_COMMAND_COMPLETED:		return "Command has already completed";
	case TDDL_E_OUTOFMEMORY:		return "Out of memory";
	case TDDL_E_ALREADY_CLOSED:		return "Device driver already closed";
	case TDDL_E_IOERROR:			return "I/O error";
	case TDDL_E_COMMAND_ABORTED:		return "TPM aborted processing of command";

	case TCS_E_KEY_MISMATCH:		return "UUID does not match key handle";
	case TCS_E_KM_LOADFAILED:		return "Key load failed: parent key requires authorization";
	case TCS_E_KEY_CONTEXT_RELOAD:		return "Reload of key context failed";
	case TCS_E_INVALID_CONTEXTHANDLE:	return "Invalid context handle";
	case TCS_E_INVALID_KEYHANDLE:		return "Invalid key handle";
	case TCS_E_INVALID_AUTHHANDLE:		return "Invalid authorization session handle";
	case TCS_E_INVALID_AUTHSESSION:		return "Authorization session has been closed by TPM";
	case TCS_E_INVALID_KEY:			return "Invalid key";


	case TCS_E_FAIL:			/* fall through */
	case TSS_E_FAIL:			/* fall through */
	case TDDL_E_FAIL:			return "General failure";
	case TSS_E_BAD_PARAMETER:		return "Bad parameter";
	case TSS_E_INTERNAL_ERROR:		return "Internal software error";
	case TSS_E_NOTIMPL:			return "Not implemented";
	case TCS_E_KEY_NOT_REGISTERED:		/* fall through */
	case TSS_E_PS_KEY_NOTFOUND:		return "Key not found in persistent storage";
	case TCS_E_KEY_ALREADY_REGISTERED:	/* fall through */
	case TSS_E_KEY_ALREADY_REGISTERED:	return "UUID already registered";
	case TSS_E_CANCELED:			return "The action was cancelled by request";
	case TSS_E_TIMEOUT:			return "The operation has timed out";
	case TSS_E_OUTOFMEMORY:			return "Out of memory";
	case TSS_E_TPM_UNEXPECTED:		return "Unexpected TPM output";
	case TSS_E_COMM_FAILURE:		return "Communication failure";
	case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "Unsupported feature";

	case TSS_E_INVALID_OBJECT_TYPE:		return "Object type not valid for this operation";
	case TSS_E_INVALID_OBJECT_INIT_FLAG:	return "Wrong flag creation for object creation";
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

	case TCPA_AUTHFAIL:			return "Authentication failed";
	case TCPA_BADINDEX:			return "Bad index";
	case TCPA_BADPARAMETER:			return "Bad parameter";
	case TCPA_AUDITFAILURE:			return "Audit failure";
	case TCPA_CLEAR_DISABLED:		return "Clear has been disabled";
	case TCPA_DEACTIVATED:			return "TPM is deactivated";
	case TCPA_DISABLED:			return "TPM is disabled";
	case TCPA_DISABLED_CMD:			return "Diabled command";
	case TCPA_FAIL:				return "Operation failed";
	case TCPA_BAD_ORDINAL:			return "Unknown command";
	case TCPA_INSTALL_DISABLED:		return "Owner install disabled";
	case TCPA_INVALID_KEYHANDLE:		return "Invalid keyhandle";
	case TCPA_KEYNOTFOUND:			return "Key not found";
	case TCPA_INAPPROPRIATE_ENC:		return "Bad encryption scheme";
	case TCPA_MIGRATE_FAIL:			return "Migration authorization failed";
	case TCPA_INVALID_PCR_INFO:		return "PCR information uninterpretable";
	case TCPA_NOSPACE:			return "No space to load key";
	case TCPA_NOSRK:			return "No SRK";
	case TCPA_NOTSEALED_BLOB:		return "Encrypted blob invalid";
	case TCPA_OWNER_SET:			return "Owner already set";
	case TCPA_RESOURCES:			return "Insufficient TPM resources";
	case TCPA_SHORTRANDOM:			return "Random string too short";
	case TCPA_SIZE:				return "TPM out of space";
	case TCPA_WRONGPCRVAL:			return "Wrong PCR value";
	case TCPA_BAD_PARAM_SIZE:		return "Bad input size";
	case TCPA_SHA_THREAD:			return "No existing SHA-1 thread";
	case TCPA_SHA_ERROR:			return "SHA-1 error";
	case TCPA_FAILEDSELFTEST:		return "Self-test failed, TPM shutdown";
	case TCPA_AUTH2FAIL:			return "Second authorization session failed";
	case TCPA_BADTAG:			return "Invalid tag";
	case TCPA_IOERROR:			return "I/O error";
	case TCPA_ENCRYPT_ERROR:		return "Encryption error";
	case TCPA_DECRYPT_ERROR:		return "Decryption error";
	case TCPA_INVALID_AUTHHANDLE:		return "Invalid authorization handle";
	case TCPA_NO_ENDORSEMENT:		return "No EK";
	case TCPA_INVALID_KEYUSAGE:		return "Invalid key usage";
	case TCPA_WRONG_ENTITYTYPE:		return "Invalid entity type";
	case TCPA_INVALID_POSTINIT:		return "Invalid POST init sequence";
	case TCPA_INAPPRORIATE_SIG:		return "Invalid signature format";
	case TCPA_BAD_KEY_PROPERTY:		return "Unsupported key parameters";
	case TCPA_BAD_MIGRATION:		return "Invalid migration properties";
	case TCPA_BAD_SCHEME:			return "Invalid signature or encryption scheme";
	case TCPA_BAD_DATASIZE:			return "Invalid data size";
	case TCPA_BAD_MODE:			return "Bad mode parameter";
	case TCPA_BAD_PRESENCE:			return "Bad physical presence value";
	case TCPA_BAD_VERSION:			return "Invalid version";
	case TCPA_RETRY:			return "TPM busy: Retry command at a later time";
	default:				return "Unknown error";
	}
}
