
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
#include <syslog.h>
#include <string.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcs_utils.h"

void
LoadBlob_Auth_Special(UINT16 * offset, BYTE * blob, TCS_AUTH * auth)
{
	LoadBlob(offset, 20, blob, auth->NonceEven.nonce, NULL);
	LoadBlob_BOOL(offset, auth->fContinueAuthSession, blob, NULL);
	LoadBlob(offset, 20, blob, auth->HMAC, NULL);
}

void
UnloadBlob_Auth_Special(UINT16 * offset, BYTE * blob, TCS_AUTH * auth)
{
	UnloadBlob_UINT32(offset, &auth->AuthHandle, blob, NULL);
	UnloadBlob(offset, 20, blob, auth->NonceOdd.nonce, NULL);
	UnloadBlob_BOOL(offset, &auth->fContinueAuthSession, blob, NULL);
	UnloadBlob(offset, 20, blob, auth->HMAC, NULL);
}

/* 2004-05-12 Seiji Munetoh added for EnumRegisterdKey */
void
LoadBlob_KM_KEYINFO( UINT16* offset, BYTE* blob, TSS_KM_KEYINFO* info )
{
	LoadBlob_VERSION( offset, blob, (TCPA_VERSION *)&(info->versionInfo));
	LoadBlob_UUID( offset, blob, info->keyUUID);
	LoadBlob_UUID( offset, blob, info->parentKeyUUID );
	LoadBlob_BYTE( offset, info->bAuthDataUsage, blob, NULL );
	LoadBlob_BOOL( offset, info->fIsLoaded, blob, NULL );
	LoadBlob_UINT32( offset, info->ulVendorDataLength, blob, NULL );
	LoadBlob(offset, info->ulVendorDataLength, blob, info->rgbVendorData, NULL );
}

void
UnloadBlob_KM_KEYINFO( UINT16* offset, BYTE* blob, TSS_KM_KEYINFO* info )
{
	UnloadBlob_VERSION( offset, blob, (TCPA_VERSION *)&(info->versionInfo));
	UnloadBlob_UUID( offset, blob, &info->keyUUID);
	UnloadBlob_UUID( offset, blob, &info->parentKeyUUID);
	UnloadBlob_BYTE( offset, blob, &info->bAuthDataUsage, NULL );
	UnloadBlob_BOOL( offset, &info->fIsLoaded, blob, NULL );
	UnloadBlob_UINT32( offset, &info->ulVendorDataLength, blob, NULL );
	UnloadBlob(offset, info->ulVendorDataLength, info->rgbVendorData, blob, NULL );
}

void
LoadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	LoadBlob_UUID(offset, blob, info->keyUUID);
	LoadBlob_UUID(offset, blob, info->parentKeyUUID);
	LoadBlob(offset, TPM_DIGEST_SIZE, blob, info->paramDigest.digest, NULL);
	LoadBlob_Auth(offset, blob, (TCS_AUTH *)&(info->authData));
}

void
UnloadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	UnloadBlob_UUID(offset, blob, &info->keyUUID);
	UnloadBlob_UUID(offset, blob, &info->parentKeyUUID);
	UnloadBlob(offset, TPM_DIGEST_SIZE, info->paramDigest.digest, blob, NULL);
	UnloadBlob_Auth(offset, blob, (TCS_AUTH *)&(info->authData));
}

void
LoadBlob_PCR_EVENT(UINT16 *offset, BYTE *blob, TSS_PCR_EVENT *event)
{
	LoadBlob_VERSION(offset, blob, (TCPA_VERSION *)&(event->versionInfo));
	LoadBlob_UINT32(offset, event->ulPcrIndex, blob, NULL);
	LoadBlob_UINT32(offset, event->eventType, blob, NULL);

	LoadBlob_UINT32(offset, event->ulPcrValueLength, blob, NULL);
	if (event->ulPcrValueLength > 0)
		LoadBlob(offset, event->ulPcrValueLength, blob, event->rgbPcrValue, NULL);

	LoadBlob_UINT32(offset, event->ulEventLength, blob, NULL);
	if (event->ulEventLength > 0)
		LoadBlob(offset, event->ulEventLength, blob, event->rgbEvent, NULL);

}

TSS_RESULT
UnloadBlob_PCR_EVENT(UINT16 *offset, BYTE *blob, TSS_PCR_EVENT *event)
{
	UnloadBlob_VERSION(offset, blob, (TCPA_VERSION *)&(event->versionInfo));
	UnloadBlob_UINT32(offset, &event->ulPcrIndex, blob, NULL);
	UnloadBlob_UINT32(offset, &event->eventType, blob, NULL);

	UnloadBlob_UINT32(offset, &event->ulPcrValueLength, blob, NULL);
	if (event->ulPcrValueLength > 0) {
		event->rgbPcrValue = malloc(event->ulPcrValueLength);
		if (event->rgbPcrValue == NULL) {
			LogError("malloc of %d bytes failed.", event->ulPcrValueLength);
			return TSS_E_OUTOFMEMORY;
		}

		UnloadBlob(offset, event->ulPcrValueLength, blob, event->rgbPcrValue, NULL);
	} else {
		event->rgbPcrValue = NULL;
	}

	UnloadBlob_UINT32(offset, &event->ulEventLength, blob, NULL);
	if (event->ulEventLength > 0) {
		event->rgbEvent = malloc(event->ulEventLength);
		if (event->rgbEvent == NULL) {
			LogError("malloc of %d bytes failed.", event->ulEventLength);
			return TSS_E_OUTOFMEMORY;
		}

		UnloadBlob(offset, event->ulEventLength, blob, event->rgbEvent, NULL);
	} else {
		event->rgbEvent = NULL;
	}

	return TSS_SUCCESS;
}

int
setData(BYTE dataType, int index, void *theData, int theDataSize, struct tcsd_packet_hdr *hdr)
{
	UINT16 offset;

	if (index == 0) {
		/* min packet size should be everything except the 1 byte 'data' field */
		hdr->packet_size = sizeof(struct tcsd_packet_hdr) - 1;
		hdr->num_parms = 0;
		memset(hdr->parm_types, 0, sizeof(hdr->parm_types));
	}
	offset = hdr->packet_size;
	if (index > TCSD_MAX_NUM_PARMS) {
		LogError1("Too many elements in TCSD packet!");
		return TSS_E_INTERNAL_ERROR;
	}
	switch (dataType) {
	case TCSD_PACKET_TYPE_BYTE:
		LoadBlob_BYTE(&offset, *((BYTE *) (theData)), (void *)hdr, NULL);
		break;
	case TCSD_PACKET_TYPE_BOOL:
		LoadBlob_BOOL(&offset, *((BOOL *) (theData)), (void *)hdr, NULL);
		break;
	case TCSD_PACKET_TYPE_UINT16:
		LoadBlob_UINT16(&offset, *((UINT16 *) (theData)), (void *)hdr, NULL);
		break;
	case TCSD_PACKET_TYPE_UINT32:
		LoadBlob_UINT32(&offset, *((UINT32 *) (theData)), (void *)hdr, NULL);
		break;
	case TCSD_PACKET_TYPE_PBYTE:
		LoadBlob(&offset, theDataSize, (void *)hdr, theData, NULL);
		break;
	case TCSD_PACKET_TYPE_NONCE:
		LoadBlob(&offset, sizeof(TCPA_NONCE), (void *)hdr, ((TCPA_NONCE *)theData)->nonce, NULL);
		break;
	case TCSD_PACKET_TYPE_DIGEST:
		LoadBlob(&offset, sizeof(TCPA_DIGEST), (void *)hdr, ((TCPA_DIGEST *)theData)->digest, NULL);
		break;
	case TCSD_PACKET_TYPE_AUTH:
		LoadBlob_Auth_Special(&offset, (void *)hdr, ((TCS_AUTH *)theData));
		break;
	case TCSD_PACKET_TYPE_UUID:
		LoadBlob_UUID(&offset, (void *)hdr, *((TSS_UUID *)theData));
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		LoadBlob(&offset, sizeof(TCPA_ENCAUTH), (void *)hdr, ((TCPA_ENCAUTH *)theData)->encauth, NULL);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		LoadBlob_VERSION(&offset, (void *)hdr, ((TCPA_VERSION *)theData));
		break;
		/* 2005-05-12 Seiji Munetoh  added */
	case TCSD_PACKET_TYPE_KM_KEYINFO:
		LoadBlob_KM_KEYINFO(&offset, (void *)hdr, ((TSS_KM_KEYINFO *)theData));
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		LoadBlob_LOADKEY_INFO(&offset, (void *)hdr, ((TCS_LOADKEY_INFO *)theData));
		break;
	case TCSD_PACKET_TYPE_PCR_EVENT:
		LoadBlob_PCR_EVENT(&offset, (void *)hdr, ((TSS_PCR_EVENT *)theData));
		break;
	default:
		LogError("TCSD packet type unknown! (0x%x)", dataType & 0xff);
		return TSS_E_INTERNAL_ERROR;
	}

	hdr->parm_types[index] = dataType;
	hdr->packet_size = offset;
	hdr->num_parms++;
	return 0;
}

UINT32
getData(BYTE dataType, int index, void *theData, int theDataSize, struct tsp_packet * packet)
{
	TSS_RESULT result;
	UINT16 offset;

	if (index == 0) {
		/*            memset( packet, 0x00, sizeof( packet )); */
		packet->dataSize = 0;
		/*      packet->numParms = 0; */
		/*      memset( packet->types, 0x00, sizeof( packet->types )); */
	}
	offset = packet->dataSize;
	if (index >= TCSD_MAX_NUM_PARMS) {
		LogError1("Too many elements in TCSD packet!");
		return TSS_E_INTERNAL_ERROR;
	}
	if (index >= packet->numParms) {
#if 0
		/* XXX getting rid of this Error log. Sometimes we allow this to check
		 * for things like whether we got passed a NULL data object over the
		 * wire.  This needs to be looked at thoroughly
		 */
		LogError1("Attempted to get data past the end of the TCSD packet!");
#endif
		return TSS_E_INTERNAL_ERROR;
	}
	if (dataType != packet->types[index]) {
		LogError("Data type of TCS packet element %d doesn't match!", index);
		return TSS_E_INTERNAL_ERROR;
	}
	switch (dataType) {
	case TCSD_PACKET_TYPE_BYTE:
		UnloadBlob_BYTE(&offset, (BYTE *) (theData), packet->dataBuffer, NULL);
		break;
	case TCSD_PACKET_TYPE_BOOL:
		UnloadBlob_BOOL(&offset, (BOOL *) (theData), packet->dataBuffer, NULL);
		break;
	case TCSD_PACKET_TYPE_UINT16:
		UnloadBlob_UINT16(&offset, (UINT16 *) (theData), packet->dataBuffer, NULL);
		break;
	case TCSD_PACKET_TYPE_UINT32:
		UnloadBlob_UINT32(&offset, (UINT32 *) (theData), packet->dataBuffer, NULL);
		break;
	case TCSD_PACKET_TYPE_PBYTE:
		UnloadBlob(&offset, theDataSize, packet->dataBuffer, theData, NULL);
		break;
	case TCSD_PACKET_TYPE_NONCE:
		UnloadBlob(&offset, sizeof(TCPA_NONCE), packet->dataBuffer,
			   ((TCPA_NONCE *) (theData))->nonce, NULL);
		break;
	case TCSD_PACKET_TYPE_DIGEST:
		UnloadBlob(&offset, sizeof(TCPA_DIGEST), packet->dataBuffer,
			   ((TCPA_DIGEST *) (theData))->digest, NULL);
		break;
	case TCSD_PACKET_TYPE_AUTH:
		UnloadBlob_Auth_Special(&offset, packet->dataBuffer, ((TCS_AUTH *) theData));
		break;
	case TCSD_PACKET_TYPE_UUID:
		UnloadBlob_UUID(&offset, packet->dataBuffer, (TSS_UUID *) theData);
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		UnloadBlob(&offset, sizeof(TCPA_ENCAUTH), packet->dataBuffer,
			   ((TCPA_ENCAUTH *) theData)->encauth, NULL);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		UnloadBlob_VERSION(&offset, packet->dataBuffer, ((TCPA_VERSION *) theData));
		break;
	case TCSD_PACKET_TYPE_KM_KEYINFO:
		UnloadBlob_KM_KEYINFO( &offset, packet->dataBuffer, ((TSS_KM_KEYINFO*)theData ) );
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		UnloadBlob_LOADKEY_INFO(&offset, packet->dataBuffer, ((TCS_LOADKEY_INFO *)theData));
		break;
	case TCSD_PACKET_TYPE_PCR_EVENT:
		if ((result = UnloadBlob_PCR_EVENT(&offset, packet->dataBuffer, ((TSS_PCR_EVENT *)theData))))
			return result;
		break;
	default:
		LogError("TCSD packet type unknown! (0x%x)", dataType & 0xff);
		return TSS_E_INTERNAL_ERROR;
	}
	packet->dataSize = offset;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_Error(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	LogError("%s reached.", __FUNCTION__);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->result = TCS_E_FAIL;
	(*hdr)->packet_size = size;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_OpenContext(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	LogDebug("thread %x servicing a %s request", (UINT32)pthread_self(), __FUNCTION__);

	result = TCS_OpenContext_Internal(&hContext);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, *hdr))
			return TSS_E_INTERNAL_ERROR;

		/* Set the context in the thread's object. Later, if something goes wrong
		 * and the connection can't be closed cleanly, we'll still have a reference
		 * to what resources need to be freed.
		 */
		data->context = hContext;
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetRandom(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 bytesRequested;
	BYTE *randomBytes = NULL;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &bytesRequested, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_GetRandom_Internal(hContext, &bytesRequested, &randomBytes);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + bytesRequested);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + bytesRequested);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &bytesRequested, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, randomBytes, bytesRequested, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(randomBytes);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_ReadPubek(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_NONCE antiReplay;
	UINT32 pubEKSize;
	BYTE *pubEK;
	TCPA_DIGEST checksum;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_ReadPubek_Internal(hContext, antiReplay, &pubEKSize, &pubEK,
				    &checksum);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + pubEKSize + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + pubEKSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &pubEKSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, pubEK, pubEKSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(pubEK);
		if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &checksum, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_CloseContext(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCS_CloseContext_Internal(hContext);

	/* This will signal the thread that the connection has been closed cleanly */
	if (result == TCS_SUCCESS)
		data->context = NULL_TCS_HANDLE;

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_EvictKey(struct tcsd_thread_data *data,
		  struct tsp_packet *tsp_data,
		  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	//result = TCSP_EvictKey_Internal(hContext, hKey);
	result = key_mgr_evict(hContext, hKey);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetPubkey(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	TCS_AUTH auth;
	TCS_AUTH *pAuth;
	UINT32 pubKeySize;
	BYTE *pubKey;
	TSS_RESULT result;
	int i;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_AUTH, 2, &auth, 0, tsp_data))
		pAuth = NULL;
	else
		pAuth = &auth;

	result = TCSP_GetPubKey_Internal(hContext, hKey, pAuth, &pubKeySize, &pubKey);
	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + sizeof(UINT32) + pubKeySize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					sizeof(UINT32) + pubKeySize);
			return TSS_E_OUTOFMEMORY;
		}
		if (pAuth != NULL)
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pubKeySize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, pubKey, pubKeySize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(pubKey);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_OIAP(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_AUTHHANDLE authHandle;
	TCPA_NONCE n0;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;


	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

#if 0
	result = TCSP_OIAP_Internal(hContext, &authHandle, &n0);
#else
	result = auth_mgr_oiap(hContext, &authHandle, &n0);
#endif
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + sizeof(TCPA_NONCE));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size +
					sizeof(UINT32) + sizeof(TCPA_NONCE));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &authHandle, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_NONCE, 1, &n0, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_TerminateHandle(struct tcsd_thread_data *data,
			 struct tsp_packet *tsp_data,
			 struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_AUTHHANDLE authHandle;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &authHandle, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_TerminateHandle_Internal(hContext, authHandle);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_Extend(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 pcrIndex;
	TCPA_DIGEST inDigest;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TCPA_DIGEST outDigest;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &pcrIndex, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &inDigest, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_Extend_Internal(hContext, pcrIndex, inDigest, &outDigest);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCPA_DIGEST));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &outDigest, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PcrRead(struct tcsd_thread_data *data,
		 struct tsp_packet *tsp_data,
		 struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 pcrIndex;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TCPA_DIGEST digest;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &pcrIndex, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_PcrRead_Internal(hContext, pcrIndex, &digest);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCPA_DIGEST));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &digest, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetCapability(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_CAPABILITY_AREA capArea;
	UINT32 subCapSize;
	BYTE *subCap;
	UINT32 respSize;
	BYTE *resp;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (subCapSize == 0)
		subCap = NULL;
	else {
		subCap = calloc(1, subCapSize);
		if (subCap == NULL) {
			LogError("malloc of %d bytes failed.", subCapSize);
			return TSS_E_INTERNAL_ERROR;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, tsp_data)) {
			free(subCap);
			return TSS_E_INTERNAL_ERROR;
		}
	}

	result = TCSP_GetCapability_Internal(hContext, capArea, subCapSize, subCap,
					&respSize, &resp);
	if (subCap)
		free(subCap);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + respSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + respSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &respSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, resp, respSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(resp);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetCapabilityOwner(struct tcsd_thread_data *data,
			    struct tsp_packet *tsp_data,
			    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_AUTH ownerAuth;

	TCPA_VERSION version;
	UINT32 nonVol;
	UINT32 vol;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &ownerAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_GetCapabilityOwner_Internal(hContext, &ownerAuth, &version,
					     &nonVol, &vol);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_VERSION) + (2 * sizeof(UINT32)) +
				sizeof(TCS_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCPA_VERSION) +
					(2 * sizeof(UINT32)) + sizeof(TCS_AUTH));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_VERSION, 0, &version, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &nonVol, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 2, &vol, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 3, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_TCSGetCapability(struct tcsd_thread_data *data,
			  struct tsp_packet *tsp_data,
			  struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_CAPABILITY_AREA capArea;
	UINT32 subCapSize;
	BYTE *subCap;
	UINT32 respSize;
	BYTE *resp;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	subCap = calloc(1, subCapSize);
	if (subCap == NULL) {
		LogError("malloc of %d bytes failed.", subCapSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, tsp_data)) {
		free(subCap);
		return TSS_E_INTERNAL_ERROR;
	}

	result = TCS_GetCapability_Internal(hContext, capArea, subCapSize, subCap,
				       &respSize, &resp);
	free(subCap);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + respSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + respSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &respSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, resp, respSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(resp);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PhysicalSetDeactivated(struct tcsd_thread_data *data,
				struct tsp_packet *tsp_data,
				struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	BOOL state;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_PhysicalSetDeactivated_Internal(hContext, state);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_TakeOwnership(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT16 protocolID;
	UINT32 encOwnerAuthSize;
	BYTE *encOwnerAuth;
	UINT32 encSrkAuthSize;
	BYTE *encSrkAuth;
	UINT32 srkInfoSize;
	BYTE *srkInfo;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TCS_AUTH ownerAuth;

	UINT32 srkKeySize;
	BYTE *srkKey;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	/*   printf( "hContext %x\n", hContext ); */
	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &encOwnerAuthSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	encOwnerAuth = calloc(1, encOwnerAuthSize);
	if (encOwnerAuth == NULL) {
		LogError("malloc of %d bytes failed.", encOwnerAuthSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, encOwnerAuth, encOwnerAuthSize, tsp_data)) {
		free(encOwnerAuth);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_UINT32, 4, &encSrkAuthSize, 0, tsp_data)) {
		free(encOwnerAuth);
		return TSS_E_INTERNAL_ERROR;
	}
	encSrkAuth = calloc(1, encSrkAuthSize);
	if (encSrkAuth == NULL) {
		LogError("malloc of %d bytes failed.", encSrkAuthSize);
		free(encOwnerAuth);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 5, encSrkAuth, encSrkAuthSize, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_UINT32, 6, &srkInfoSize, 0, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		return TSS_E_INTERNAL_ERROR;
	}

	srkInfo = calloc(1, srkInfoSize);
	if (srkInfo == NULL) {
		LogError("malloc of %d bytes failed.", srkInfoSize);
		free(encOwnerAuth);
		free(encSrkAuth);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 7, srkInfo, srkInfoSize, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		free(srkInfo);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 8, &ownerAuth, 0, tsp_data)) {
		free(encOwnerAuth);
		free(encSrkAuth);
		free(srkInfo);
		return TSS_E_INTERNAL_ERROR;
	}

	result = TCSP_TakeOwnership_Internal(hContext, protocolID, encOwnerAuthSize,
					encOwnerAuth, encSrkAuthSize,
					encSrkAuth, srkInfoSize, srkInfo,
					&ownerAuth, &srkKeySize, &srkKey);
	free(encOwnerAuth);
	free(encSrkAuth);
	free(srkInfo);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + sizeof(UINT32) + srkKeySize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					sizeof(UINT32) + srkKeySize);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &srkKeySize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, srkKey, srkKeySize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(srkKey);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_ForceClear(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;


	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_ForceClear_Internal(hContext);

	tsp_data->numParms = 0;
	tsp_data->dataSize = 0;
	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}

	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PhysicalEnable(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_PhysicalEnable_Internal(hContext);

	tsp_data->numParms = 0;
	tsp_data->dataSize = 0;

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_RegisterKey(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_UUID WrappingKeyUUID;
	TSS_UUID KeyUUID;
	UINT32 cKeySize;
	BYTE *rgbKey;
	UINT32 cVendorData;
	BYTE *gbVendorData;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UUID, 1, &WrappingKeyUUID, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UUID, 2, &KeyUUID, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &cKeySize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	rgbKey = calloc(1, cKeySize);
	if (rgbKey == NULL) {
		LogError("malloc of %d bytes failed.", cKeySize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, rgbKey, cKeySize, tsp_data)) {
		free(rgbKey);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_UINT32, 5, &cVendorData, 0, tsp_data)) {
		free(rgbKey);
		return TSS_E_INTERNAL_ERROR;
	}

	if (cVendorData == 0)
		gbVendorData = NULL;
	else {
		gbVendorData = calloc(1, cVendorData);
		if (gbVendorData == NULL) {
			LogError("malloc of %d bytes failed.", cVendorData);
			free(rgbKey);
			return TSS_E_INTERNAL_ERROR;
		}

		if (getData(TCSD_PACKET_TYPE_PBYTE, 6, gbVendorData, cVendorData, tsp_data)) {
			free(rgbKey);
			free(gbVendorData);
			return TSS_E_INTERNAL_ERROR;
		}
	}

	result = TCS_RegisterKey_Internal(hContext, &WrappingKeyUUID, &KeyUUID,
				     cKeySize, rgbKey, cVendorData,
				     gbVendorData);
	free(rgbKey);
	free(gbVendorData);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_UnregisterKey(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_UUID uuid;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UUID, 1, &uuid, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_UnregisterKey_Internal(hContext, uuid);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}

	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetRegisteredKeyBlob(struct tcsd_thread_data *data,
				struct tsp_packet *tsp_data,
				struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_UUID uuid;
	UINT32 pcKeySize;
	BYTE *prgbKey;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UUID, 1, &uuid, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCS_GetRegisteredKeyBlob_Internal(hContext, &uuid, &pcKeySize,
					      &prgbKey);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + pcKeySize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + pcKeySize);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &pcKeySize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, prgbKey, pcKeySize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(prgbKey);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_LoadKeyByBlob(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hUnwrappingKey;
	UINT32 cWrappedKeyBlob;
	BYTE *rgbWrappedKeyBlob;

	TCS_AUTH auth;

	TCS_KEY_HANDLE phKeyTCSI;
	TCS_KEY_HANDLE phKeyHMAC;

	TCS_AUTH *pAuth;
	TSS_RESULT result;
	int i;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hUnwrappingKey, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &cWrappedKeyBlob, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	rgbWrappedKeyBlob = calloc(1, cWrappedKeyBlob);
	if (rgbWrappedKeyBlob == NULL) {
		LogError("malloc of %d bytes failed.", cWrappedKeyBlob);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, rgbWrappedKeyBlob, cWrappedKeyBlob, tsp_data)) {
		free(rgbWrappedKeyBlob);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &auth, 0, tsp_data))
		pAuth = NULL;
	else
		pAuth = &auth;

	//result = TCSP_LoadKeyByBlob_Internal(hContext, hUnwrappingKey,
	//				cWrappedKeyBlob, rgbWrappedKeyBlob,
	//				pAuth, &phKeyTCSI, &phKeyHMAC);
	result = key_mgr_load_by_blob(hContext, hUnwrappingKey,
					cWrappedKeyBlob, rgbWrappedKeyBlob,
					pAuth, &phKeyTCSI, &phKeyHMAC);

	if (!result)
		result = ctx_mark_key_loaded(hContext, phKeyTCSI);

	free(rgbWrappedKeyBlob);

	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + (2 * sizeof(UINT32)));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					(2 * sizeof(UINT32)));
			return TSS_E_OUTOFMEMORY;
		}
		if (pAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &phKeyTCSI, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &phKeyHMAC, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_LoadKeyByUUID(struct tcsd_thread_data *data,
		       struct tsp_packet *tsp_data,
		       struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_UUID uuid;
	TCS_LOADKEY_INFO info, *pInfo;
	TCS_KEY_HANDLE phKeyTCSI;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UUID, 1, &uuid, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (getData(TCSD_PACKET_TYPE_LOADKEY_INFO, 2, &info, 0, tsp_data))
		pInfo = NULL;
	else
		pInfo = &info;

	//result = TCSP_LoadKeyByUUID_Internal(hContext, &uuid, pInfo, &phKeyTCSI);
	result = key_mgr_load_by_uuid(hContext, &uuid, pInfo, &phKeyTCSI);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + sizeof(TCS_LOADKEY_INFO));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &phKeyTCSI, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (pInfo != NULL) {
			if (setData(TCSD_PACKET_TYPE_LOADKEY_INFO, 1, pInfo, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_OSAP(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_ENTITY_TYPE entityType;
	UINT32 entityValue;
	TCPA_NONCE nonceOddOSAP;

	TCS_AUTHHANDLE authHandle;
	TCPA_NONCE nonceEven;
	TCPA_NONCE nonceEvenOSAP;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &entityType, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &entityValue, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_NONCE, 3, &nonceOddOSAP, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

#if 0
	result = TCSP_OSAP_Internal(hContext, entityType, entityValue, nonceOddOSAP,
			       &authHandle, &nonceEven, &nonceEvenOSAP);
#else
	result = auth_mgr_osap(hContext, entityType, entityValue, nonceOddOSAP,
			       &authHandle, &nonceEven, &nonceEvenOSAP);
#endif

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + (2 * sizeof(TCPA_NONCE)));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) +
					(2 * sizeof(TCPA_NONCE)));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &authHandle, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_NONCE, 1, &nonceEven, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_NONCE, 2, &nonceEvenOSAP, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_Sign(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	UINT32 areaToSignSize;
	BYTE *areaToSign;

	TCS_AUTH auth;
	TCS_AUTH *pAuth;

	UINT32 sigSize;
	BYTE *sig;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &areaToSignSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	areaToSign = calloc(1, areaToSignSize);
	if (areaToSign == NULL) {
		LogError("malloc of %d bytes failed.", areaToSignSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, areaToSign, areaToSignSize, tsp_data)) {
		free(areaToSign);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &auth, 0, tsp_data))
		pAuth = NULL;
	else
		pAuth = &auth;

	result = TCSP_Sign_Internal(hContext, hKey, areaToSignSize, areaToSign,
			       pAuth, &sigSize, &sig);
	free(areaToSign);

	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + sizeof(UINT32) + sigSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					sizeof(UINT32) + sigSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (pAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, &auth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &sigSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, sig, sigSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(sig);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_DirWriteAuth(struct tcsd_thread_data *data,
		      struct tsp_packet *tsp_data,
		      struct tcsd_packet_hdr **hdr)
{
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_HCONTEXT hContext;
	TCPA_DIRINDEX dirIndex;
	TCPA_DIGEST dirDigest;
	TCS_AUTH auth;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &dirIndex, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &dirDigest, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_AUTH, 3, &auth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_DirWriteAuth_Internal(hContext, dirIndex, dirDigest, &auth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCS_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH));
			return TSS_E_OUTOFMEMORY;
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &auth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_DirRead(struct tcsd_thread_data *data,
		 struct tsp_packet *tsp_data,
		 struct tcsd_packet_hdr **hdr)
{
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_HCONTEXT hContext;
	TCPA_DIRINDEX dirIndex;
	TCPA_DIRVALUE dirValue;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &dirIndex, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_DirRead_Internal(hContext, dirIndex, &dirValue);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH));
			return TSS_E_OUTOFMEMORY;
		}

		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &dirValue, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_Seal(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE keyHandle;
	TCPA_ENCAUTH KeyUsageAuth;
	UINT32 PCRInfoSize, inDataSize;
	BYTE *PCRInfo = NULL, *inData = NULL;
	TCS_AUTH emptyAuth, pubAuth, *pAuth;
	UINT32 outDataSize;
	BYTE *outData;

	int i = 0;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	memset(&emptyAuth, 0, sizeof(TCS_AUTH));
	memset(&pubAuth, 0, sizeof(TCS_AUTH));

	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &keyHandle, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, i++, &KeyUsageAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &PCRInfoSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (PCRInfoSize > 0) {
		PCRInfo = calloc(1, PCRInfoSize);
		if (PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", PCRInfoSize);
			return TSS_E_INTERNAL_ERROR;
		}
	}
	/* attempt to pull out PCRInfo even if size is 0 */
	if (getData(TCSD_PACKET_TYPE_PBYTE, i++, PCRInfo, PCRInfoSize, tsp_data)) {
		free(PCRInfo);
		return TSS_E_INTERNAL_ERROR;
	}

	if (getData(TCSD_PACKET_TYPE_UINT32, i++, &inDataSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (inDataSize > 0) {
		inData = calloc(1, inDataSize);
		if (inData == NULL) {
			LogError("malloc of %d bytes failed.", inDataSize);
			return TSS_E_INTERNAL_ERROR;
		}
	}
	/* attempt to pull out InData even if size is 0 */
	if (getData(TCSD_PACKET_TYPE_PBYTE, i++, inData, inDataSize, tsp_data)) {
		free(inData);
		return TSS_E_INTERNAL_ERROR;
	}

	if (getData(TCSD_PACKET_TYPE_AUTH, i++, &pubAuth, 0, tsp_data)) {
		free(inData);
		free(PCRInfo);
		return TSS_E_INTERNAL_ERROR;
	}

	if (!memcmp(&emptyAuth, &pubAuth, sizeof(TCS_AUTH))) {
		pAuth = NULL;
	} else {
		pAuth = &pubAuth;
	}

	result = TCSP_Seal_Internal(hContext, keyHandle, KeyUsageAuth, PCRInfoSize, PCRInfo,
			inDataSize, inData, pAuth, &outDataSize, &outData);
	free(inData);
	free(PCRInfo);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					sizeof(UINT32) + outDataSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (pAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, pAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		} else {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, &emptyAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 1, &outDataSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 2, outData, outDataSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(outData);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_UnSeal(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE parentHandle;
	UINT32 inDataSize;
	BYTE *inData;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TCS_AUTH parentAuth, dataAuth, emptyAuth;
	TCS_AUTH *pParentAuth, *pDataAuth;

	UINT32 outDataSize;
	BYTE *outData;
	TSS_RESULT result;

	memset(&emptyAuth, 0, sizeof(TCS_AUTH));

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &inDataSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	inData = calloc(1, inDataSize);
	if (inData == NULL) {
		LogError("malloc of %d bytes failed.", inDataSize);
		return TSS_E_OUTOFMEMORY;
	}

	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, inData, inDataSize, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &parentAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (!memcmp(&emptyAuth, &parentAuth, sizeof(TCS_AUTH)))
		pParentAuth = NULL;
	else
		pParentAuth = &parentAuth;

	if (getData(TCSD_PACKET_TYPE_AUTH, 5, &dataAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_Unseal_Internal(hContext, parentHandle, inDataSize, inData,
				 pParentAuth, &dataAuth, &outDataSize, &outData);
	free(inData);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + (2 * sizeof(TCS_AUTH)) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + (2 * sizeof(TCS_AUTH)) +
					sizeof(UINT32) + outDataSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (pParentAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, pParentAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		} else {
			if (setData(TCSD_PACKET_TYPE_AUTH, 0, &emptyAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 1, &dataAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 2, &outDataSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 3, outData, outDataSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(outData);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_UnBind(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE keyHandle;
	UINT32 inDataSize;
	BYTE *inData;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TCS_AUTH privAuth;
	TCS_AUTH *pPrivAuth;

	UINT32 outDataSize;
	BYTE *outData;
	TSS_RESULT result;

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &inDataSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	inData = calloc(1, inDataSize);
	if (inData == NULL) {
		LogError("malloc of %d bytes failed.", inDataSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 3, inData, inDataSize, tsp_data)) {
		free(inData);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &privAuth, 0, tsp_data))
		pPrivAuth = NULL;
	else
		pPrivAuth = &privAuth;

	result = TCSP_UnBind_Internal(hContext, keyHandle, inDataSize, inData,
				 pPrivAuth, &outDataSize, &outData);
	free(inData);

	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					sizeof(UINT32) + outDataSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (pPrivAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pPrivAuth, 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &outDataSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, outData, outDataSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(outData);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_StirRandom(struct tcsd_thread_data *data,
		    struct tsp_packet *tsp_data,
		    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 inDataSize;
	BYTE *inData;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &inDataSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	inData = calloc(1, inDataSize);
	if (inData == NULL) {
		LogError("malloc of %d bytes failed.", inDataSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 2, inData, inDataSize, tsp_data)) {
		free(inData);
		return TSS_E_INTERNAL_ERROR;
	}

	result = TCSP_StirRandom_Internal(hContext, inDataSize, inData);

	free(inData);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_CreateWrapKey(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hWrappingKey;
	TCPA_ENCAUTH KeyUsageAuth;
	TCPA_ENCAUTH KeyMigrationAuth;
	UINT32 keyInfoSize;
	BYTE *keyInfo;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TCS_AUTH pAuth;

	UINT32 keyDataSize;
	BYTE *keyData;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hWrappingKey, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 2, &KeyUsageAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 3, &KeyMigrationAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 4, &keyInfoSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	keyInfo = calloc(1, keyInfoSize);
	if (keyInfo == NULL) {
		LogError("malloc of %d bytes failed.", keyInfoSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 5, keyInfo, keyInfoSize, tsp_data)) {
		free(keyInfo);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 6, &pAuth, 0, tsp_data)) {
		free(keyInfo);
		return TSS_E_INTERNAL_ERROR;
	}

	result = TCSP_CreateWrapKey_Internal(hContext, hWrappingKey, KeyUsageAuth,
					KeyMigrationAuth, keyInfoSize, keyInfo,
					&keyDataSize, &keyData, &pAuth);

	free(keyInfo);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + keyDataSize + sizeof(TCS_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) +
					keyDataSize + sizeof(TCS_AUTH));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &keyDataSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, keyData, keyDataSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(keyData);
		if (setData(TCSD_PACKET_TYPE_AUTH, 2, &pAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_ChangeAuth(struct tcsd_thread_data *data,
		    struct tsp_packet *tsp_data,
		    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE parentHandle;
	TCPA_PROTOCOL_ID protocolID;
	TCPA_ENCAUTH newAuth;
	TCPA_ENTITY_TYPE entityType;
	UINT32 encDataSize;
	BYTE *encData;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TCS_AUTH ownerAuth;
	TCS_AUTH entityAuth;

	UINT32 outDataSize;
	BYTE *outData;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT16, 2, &protocolID, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 3, &newAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT16, 4, &entityType, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 5, &encDataSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	encData = calloc(1, encDataSize);
	if (encData == NULL) {
		LogError("malloc of %d bytes failed.", encDataSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 6, encData, encDataSize, tsp_data)) {
		free(encData);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 7, &ownerAuth, 0, tsp_data)) {
		free(encData);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 8, &entityAuth, 0, tsp_data)) {
		free(encData);
		return TSS_E_INTERNAL_ERROR;
	}

	result = TCSP_ChangeAuth_Internal(hContext, parentHandle, protocolID,
				     newAuth, entityType, encDataSize, encData,
				     &ownerAuth, &entityAuth, &outDataSize,
				     &outData);
	free(encData);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + (2 * sizeof(TCS_AUTH)) + sizeof(UINT32) + outDataSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + (2 * sizeof(TCS_AUTH)) +
					sizeof(UINT32) + outDataSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 1, &entityAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 2, &outDataSize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 3, outData, outDataSize, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
		free(outData);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_ChangeAuthOwner(struct tcsd_thread_data *data,
			 struct tsp_packet *tsp_data,
			 struct tcsd_packet_hdr **hdr)
{

	TCS_CONTEXT_HANDLE hContext;
	TCPA_PROTOCOL_ID protocolID;
	TCPA_ENCAUTH newAuth;
	TCPA_ENTITY_TYPE entityType;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TCS_AUTH ownerAuth;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 2, &newAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT16, 3, &entityType, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_AUTH, 4, &ownerAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_ChangeAuthOwner_Internal(hContext, protocolID, newAuth,
					  entityType, &ownerAuth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCS_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_Quote(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCS_KEY_HANDLE hKey;
	TCPA_NONCE antiReplay;
	UINT32 pcrDataSizeIn;
	BYTE *pcrDataIn;

	TCS_AUTH privAuth;
	TCS_AUTH *pPrivAuth;

	UINT32 pcrDataSizeOut;
	BYTE *pcrDataOut;
	UINT32 sigSize;
	BYTE *sig;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &pcrDataSizeIn, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	pcrDataIn = (BYTE *) calloc(1, pcrDataSizeIn);
	if (pcrDataIn == NULL) {
		LogError("malloc of %d bytes failed.", pcrDataSizeIn);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, pcrDataIn, pcrDataSizeIn, tsp_data)) {
		free(pcrDataIn);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 5, &privAuth, 0, tsp_data))
		pPrivAuth = NULL;
	else
		pPrivAuth = &privAuth;

	result = TCSP_Quote_Internal(hContext, hKey, antiReplay, pcrDataSizeIn,
				pcrDataIn, pPrivAuth, &pcrDataSizeOut,
				&pcrDataOut, &sigSize, &sig);
	free(pcrDataIn);
	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size + sizeof(TCS_AUTH) + (2 * sizeof(UINT32)) +
				pcrDataSizeOut + sigSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH) +
					(2 * sizeof(UINT32)) + pcrDataSizeOut + sigSize);
			return TSS_E_OUTOFMEMORY;
		}
		if (pPrivAuth != NULL) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pPrivAuth, 0, *hdr)) {
				free(*hdr);
				free(pcrDataOut);
				free(sig);
				return TSS_E_INTERNAL_ERROR;
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcrDataSizeOut, 0, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, pcrDataOut, pcrDataSizeOut, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &sigSize, 0, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TSS_E_INTERNAL_ERROR;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, sig, sigSize, *hdr)) {
			free(*hdr);
			free(pcrDataOut);
			free(sig);
			return TSS_E_INTERNAL_ERROR;
		}

		free(pcrDataOut);
		free(sig);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_MakeIdentity(struct tcsd_thread_data *data,
		      struct tsp_packet *tsp_data,
		      struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TCPA_ENCAUTH identityAuth;
	TCPA_CHOSENID_HASH privCAHash;
	UINT32 idKeyInfoSize;
	BYTE *idKeyInfo;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	TCS_AUTH srkAuth;
	TCS_AUTH ownerAuth;
	TCS_AUTH *pSRKAuth;
/* 	TCS_AUTH* pOwnerauth; */

	UINT32 idKeySize;
	BYTE *idKey;
	UINT32 pcIDBindSize;
	BYTE *prgbIDBind;
	UINT32 pcECSize;
	BYTE *prgbEC;
	UINT32 pcPlatCredSize;
	BYTE *prgbPlatCred;
	UINT32 pcConfCredSize;
	BYTE *prgbConfCred;
	TSS_RESULT result;

	int i;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_ENCAUTH, 1, &identityAuth, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &privCAHash, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &idKeyInfoSize, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;
	idKeyInfo = (BYTE *) calloc(1, idKeyInfoSize);
	if (idKeyInfo == NULL) {
		LogError("malloc of %d bytes failed.", idKeyInfoSize);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, idKeyInfo, idKeyInfoSize, tsp_data)) {
		free(idKeyInfo);
		return TSS_E_INTERNAL_ERROR;
	}
	if (getData(TCSD_PACKET_TYPE_AUTH, 5, &srkAuth, 0, tsp_data)) {
		free(idKeyInfo);
		return TSS_E_INTERNAL_ERROR;
	}
	/* ---  if the next one is missing, then the previous was really the owner auth */
	if (getData(TCSD_PACKET_TYPE_AUTH, 6, &ownerAuth, 0, tsp_data)) {
		LogDebug1("Failed to get ownerAuth.  SRK auth is really NULL and single auth is ownerAuth");
		pSRKAuth = NULL;
		memcpy(&ownerAuth, &srkAuth, sizeof (TCS_AUTH));
	} else {
		LogDebug1("two Auth");
		pSRKAuth = &srkAuth;
	}
	result = TCSP_MakeIdentity_Internal(hContext, identityAuth, privCAHash,
				       idKeyInfoSize, idKeyInfo, pSRKAuth,
				       &ownerAuth, &idKeySize, &idKey,
				       &pcIDBindSize, &prgbIDBind, &pcECSize,
				       &prgbEC, &pcPlatCredSize, &prgbPlatCred,
				       &pcConfCredSize, &prgbConfCred);
	free(idKeyInfo);
	/*      printf( "before %.8X\n", pcECSize ); */
	if (result == TSS_SUCCESS) {
		i = 0;
		*hdr = calloc(1, size +
				2 * sizeof(TCS_AUTH) +
				5 * sizeof(UINT32) +
			        idKeySize + pcIDBindSize +
				pcECSize + pcPlatCredSize +
				pcConfCredSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		if (pSRKAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pSRKAuth, 0, *hdr)) {
				goto internal_error;
			}
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, &ownerAuth, 0, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &idKeySize, 0, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, idKey, idKeySize, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcIDBindSize, 0, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbIDBind, pcIDBindSize, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcECSize, 0, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbEC, pcECSize, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcPlatCredSize, 0, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbPlatCred, pcPlatCredSize, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &pcConfCredSize, 0, *hdr)) {
			goto internal_error;
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, prgbConfCred, pcConfCredSize, *hdr)) {
			goto internal_error;
		}

		free(idKey);
		free(prgbIDBind);
		free(prgbEC);
		free(prgbPlatCred);
		free(prgbConfCred);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	LogDebug1("tcs_wrap_MakeIdentity done. SMDEBUG <<<<<<");

	return TCS_SUCCESS;

internal_error:
	free(*hdr);
	free(idKey);
	free(prgbIDBind);
	free(prgbEC);
	free(prgbPlatCred);
	free(prgbConfCred);
	return TSS_E_INTERNAL_ERROR;
}

/* 2004-05-12 Seiji Munetoh added  */
TSS_RESULT
tcs_wrap_EnumRegisteredKeys(struct tcsd_thread_data *data,
			    struct tsp_packet *tsp_data,
			    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_UUID uuid, *pUuid;
	UINT32 cKeyHierarchySize;
	TSS_KM_KEYINFO *pKeyHierarchy;
	unsigned int i,j;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	/* Receive */
	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData( TCSD_PACKET_TYPE_UUID , 1, &uuid, 0, tsp_data ))
		pUuid = NULL;
	else
		pUuid = &uuid;

	result = TCS_EnumRegisteredKeys_Internal(
			hContext,
			pUuid,
			&cKeyHierarchySize,
			&pKeyHierarchy);

	if(result == TSS_SUCCESS) {
		i=0;
		*hdr = calloc(1, size + sizeof(UINT32) + (cKeyHierarchySize * sizeof(TSS_KM_KEYINFO)));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) +
					(cKeyHierarchySize * sizeof(TSS_KM_KEYINFO)));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData( TCSD_PACKET_TYPE_UINT32, i++, &cKeyHierarchySize, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}

		for (j=0;j<cKeyHierarchySize;j++) {
			if (setData( TCSD_PACKET_TYPE_KM_KEYINFO, i++, &pKeyHierarchy[j], 0, *hdr)) {
				free(*hdr);
				return TSS_E_INTERNAL_ERROR;
			}
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_LogPcrEvent(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_PCR_EVENT event;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	UINT32 number;

	/* Receive */
	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_PCR_EVENT , 1, &event, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	result = TCS_LogPcrEvent_Internal(hContext, event, &number);

	if(result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32));
			return TSS_E_OUTOFMEMORY;
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &number, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}


TSS_RESULT
tcs_wrap_GetPcrEvent(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_PCR_EVENT *pEvent;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	UINT32 pcrIndex, number, totalSize;

	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData( TCSD_PACKET_TYPE_UINT32, 1, &pcrIndex, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	if (getData( TCSD_PACKET_TYPE_UINT32, 2, &number, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	result = TCS_GetPcrEvent_Internal(hContext, pcrIndex, &number, &pEvent);

	if(result == TSS_SUCCESS) {
		totalSize = get_pcr_event_size(pEvent);

		*hdr = calloc(1, size + sizeof(UINT32) + totalSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + totalSize);
			free(pEvent);
			return TSS_E_OUTOFMEMORY;
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &number, 0, *hdr)) {
			free(*hdr);
			free(pEvent);
			return TSS_E_INTERNAL_ERROR;
		}

		if (setData(TCSD_PACKET_TYPE_PCR_EVENT, 1, pEvent, 0, *hdr)) {
			free(*hdr);
			free(pEvent);
			return TSS_E_INTERNAL_ERROR;
		}
		free(pEvent);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}


TSS_RESULT
tcs_wrap_GetPcrEventsByPcr(struct tcsd_thread_data *data,
			   struct tsp_packet *tsp_data,
			   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_PCR_EVENT *ppEvents;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	UINT32 firstEvent, eventCount, totalSize, pcrIndex, i, j;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &pcrIndex, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (getData(TCSD_PACKET_TYPE_UINT32, 2, &firstEvent, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &eventCount, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCS_GetPcrEventsByPcr_Internal(hContext, pcrIndex, firstEvent, &eventCount, &ppEvents);

	if(result == TSS_SUCCESS) {
		for (i = 0, totalSize = 0; i < eventCount; i++)
			totalSize += get_pcr_event_size(&(ppEvents[i]));

		*hdr = calloc(1, size + sizeof(UINT32) + totalSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + totalSize);
			free(ppEvents);
			return TSS_E_OUTOFMEMORY;
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &eventCount, 0, *hdr)) {
			free(*hdr);
			free(ppEvents);
			return TSS_E_INTERNAL_ERROR;
		}

		i = 1;
		for (j = 0; j < eventCount; j++) {
			if (setData(TCSD_PACKET_TYPE_PCR_EVENT, i++, &(ppEvents[j]), 0, *hdr)) {
				free(*hdr);
				free(ppEvents);
				return TSS_E_INTERNAL_ERROR;
			}
		}

		free(ppEvents);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_GetPcrEventLog(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_PCR_EVENT *ppEvents;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	UINT32 eventCount, totalSize, i, j;

	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCS_GetPcrEventLog_Internal(hContext, &eventCount, &ppEvents);

	if( result == TSS_SUCCESS ) {
		for (i = 0, totalSize = 0; i < eventCount; i++)
			totalSize += get_pcr_event_size(&(ppEvents[i]));

		*hdr = calloc(1, size + sizeof(UINT32) + totalSize);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(UINT32) + totalSize);
			free(ppEvents);
			return TSS_E_OUTOFMEMORY;
		}

		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &eventCount, 0, *hdr)) {
			free(*hdr);
			free(ppEvents);
			return TSS_E_INTERNAL_ERROR;
		}

		i = 1;
		for (j = 0; j < eventCount; j++) {
			if (setData(TCSD_PACKET_TYPE_PCR_EVENT, i++, &(ppEvents[j]), 0, *hdr)) {
				free(*hdr);
				free(ppEvents);
				return TSS_E_INTERNAL_ERROR;
			}
		}

		free(ppEvents);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_SelfTestFull(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_RESULT result;

	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x servicing a %s request", (UINT32)pthread_self(), __FUNCTION__);

	result = TCSP_SelfTestFull_Internal(hContext);
	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_SetOwnerInstall(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	BOOL state;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_SetOwnerInstall_Internal(hContext, state);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_OwnerSetDisable(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	BOOL disableState;
	TCS_AUTH ownerAuth;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData( TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &disableState, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	if (getData(TCSD_PACKET_TYPE_AUTH, 2, &ownerAuth, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_OwnerSetDisable_Internal(hContext, disableState, &ownerAuth);

	if( result == TSS_SUCCESS ) {
		*hdr = calloc(1, size + sizeof(TCS_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size + sizeof(TCS_AUTH));
			return TSS_E_OUTOFMEMORY;
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
			free(*hdr);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PhysicalDisable(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_PhysicalDisable_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PhysicalPresence(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TCPA_PHYSICAL_PRESENCE phyPresFlags;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &phyPresFlags, 0, tsp_data))
		return TSS_E_INTERNAL_ERROR;

	result = TCSP_PhysicalPresence_Internal(hContext, phyPresFlags);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}

TSS_RESULT
tcs_wrap_SetTempDeactivated(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data ))
		return TSS_E_INTERNAL_ERROR;

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_SetTempDeactivated_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TSS_E_OUTOFMEMORY;
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TCS_SUCCESS;
}



/* -------------------- */
/*	Dispatch	*/
/* -------------------- */
typedef struct tdDispatchTable {
	TSS_RESULT (*Func) (struct tcsd_thread_data *,
			    struct tsp_packet *,
			    struct tcsd_packet_hdr **);
} DispatchTable;

/* 2004-06-09 Seiji Munetoh update ORDs and table */
DispatchTable table[TCSD_MAX_NUM_ORDS] = {
	{tcs_wrap_Error},   /* 0 */
	{tcs_wrap_OpenContext}, /*  1 */
	{tcs_wrap_CloseContext}, /*  2 */
	{tcs_wrap_Error}, /*  3 */
	{tcs_wrap_TCSGetCapability}, /*  4 */
	{tcs_wrap_RegisterKey}, /*  5 */
	{tcs_wrap_UnregisterKey}, /*  6 */
	{tcs_wrap_EnumRegisteredKeys}, /*  7  Seiji Munetoh Added */
	{tcs_wrap_Error}, /*  8 */
	{tcs_wrap_GetRegisteredKeyBlob}, /*  9 */
	{tcs_wrap_Error}, /* 10 */
	{tcs_wrap_LoadKeyByBlob}, /* 11 */
	{tcs_wrap_LoadKeyByUUID}, /* 12 */
	{tcs_wrap_EvictKey}, /* 13 */
	{tcs_wrap_CreateWrapKey}, /* 14 */
	{tcs_wrap_GetPubkey}, /* 15 */
	{tcs_wrap_MakeIdentity}, /* 16 */
	{tcs_wrap_LogPcrEvent}, /* 17 */
	{tcs_wrap_GetPcrEvent}, /* 18 */
	{tcs_wrap_GetPcrEventsByPcr}, /* 19 */
	{tcs_wrap_GetPcrEventLog}, /* 20 */
	{tcs_wrap_SetOwnerInstall}, /* 21 */
	{tcs_wrap_TakeOwnership}, /* 22 */
	{tcs_wrap_OIAP}, /* 23 */
	{tcs_wrap_OSAP}, /* 24 */
	{tcs_wrap_ChangeAuth}, /* 25 */
	{tcs_wrap_ChangeAuthOwner}, /* 26 */
	{tcs_wrap_Error}, /* 27 */
	{tcs_wrap_Error}, /* 28 */
	{tcs_wrap_TerminateHandle}, /* 29 */
	{tcs_wrap_Error}, /* 30 */
	{tcs_wrap_Extend}, /* 31 */
	{tcs_wrap_PcrRead}, /* 32 */
	{tcs_wrap_Quote}, /* 33 */
	{tcs_wrap_DirWriteAuth}, /* 34 */
	{tcs_wrap_DirRead}, /* 35 */
	{tcs_wrap_Seal}, /* 36 */
	{tcs_wrap_UnSeal}, /* 37 */
	{tcs_wrap_UnBind}, /* 38 */
	{tcs_wrap_Error}, /* 39 */
	{tcs_wrap_Error}, /* 40 */
	{tcs_wrap_Error}, /* 41 */
	{tcs_wrap_Error}, /* 42 */
	{tcs_wrap_Sign}, /* 43 */
	{tcs_wrap_GetRandom}, /* 44 */
	{tcs_wrap_StirRandom}, /* 45 */
	{tcs_wrap_GetCapability}, /* 46 */
	{tcs_wrap_Error}, /* 47 */
	{tcs_wrap_GetCapabilityOwner}, /* 48 */
	{tcs_wrap_Error}, /* 49 */
	{tcs_wrap_ReadPubek}, /* 50 */
	{tcs_wrap_Error}, /* 51 */
	{tcs_wrap_Error}, /* 52 */
	{tcs_wrap_SelfTestFull}, /* 53 */
	{tcs_wrap_Error}, /* 54 */
	{tcs_wrap_Error}, /* 55 */
	{tcs_wrap_Error}, /* 56 */
	{tcs_wrap_OwnerSetDisable}, /* 57 */
	{tcs_wrap_Error}, /* 58 */
	{tcs_wrap_Error}, /* 59 */
	{tcs_wrap_ForceClear}, /* 60 */
	{tcs_wrap_Error}, /* 61 */
	{tcs_wrap_PhysicalDisable}, /* 62 */
	{tcs_wrap_PhysicalEnable}, /* 63 */
	{tcs_wrap_PhysicalSetDeactivated}, /* 64 */
	{tcs_wrap_SetTempDeactivated}, /* 65 */
	{tcs_wrap_PhysicalPresence}, /* 66 */
	{tcs_wrap_Error}, /* 67 */
	{tcs_wrap_Error}, /* 68 */
	{tcs_wrap_Error}, /* 69 */
	{tcs_wrap_Error}, /* 70 */
	{tcs_wrap_Error}, /* 71 */
	{tcs_wrap_Error}, /* 72 */
	{tcs_wrap_Error}, /* 73 */
	{tcs_wrap_Error}, /* 74 */ /* tcs_wrap_Atmel_SetState */
	{tcs_wrap_Error}, /* 75 */ /* tcs_wrap_Atmel_OwnerSetState */
	{tcs_wrap_Error}  /* 76  last */ /* tcs_wrap_Atmel_GetState */
};

int
access_control(struct tcsd_thread_data *thread_data, struct tsp_packet *tsp_data)
{
	int i = 0;

	/* if the request comes from localhost, or is in the accepted ops list,
	 * approve it */
	if (!strcmp(thread_data->hostname, "localhost")) {
		return 0;
	} else {
		while (tcsd_options.remote_ops[i]) {
			if (tcsd_options.remote_ops[i] == tsp_data->ordinal) {
				return 0;
			}
			i++;
		}
	}

	return 1;
}

TSS_RESULT
dispatchCommand(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	/* ---  First, check the ordinal bounds */
	if (tsp_data->ordinal >= TCSD_MAX_NUM_ORDS) {
		LogError1("Illegal TCSD Ordinal");
		return TCS_E_FAIL;
	}

	if (access_control(data, tsp_data)) {
		*hdr = calloc(1, sizeof(struct tcsd_packet_hdr));
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.",
					sizeof(struct tcsd_packet_hdr));
			return TSS_E_OUTOFMEMORY;
		}
		(*hdr)->result = TSS_E_CONNECTION_FAILED;
		(*hdr)->packet_size = sizeof(struct tcsd_packet_hdr);

		LogInfo("Access to ordinal %d from host %s denied.",
				tsp_data->ordinal, data->hostname);

		return TSS_SUCCESS;
	}

	/* --   Now, dispatch */
	return table[tsp_data->ordinal].Func(data, tsp_data, hdr);
}

/* -------------------- */

TSS_RESULT
getTCSDPacket(struct tcsd_thread_data *data, struct tcsd_packet_hdr **hdr)
{
	struct tsp_packet tsp_data;
	BYTE tmp_data[1024];
	UINT16 offset = 0, tmp_offset;
	UINT32 totalSize;
	UINT32 result, operation_result;

	/* unload the wire blob (data->buf) into a host blob (tsp_data) */
	UnloadBlob_UINT32(&offset, &tsp_data.ordinal, data->buf, NULL);
	UnloadBlob_UINT32(&offset, &totalSize, data->buf, NULL);
	UnloadBlob_UINT16(&offset, &tsp_data.numParms, data->buf, NULL);
	UnloadBlob(&offset, tsp_data.numParms, data->buf, tsp_data.types, NULL);
	UnloadBlob(&offset, totalSize - offset, data->buf, tsp_data.dataBuffer, NULL);

#if 0
	LogDebug("Dispatching command to TCSD_ORD_ 0x%X", tsp_data.ordinal);
#endif
	/* ---  dispatch the command to the TCS */
	if ((result = dispatchCommand(data, &tsp_data, hdr)))
		return result;

	operation_result = (*hdr)->result;
	totalSize = (*hdr)->packet_size;

	offset = 0;
	LoadBlob_UINT32(&offset, (*hdr)->result, (BYTE *)*hdr, NULL);
	LoadBlob_UINT32(&offset, (*hdr)->packet_size, (BYTE *)*hdr, NULL);

	if (operation_result == TSS_SUCCESS) {
		LoadBlob_UINT16(&offset, (*hdr)->num_parms, (BYTE *)*hdr, NULL);

#if 0
		LoadBlob(&offset, TCSD_MAX_NUM_PARMS, (BYTE *)*hdr, (*hdr)->parm_types, NULL);
		LoadBlob(&offset, totalSize - offset, (BYTE *)*hdr, &((*hdr)->data), NULL);
#else
		/* XXX TEST */
		tmp_offset = 0;
		LoadBlob(&tmp_offset, TCSD_MAX_NUM_PARMS, tmp_data, (*hdr)->parm_types, NULL);
		LoadBlob(&offset, TCSD_MAX_NUM_PARMS, (BYTE *)*hdr, tmp_data, NULL);

		tmp_offset = 0;
		if (totalSize - offset > 1024)
			LogError1("%s: ************** ERROR ***********************");
		LoadBlob(&tmp_offset, totalSize - offset, tmp_data, &((*hdr)->data), NULL);
		LoadBlob(&offset, totalSize - offset, (BYTE *)*hdr, tmp_data, NULL);
#endif
	}

	return result;
}

