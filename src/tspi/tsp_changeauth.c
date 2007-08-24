
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
#include <time.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Trspi_UnloadBlob_STORED_DATA(UINT64 *offset, BYTE *blob, TCPA_STORED_DATA *data)
{
	Trspi_UnloadBlob_TCPA_VERSION(offset, blob, &data->ver);
	Trspi_UnloadBlob_UINT32(offset, &data->sealInfoSize, blob);

	if (data->sealInfoSize > 0) {
		data->sealInfo = malloc(data->sealInfoSize);
		if (data->sealInfo == NULL) {
			LogError("malloc of %d bytes failed.", data->sealInfoSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, data->sealInfoSize, blob, data->sealInfo);
	} else {
		data->sealInfo = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &data->encDataSize, blob);

	if (data->encDataSize > 0) {
		data->encData = malloc(data->encDataSize);
		if (data->encData == NULL) {
			LogError("malloc of %d bytes failed.", data->encDataSize);
			free(data->sealInfo);
			data->sealInfo = NULL;
			return TSPERR(TSS_E_OUTOFMEMORY);
		}

		Trspi_UnloadBlob(offset, data->encDataSize, blob, data->encData);
	} else {
		data->encData = NULL;
	}

	return TSS_SUCCESS;
}

void
Trspi_LoadBlob_STORED_DATA(UINT64 *offset, BYTE *blob, TCPA_STORED_DATA *data)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, data->ver);
	Trspi_LoadBlob_UINT32(offset, data->sealInfoSize, blob);
	Trspi_LoadBlob(offset, data->sealInfoSize, blob, data->sealInfo);
	Trspi_LoadBlob_UINT32(offset, data->encDataSize, blob);
	Trspi_LoadBlob(offset, data->encDataSize, blob, data->encData);
}

#ifdef TSS_BUILD_TRANSPORT
TSS_RESULT
Transport_ChangeAuth(TSS_HCONTEXT tspContext,	/* in */
		     TCS_KEY_HANDLE parentHandle,	/* in */
		     TCPA_PROTOCOL_ID protocolID,	/* in */
		     TCPA_ENCAUTH *newAuth,	/* in */
		     TCPA_ENTITY_TYPE entityType,	/* in */
		     UINT32 encDataSize,	/* in */
		     BYTE * encData,	/* in */
		     TPM_AUTH * ownerAuth,	/* in, out */
		     TPM_AUTH * entityAuth,	/* in, out */
		     UINT32 * outDataSize,	/* out */
		     BYTE ** outData)	/* out */
{
	TSS_RESULT result;
	UINT32 handlesLen, dataLen, decLen;
	TCS_HANDLE *handles;
	BYTE *dec = NULL;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;
	UINT64 offset;
	BYTE *data;

	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(parentHandle, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = parentHandle;

	dataLen = sizeof(TCPA_PROTOCOL_ID) + sizeof(TCPA_ENCAUTH)
					   + sizeof(TCPA_ENTITY_TYPE)
					   + sizeof(UINT32)
					   + encDataSize;
	if ((data = malloc(dataLen)) == NULL) {
		free(handles);
		LogError("malloc of %u bytes failed", dataLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_LoadBlob_UINT16(&offset, protocolID, data);
	Trspi_LoadBlob(&offset, sizeof(TCPA_ENCAUTH), data, newAuth->authdata);
	Trspi_LoadBlob_UINT16(&offset, entityType, data);
	Trspi_LoadBlob_UINT32(&offset, encDataSize, data);
	Trspi_LoadBlob(&offset, encDataSize, data, encData);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_ChangeAuth, dataLen, data,
						    &pubKeyHash, &handlesLen, &handles,
						    ownerAuth, entityAuth, &decLen, &dec))) {
		free(data);
		free(handles);
		return result;
	}
	free(data);

	offset = 0;
	Trspi_UnloadBlob_UINT32(&offset, outDataSize, dec);

	if ((*outData = malloc(*outDataSize)) == NULL) {
		free(dec);
		LogError("malloc of %u bytes failed", *outDataSize);
		*outDataSize = 0;
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *outDataSize, dec, *outData);

	free(dec);

	return result;
}

TSS_RESULT
Transport_ChangeAuthOwner(TSS_HCONTEXT tspContext,	/* in */
			  TCPA_PROTOCOL_ID protocolID,	/* in */
			  TCPA_ENCAUTH *newAuth,	/* in */
			  TCPA_ENTITY_TYPE entityType,	/* in */
			  TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result;
	UINT32 handlesLen;
	UINT64 offset;
	BYTE data[sizeof(TCPA_PROTOCOL_ID) + sizeof(TCPA_ENCAUTH) + sizeof(TCPA_ENTITY_TYPE)];

	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	offset = 0;
	Trspi_LoadBlob_UINT16(&offset, protocolID, data);
	Trspi_LoadBlob(&offset, sizeof(TCPA_ENCAUTH), data, newAuth->authdata);
	Trspi_LoadBlob_UINT16(&offset, entityType, data);

	return obj_context_transport_execute(tspContext, TPM_ORD_ChangeAuthOwner, sizeof(data),
					     data, NULL, &handlesLen, NULL, ownerAuth, NULL, NULL,
					     NULL);
}
#endif
