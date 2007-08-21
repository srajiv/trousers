
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Trspi_UnloadBlob_PCR_COMPOSITE(UINT64 *offset, BYTE *blob, TCPA_PCR_COMPOSITE *out)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_PCR_SELECTION(offset, blob, &out->select)))
		return result;

	Trspi_UnloadBlob_UINT32(offset, &out->valueSize, blob);
	out->pcrValue = malloc(out->valueSize);
	if (out->pcrValue == NULL) {
		LogError("malloc of %u bytes failed.", out->valueSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(offset, out->valueSize, blob, (BYTE *)out->pcrValue);

	return TSS_SUCCESS;
}

#ifdef TSS_BUILD_TRANSPORT
TSS_RESULT
Transport_Quote(TSS_HCONTEXT tspContext,	/* in */
		TCS_KEY_HANDLE keyHandle,	/* in */
		TCPA_NONCE *antiReplay,	/* in */
		UINT32 pcrDataSizeIn,	/* in */
		BYTE * pcrDataIn,	/* in */
		TPM_AUTH * privAuth,	/* in, out */
		UINT32 * pcrDataSizeOut,	/* out */
		BYTE ** pcrDataOut,	/* out */
		UINT32 * sigSize,	/* out */
		BYTE ** sig)	/* out */
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

	if ((result = obj_tcskey_get_pubkeyhash(keyHandle, pubKeyHash.digest)))
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

	*handles = keyHandle;

	dataLen = sizeof(TCPA_NONCE) + pcrDataSizeIn;
	if ((data = malloc(dataLen)) == NULL) {
		free(handles);
		LogError("malloc of %u bytes failed", dataLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_LoadBlob_NONCE(&offset, data, antiReplay);
	Trspi_LoadBlob(&offset, pcrDataSizeIn, data, pcrDataIn);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_Quote, dataLen, data,
						    &pubKeyHash, &handlesLen, &handles,
						    privAuth, NULL, &decLen, &dec))) {
		free(data);
		free(handles);
		return result;
	}
	free(data);

	offset = 0;
	Trspi_UnloadBlob_PCR_COMPOSITE(&offset, dec, NULL);
	*pcrDataSizeOut = offset;

	if ((*pcrDataOut = malloc(*pcrDataSizeOut)) == NULL) {
		free(dec);
		LogError("malloc of %u bytes failed", *pcrDataSizeOut);
		*pcrDataSizeOut = 0;
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_UnloadBlob(&offset, *pcrDataSizeOut, dec, *pcrDataOut);
	Trspi_UnloadBlob_UINT32(&offset, sigSize, dec);

	if ((*sig = malloc(*sigSize)) == NULL) {
		free(*pcrDataOut);
		*pcrDataOut = NULL;
		*pcrDataSizeOut = 0;
		free(dec);
		LogError("malloc of %u bytes failed", *sigSize);
		*sigSize = 0;
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *sigSize, dec, *sig);

	free(dec);

	return result;
}
#endif

