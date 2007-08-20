
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2007
 *
 */


#include <stdlib.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


#ifdef TSS_BUILD_TRANSPORT
TSS_RESULT
Transport_CertifyKey(TSS_HCONTEXT tspContext,	/* in */
		     TCS_KEY_HANDLE certHandle,	/* in */
		     TCS_KEY_HANDLE keyHandle,	/* in */
		     TPM_NONCE * antiReplay,	/* in */
		     TPM_AUTH * certAuth,	/* in, out */
		     TPM_AUTH * keyAuth,	/* in, out */
		     UINT32 * CertifyInfoSize,	/* out */
		     BYTE ** CertifyInfo,	/* out */
		     UINT32 * outDataSize,	/* out */
		     BYTE ** outData)		/* out */
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles;
	BYTE *dec = NULL;
	TPM_DIGEST pubKeyHash1, pubKeyHash2;
	Trspi_HashCtx hashCtx;
	UINT64 offset;
	BYTE data[sizeof(TPM_NONCE)];


	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(certHandle, pubKeyHash1.digest)))
		return result;

	if ((result = obj_tcskey_get_pubkeyhash(keyHandle, pubKeyHash2.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash1.digest);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash2.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash1.digest)))
		return result;

	handlesLen = 2;
	if ((handles = malloc(2 * sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", 2 * sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	handles[0] = certHandle;
	handles[1] = keyHandle;

	offset = 0;
	Trspi_LoadBlob_NONCE(&offset, data, antiReplay);

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_CertifyKey, sizeof(data),
						    data, &pubKeyHash1, &handlesLen, &handles,
						    certAuth, keyAuth, &decLen, &dec))) {
		free(handles);
		return result;
	}

	offset = 0;
	Trspi_UnloadBlob_CERTIFY_INFO(&offset, dec, NULL);
	*CertifyInfoSize = offset;

	if ((*CertifyInfo = malloc(*CertifyInfoSize)) == NULL) {
		*CertifyInfoSize = 0;
		free(dec);
		LogError("malloc of %u bytes failed", *CertifyInfoSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;
	Trspi_UnloadBlob(&offset, *CertifyInfoSize, dec, *CertifyInfo);
	Trspi_UnloadBlob_UINT32(&offset, outDataSize, dec);

	if ((*outData = malloc(*outDataSize)) == NULL) {
		free(*CertifyInfo);
		*CertifyInfo = NULL;
		*CertifyInfoSize = 0;
		*outDataSize = 0;
		free(dec);
		LogError("malloc of %u bytes failed", *outDataSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	Trspi_UnloadBlob(&offset, *outDataSize, dec, *outData);

	free(dec);

	return result;
}
#endif

