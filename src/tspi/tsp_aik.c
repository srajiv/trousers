
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
Transport_ActivateTPMIdentity(TSS_HCONTEXT tspContext,
			      TCS_KEY_HANDLE idKey,        /* in */
			      UINT32 blobSize,     /* in */
			      BYTE * blob, /* in */
			      TPM_AUTH * idKeyAuth,        /* in, out */
			      TPM_AUTH * ownerAuth,        /* in, out */
			      UINT32 * SymmetricKeySize,   /* out */
			      BYTE ** SymmetricKey)        /* out */
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;
	BYTE *dec;

	if ((result = obj_context_transport_init(tspContext)))
		return result;

	LogDebugFn("Executing in a transport session");

	if ((result = obj_tcskey_get_pubkeyhash(idKey, pubKeyHash.digest)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_DIGEST(&hashCtx, pubKeyHash.digest);
	if ((result |= Trspi_HashFinal(&hashCtx, pubKeyHash.digest)))
		return result;

	/* Call ExecuteTransport */
	handlesLen = 1;
	if ((handles = malloc(sizeof(TCS_HANDLE))) == NULL) {
		LogError("malloc of %zd bytes failed", sizeof(TCS_HANDLE));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	*handles = idKey;

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_ActivateIdentity, blobSize,
						    blob, &pubKeyHash, &handlesLen, &handles,
						    idKeyAuth, ownerAuth, &decLen, &dec)))
		return result;

	*SymmetricKeySize = decLen;
	*SymmetricKey = dec;

	return result;
}
#endif

