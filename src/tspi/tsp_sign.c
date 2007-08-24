
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
Transport_Sign(TSS_HCONTEXT tspContext,    /* in */
	       TCS_KEY_HANDLE keyHandle,   /* in */
	       UINT32 areaToSignSize,      /* in */
	       BYTE * areaToSign,  /* in */
	       TPM_AUTH * privAuth,        /* in, out */
	       UINT32 * sigSize,   /* out */
	       BYTE ** sig)        /* out */
{
	TSS_RESULT result;
	UINT32 handlesLen, decLen;
	TCS_HANDLE *handles, handle;
	TPM_DIGEST pubKeyHash;
	Trspi_HashCtx hashCtx;
	BYTE *dec;


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
	handle = keyHandle;
	handles = &handle;

	if ((result = obj_context_transport_execute(tspContext, TPM_ORD_Sign, areaToSignSize,
						    areaToSign, &pubKeyHash, &handlesLen, &handles,
						    privAuth, NULL, &decLen, &dec)))
		return result;

	*sigSize = decLen;
	*sig = dec;

	return result;
}
#endif

