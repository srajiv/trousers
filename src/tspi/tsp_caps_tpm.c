
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


/*
 * This function provides a funnel through which all the TCSP_SetCapability requests can be
 * sent.  This will keep the owner auth code from being duplicated around the TSP.
 */
TSS_RESULT
TSP_SetCapability(TSS_HCONTEXT tspContext,
		  TSS_HTPM hTPM,
		  TSS_HPOLICY hTPMPolicy,
		  TPM_CAPABILITY_AREA tcsCapArea,
		  UINT32 subCap,
		  TSS_BOOL value)
{
	TSS_RESULT result;
	Trspi_HashCtx hashCtx;
	TPM_DIGEST digest;
	TPM_AUTH auth;

	subCap = endian32(subCap);

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_SetCapability);
	result |= Trspi_Hash_UINT32(&hashCtx, tcsCapArea);
	result |= Trspi_Hash_UINT32(&hashCtx, (UINT32)sizeof(UINT32));
	result |= Trspi_HashUpdate(&hashCtx, (UINT32)sizeof(UINT32), (BYTE *)&subCap);
	result |= Trspi_Hash_UINT32(&hashCtx, (UINT32)sizeof(TSS_BOOL));
	result |= Trspi_Hash_BOOL(&hashCtx, value);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_SetCapability, hTPMPolicy, FALSE,
					      &digest, &auth)))
		return result;

	if ((result = TCSP_SetCapability(tspContext, tcsCapArea, sizeof(UINT32), (BYTE *)&subCap,
					 sizeof(TSS_BOOL), (BYTE *)&value, &auth)))
		return result;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_SetCapability);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		return result;

	return obj_policy_validate_auth_oiap(hTPMPolicy, &digest, &auth);
}
