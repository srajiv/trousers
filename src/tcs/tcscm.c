
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

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"


TSS_RESULT
TCS_OpenContext_Internal(TCS_CONTEXT_HANDLE * hContext)	/* out  */
{
	*hContext = make_context();
	if (*hContext == 0)
		return TCS_E_FAIL;

#if 0
	initKeyFile(*hContext);
#endif
	return TSS_SUCCESS;
}

TSS_RESULT
TCS_CloseContext_Internal(TCS_CONTEXT_HANDLE hContext)	/* in */
{
	TSS_RESULT result;

	LogDebug("Closing context %.8X", hContext);

	if ((result = ctx_verify_context(hContext)))
		return result;

	auth_mgr_close_context(hContext);

	destroy_context(hContext);

	key_mgr_ref_count();

	LogDebug("Context %.8X closed", hContext);
	return TSS_SUCCESS;
}

TSS_RESULT
TCS_FreeMemory_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			BYTE *pMemory)			/* in */
{
	free(pMemory);

	return TCS_SUCCESS;
}
