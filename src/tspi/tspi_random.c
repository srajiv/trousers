
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_TPM_GetRandom(TSS_HTPM hTPM,		/* in */
		   UINT32 ulRandomDataLength,	/* in */
		   BYTE ** prgbRandomData)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if (prgbRandomData == NULL || ulRandomDataLength > 4096)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if (ulRandomDataLength == 0)
		return TSS_SUCCESS;

	if ((result = TCSP_GetRandom(tcsContext, ulRandomDataLength, prgbRandomData)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_StirRandom(TSS_HTPM hTPM,		/* in */
		    UINT32 ulEntropyDataLength,	/* in */
		    BYTE * rgbEntropyData)	/* in */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if (ulEntropyDataLength > 0 && rgbEntropyData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCSP_StirRandom(tcsContext, ulEntropyDataLength, rgbEntropyData)))
		return result;

	return TSS_SUCCESS;
}
