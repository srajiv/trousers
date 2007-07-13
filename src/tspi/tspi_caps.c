
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

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "tcs_tsp.h"
#include "tspps.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "obj.h"


TSS_RESULT
Tspi_Context_GetCapability(TSS_HCONTEXT tspContext,	/* in */
			   TSS_FLAG capArea,		/* in */
			   UINT32 ulSubCapLength,	/* in */
			   BYTE * rgbSubCap,		/* in */
			   UINT32 * pulRespDataLength,	/* out */
			   BYTE ** prgbRespData)	/* out */
{
	TSS_RESULT result;
	UINT32 subCap;

	if (prgbRespData == NULL || pulRespDataLength == NULL )
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (rgbSubCap == NULL && ulSubCapLength != 0)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulSubCapLength > sizeof(UINT32))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	switch (capArea) {
		case TSS_TSPCAP_ALG:
		case TSS_TSPCAP_VERSION:
		case TSS_TSPCAP_PERSSTORAGE:
			if (capArea == TSS_TSPCAP_ALG) {
				if (ulSubCapLength != sizeof(UINT32) || !rgbSubCap)
					return TSPERR(TSS_E_BAD_PARAMETER);
			}

			result = internal_GetCap(tspContext, capArea,
						 rgbSubCap ? *(UINT32 *)rgbSubCap : 0,
						 pulRespDataLength,
						 prgbRespData);
			break;
		case TSS_TCSCAP_ALG:
		case TSS_TCSCAP_VERSION:
		case TSS_TCSCAP_CACHING:
		case TSS_TCSCAP_PERSSTORAGE:
		case TSS_TCSCAP_MANUFACTURER:
		case TSS_TCSCAP_TRANSPORT:
			if (capArea == TSS_TCSCAP_ALG) {
				if (ulSubCapLength != sizeof(UINT32) || !rgbSubCap)
					return TSPERR(TSS_E_BAD_PARAMETER);
			}

			subCap = rgbSubCap ? endian32(*(UINT32 *)rgbSubCap) : 0;

			result = TCS_GetCapability(tspContext, capArea, ulSubCapLength,
						   (BYTE *)&subCap, pulRespDataLength,
						   prgbRespData);
			break;
		default:
			result = TSPERR(TSS_E_BAD_PARAMETER);
			break;
	}

	return result;
}
