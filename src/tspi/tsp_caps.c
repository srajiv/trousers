
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
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
internal_GetCap(TSS_HCONTEXT tspContext, TSS_FLAG capArea, UINT32 subCap,
		UINT32 * respSize, BYTE ** respData)
{
	UINT64 offset = 0;
	TSS_VERSION v = INTERNAL_CAP_TSP_VERSION;

	if (capArea == TSS_TSPCAP_VERSION) {
		if ((*respData = calloc_tspi(tspContext, sizeof(TSS_VERSION))) == NULL)
			return TSPERR(TSS_E_OUTOFMEMORY);

		Trspi_LoadBlob_TSS_VERSION(&offset, *respData, v);
		*respSize = offset;
	} else if (capArea == TSS_TSPCAP_ALG) {
		if ((*respData = calloc_tspi(tspContext, 1)) == NULL)
			return TSPERR(TSS_E_OUTOFMEMORY);
		*respSize = 1;

		switch (subCap) {
			case TSS_ALG_RSA:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_RSA;
				break;
			case TSS_ALG_AES:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_AES;
				break;
			case TSS_ALG_SHA:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_SHA;
				break;
			case TSS_ALG_HMAC:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_HMAC;
				break;
			case TSS_ALG_DES:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_DES;
				break;
			case TSS_ALG_3DES:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_3DES;
				break;
			default:
				free_tspi(tspContext, *respData);
				return TSPERR(TSS_E_BAD_PARAMETER);
		}
	} else if (capArea == TSS_TSPCAP_PERSSTORAGE) {
		if ((*respData = calloc_tspi(tspContext, 1)) == NULL)
			return TSPERR(TSS_E_OUTOFMEMORY);

		*respSize = 1;
		(*respData)[0] = INTERNAL_CAP_TSP_PERSSTORAGE;
	} else
		return TSPERR(TSS_E_BAD_PARAMETER);

	return TSS_SUCCESS;
}
