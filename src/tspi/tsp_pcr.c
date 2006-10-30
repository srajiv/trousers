
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
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


UINT16
get_num_pcrs(TCS_CONTEXT_HANDLE hContext)
{
	TSS_RESULT result;
	static UINT16 ret = 0;
	UINT32 subCap;
	UINT32 respSize;
	BYTE *resp;

	if (ret != 0)
		return ret;

	subCap = endian32(TPM_CAP_PROP_PCR);
	if ((result = TCSP_GetCapability(hContext, TCPA_CAP_PROPERTY, sizeof(UINT32),
					 (BYTE *)&subCap, &respSize, &resp))) {
		if ((resp = (BYTE *)getenv("TSS_DEFAULT_NUM_PCRS")) == NULL)
			return TSS_DEFAULT_NUM_PCRS;

		/* don't set ret here, next time we may be connected */
		return atoi((char *)resp);
	}

	ret = (UINT16)Decode_UINT32(resp);
	free(resp);

	return ret;
}
