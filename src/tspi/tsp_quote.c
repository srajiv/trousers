
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
