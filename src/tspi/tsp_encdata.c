
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
#include <langinfo.h>
#include <iconv.h>
#include <wchar.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Trspi_UnloadBlob_PCR_INFO(UINT64 *offset, BYTE *blob, TCPA_PCR_INFO *pcr)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_PCR_SELECTION(offset, blob, &pcr->pcrSelection)))
		return result;
	Trspi_UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, pcr->digestAtRelease.digest);
	Trspi_UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, pcr->digestAtCreation.digest);
	return TSS_SUCCESS;
}
