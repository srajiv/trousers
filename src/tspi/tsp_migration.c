
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
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_RESULT
Trspi_UnloadBlob_MigrationKeyAuth(UINT64 *offset, BYTE *blob, TCPA_MIGRATIONKEYAUTH *migAuth)
{
	TSS_RESULT result;

	if ((result = Trspi_UnloadBlob_PUBKEY(offset, blob, &migAuth->migrationKey)))
		return result;

	Trspi_UnloadBlob_UINT16(offset, &migAuth->migrationScheme, blob);
	Trspi_UnloadBlob_DIGEST(offset, blob, migAuth->digest);

	return TSS_SUCCESS;
}


