
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
#include <assert.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"
#include "rpc_tcstp_tsp.h"


TSS_RESULT
TCSP_CreateMigrationBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE parentHandle,	/* in */
					TSS_MIGRATE_SCHEME migrationType,	/* in */
					UINT32 MigrationKeyAuthSize,	/* in */
					BYTE * MigrationKeyAuth,	/* in */
					UINT32 encDataSize,	/* in */
					BYTE * encData,	/* in */
					TPM_AUTH * parentAuth,	/* in, out */
					TPM_AUTH * entityAuth,	/* in, out */
					UINT32 * randomSize,	/* out */
					BYTE ** random,	/* out */
					UINT32 * outDataSize,	/* out */
					BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;
	TPM_AUTH null_auth;
	UINT32 i;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));
	memset(&null_auth, 0, sizeof(TPM_AUTH));

	data.ordinal = TCSD_ORD_CREATEMIGRATIONBLOB;
	LogDebugFn("TCS Context: 0x%x", hContext);

	i = 0;
	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &parentHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, i++, &migrationType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &MigrationKeyAuthSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, i++, MigrationKeyAuth, MigrationKeyAuthSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, i++, &encDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, i++, encData, encDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (parentAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, parentAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if (setData(TCSD_PACKET_TYPE_AUTH, i++, entityAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (parentAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, parentAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, i++, entityAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		if (getData(TCSD_PACKET_TYPE_UINT32, i++, randomSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		if (*randomSize > 0) {
			*random = (BYTE *)calloc_tspi(tspContext, *randomSize);
			if (*random == NULL) {
				LogError("malloc of %u bytes failed.", *randomSize);
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto done;
			}
			if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *random, *randomSize, hdr)) {
				free_tspi(tspContext, *random);
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}

		if (getData(TCSD_PACKET_TYPE_UINT32, i++, outDataSize, 0, hdr)) {
			if (*randomSize > 0)
				free_tspi(tspContext, *random);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = (BYTE *)calloc_tspi(tspContext, *outDataSize);
		if (*outData == NULL) {
			if (*randomSize > 0)
				free_tspi(tspContext, *random);
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *outData, *outDataSize, hdr)) {
			if (*randomSize > 0)
				free_tspi(tspContext, *random);
			free_tspi(tspContext, *outData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ConvertMigrationBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCS_KEY_HANDLE parentHandle,	/* in */
					 UINT32 inDataSize,	/* in */
					 BYTE * inData,	/* in */
					 UINT32 randomSize,	/* in */
					 BYTE * random,	/* in */
					 TPM_AUTH * parentAuth,	/* in, out */
					 UINT32 * outDataSize,	/* out */
					 BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	UINT32 i;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CONVERTMIGRATIONBLOB;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &inDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, inData, inDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 4, &randomSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 5, random, randomSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (parentAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 6, parentAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (parentAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, parentAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}

		if (getData(TCSD_PACKET_TYPE_UINT32, i++, outDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = (BYTE *)malloc(*outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *outData, *outDataSize, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_AuthorizeMigrationKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TSS_MIGRATE_SCHEME migrateScheme,	/* in */
					  UINT32 MigrationKeySize,	/* in */
					  BYTE * MigrationKey,	/* in */
					  TPM_AUTH * ownerAuth,	/* in, out */
					  UINT32 * MigrationKeyAuthSize,	/* out */
					  BYTE ** MigrationKeyAuth	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_AUTHORIZEMIGRATIONKEY;
	LogDebugFn("TCS Context: 0x%x", hContext);

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &migrateScheme, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &MigrationKeySize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, MigrationKey, MigrationKeySize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 4, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, 1, MigrationKeyAuthSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*MigrationKeyAuth = (BYTE *)calloc_tspi(tspContext, *MigrationKeyAuthSize);
		if (*MigrationKeyAuth == NULL) {
			LogError("malloc of %u bytes failed.", *MigrationKeyAuthSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 2, *MigrationKeyAuth, *MigrationKeyAuthSize,
			    hdr)) {
			free(*MigrationKeyAuth);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}
