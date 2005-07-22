
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
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"

TSS_RESULT send_init(struct host_table_entry *, BYTE *, int, struct tcsd_packet_hdr **);
TSS_RESULT sendit(struct host_table_entry *, BYTE *data, int, struct tcsd_packet_hdr **);

int
setData(BYTE dataType, int index, void *theData, int theDataSize, struct tsp_packet *packet)
{
	UINT16 offset;
	if (index == 0) {
		packet->dataSize = 0;
		packet->numParms = 0;
		memset(packet->types, 0, sizeof (packet->types));
	}
	offset = packet->dataSize;
	if ((unsigned int)index > sizeof(packet->types))
		return -1;
	switch (dataType) {
	case TCSD_PACKET_TYPE_BYTE:
		Trspi_LoadBlob_BYTE(&offset, *((BYTE *) (theData)), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_BOOL:
		Trspi_LoadBlob_BOOL(&offset, *((TSS_BOOL *) (theData)), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_UINT16:
		Trspi_LoadBlob_UINT16(&offset, *((UINT16 *) (theData)), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_UINT32:
		Trspi_LoadBlob_UINT32(&offset, *((UINT32 *) (theData)), packet->dataBuffer);
		break;
	case TCSD_PACKET_TYPE_PBYTE:
		Trspi_LoadBlob(&offset, theDataSize, packet->dataBuffer, (BYTE *)theData);
		break;
	case TCSD_PACKET_TYPE_NONCE:
		Trspi_LoadBlob(&offset, 20, packet->dataBuffer, ((TCPA_NONCE *)theData)->nonce);
		break;
	case TCSD_PACKET_TYPE_DIGEST:
		Trspi_LoadBlob(&offset, 20, packet->dataBuffer, ((TCPA_DIGEST *)theData)->digest);
		break;
	case TCSD_PACKET_TYPE_AUTH:
		LoadBlob_AUTH(&offset, packet->dataBuffer, ((TPM_AUTH *)theData));
		break;
	case TCSD_PACKET_TYPE_UUID:
		Trspi_LoadBlob_UUID(&offset, packet->dataBuffer, *((TSS_UUID *)theData));
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		Trspi_LoadBlob(&offset, 20, packet->dataBuffer, ((TCPA_ENCAUTH *)theData)->authdata);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		Trspi_LoadBlob_TCPA_VERSION(&offset, packet->dataBuffer, *((TCPA_VERSION *)theData));
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		LoadBlob_LOADKEY_INFO(&offset, packet->dataBuffer, ((TCS_LOADKEY_INFO *)theData));
		break;
	case TCSD_PACKET_TYPE_PCR_EVENT:
		Trspi_LoadBlob_PCR_EVENT(&offset, packet->dataBuffer, ((TSS_PCR_EVENT *)theData));
		break;
	default:
		LogError1("Unknown TCSD packet type!");
		return -1;
	}
	packet->types[index] = dataType;
	packet->dataSize = offset;
	packet->numParms++;
	return 0;
}

int
getData(BYTE dataType, int index, void *theData, int theDataSize, struct tcsd_packet_hdr *hdr)
{
	UINT16 offset;
	if (index == 0) {
		hdr->packet_size = sizeof(struct tcsd_packet_hdr) - 1;
	}
	offset = hdr->packet_size;
	if (index > TCSD_MAX_NUM_PARMS) {
		LogError1("Too many elements in TCSD packet!");
		return -1;
	}
	if (index >= hdr->num_parms) {
		LogError1("Attempted to get data past the end of the TCSD packet!");
		return -1;
	}
	if (dataType != hdr->parm_types[index]) {
		LogError("Data type of TCS packet element %d doesn't match!", index);
		return -1;
	}
	switch (dataType) {
	case TCSD_PACKET_TYPE_BYTE:
		Trspi_UnloadBlob_BYTE(&offset, (BYTE *)theData, (BYTE *)hdr);
		break;
	case TCSD_PACKET_TYPE_BOOL:
		Trspi_UnloadBlob_BOOL(&offset, (TSS_BOOL *)theData, (BYTE *)hdr);
		break;
	case TCSD_PACKET_TYPE_UINT16:
		Trspi_UnloadBlob_UINT16(&offset, (UINT16 *)theData, (BYTE *)hdr);
		break;
	case TCSD_PACKET_TYPE_UINT32:
		Trspi_UnloadBlob_UINT32(&offset, (UINT32 *) (theData), (BYTE *)hdr);
		break;
	case TCSD_PACKET_TYPE_PBYTE:
		Trspi_UnloadBlob(&offset, theDataSize, (BYTE *)hdr, (BYTE *)theData);
		break;
	case TCSD_PACKET_TYPE_NONCE:
		Trspi_UnloadBlob(&offset, sizeof(TCPA_NONCE), (BYTE *)hdr, ((TCPA_NONCE *)theData)->nonce);
		break;
	case TCSD_PACKET_TYPE_DIGEST:
		Trspi_UnloadBlob(&offset, sizeof(TCPA_DIGEST), (BYTE *)hdr, ((TCPA_DIGEST *)theData)->digest);
		break;
	case TCSD_PACKET_TYPE_AUTH:
		UnloadBlob_AUTH(&offset, (BYTE *)hdr, ((TPM_AUTH *)theData));
		break;
	case TCSD_PACKET_TYPE_UUID:
		Trspi_UnloadBlob_UUID(&offset, (BYTE *)hdr, ((TSS_UUID *)theData));
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		Trspi_UnloadBlob(&offset, sizeof(TPM_AUTH), (BYTE *)hdr, ((TCPA_ENCAUTH *)theData)->authdata);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		Trspi_UnloadBlob_TCPA_VERSION(&offset, (BYTE *)hdr, ((TCPA_VERSION *)theData));
		break;
	case TCSD_PACKET_TYPE_KM_KEYINFO:
		Trspi_UnloadBlob_KM_KEYINFO( &offset,	(BYTE *)hdr, ((TSS_KM_KEYINFO *)theData ) );
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		UnloadBlob_LOADKEY_INFO(&offset, (BYTE *)hdr, ((TCS_LOADKEY_INFO *)theData));
		break;
	case TCSD_PACKET_TYPE_PCR_EVENT:
		Trspi_UnloadBlob_PCR_EVENT(&offset, (BYTE *)hdr, ((TSS_PCR_EVENT *)theData));
		break;
	default:
		LogError("unknown data type (%d) in TCSD packet!", dataType);
		return -1;
	}
	hdr->packet_size = offset;
	return 0;
}

#if 0
void
printBuffer(BYTE * b, int size)
{
	int i;
	return;
	for (i = 0; i < size; i++) {
		if ((i % 16) == 0)
			printf("\n");
		printf("%.2X ", b[i]);
	}
	printf("\n");
	return;
}
#endif

/* XXX Naming is bad in this function. hdr is set inside send_init() or sendit()
 * as a malloc'd buffer holding raw data off the wire. tmp_hdr is then created
 * and the data in hdr is copied into it and converted endianly so that its readable
 * by us. Then hdr is freed and *hdr is set to tmp_hdr, which the parent later frees.
 */
TSS_RESULT
sendTCSDPacket(struct host_table_entry *hte,
		TCS_CONTEXT_HANDLE tcsContext,
		struct tsp_packet *dataToSend,
		struct tcsd_packet_hdr **hdr)
{
	UINT32 totalSize;
	TSS_RESULT rc;
	BYTE transmitBuffer[1024];
	UINT16 offset = 0;
	struct tcsd_packet_hdr *tmp_hdr;

	memset(transmitBuffer, 0, sizeof(transmitBuffer));

	Trspi_LoadBlob_UINT32(&offset, dataToSend->ordinal, transmitBuffer);
	offset += sizeof(UINT32);		/* skip the size */
	Trspi_LoadBlob_UINT16(&offset, dataToSend->numParms, transmitBuffer);
	Trspi_LoadBlob(&offset, dataToSend->numParms, transmitBuffer, dataToSend->types);
	Trspi_LoadBlob(&offset, dataToSend->dataSize, transmitBuffer, dataToSend->dataBuffer);
	UINT32ToArray(offset, &transmitBuffer[4]);

#if 0
	/* ---  Send it */
	printBuffer(transmitBuffer, offset);
	LogInfo("Sending Packet with TCSD ordinal 0x%X", dataToSend->ordinal);
#endif
	/* if the ordinal is open context, there are some host table entry
	 * manipulations that must be done, so call _init
	 */
	if (dataToSend->ordinal == TCSD_ORD_OPENCONTEXT) {
		if ((rc = send_init(hte, transmitBuffer, offset, hdr))) {
			LogError1("Failed to send packet");
			return rc;
		}
	} else {
		if ((rc = sendit(hte, transmitBuffer, offset, hdr))) {
			LogError1("Failed to send packet");
			return rc;
		}
	}

	/* ---  Get the result */
	offset = sizeof(UINT32);
	Trspi_UnloadBlob_UINT32(&offset, &totalSize, (BYTE *)(*hdr));

	tmp_hdr = calloc(1, totalSize);
	if (tmp_hdr == NULL) {
		LogError("malloc of %u bytes failed.", totalSize);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	offset = 0;

	Trspi_UnloadBlob_UINT32(&offset, &tmp_hdr->result, (BYTE *)(*hdr));

	if (tmp_hdr->result == 0) {
		Trspi_UnloadBlob_UINT32(&offset, &tmp_hdr->packet_size, (BYTE *)(*hdr));
		Trspi_UnloadBlob_UINT16(&offset, &tmp_hdr->num_parms, (BYTE *)(*hdr));
		Trspi_UnloadBlob(&offset, TCSD_MAX_NUM_PARMS, (BYTE *)(*hdr), tmp_hdr->parm_types);
		Trspi_UnloadBlob(&offset, tmp_hdr->packet_size - offset, (BYTE *)(*hdr), &tmp_hdr->data);
	}

	free(*hdr);
	*hdr = tmp_hdr;
	LogDebug1("Finished sending and receiving response from TCSD");
	return TSS_SUCCESS;
}

/* ---------------------------------------------- */
/*	TCS Commands                              */
/* ---------------------------------------------- */

TSS_RESULT
Atmel_TPM_SetState_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,
		      BYTE stateID, UINT32 stateSize, BYTE * stateValue)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_ATMEL_SETSTATE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BYTE, 1, &stateID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &stateSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, stateValue, stateSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, hContext, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
Atmel_TPM_OwnerSetState_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,
			   BYTE stateID, UINT32 stateSize, BYTE * stateValue,
			   TPM_AUTH * ownerAuth)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_ATMEL_OWNERSETSTATE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BYTE, 1, &stateID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &stateSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, stateValue, stateSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 4, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, hContext, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
Atmel_TPM_GetState_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,
		      BYTE stateID, UINT32 * stateSize, BYTE ** stateValue)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_ATMEL_GETSTATE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BYTE, 1, &stateID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if ((result = sendTCSDPacket(hte, hContext, &data, &hdr)))
		return result;

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, stateSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*stateValue = (unsigned char *) malloc(*stateSize);
		if (*stateValue == NULL) {
			LogError("malloc of %u bytes failed.", *stateSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *stateValue, *stateSize, hdr)) {
			free(*stateValue);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_OpenContext_RPC_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE * hContext)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OPENCONTEXT;
	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, hContext, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetRegisteredKeyByPublicInfo_TP(struct host_table_entry *hte,
				     TCS_CONTEXT_HANDLE hContext,
				     TCPA_ALGORITHM_ID algID,	/* in */
				     UINT32 ulPublicInfoLength,	/* in */
				     BYTE * rgbPublicInfo,	/* in */
				     UINT32 * keySize,		/* out */
				     BYTE ** keyBlob)		/* out */
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETREGISTEREDKEYBYPUBLICINFO;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &algID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &ulPublicInfoLength, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, rgbPublicInfo, ulPublicInfoLength, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, keySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*keyBlob = (BYTE *) malloc(*keySize);
		if (*keyBlob == NULL) {
			LogError("malloc of %u bytes failed.", *keySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *keyBlob, *keySize, hdr)) {
			free(*keyBlob);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TSC_PhysicalPresence_TP(UINT16 physPres)
{
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCS_CloseContext_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext)
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CLOSECONTEXT;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCS_FreeMemory_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/*  in */
			      BYTE * pMemory	/*  in */
    ) {
	free(pMemory);

	return TSS_SUCCESS;
}

TSS_RESULT
TCS_LogPcrEvent_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/*  in   */
			       TSS_PCR_EVENT Event,	/*  in  */
			       UINT32 * pNumber	/*  out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_LOGPCREVENT;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_PCR_EVENT, 1, &Event, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pNumber, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCS_GetPcrEvent_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT32 PcrIndex,	/* in */
			       UINT32 * pNumber,	/* in, out */
			       TSS_PCR_EVENT ** ppEvent	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETPCREVENT;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &PcrIndex, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_UINT32, 2, pNumber, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pNumber, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*ppEvent = malloc(sizeof(TSS_PCR_EVENT));
		if (*ppEvent == NULL) {
			LogError("malloc of %d bytes failed.", sizeof(TSS_PCR_EVENT));
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		if (getData(TCSD_PACKET_TYPE_PCR_EVENT, 1, *ppEvent, 0, hdr)) {
			free(*ppEvent);
			*ppEvent = NULL;
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_GetPcrEventsByPcr_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				     UINT32 PcrIndex,	/* in */
				     UINT32 FirstEvent,	/* in */
				     UINT32 * pEventCount,	/* in, out */
				     TSS_PCR_EVENT ** ppEvents	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	UINT32 i, j;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETPCREVENTBYPCR;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &PcrIndex, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &FirstEvent, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_UINT32, 3, pEventCount, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pEventCount, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		if (*pEventCount > 0) {
			*ppEvents = calloc_tspi(tspContext, sizeof(TSS_PCR_EVENT) * (*pEventCount));
			if (*ppEvents == NULL) {
				LogError("malloc of %d bytes failed.", sizeof(TSS_PCR_EVENT) * (*pEventCount));
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto done;
			}

			i = 1;
			for (j = 0; j < (*pEventCount); j++) {
				if (getData(TCSD_PACKET_TYPE_PCR_EVENT, i++, &((*ppEvents)[j]), 0, hdr)) {
					free(*ppEvents);
					*ppEvents = NULL;
					result = TSPERR(TSS_E_INTERNAL_ERROR);
					goto done;
				}
			}
		} else {
			*ppEvents = NULL;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_GetPcrEventLog_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  UINT32 * pEventCount,	/* out */
				  TSS_PCR_EVENT ** ppEvents	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	int i, j;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETPCREVENTLOG;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pEventCount, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		if (*pEventCount > 0) {
			*ppEvents = calloc_tspi(tspContext, sizeof(TSS_PCR_EVENT) * (*pEventCount));
			if (*ppEvents == NULL) {
				LogError("malloc of %d bytes failed.", sizeof(TSS_PCR_EVENT) * (*pEventCount));
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto done;
			}

			i = 1;
			for (j = 0; (UINT32)j < (*pEventCount); j++) {
				if (getData(TCSD_PACKET_TYPE_PCR_EVENT, i++, &((*ppEvents)[j]), 0, hdr)) {
					free(*ppEvents);
					*ppEvents = NULL;
					result = TSPERR(TSS_E_INTERNAL_ERROR);
					goto done;
				}
			}
		} else {
			*ppEvents = NULL;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_RegisterKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_UUID WrappingKeyUUID,	/* in */
			       TSS_UUID KeyUUID,	/* in */
			       UINT32 cKeySize,	/* in */
			       BYTE * rgbKey,	/* in */
			       UINT32 cVendorData,	/* in */
			       BYTE * gbVendorData	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_REGISTERKEY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &WrappingKeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 2, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &cKeySize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, rgbKey, cKeySize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 5, &cVendorData, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 6, gbVendorData, cVendorData, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_UnregisterKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TSS_UUID KeyUUID	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_UNREGISTERKEY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCS_EnumRegisteredKeys_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				      TSS_UUID * pKeyUUID,	/* in */
				      UINT32 * pcKeyHierarchySize,	/* out */
				      TSS_KM_KEYINFO ** ppKeyHierarchy	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	//TSS_UUID uuid;
	struct tcsd_packet_hdr *hdr;
	int i, j;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_ENUMREGISTEREDKEYS;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

#if 0
	if (pKeyUUID == NULL) {
		if (setData(TCSD_PACKET_TYPE_UUID, 1, &uuid, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	} else {
		if (setData(TCSD_PACKET_TYPE_UUID, 1, pKeyUUID, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}
#else
	if (pKeyUUID != NULL) {
		if (setData(TCSD_PACKET_TYPE_UUID, 1, pKeyUUID, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}
#endif

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcKeyHierarchySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*ppKeyHierarchy = malloc(*pcKeyHierarchySize * sizeof(TSS_KM_KEYINFO));
		if (*ppKeyHierarchy == NULL) {
			LogError("malloc of %u bytes failed.", *pcKeyHierarchySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		for (j = 0; (UINT32)j < *pcKeyHierarchySize; j++) {
			if (getData( TCSD_PACKET_TYPE_KM_KEYINFO, i++, &((*ppKeyHierarchy)[j]), 0, hdr)) {
				free(*ppKeyHierarchy);
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_GetRegisteredKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TSS_UUID KeyUUID,	/* in */
				    TSS_KM_KEYINFO ** ppKeyInfo	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCS_GetRegisteredKeyBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TSS_UUID KeyUUID,	/* in */
					UINT32 * pcKeySize,	/* out */
					BYTE ** prgbKey	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETREGISTEREDKEYBLOB;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pcKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*prgbKey = malloc(*pcKeySize);
		if (*prgbKey == NULL) {
			LogError("malloc of %u bytes failed.", *pcKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *prgbKey, *pcKeySize, hdr)) {
			free(*prgbKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;

}

TSS_RESULT
TCSP_LoadKeyByBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE hUnwrappingKey,	/* in */
				  UINT32 cWrappedKeyBlobSize,	/* in */
				  BYTE * rgbWrappedKeyBlob,	/* in */
				  TPM_AUTH * pAuth,	/* in, out */
				  TCS_KEY_HANDLE * phKeyTCSI,	/* out */
				  TCS_KEY_HANDLE * phKeyHMAC	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_LOADKEYBYBLOB;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &hUnwrappingKey, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &cWrappedKeyBlobSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, rgbWrappedKeyBlob, cWrappedKeyBlobSize, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	if (pAuth != NULL)
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, pAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (pAuth != NULL) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, pAuth, 0, hdr))
				result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, phKeyTCSI, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, phKeyHMAC, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_LoadKeyByUUID_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TSS_UUID KeyUUID,	/* in */
				  TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in, out */
				  TCS_KEY_HANDLE * phKeyTCSI	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TCS_LOADKEY_INFO tmpInfo;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_LOADKEYBYUUID;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UUID, 1, &KeyUUID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (pLoadKeyInfo != NULL)
		if (setData(TCSD_PACKET_TYPE_LOADKEY_INFO, 2, pLoadKeyInfo, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, phKeyTCSI, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);

		if (getData(TCSD_PACKET_TYPE_LOADKEY_INFO, 1, &tmpInfo, 0, hdr)) {
			pLoadKeyInfo = NULL;
		} else {
			memcpy(pLoadKeyInfo, &tmpInfo, sizeof(TCS_LOADKEY_INFO));
		}
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_EvictKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			     TCS_KEY_HANDLE hKey	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_EVICTKEY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_CreateWrapKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE hWrappingKey,	/* in */
				  TCPA_ENCAUTH KeyUsageAuth,	/* in */
				  TCPA_ENCAUTH KeyMigrationAuth,	/* in */
				  UINT32 keyInfoSize,	/* in */
				  BYTE * keyInfo,	/* in */
				  UINT32 * keyDataSize,	/* out */
				  BYTE ** keyData,	/* out */
				  TPM_AUTH * pAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CREATEWRAPKEY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &hWrappingKey, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 2, &KeyUsageAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 3, &KeyMigrationAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 4, &keyInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 5, keyInfo, keyInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 6, pAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, keyDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*keyData = (BYTE *) malloc(*keyDataSize);
		if (*keyData == NULL) {
			LogError("malloc of %u bytes failed.", *keyDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *keyData, *keyDataSize, hdr)) {
			free(*keyData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, 2, pAuth, 0, hdr)) {
			free(*keyData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetPubKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCS_KEY_HANDLE hKey,	/* in */
			      TPM_AUTH * pAuth,	/* in, out */
			      UINT32 * pcPubKeySize,	/* out */
			      BYTE ** prgbPubKey	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETPUBKEY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &hKey, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (pAuth != NULL)
		if (setData(TCSD_PACKET_TYPE_AUTH, 2, pAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	i = 0;
	if (result == TSS_SUCCESS) {
		if (pAuth != NULL) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, pAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcPubKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbPubKey = (BYTE *) malloc(*pcPubKeySize);
		if (*prgbPubKey == NULL) {
			LogError("malloc of %u bytes failed.", *pcPubKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbPubKey, *pcPubKeySize, hdr)) {
			free(*prgbPubKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_MakeIdentity_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_ENCAUTH identityAuth,	/* in */
				 TCPA_CHOSENID_HASH IDLabel_PrivCAHash,	/* in */
				 UINT32 idKeyInfoSize,	/* in */
				 BYTE * idKeyInfo,	/* in */
				 TPM_AUTH * pSrkAuth,	/* in, out */
				 TPM_AUTH * pOwnerAuth,	/* in, out */
				 UINT32 * idKeySize,	/* out */
				 BYTE ** idKey,	/* out */
				 UINT32 * pcIdentityBindingSize,	/* out */
				 BYTE ** prgbIdentityBinding,	/* out */
				 UINT32 * pcEndorsementCredentialSize,	/* out */
				 BYTE ** prgbEndorsementCredential,	/* out */
				 UINT32 * pcPlatformCredentialSize,	/* out */
				 BYTE ** prgbPlatformCredential,	/* out */
				 UINT32 * pcConformanceCredentialSize,	/* out */
				 BYTE ** prgbConformanceCredential	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_MAKEIDENTITY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 1, &identityAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &IDLabel_PrivCAHash, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &idKeyInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, idKeyInfo, idKeyInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	i = 5;
	if (pSrkAuth)
		if (setData(TCSD_PACKET_TYPE_AUTH, i++, pSrkAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	i = 0;
	if (result == TSS_SUCCESS) {
		i = 0;
		if (pSrkAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, pSrkAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, idKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*idKey = (BYTE *) malloc(*idKeySize);
		if (*idKey == NULL) {
			LogError("malloc of %u bytes failed.", *idKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *idKey, *idKeySize, hdr)) {
			free(*idKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcIdentityBindingSize, 0, hdr)) {
			free(*idKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbIdentityBinding = (BYTE *) malloc(*pcIdentityBindingSize);
		if (*prgbIdentityBinding == NULL) {
			LogError("malloc of %u bytes failed.", *pcIdentityBindingSize);
			free(*idKey);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbIdentityBinding, *pcIdentityBindingSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcEndorsementCredentialSize, 0, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbEndorsementCredential = (BYTE *) malloc(*pcEndorsementCredentialSize);
		if (*prgbEndorsementCredential == NULL) {
			LogError("malloc of %u bytes failed.", *pcEndorsementCredentialSize);
			free(*idKey);
			free(*prgbIdentityBinding);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbEndorsementCredential, *pcEndorsementCredentialSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcPlatformCredentialSize, 0, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbPlatformCredential = (BYTE *) malloc(*pcPlatformCredentialSize);
		if (*prgbPlatformCredential == NULL) {
			LogError("malloc of %u bytes failed.", *pcPlatformCredentialSize);
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbPlatformCredential, *pcPlatformCredentialSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcConformanceCredentialSize, 0, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*prgbConformanceCredential = (BYTE *) malloc(*pcConformanceCredentialSize);
		if (*prgbConformanceCredential == NULL) {
			LogError("malloc of %u bytes failed.", *pcConformanceCredentialSize);
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *prgbConformanceCredential, *pcConformanceCredentialSize, hdr)) {
			free(*idKey);
			free(*prgbIdentityBinding);
			free(*prgbEndorsementCredential);
			free(*prgbPlatformCredential);
			free(*prgbConformanceCredential);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_SetOwnerInstall_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TSS_BOOL state	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_SETOWNERINSTALL;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_TakeOwnership_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  UINT16 protocolID,	/* in */
				  UINT32 encOwnerAuthSize,	/* in */
				  BYTE * encOwnerAuth,	/* in */
				  UINT32 encSrkAuthSize,	/* in */
				  BYTE * encSrkAuth,	/* in */
				  UINT32 srkInfoSize,	/* in */
				  BYTE * srkInfo,	/* in */
				  TPM_AUTH * ownerAuth,	/* in, out */
				  UINT32 * srkKeySize, BYTE ** srkKey) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_TAKEOWNERSHIP;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &encOwnerAuthSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, encOwnerAuth, encOwnerAuthSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 4, &encSrkAuthSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 5, encSrkAuth, encSrkAuthSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 6, &srkInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 7, srkInfo, srkInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 8, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, 1, srkKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*srkKey = (BYTE *) malloc(*srkKeySize);
		if (*srkKey == NULL) {
			LogError("malloc of %u bytes failed.", *srkKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 2, *srkKey, *srkKeySize, hdr)) {
			free(*srkKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_OIAP_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCS_AUTHHANDLE * authHandle,	/* out */
			 TCPA_NONCE * nonce0	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OIAP;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, authHandle, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_NONCE, 1, nonce0, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_OSAP_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_ENTITY_TYPE entityType,	/* in */
			 UINT32 entityValue,	/* in */
			 TCPA_NONCE nonceOddOSAP,	/* in */
			 TCS_AUTHHANDLE * authHandle,	/* out */
			 TCPA_NONCE * nonceEven,	/* out */
			 TCPA_NONCE * nonceEvenOSAP	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OSAP;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &entityType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &entityValue, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 3, &nonceOddOSAP, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, authHandle, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_NONCE, 1, nonceEven, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_NONCE, 2, nonceEvenOSAP, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ChangeAuth_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE contextHandle,	/* in */
			       TCS_KEY_HANDLE parentHandle,	/* in */
			       TCPA_PROTOCOL_ID protocolID,	/* in */
			       TCPA_ENCAUTH newAuth,	/* in */
			       TCPA_ENTITY_TYPE entityType,	/* in */
			       UINT32 encDataSize,	/* in */
			       BYTE * encData,	/* in */
			       TPM_AUTH * ownerAuth,	/* in, out */
			       TPM_AUTH * entityAuth,	/* in, out */
			       UINT32 * outDataSize,	/* out */
			       BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CHANGEAUTH;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &contextHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 2, &protocolID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 3, &newAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 4, &entityType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 5, &encDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 6, encData, encDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 7, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 8, entityAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_AUTH, 1, entityAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, 2, outDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = (BYTE *) malloc(*outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, *outData, *outDataSize, hdr)) {
			free(*outData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthOwner_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCPA_PROTOCOL_ID protocolID,	/* in */
				    TCPA_ENCAUTH newAuth,	/* in */
				    TCPA_ENTITY_TYPE entityType,	/* in */
				    TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CHANGEAUTHOWNER;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &protocolID, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 2, &newAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 3, &entityType, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 4, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (hdr->result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthAsymStart_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE idHandle,	/* in */
					TCPA_NONCE antiReplay,	/* in */
					UINT32 KeySizeIn,	/* in */
					BYTE * KeyDataIn,	/* in */
					TPM_AUTH * pAuth,	/* in, out */
					UINT32 * KeySizeOut,	/* out */
					BYTE ** KeyDataOut,	/* out */
					UINT32 * CertifyInfoSize,	/* out */
					BYTE ** CertifyInfo,	/* out */
					UINT32 * sigSize,	/* out */
					BYTE ** sig,	/* out */
					TCS_KEY_HANDLE * ephHandle	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_ChangeAuthAsymFinish_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCS_KEY_HANDLE parentHandle,	/* in */
					 TCS_KEY_HANDLE ephHandle,	/* in */
					 TCPA_ENTITY_TYPE entityType,	/* in */
					 TCPA_HMAC newAuthLink,	/* in */
					 UINT32 newAuthSize,	/* in */
					 BYTE * encNewAuth,	/* in */
					 UINT32 encDataSizeIn,	/* in */
					 BYTE * encDataIn,	/* in */
					 TPM_AUTH * ownerAuth,	/* in, out */
					 UINT32 * encDataSizeOut,	/* out */
					 BYTE ** encDataOut,	/* out */
					 TCPA_SALT_NONCE * saltNonce,	/* out */
					 TCPA_DIGEST * changeProof	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_TerminateHandle_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCS_AUTHHANDLE handle	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_TERMINATEHANDLE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &handle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ActivateTPMIdentity_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE idKey,	/* in */
					UINT32 blobSize,	/* in */
					BYTE * blob,	/* in */
					TPM_AUTH * idKeyAuth,	/* in, out */
					TPM_AUTH * ownerAuth,	/* in, out */
					UINT32 * SymmetricKeySize,	/* out */
					BYTE ** SymmetricKey	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_Extend_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_PCRINDEX pcrNum,	/* in */
			   TCPA_DIGEST inDigest,	/* in */
			   TCPA_PCRVALUE * outDigest	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_EXTEND;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &pcrNum, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &inDigest, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_DIGEST, 0, outDigest, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_PcrRead_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCPA_PCRINDEX pcrNum,	/* in */
			    TCPA_PCRVALUE * outDigest	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_PCRREAD;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &pcrNum, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_DIGEST, 0, outDigest, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_Quote_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			  TCS_KEY_HANDLE keyHandle,	/* in */
			  TCPA_NONCE antiReplay,	/* in */
			  UINT32 pcrDataSizeIn,	/* in */
			  BYTE * pcrDataIn,	/* in */
			  TPM_AUTH * privAuth,	/* in, out */
			  UINT32 * pcrDataSizeOut,	/* out */
			  BYTE ** pcrDataOut,	/* out */
			  UINT32 * sigSize,	/* out */
			  BYTE ** sig	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_QUOTE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &pcrDataSizeIn, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, pcrDataIn, pcrDataSizeIn, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (privAuth)
		if (setData(TCSD_PACKET_TYPE_AUTH, 5, privAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (privAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, privAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, pcrDataSizeOut, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*pcrDataOut = (BYTE *) malloc(*pcrDataSizeOut);
		if (*pcrDataOut == NULL) {
			LogError("malloc of %u bytes failed.", *pcrDataSizeOut);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *pcrDataOut, *pcrDataSizeOut, hdr)) {
			free(*pcrDataOut);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, sigSize, 0, hdr)) {
			free(*pcrDataOut);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*sig = (BYTE *) malloc(*sigSize);
		if (*sig == NULL) {
			LogError("malloc of %u bytes failed.", *sigSize);
			free(*pcrDataOut);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *sig, *sigSize, hdr)) {
			free(*pcrDataOut);
			free(*sig);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_DirWriteAuth_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_DIRINDEX dirIndex,	/* in */
				 TCPA_DIRVALUE newContents,	/* in */
				 TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_DIRWRITEAUTH;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &dirIndex, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_DIGEST, 2, &newContents, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 3, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_DirRead_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCPA_DIRINDEX dirIndex,	/* in */
			    TCPA_DIRVALUE * dirValue	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_DIRREAD;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &dirIndex, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (hdr->result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_DIGEST, 0, dirValue, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_Seal_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCS_KEY_HANDLE keyHandle,	/* in */
			 TCPA_ENCAUTH encAuth,	/* in */
			 UINT32 pcrInfoSize,	/* in */
			 BYTE * PcrInfo,	/* in */
			 UINT32 inDataSize,	/* in */
			 BYTE * inData,	/* in */
			 TPM_AUTH * pubAuth,	/* in, out */
			 UINT32 * SealedDataSize,	/* out */
			 BYTE ** SealedData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TPM_AUTH emptyAuth, tmpAuth;

	memset(&data, 0, sizeof(struct tsp_packet));
	memset(&emptyAuth, 0, sizeof(TPM_AUTH));

	data.ordinal = TCSD_ORD_SEAL;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_ENCAUTH, 2, &encAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 3, &pcrInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 4, PcrInfo, pcrInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 5, &inDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 6, inData, inDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (pubAuth == NULL) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 7, &emptyAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	} else {
		if (setData(TCSD_PACKET_TYPE_AUTH, 7, pubAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (hdr->result == TSS_SUCCESS) {
		if (pubAuth != NULL) {
			if (getData(TCSD_PACKET_TYPE_AUTH, 0, pubAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		} else {
			if (getData(TCSD_PACKET_TYPE_AUTH, 0, &tmpAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}

		if (getData(TCSD_PACKET_TYPE_UINT32, 1, SealedDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*SealedData = (BYTE *) malloc(*SealedDataSize);
		if (*SealedData == NULL) {
			LogError("malloc of %u bytes failed.", *SealedDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 2, *SealedData, *SealedDataSize, hdr)) {
			free(*SealedData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_Unseal_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCS_KEY_HANDLE parentHandle,	/* in */
			   UINT32 SealedDataSize,	/* in */
			   BYTE * SealedData,	/* in */
			   TPM_AUTH * parentAuth,	/* in, out */
			   TPM_AUTH * dataAuth,	/* in, out */
			   UINT32 * DataSize,	/* out */
			   BYTE ** Data	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TPM_AUTH emptyAuth;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));
	memset(&emptyAuth, 0, sizeof(TPM_AUTH));

	data.ordinal = TCSD_ORD_UNSEAL;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &parentHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &SealedDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, SealedData, SealedDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (parentAuth == NULL) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, &emptyAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	} else {
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, parentAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if (setData(TCSD_PACKET_TYPE_AUTH, 5, dataAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (parentAuth == NULL) {
			if (getData(TCSD_PACKET_TYPE_AUTH, 0, &emptyAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		} else {
			if (getData(TCSD_PACKET_TYPE_AUTH, 0, parentAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}

		if (getData(TCSD_PACKET_TYPE_AUTH, 1, dataAuth, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		if (getData(TCSD_PACKET_TYPE_UINT32, 2, DataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*Data = (BYTE *) calloc_tspi(tspContext, *DataSize);
		if (*Data == NULL) {
			LogError("malloc of %u bytes failed.", *DataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 3, *Data, *DataSize, hdr)) {
			free_tspi(tspContext, *Data);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_UnBind_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCS_KEY_HANDLE keyHandle,	/* in */
			   UINT32 inDataSize,	/* in */
			   BYTE * inData,	/* in */
			   TPM_AUTH * privAuth,	/* in, out */
			   UINT32 * outDataSize,	/* out */
			   BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_UNBIND;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &inDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, inData, inDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (privAuth != NULL)
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, privAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (privAuth != NULL) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, privAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, outDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = (BYTE *) calloc_tspi(tspContext, *outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *outData, *outDataSize, hdr)) {
			free_tspi(tspContext, *outData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_CreateMigrationBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE parentHandle,	/* in */
					TCPA_MIGRATE_SCHEME migrationType,	/* in */
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
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_ConvertMigrationBlob_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCS_KEY_HANDLE parentHandle,	/* in */
					 UINT32 inDataSize,	/* in */
					 BYTE * inData,	/* in */
					 TPM_AUTH * parentAuth,	/* in, out */
					 UINT32 randomSize,	/*  should be in */
					 BYTE * random,	/*  should be in */
					 UINT32 * outDataSize,	/* out */
					 BYTE ** outData	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_AuthorizeMigrationKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
					  UINT32 MigrationKeySize,	/* in */
					  BYTE * MigrationKey,	/* in */
					  TPM_AUTH * ownerAuth,	/* in, out */
					  UINT32 * MigrationKeyAuthSize,	/* out */
					  BYTE ** MigrationKeyAuth	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_CertifyKey_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCS_KEY_HANDLE certHandle,	/* in */
			       TCS_KEY_HANDLE keyHandle,	/* in */
			       TCPA_NONCE antiReplay,	/* in */
			       TPM_AUTH * certAuth,	/* in, out */
			       TPM_AUTH * keyAuth,	/* in, out */
			       UINT32 * CertifyInfoSize,	/* out */
			       BYTE ** CertifyInfo,	/* out */
			       UINT32 * outDataSize,	/* out */
			       BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;
	TPM_AUTH null_auth;
	int i;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));
	memset(&null_auth, 0, sizeof(TPM_AUTH));

	data.ordinal = TCSD_ORD_CERTIFYKEY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &certHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 3, &antiReplay, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (certAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, certAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	} else {
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, &null_auth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	if (keyAuth) {
		if (setData(TCSD_PACKET_TYPE_AUTH, 5, keyAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	} else {
		if (setData(TCSD_PACKET_TYPE_AUTH, 5, &null_auth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (certAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, certAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (keyAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, keyAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, CertifyInfoSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*CertifyInfo = (BYTE *) malloc(*CertifyInfoSize);
		if (*CertifyInfo == NULL) {
			LogError("malloc of %u bytes failed.", *CertifyInfoSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *CertifyInfo, *CertifyInfoSize, hdr)) {
			free(*CertifyInfo);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, outDataSize, 0, hdr)) {
			free(*CertifyInfo);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = (BYTE *) malloc(*outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			free(*CertifyInfo);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *outData, *outDataSize, hdr)) {
			free(*CertifyInfo);
			free(*outData);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_Sign_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCS_KEY_HANDLE keyHandle,	/* in */
			 UINT32 areaToSignSize,	/* in */
			 BYTE * areaToSign,	/* in */
			 TPM_AUTH * privAuth,	/* in, out */
			 UINT32 * sigSize,	/* out */
			 BYTE ** sig	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	int i;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_SIGN;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &areaToSignSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, areaToSign, areaToSignSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (privAuth)
		if (setData(TCSD_PACKET_TYPE_AUTH, 4, privAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (privAuth) {
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, privAuth, 0, hdr)) {
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, sigSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*sig = (BYTE *) malloc(*sigSize);
		if (*sig == NULL) {
			LogError("malloc of %u bytes failed.", *sigSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *sig, *sigSize, hdr)) {
			free(*sig);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetRandom_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			      UINT32 bytesRequested,	/* in */
			      BYTE ** randomBytes	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETRANDOM;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &bytesRequested, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, &bytesRequested, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*randomBytes = (BYTE *) calloc_tspi(tspContext, bytesRequested);
		if (*randomBytes == NULL) {
			LogError("malloc of %u bytes failed.", bytesRequested);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *randomBytes, bytesRequested, hdr)) {
			free_tspi(tspContext, *randomBytes);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_StirRandom_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT32 inDataSize,	/* in */
			       BYTE * inData	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_STIRRANDOM;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &inDataSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 2, inData, inDataSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetCapability_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCPA_CAPABILITY_AREA capArea,	/* in */
				  UINT32 subCapSize,	/* in */
				  BYTE * subCap,	/* in */
				  UINT32 * respSize,	/* out */
				  BYTE ** resp	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETCAPABILITY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, respSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*resp = (BYTE *) malloc(*respSize);
		if (*resp == NULL) {
			LogError("malloc of %u bytes failed.", *respSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *resp, *respSize, hdr)) {
			free(*resp);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCS_GetCapability_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_CAPABILITY_AREA capArea,	/* in */
				 UINT32 subCapSize,	/* in */
				 BYTE * subCap,	/* in */
				 UINT32 * respSize,	/* out */
				 BYTE ** resp	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_TCSGETCAPABILITY;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &capArea, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &subCapSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, subCap, subCapSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, respSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*resp = (BYTE *) calloc_tspi(tspContext, *respSize);
		if (*resp == NULL) {
			LogError("malloc of %u bytes failed.", *respSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *resp, *respSize, hdr)) {
			free_tspi(tspContext, *resp);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetCapabilitySigned_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_KEY_HANDLE keyHandle,	/* in */
					TCPA_NONCE antiReplay,	/* in */
					TCPA_CAPABILITY_AREA capArea,	/* in */
					UINT32 subCapSize,	/* in */
					BYTE * subCap,	/* in */
					TPM_AUTH * privAuth,	/* in, out */
					TCPA_VERSION * Version,	/* out */
					UINT32 * respSize,	/* out */
					BYTE ** resp,	/* out */
					UINT32 * sigSize,	/* out */
					BYTE ** sig	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_GetCapabilityOwner_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				       TPM_AUTH * pOwnerAuth,	/* out */
				       TCPA_VERSION * pVersion,	/* out */
				       UINT32 * pNonVolatileFlags,	/* out */
				       UINT32 * pVolatileFlags	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETCAPABILITYOWNER;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 1, pOwnerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_VERSION, 0, pVersion, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_UINT32, 1, pNonVolatileFlags, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_UINT32, 2, pVolatileFlags, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		if (getData(TCSD_PACKET_TYPE_AUTH, 3, pOwnerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_CreateEndorsementKeyPair_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					     TCPA_NONCE antiReplay,	/* in */
					     UINT32 endorsementKeyInfoSize,	/* in */
					     BYTE * endorsementKeyInfo,	/* in */
					     UINT32 * endorsementKeySize,	/* out */
					     BYTE ** endorsementKey,	/* out */
					     TCPA_DIGEST * checksum	/* out */
    ) {

	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CREATEENDORSEMENTKEYPAIR;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 2, &endorsementKeyInfoSize, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_PBYTE, 3, endorsementKeyInfo, endorsementKeyInfoSize, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, endorsementKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*endorsementKey = (BYTE *) malloc(*endorsementKeySize);
		if (*endorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *endorsementKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *endorsementKey, *endorsementKeySize, hdr)) {
			free(*endorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &(checksum->digest), 0, hdr)) {
			free(*endorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_ReadPubek_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_NONCE antiReplay,	/* in */
			      UINT32 * pubEndorsementKeySize,	/* out */
			      BYTE ** pubEndorsementKey,	/* out */
			      TCPA_DIGEST * checksum	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_READPUBEK;
	/*      data.numParms = 2; */

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 1, &antiReplay, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, pubEndorsementKeySize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*pubEndorsementKey = (BYTE *) malloc(*pubEndorsementKeySize);
		if (*pubEndorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *pubEndorsementKeySize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *pubEndorsementKey, *pubEndorsementKeySize, hdr)) {
			free(*pubEndorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &(checksum->digest), 0, hdr)) {
			free(*pubEndorsementKey);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}
done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_DisablePubekRead_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				     TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_DISABLEPUBEKREAD;

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

	if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte, 0, &data, &hdr);

        if (result == TSS_SUCCESS) 
                result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_OwnerReadPubek_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				   TPM_AUTH * ownerAuth,	/* in, out */
				   UINT32 * pubEndorsementKeySize,	/* out */
				   BYTE ** pubEndorsementKey	/* out */
    ) {

        TSS_RESULT result;
        struct tsp_packet data;
        struct tcsd_packet_hdr *hdr;

        memset(&data, 0, sizeof(struct tsp_packet));

        data.ordinal = TCSD_ORD_OWNERREADPUBEK;

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);
        if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte, 0, &data, &hdr);

        if (result == TSS_SUCCESS)
                result = hdr->result;

        if (result == TSS_SUCCESS) {
                if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr)){
			free(*pubEndorsementKey);
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
		}

                if (getData(TCSD_PACKET_TYPE_UINT32, 1, pubEndorsementKeySize, 0, hdr)) {
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
                        goto done;
                }

                *pubEndorsementKey = (BYTE *) malloc(*pubEndorsementKeySize);
                if (*pubEndorsementKey == NULL) {
                        LogError("malloc of %u bytes failed.", *pubEndorsementKeySize);
                        result = TSPERR(TSS_E_OUTOFMEMORY);
                        goto done;
                }

                if (getData(TCSD_PACKET_TYPE_PBYTE, 2, *pubEndorsementKey, *pubEndorsementKeySize, hdr)) {
                        free(*pubEndorsementKey);
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
                }
        }

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_SelfTestFull_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_SELFTESTFULL;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_CertifySelfTest_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCS_KEY_HANDLE keyHandle,	/* in */
				    TCPA_NONCE antiReplay,	/* in */
				    TPM_AUTH * privAuth,	/* in, out */
				    UINT32 * sigSize,	/* out */
				    BYTE ** sig	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	int i;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_CERTIFYSELFTEST;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT32, 1, &keyHandle, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_NONCE, 2, &antiReplay, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (privAuth)
		if (setData(TCSD_PACKET_TYPE_AUTH, 3, privAuth, 0, &data))
			return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		i = 0;
		if (privAuth)
			if (getData(TCSD_PACKET_TYPE_AUTH, i++, privAuth, 0, hdr)) {
				LogDebug1("privAuth");
				result = TSPERR(TSS_E_INTERNAL_ERROR);
				goto done;
			}
		if (getData(TCSD_PACKET_TYPE_UINT32, i++, sigSize, 0, hdr)) {
			LogDebug1("sigSize");
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}
		*sig = (BYTE *) malloc(*sigSize);
		if (*sig == NULL) {
			LogError("malloc of %u bytes failed.", *sigSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (getData(TCSD_PACKET_TYPE_PBYTE, i++, *sig, *sigSize, hdr)) {
			LogDebug1("sig");
			free(*sig);
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_GetTestResult_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				  UINT32 * outDataSize,	/* out */
				  BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(hContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_GETTESTRESULT;

	LogDebug1("TCSP_GetTestResult_TP");
	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		LogDebug1("sendTCSDPacket succeeded");
		if (getData(TCSD_PACKET_TYPE_UINT32, 0, outDataSize, 0, hdr)) {
			result = TSPERR(TSS_E_INTERNAL_ERROR);
			goto done;
		}

		*outData = calloc_tspi(tspContext, *outDataSize);
		if (*outData == NULL) {
			LogError("malloc of %u bytes failed.", *outDataSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}

		if (getData(TCSD_PACKET_TYPE_PBYTE, 1, *outData, *outDataSize, hdr)) {
			free_tspi(tspContext, *outData);
			*outData = NULL;
			result = TSPERR(TSS_E_INTERNAL_ERROR);
		}
	}
	LogDebug1("TCSP_GetTestResult_TP exit");

done:
	free(hdr);
	return result;
}

TSS_RESULT
TCSP_OwnerClear_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
			       TPM_AUTH * ownerAuth	/* in, out */
    ) {
        TSS_RESULT result;
        struct tsp_packet data;
        struct tcsd_packet_hdr *hdr;

        memset(&data, 0, sizeof(struct tsp_packet));

        data.ordinal = TCSD_ORD_OWNERCLEAR;

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte, 0, &data, &hdr);

        if (result == TSS_SUCCESS)
                result = hdr->result;

        if (result == TSS_SUCCESS ){
                if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
        }

        free(hdr);
        return result;
}

TSS_RESULT
TCSP_DisableOwnerClear_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				      TPM_AUTH * ownerAuth	/* in, out */
    ) {
        TSS_RESULT result;
        struct tsp_packet data;
        struct tcsd_packet_hdr *hdr;

        memset(&data, 0, sizeof(struct tsp_packet));

        data.ordinal = TCSD_ORD_DISABLEOWNERCLEAR;

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        if (setData(TCSD_PACKET_TYPE_AUTH, 1, ownerAuth, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte, 0, &data, &hdr);

        if (result == TSS_SUCCESS)
                result = hdr->result;

        if (result == TSS_SUCCESS ){
                if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
                        result = TSPERR(TSS_E_INTERNAL_ERROR);
        }

        free(hdr);
        return result;
}

TSS_RESULT
TCSP_ForceClear_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_FORCECLEAR;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_DisableForceClear_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
        TSS_RESULT result;
        struct tsp_packet data;
        struct tcsd_packet_hdr *hdr;

        memset(&data, 0, sizeof(struct tsp_packet));

        data.ordinal = TCSD_ORD_DISABLEFORCECLEAR;

        if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        result = sendTCSDPacket(hte, 0, &data, &hdr);

        if (result == TSS_SUCCESS)
                result = hdr->result;

        free(hdr);
        return result;
}

TSS_RESULT
TCSP_PhysicalDisable_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_PHYSICALDISABLE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_PhysicalEnable_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_PHYSICALENABLE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_OwnerSetDisable_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,   /*  in */
			TSS_BOOL disableState,     /*  in */
			TPM_AUTH * ownerAuth   /*  in, out */
) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_OWNERSETDISABLE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BOOL, 1, &disableState, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_AUTH, 2, ownerAuth, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	if (result == TSS_SUCCESS) {
		if (getData(TCSD_PACKET_TYPE_AUTH, 0, ownerAuth, 0, hdr))
			result = TSPERR(TSS_E_INTERNAL_ERROR);
	}

	free(hdr);
	return result;
}


TSS_RESULT
TCSP_PhysicalSetDeactivated_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					   TSS_BOOL state	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_PHYSICALSETDEACTIVATED;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_PhysicalPresence_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				TCPA_PHYSICAL_PRESENCE fPhysicalPresence	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_PHYSICALPRESENCE;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	if (setData(TCSD_PACKET_TYPE_UINT16, 1, &fPhysicalPresence, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_SetTempDeactivated_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct tsp_packet data;
	struct tcsd_packet_hdr *hdr;

	memset(&data, 0, sizeof(struct tsp_packet));

	data.ordinal = TCSD_ORD_SETTEMPDEACTIVATED;

	if (setData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, &data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	result = sendTCSDPacket(hte, 0, &data, &hdr);

	if (result == TSS_SUCCESS)
		result = hdr->result;

	free(hdr);
	return result;
}

TSS_RESULT
TCSP_FieldUpgrade_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				 UINT32 dataInSize,	/* in */
				 BYTE * dataIn,	/* in */
				 UINT32 * dataOutSize,	/* out */
				 BYTE ** dataOut,	/* out */
				 TPM_AUTH * ownerAuth	/* in, out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}

TSS_RESULT
TCSP_SetRedirection_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE keyHandle,	/* in */
				   UINT32 c1,	/* in */
				   UINT32 c2,	/* in */
				   TPM_AUTH * privAuth	/* in, out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);

}

TSS_RESULT
TCSP_CreateMaintenanceArchive_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					     TSS_BOOL generateRandom,	/* in */
					     TPM_AUTH * ownerAuth,	/* in, out */
					     UINT32 * randomSize,	/* out */
					     BYTE ** random,	/* out */
					     UINT32 * archiveSize,	/* out */
					     BYTE ** archive	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);

}

TSS_RESULT
TCSP_LoadMaintenanceArchive_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					   UINT32 dataInSize,	/* in */
					   BYTE * dataIn,	/* in */
					   UINT32 * dataOutSize,	/* out */
					   BYTE ** dataOut,	/* out */
					   TPM_AUTH * ownerAuth	/* in, out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);

}

TSS_RESULT
TCSP_KillMaintenanceFeature_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
					   TPM_AUTH * ownerAuth	/* in , out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);

}

TSS_RESULT
TCSP_LoadManuMaintPub_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCPA_NONCE antiReplay,	/* in */
				     UINT32 PubKeySize,	/* in */
				     BYTE * PubKey,	/* in */
				     TCPA_DIGEST * checksum	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);

}

TSS_RESULT
TCSP_ReadManuMaintPub_TP(struct host_table_entry *hte, TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCPA_NONCE antiReplay,	/* in */
				     TCPA_DIGEST * checksum	/* out */
    ) {
	return TSPERR(TSS_E_NOTIMPL);
}
