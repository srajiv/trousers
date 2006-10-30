
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>

//#include "tcs_internal_types.h"
//#include "tcs_tsp.h"
//#include "tcs_utils.h"
//#include "tcs_int_literals.h"
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


int
setData(BYTE dataType, int index, void *theData, int theDataSize, struct tsp_packet *packet)
{
	UINT64 offset;
	if (index == 0) {
		packet->dataSize = 0;
		packet->numParms = 0;
		memset(packet->types, 0, sizeof(packet->types));
	}
	offset = packet->dataSize;
	if ((unsigned int)index >= sizeof(packet->types))
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
	case TCSD_PACKET_TYPE_VERSION:
		Trspi_LoadBlob_TCPA_VERSION(&offset, packet->dataBuffer, *((TCPA_VERSION *)theData));
		break;
	case TCSD_PACKET_TYPE_ENCAUTH:
		Trspi_LoadBlob(&offset, 20, packet->dataBuffer, ((TCPA_ENCAUTH *)theData)->authdata);
		break;
#ifdef TSS_BUILD_PS
	case TCSD_PACKET_TYPE_UUID:
		Trspi_LoadBlob_UUID(&offset, packet->dataBuffer, *((TSS_UUID *)theData));
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		LoadBlob_LOADKEY_INFO(&offset, packet->dataBuffer, ((TCS_LOADKEY_INFO *)theData));
		break;
#endif
	case TCSD_PACKET_TYPE_PCR_EVENT:
		Trspi_LoadBlob_PCR_EVENT(&offset, packet->dataBuffer, ((TSS_PCR_EVENT *)theData));
		break;
	default:
		LogError("Unknown TCSD packet type!");
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
	UINT64 offset;
	if (index == 0) {
		hdr->packet_size = sizeof(struct tcsd_packet_hdr) - 1;
	}
	offset = hdr->packet_size;
	if (index >= TCSD_MAX_NUM_PARMS) {
		LogError("Too many elements in TCSD packet!");
		return -1;
	}
	if (index >= hdr->num_parms) {
		LogError("Attempted to get data past the end of the TCSD packet!");
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
	case TCSD_PACKET_TYPE_ENCAUTH:
		Trspi_UnloadBlob(&offset, sizeof(TPM_AUTH), (BYTE *)hdr, ((TCPA_ENCAUTH *)theData)->authdata);
		break;
	case TCSD_PACKET_TYPE_VERSION:
		Trspi_UnloadBlob_TCPA_VERSION(&offset, (BYTE *)hdr, ((TCPA_VERSION *)theData));
		break;
#ifdef TSS_BUILD_PS
	case TCSD_PACKET_TYPE_UUID:
		Trspi_UnloadBlob_UUID(&offset, (BYTE *)hdr, ((TSS_UUID *)theData));
		break;
	case TCSD_PACKET_TYPE_KM_KEYINFO:
		Trspi_UnloadBlob_KM_KEYINFO( &offset,	(BYTE *)hdr, ((TSS_KM_KEYINFO *)theData ) );
		break;
	case TCSD_PACKET_TYPE_LOADKEY_INFO:
		UnloadBlob_LOADKEY_INFO(&offset, (BYTE *)hdr, ((TCS_LOADKEY_INFO *)theData));
		break;
#endif
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
	UINT64 offset = 0;
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
			LogError("Failed to send packet");
			return rc;
		}
	} else {
		if ((rc = sendit(hte, transmitBuffer, offset, hdr))) {
			LogError("Failed to send packet");
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

	if (tmp_hdr->result == 0 ||
	    (dataToSend->ordinal == TCSD_ORD_LOADKEYBYUUID &&
	     tmp_hdr->result == TCSERR(TCS_E_KM_LOADFAILED))) {
		Trspi_UnloadBlob_UINT32(&offset, &tmp_hdr->packet_size, (BYTE *)(*hdr));
		Trspi_UnloadBlob_UINT16(&offset, &tmp_hdr->num_parms, (BYTE *)(*hdr));
		Trspi_UnloadBlob(&offset, TCSD_MAX_NUM_PARMS, (BYTE *)(*hdr), tmp_hdr->parm_types);
		Trspi_UnloadBlob(&offset, tmp_hdr->packet_size - offset, (BYTE *)(*hdr), &tmp_hdr->data);
	}

	free(*hdr);
	*hdr = tmp_hdr;

	return TSS_SUCCESS;
}

TSS_RESULT
send_init(struct host_table_entry *hte, BYTE *data, int dataLength, struct tcsd_packet_hdr **hdr)
{
	struct tcsd_packet_hdr loc_hdr, *hdr_p;
	int sd, hdr_size = sizeof(struct tcsd_packet_hdr);
	int returnSize;
	TSS_RESULT result;

	struct sockaddr_in addr;
	struct hostent *hEnt = NULL;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		LogError("socket: %s", strerror(errno));
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(get_port());

	LogDebug("Sending TSP packet to host %s.", hte->hostname);

	/* try to resolve by hostname first */
	hEnt = gethostbyname((char *)hte->hostname);
	if (hEnt == NULL) {
		/* if by hostname fails, try by dot notation */
		if (inet_aton((char *)hte->hostname, &addr.sin_addr) == 0) {
			LogError("hostname %s does not resolve to a valid address.",
				 hte->hostname);
			result = TSPERR(TSS_E_CONNECTION_FAILED);
			goto err_exit;
		}
	} else {
		memcpy(&addr.sin_addr, hEnt->h_addr_list[0], 4);
	}

	LogDebug("Connecting to %s", inet_ntoa(addr.sin_addr));

	if (connect(sd, (struct sockaddr *) &addr, sizeof (addr))) {
		LogError("connect: %s", strerror(errno));
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	if (send(sd, data, dataLength, 0) < 0) {
		LogError("send: %s", strerror(errno));
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}
retry1:
	errno = 0;
	if ((returnSize = recv(sd, &loc_hdr, hdr_size - 1, 0)) < 0) {
		if (errno == EINTR)
			goto retry1;
		LogError("recv: %s", strerror(errno));
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	} else if (returnSize == 0) {
		LogError("recv: No bytes returned from the TCSD.");
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	} else if ((UINT32)returnSize < (2 * sizeof(UINT32))) {
		LogError("TCSD returned too few bytes to report its packet size! (%d bytes)",
				returnSize);
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	} else {
		if (Decode_UINT32((BYTE *)&loc_hdr.result) == TSS_SUCCESS)
			returnSize = Decode_UINT32((BYTE *)&loc_hdr.packet_size);
		else
			returnSize = hdr_size;

		if (returnSize > 0) {
			/* malloc space for the body of the packet */
			hdr_p = calloc(1, returnSize);
			if (hdr_p == NULL) {
				LogError("malloc of %d bytes failed", returnSize);
				result = TSPERR(TSS_E_OUTOFMEMORY);
				goto err_exit;
			}

			memcpy(hdr_p, &loc_hdr, returnSize);

			if (returnSize > hdr_size) {
retry2:
				errno = 0;
				if ((returnSize = recv(sd, &hdr_p->data, returnSize - (hdr_size-1),
						       0)) < 0) {
					if (errno == EINTR)
						goto retry2;
					LogError("recv: %s", strerror(errno));
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				} else if (returnSize == 0) {
					LogError("recv: No bytes returned....something went wrong");
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				}
			}
		} else {
			LogError("Packet received from TCSD has an invalid size field.");
			result = TSPERR(TSS_E_COMM_FAILURE);
			goto err_exit;
		}
		/* at this point the entire packet has been received */
	}

	*hdr = hdr_p;
	hte->socket = sd;

	return TSS_SUCCESS;

err_exit:
	close(sd);
	*hdr = NULL;
	return result;
}

/*
 * All the (hdr_size - 1)'s in sendit exist because the structure used for the header
 * has 1 char at the end, used to reference the body of the packet. So a TCSD packet
 * header is actually of size (sizeof(struct tcsd_packet_hdr) - 1).
 */

TSS_RESULT
sendit(struct host_table_entry *hte, BYTE *data, int dataLength, struct tcsd_packet_hdr **hdr)
{
	struct tcsd_packet_hdr loc_hdr, *hdr_p;
	int hdr_size = sizeof(struct tcsd_packet_hdr);
	int returnSize, sent_total = 0, sent = 0, recd_total = 0, recd = 0;
	TSS_RESULT result;

	while (sent_total < dataLength) {
		if ((sent = send(hte->socket, &data[sent_total], (dataLength - sent_total), 0)) < 0) {
			LogError("send: %s", strerror(errno));
			result = TSPERR(TSS_E_COMM_FAILURE);
			goto err_exit;
		}
		sent_total += sent;
	}

	/* keep calling receive until at least 1 header struct has been read in */
	while (recd_total < (hdr_size - 1)) {
retry1:
		errno = 0;
		if ((recd = recv(hte->socket, &(((BYTE *)&loc_hdr)[recd_total]),
						(hdr_size - 1) - recd_total, 0)) < 0) {
			if (errno == EINTR)
				goto retry1;
			LogError("Socket connection error: %s", strerror(errno));
			result = TSPERR(TSS_E_COMM_FAILURE);
			goto err_exit;
		} else if (recd == 0) {
			LogError("Connection closed by the TCSD.");
			result = TSPERR(TSS_E_COMM_FAILURE);
			goto err_exit;
		}
		recd_total += recd;
	}

	/* at this point there has been one header received. Check the return code. If
	 * its success, we'll probably have more data to receive.
	 */
	/* XXX */
	if (Decode_UINT32((BYTE *)&loc_hdr.result) == TSS_SUCCESS ||
	    Decode_UINT32((BYTE *)&loc_hdr.result) == TCSERR(TCS_E_KM_LOADFAILED))
		returnSize = Decode_UINT32((BYTE *)&loc_hdr.packet_size);
	else
		returnSize = hdr_size;

	/* protect against a corrupted packet size value */
	if (returnSize > 0) {
		/* malloc space for the body of the packet */
		hdr_p = calloc(1, returnSize);
		if (hdr_p == NULL) {
			LogError("malloc of %d bytes failed", returnSize);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto err_exit;
		}

		/* copy over the header portion so that once the body is read in, all
		 * the data will be contiguous
		 */
		memcpy(hdr_p, &loc_hdr, hdr_size - 1);

		if (returnSize > (hdr_size - 1)) {
			/* offset is used to address where in the body of the packet we're currently
			 * reading in. recd_total here still has the value (hdr_size - 1) and is
			 * added to as more data comes in. recd_total will increase until it hits
			 * returnSize, which is the amount of data the TCSD has told us its sending.
			 */
			int offset = 0;
			while (recd_total < returnSize) {
retry2:
				errno = 0;
				if ((recd = recv(hte->socket,
						 &(((BYTE *)&hdr_p->data)[offset]),
						 returnSize - (hdr_size-1+offset),
						 0)) < 0) {
					if (errno == EINTR)
						goto retry2;
					LogError("Socket connection error: %s", strerror(errno));
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				} else if (recd == 0) {
					LogError("Connection closed by the TCSD.");
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				}
				recd_total += recd;
				offset += recd;
			}
		}
	} else {
		LogError("Packet received from TCSD has an invalid size field.");
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}
	/* at this point the entire packet has been received */

	*hdr = hdr_p;
	return TSS_SUCCESS;

err_exit:
	*hdr = NULL;
	return result;
}

short
get_port(void)
{
	char *env_port;
	int port = 0;

	env_port = getenv("TSS_TCSD_PORT");

	if (env_port == NULL)
		return TCSD_DEFAULT_PORT;

	port = atoi(env_port);

	if (port == 0 || port > 65535)
		return TCSD_DEFAULT_PORT;

	return (short)port;
}

