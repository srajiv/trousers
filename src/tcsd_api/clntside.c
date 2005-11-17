
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
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

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "tcsd_wrap.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"

short get_port();

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
	hEnt = gethostbyname(hte->hostname);
	if (hEnt == NULL) {
		/* if by hostname fails, try by dot notation */
		if (inet_aton(hte->hostname, &addr.sin_addr) == 0) {
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

	if ((returnSize = recv(sd, &loc_hdr, hdr_size - 1, 0)) < 0) {
		LogError("recv: %s", strerror(errno));
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	} else if (returnSize == 0) {
		LogError1("recv: No bytes returned from the TCSD.");
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

			memcpy(hdr_p, &loc_hdr, hdr_size - 1);

			if (returnSize > hdr_size) {
				if ((returnSize = recv(sd, &hdr_p->data, returnSize - (hdr_size-1), 0)) < 0) {
					LogError("recv: %s", strerror(errno));
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				} else if (returnSize == 0) {
					LogError1("recv: No bytes returned....something went wrong");
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				}
			}
		} else {
			LogError1("Packet received from TCSD has an invalid size field.");
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
		if ((recd = recv(hte->socket, &(((BYTE *)&loc_hdr)[recd_total]),
						(hdr_size - 1) - recd_total, 0)) < 0) {
			LogError("Socket connection error: %s", strerror(errno));
			result = TSPERR(TSS_E_COMM_FAILURE);
			goto err_exit;
		} else if (recd == 0) {
			LogError1("Connection closed by the TCSD.");
			result = TSPERR(TSS_E_COMM_FAILURE);
			goto err_exit;
		}
		recd_total += recd;
	}

	/* at this point there has been one header received. Check the return code. If
	 * its success, we'll probably have more data to receive.
	 */
	if (Decode_UINT32((BYTE *)&loc_hdr.result) == TSS_SUCCESS)
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
				if ((recd = recv(hte->socket,
						 &(((BYTE *)&hdr_p->data)[offset]),
						 returnSize - (hdr_size-1+offset),
						 0)) < 0) {
					LogError("Socket connection error: %s", strerror(errno));
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				} else if (recd == 0) {
					LogError1("Connection closed by the TCSD.");
					free(hdr_p);
					result = TSPERR(TSS_E_COMM_FAILURE);
					goto err_exit;
				}
				recd_total += recd;
				offset += recd;
			}
		}
	} else {
		LogError1("Packet received from TCSD has an invalid size field.");
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

