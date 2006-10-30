
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
#include <syslog.h>
#include <string.h>
#include <netdb.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcs_utils.h"
#include "rpc_tcstp_tcs.h"


TSS_RESULT
tcs_wrap_GetRandom(struct tcsd_thread_data *data,
		   struct tsp_packet *tsp_data,
		   struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 bytesRequested;
	BYTE *randomBytes = NULL;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &bytesRequested, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_GetRandom_Internal(hContext, &bytesRequested, &randomBytes);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(UINT32) + bytesRequested);
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(UINT32) + bytesRequested);
			free(randomBytes);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, 0, &bytesRequested, 0, *hdr)) {
			free(*hdr);
			free(randomBytes);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, 1, randomBytes, bytesRequested, *hdr)) {
			free(*hdr);
			free(randomBytes);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(randomBytes);
	} else {
		*hdr = calloc(1, size);
		if (*hdr == NULL) {
			LogError("malloc of %d bytes failed.", size);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*hdr)->packet_size = size;
	}
	(*hdr)->result = result;
	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_StirRandom(struct tcsd_thread_data *data,
		    struct tsp_packet *tsp_data,
		    struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 inDataSize;
	BYTE *inData;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &inDataSize, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	inData = calloc(1, inDataSize);
	if (inData == NULL) {
		LogError("malloc of %d bytes failed.", inDataSize);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	if (getData(TCSD_PACKET_TYPE_PBYTE, 2, inData, inDataSize, tsp_data)) {
		free(inData);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	result = TCSP_StirRandom_Internal(hContext, inDataSize, inData);

	free(inData);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}
