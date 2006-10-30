
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
tcs_wrap_Extend(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 pcrIndex;
	TCPA_DIGEST inDigest;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TCPA_DIGEST outDigest;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &pcrIndex, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &inDigest, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_Extend_Internal(hContext, pcrIndex, inDigest, &outDigest);
	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TCPA_DIGEST));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &outDigest, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
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
tcs_wrap_PcrRead(struct tcsd_thread_data *data,
		 struct tsp_packet *tsp_data,
		 struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	UINT32 pcrIndex;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TCPA_DIGEST digest;
	TSS_RESULT result;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &pcrIndex, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_PcrRead_Internal(hContext, pcrIndex, &digest);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TCPA_DIGEST));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &digest, 0, *hdr)) {
			free(*hdr);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
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
