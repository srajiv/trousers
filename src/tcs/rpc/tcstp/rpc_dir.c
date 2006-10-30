
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
tcs_wrap_DirWriteAuth(struct tcsd_thread_data *data,
		      struct tsp_packet *tsp_data,
		      struct tcsd_packet_hdr **hdr)
{
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_HCONTEXT hContext;
	TCPA_DIRINDEX dirIndex;
	TCPA_DIGEST dirDigest;
	TPM_AUTH auth;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &dirIndex, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_DIGEST, 2, &dirDigest, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);
	if (getData(TCSD_PACKET_TYPE_AUTH, 3, &auth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_DirWriteAuth_Internal(hContext, dirIndex, dirDigest, &auth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &auth, 0, *hdr)) {
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
tcs_wrap_DirRead(struct tcsd_thread_data *data,
		 struct tsp_packet *tsp_data,
		 struct tcsd_packet_hdr **hdr)
{
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TSS_HCONTEXT hContext;
	TCPA_DIRINDEX dirIndex;
	TCPA_DIRVALUE dirValue;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &dirIndex, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_DirRead_Internal(hContext, dirIndex, &dirValue);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TCPA_DIGEST));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if (setData(TCSD_PACKET_TYPE_DIGEST, 0, &dirValue, 0, *hdr)) {
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
