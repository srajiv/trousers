
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
tcs_wrap_PhysicalSetDeactivated(struct tcsd_thread_data *data,
				struct tsp_packet *tsp_data,
				struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_BOOL state;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_PhysicalSetDeactivated_Internal(hContext, state);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_DisableOwnerClear(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TPM_AUTH auth;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &auth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_DisableOwnerClear_Internal(hContext, &auth);

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
tcs_wrap_ForceClear(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_ForceClear_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_DisableForceClear(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_DisableForceClear_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PhysicalEnable(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_PhysicalEnable_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_SetOwnerInstall(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_BOOL state;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &state, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_SetOwnerInstall_Internal(hContext, state);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_OwnerSetDisable(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_BOOL disableState;
	TPM_AUTH ownerAuth;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_BOOL, 1, &disableState, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_AUTH, 2, &ownerAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_OwnerSetDisable_Internal(hContext, disableState, &ownerAuth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
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
tcs_wrap_PhysicalDisable(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_PhysicalDisable_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_PhysicalPresence(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	TCPA_PHYSICAL_PRESENCE phyPresFlags;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_UINT16, 1, &phyPresFlags, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_PhysicalPresence_Internal(hContext, phyPresFlags);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_SetTempDeactivated(struct tcsd_thread_data *data,
		     struct tsp_packet *tsp_data,
		     struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	result = TCSP_SetTempDeactivated_Internal(hContext);

	*hdr = calloc(1, size);
	if (*hdr == NULL) {
		LogError("malloc of %d bytes failed.", size);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}
	(*hdr)->packet_size = size;
	(*hdr)->result = result;

	return TSS_SUCCESS;
}

TSS_RESULT
tcs_wrap_ResetLockValue(struct tcsd_thread_data *data,
			struct tsp_packet *tsp_data,
			struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TPM_AUTH ownerAuth;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x context %x: %s", (UINT32)pthread_self(), hContext, __FUNCTION__);

	if (getData(TCSD_PACKET_TYPE_AUTH, 1, &ownerAuth, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	result = TCSP_ResetLockValue_Internal(hContext, &ownerAuth);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH));
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes failed.", size + sizeof(TPM_AUTH));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (setData(TCSD_PACKET_TYPE_AUTH, 0, &ownerAuth, 0, *hdr)) {
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

