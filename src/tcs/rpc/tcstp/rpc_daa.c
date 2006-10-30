
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
tcs_wrap_DaaJoin(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr)
{
	TCS_CONTEXT_HANDLE hContext;
	TSS_HDAA hDAA;
	BYTE stage;
	UINT32 inputSize0, inputSize1, outputSize;
	BYTE *inputData0 = NULL, *inputData1 = NULL,*outputData;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TPM_AUTH ownerAuth, *pOwnerAuth;
	//      TCPA_DIGEST checksum;
	//      TPM_HANDLE handle;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x hDAA %x: %s", (UINT32)pthread_self(), hDAA, __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hDAA, 0, tsp_data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_BYTE, 2, &stage, 0, tsp_data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	LogDebug("%s getData 2 (stage=%d)", __FUNCTION__, (int)stage);

	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &inputSize0, 0, tsp_data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	LogDebug("%s getData 3  inputSize0=%d", __FUNCTION__, inputSize0);

	inputData0 = calloc(1, inputSize0);
	if (inputData0 == NULL) {
		LogError("malloc of %d bytes failed.", inputSize0);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	LogDebug("%s getData 4 inputData0", __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, inputData0, inputSize0, tsp_data)) {
		free(inputData0);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	LogDebug("%s getData 5", __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_UINT32, 5, &inputSize1, 0, tsp_data)) {
		free( inputData0);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	LogDebug("%s getData 5  inputSize1=%d", __FUNCTION__, inputSize1);

	if( inputSize1 > 0) {
		inputData1 = calloc(1, inputSize1);
		if (inputData1 == NULL) {
			LogError("malloc of %d bytes failed.", inputSize1);
			free( inputData0);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		LogDebug("%s getData 6 inputData1", __FUNCTION__);
		if (getData(TCSD_PACKET_TYPE_PBYTE, 6, inputData1, inputSize1, tsp_data)) {
			free(inputData0);
			free(inputData1);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	LogDebug("%s getData 7", __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_AUTH, 7, &ownerAuth, 0, tsp_data)) {
		//              free(inputData0);
		//              if( inputData1 != NULL) free(inputData1);
		//              return TSPERR(TSS_E_INTERNAL_ERROR);
		pOwnerAuth = NULL;
	} else {
		pOwnerAuth = &ownerAuth;
	}

	LogDebug("-> %s TCSP_DaaJoin_internal", __FUNCTION__);
	result = TCSP_DaaJoin_internal(hContext, hDAA, stage, inputSize0, inputData0, inputSize1,
				       inputData1, pOwnerAuth, &outputSize, &outputData);
	LogDebug("<- %s TCSP_DaaJoin_internal", __FUNCTION__);

	free(inputData0);
	if( inputData1 != NULL) free(inputData1);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + outputSize );
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes faile.", size + sizeof(UINT32) + outputSize +
				 sizeof(TCPA_DIGEST) + sizeof(TPM_AUTH));
			free(outputData);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		int i = 0;
		if ( pOwnerAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, *hdr)) {
				free(*hdr);
				free(outputData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &outputSize, 0, *hdr)) {
			free(*hdr);
			free(outputData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, outputData, outputSize, *hdr)) {
			free(*hdr);
			free(outputData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(outputData);
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
tcs_wrap_DaaSign(struct tcsd_thread_data *data,
		struct tsp_packet *tsp_data,
		struct tcsd_packet_hdr **hdr) {
	TCS_CONTEXT_HANDLE hContext;
	TSS_HDAA hDAA;
	BYTE stage;
	UINT32 inputSize0, inputSize1, outputSize;
	BYTE *inputData0 = NULL, *inputData1 = NULL,*outputData;
	TSS_RESULT result;
	UINT32 size = sizeof(struct tcsd_packet_hdr);
	TPM_AUTH ownerAuth, *pOwnerAuth;
	//      TCPA_DIGEST checksum;
	//      TPM_HANDLE handle;

	if (getData(TCSD_PACKET_TYPE_UINT32, 0, &hContext, 0, tsp_data))
		return TCSERR(TSS_E_INTERNAL_ERROR);

	LogDebug("thread %x hDAA %x: %s", (UINT32)pthread_self(), hDAA, __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_UINT32, 1, &hDAA, 0, tsp_data))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if (getData(TCSD_PACKET_TYPE_BYTE, 2, &stage, 0, tsp_data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	LogDebug("%s getData 2 (stage=%d)", __FUNCTION__, (int)stage);

	if (getData(TCSD_PACKET_TYPE_UINT32, 3, &inputSize0, 0, tsp_data))
		return TSPERR(TSS_E_INTERNAL_ERROR);
	LogDebug("%s getData 3  inputSize0=%d", __FUNCTION__, inputSize0);

	inputData0 = calloc(1, inputSize0);
	if (inputData0 == NULL) {
		LogError("malloc of %d bytes failed.", inputSize0);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	LogDebug("%s getData 4 inputData0", __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_PBYTE, 4, inputData0, inputSize0, tsp_data)) {
		free(inputData0);
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	LogDebug("%s getData 5", __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_UINT32, 5, &inputSize1, 0, tsp_data)) {
		free( inputData0);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	LogDebug("%s getData 5  inputSize1=%d", __FUNCTION__, inputSize1);

	if( inputSize1 > 0) {
		inputData1 = calloc(1, inputSize1);
		if (inputData1 == NULL) {
			LogError("malloc of %d bytes failed.", inputSize1);
			free( inputData0);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		LogDebug("%s getData 6 inputData1", __FUNCTION__);
		if (getData(TCSD_PACKET_TYPE_PBYTE, 6, inputData1, inputSize1, tsp_data)) {
			free(inputData0);
			free(inputData1);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
	}

	LogDebug("%s getData 7", __FUNCTION__);
	if (getData(TCSD_PACKET_TYPE_AUTH, 7, &ownerAuth, 0, tsp_data)) {
		pOwnerAuth = NULL;
	} else {
		pOwnerAuth = &ownerAuth;
	}

	LogDebugFn("-> TCSP_DaaSign_internal");
	result = TCSP_DaaSign_internal(hContext, hDAA, stage, inputSize0, inputData0, inputSize1,
				       inputData1, pOwnerAuth, &outputSize, &outputData);
	LogDebugFn("<- TCSP_DaaSign_internal");

	free(inputData0);
	if( inputData1 != NULL) free(inputData1);

	if (result == TSS_SUCCESS) {
		*hdr = calloc(1, size + sizeof(TPM_AUTH) + sizeof(UINT32) + outputSize );
		if (*hdr == NULL) {
			LogError("malloc of %zd bytes faile.", size + sizeof(UINT32) + outputSize +
				 sizeof(TCPA_DIGEST) + sizeof(TPM_AUTH));
			free(outputData);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		int i = 0;
		if ( pOwnerAuth) {
			if (setData(TCSD_PACKET_TYPE_AUTH, i++, pOwnerAuth, 0, *hdr)) {
				free(*hdr);
				free(outputData);
				return TCSERR(TSS_E_INTERNAL_ERROR);
			}
		}
		if (setData(TCSD_PACKET_TYPE_UINT32, i++, &outputSize, 0, *hdr)) {
			free(*hdr);
			free(outputData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		if (setData(TCSD_PACKET_TYPE_PBYTE, i++, outputData, outputSize, *hdr)) {
			free(*hdr);
			free(outputData);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
		free(outputData);
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
