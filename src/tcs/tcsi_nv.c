
/*
 * The Initial Developer of the Original Code is Intel Corporation.
 * Portions created by Intel Corporation are Copyright (C) 2007 Intel Corporation.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 *
 * trousers - An open source TCG Software Stack
 *
 * Author: james.xu@intel.com Rossey.liu@intel.com
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

TSS_RESULT
TCSP_NV_DefineOrReleaseSpace_Internal(TCS_CONTEXT_HANDLE hContext, /* in */
				      UINT32 cPubInfoSize,	/* in */
				      BYTE* pPubInfo,	/* in */
				      TPM_ENCAUTH encAuth,	/* in */
				      TPM_AUTH* pAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TPM_TAG tpm_tag = TPM_TAG_RQU_COMMAND;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (pAuth) {
		if((result = auth_mgr_check(hContext, &pAuth->AuthHandle)))
			goto done;
		tpm_tag = TPM_TAG_RQU_AUTH1_COMMAND;
	}
	offset = 10;

	LoadBlob(&offset, cPubInfoSize, txBlob, pPubInfo);

	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob, encAuth.authdata);
	if (pAuth)
		LoadBlob_Auth(&offset, txBlob, pAuth);

	LogDebug("load Header: ordinal: 0x%X  (oldOffset=%" PRIu64 ")", TPM_ORD_NV_DefineSpace, offset);
	LoadBlob_Header(tpm_tag, offset, TPM_ORD_NV_DefineSpace, txBlob);

	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", offset);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogDebug("UnloadBlob  (paramSize=%u) result=%u", paramSize, result);
	if (!result) {
		offset = 10;
	LogDebug("Unload Auth");
		if (pAuth)
			UnloadBlob_Auth(&offset, txBlob, pAuth);
	}
done:
	LogDebug("Leaving DefineSpace with result:%u", result);
	if (pAuth)
		auth_mgr_release_auth(pAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_NV_WriteValue_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TSS_NV_INDEX hNVStore,	/* in */
			    UINT32 offset,		/* in */
			    UINT32 ulDataLength,	/* in */
			    BYTE * rgbDataToWrite,	/* in */
			    TPM_AUTH * privAuth)	/* in, out */
{
	UINT64 off_set;
	UINT32 paramSize;
	TSS_RESULT result;
	TPM_TAG tpm_tag = TPM_TAG_RQU_COMMAND;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");
	if ( (result = ctx_verify_context(hContext)))
		return result;
	if (privAuth) {
		if( (result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			goto done;
		tpm_tag = TPM_TAG_RQU_AUTH1_COMMAND;
	}
	off_set = 10;
	LoadBlob_UINT32( &off_set, hNVStore, txBlob);
	LogDebug("load UNIT32: offset: 0x%x  (oldOffset=%" PRIu64 ")", offset, off_set);
	LoadBlob_UINT32(&off_set, offset, txBlob);
	LogDebug("load UNIT32: ulDataLength: 0x%x  (oldOffset=%" PRIu64 ")", ulDataLength, off_set);
	LoadBlob_UINT32(&off_set, ulDataLength, txBlob);
	LoadBlob(&off_set, ulDataLength, txBlob, rgbDataToWrite);

	if (privAuth)
		LoadBlob_Auth(&off_set, txBlob, privAuth);

	LogDebug("load Header: ordinal: 0x%X  (oldOffset=%" PRIu64 ")", TPM_ORD_NV_WriteValue, off_set);
	LoadBlob_Header(tpm_tag, off_set, TPM_ORD_NV_WriteValue, txBlob);
	
	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", off_set);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogDebug("UnloadBlob  (paramSize=%u) result=%u", paramSize, result);
	if (!result) {
		off_set = 10;
		LogDebug("Unload Auth");
		if (privAuth)
			UnloadBlob_Auth(&off_set, txBlob, privAuth);
	}
done:
	LogDebug("Leaving NVWriteValue with result:%u", result);
	if (privAuth)
		auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_NV_WriteValueAuth_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				TSS_NV_INDEX hNVStore,	/* in */
				UINT32 offset,		/* in */
				UINT32 ulDataLength,	/* in */
				BYTE * rgbDataToWrite,	/* in */
				TPM_AUTH * NVAuth)	/* in, out */
{
	UINT64 off_set;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");
	if ((result = ctx_verify_context(hContext)))
		return result;
	if((result = auth_mgr_check(hContext, &NVAuth->AuthHandle)))
		goto done;
	off_set = 10;
	LoadBlob_UINT32( &off_set, hNVStore, txBlob);
	LogDebug("load UNIT32: offset: 0x%x  (oldOffset=%" PRIu64 ")", offset, off_set);
	LoadBlob_UINT32(&off_set, offset, txBlob);
	LogDebug("load UNIT32: ulDataLength: 0x%x  (oldOffset=%" PRIu64 ")", ulDataLength, off_set);
	LoadBlob_UINT32(&off_set, ulDataLength, txBlob);
	LoadBlob(&off_set, ulDataLength, txBlob, rgbDataToWrite);

	LoadBlob_Auth(&off_set, txBlob, NVAuth);

	LogDebug("load Header: ordinal: 0x%X  (oldOffset=%" PRIu64 ")", TPM_ORD_NV_WriteValueAuth, off_set);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, off_set, TPM_ORD_NV_WriteValueAuth, txBlob);

	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", off_set);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogDebug("UnloadBlob  (paramSize=%u) result=%u", paramSize, result);
	if (!result) {
		off_set = 10;
		LogDebug("Unload Auth");
		UnloadBlob_Auth(&off_set, txBlob, NVAuth);
	}
done:
	LogDebug("Leaving NVWriteValueAuth with result:%u", result);
	auth_mgr_release_auth(NVAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_NV_ReadValue_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TSS_NV_INDEX hNVStore,	/* in */
			   UINT32 offset,	/* in */
			   UINT32 * pulDataLength,	/* in, out */
			   TPM_AUTH * privAuth,	/* in, out */
			   BYTE ** rgbDataRead)	/* out */
{
	UINT64 off_set;
	UINT32 paramSize;
	TSS_RESULT result;
	TPM_TAG tpm_tag = TPM_TAG_RQU_COMMAND;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");
	if ((result = ctx_verify_context(hContext)))
		return result;
	if (privAuth) {
		if((result = auth_mgr_check(hContext, &privAuth->AuthHandle)))
			goto done;
		tpm_tag = TPM_TAG_RQU_AUTH1_COMMAND;
	}
	off_set = 10;
	LoadBlob_UINT32(&off_set, hNVStore, txBlob);
	LogDebug("load UNIT32: offset: 0x%x  (oldOffset=%" PRIu64 ")", offset, off_set);
	LoadBlob_UINT32(&off_set, offset, txBlob);
	LogDebug("load UNIT32: pulDataLength: 0x%x  (oldOffset=%" PRIu64 ")", *pulDataLength, off_set);
	LoadBlob_UINT32(&off_set, *pulDataLength, txBlob);

	if (privAuth)
		LoadBlob_Auth(&off_set, txBlob, privAuth);

	LogDebug("load Header: ordinal: 0x%X  (oldOffset=%" PRIu64 ")", TPM_ORD_NV_ReadValue, off_set);
	LoadBlob_Header(tpm_tag, off_set, TPM_ORD_NV_ReadValue, txBlob);

	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", off_set);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogDebug("UnloadBlob  (paramSize=%u) result=%u", paramSize, result);
	if (!result) {
		off_set = 10;
		UnloadBlob_UINT32( &off_set, pulDataLength, txBlob);
		LogDebug("Unload outputSize=%u", *pulDataLength);

		*rgbDataRead =(BYTE *)malloc(*pulDataLength);
		if( *rgbDataRead == NULL) {
			LogError("malloc of %u bytes failed.", *pulDataLength);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		LogDebug("Unload outputData");
		UnloadBlob( &off_set, *pulDataLength, txBlob, *rgbDataRead);

		LogDebug("Unload Auth");
		if (privAuth)
			UnloadBlob_Auth(&off_set, txBlob, privAuth);
	}
done:
	LogDebug("Leaving NVReadValue with result:%u", result);
	if (privAuth)
		auth_mgr_release_auth(privAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_NV_ReadValueAuth_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_NV_INDEX hNVStore,	/* in */
			       UINT32 offset,		/* in */
			       UINT32 * pulDataLength,	/* in, out */
			       TPM_AUTH * NVAuth,	/* in, out */
			       BYTE ** rgbDataRead)	/* out */
{
	UINT64 off_set;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");
	if ((result = ctx_verify_context(hContext)))
		return result;
	if((result = auth_mgr_check(hContext, &NVAuth->AuthHandle)))
		goto done;
	off_set = 10;
	LoadBlob_UINT32( &off_set, hNVStore, txBlob);
	LogDebug("load UNIT32: offset: 0x%x  (oldOffset=%" PRIu64 ")", offset, off_set);
	LoadBlob_UINT32(&off_set, offset, txBlob);
	LogDebug("load UNIT32: pulDataLength: 0x%x  (oldOffset=%" PRIu64 ")", *pulDataLength, off_set);
	LoadBlob_UINT32(&off_set, *pulDataLength, txBlob);

	LoadBlob_Auth(&off_set, txBlob, NVAuth);

	LogDebug("load Header: ordinal: 0x%X  (oldOffset=%" PRIu64 ")", TPM_ORD_NV_ReadValueAuth, off_set);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, off_set, TPM_ORD_NV_ReadValueAuth, txBlob);

	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", off_set);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogDebug("UnloadBlob  (paramSize=%u) result=%u", paramSize, result);
	if (!result) {
		off_set = 10;
		UnloadBlob_UINT32( &off_set, pulDataLength, txBlob);
		LogDebug("Unload outputSize=%u", *pulDataLength);
		*rgbDataRead = (BYTE *)malloc(*pulDataLength);
		if(*rgbDataRead == NULL) {
			LogError("malloc of %u bytes failed.", *pulDataLength);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		LogDebug("Unload outputData");
		UnloadBlob( &off_set, *pulDataLength, txBlob, *rgbDataRead);

		LogDebug("Unload Auth");
		UnloadBlob_Auth(&off_set, txBlob, NVAuth);
	}
done:
	LogDebug("Leaving NVReadValueAuth with result:%u", result);
	auth_mgr_release_auth(NVAuth, NULL, hContext);
	return result;
}

