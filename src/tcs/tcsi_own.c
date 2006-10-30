
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
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsps.h"
#include "req_mgr.h"


TSS_RESULT
TCSP_TakeOwnership_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    UINT16 protocolID,	/* in */
			    UINT32 encOwnerAuthSize,	/* in  */
			    BYTE * encOwnerAuth,	/* in */
			    UINT32 encSrkAuthSize,	/* in */
			    BYTE * encSrkAuth,	/* in */
			    UINT32 srkInfoSize,	/*in */
			    BYTE * srkInfo,	/*in */
			    TPM_AUTH * ownerAuth,	/* in, out */
			    UINT32 * srkKeySize,	/*out */
			    BYTE ** srkKey)	/*out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY srkKeyContainer;
	BYTE oldAuthDataUsage;
	UINT64 bugOffset;
	BYTE newSRK[1024];
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		goto done;

	/* Check on the Atmel Bug Patch */
	offset = 0;
	UnloadBlob_KEY(&offset, srkInfo, &srkKeyContainer);
	oldAuthDataUsage = srkKeyContainer.authDataUsage;
	LogDebug("auth data usage is %.2X", oldAuthDataUsage);

	offset = 10;
	LoadBlob_UINT16(&offset, protocolID, txBlob);
	LoadBlob_UINT32(&offset, encOwnerAuthSize, txBlob);
	LoadBlob(&offset, encOwnerAuthSize, txBlob, encOwnerAuth);
	LoadBlob_UINT32(&offset, encSrkAuthSize, txBlob);
	LoadBlob(&offset, encSrkAuthSize, txBlob, encSrkAuth);

	LoadBlob(&offset, srkInfoSize, txBlob, srkInfo);

	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_TakeOwnership, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	offset = 10;
	if (result == 0) {
		if ((result = UnloadBlob_KEY(&offset, txBlob, &srkKeyContainer)))
			goto done;

		*srkKeySize = offset - 10;
		*srkKey = calloc(1, *srkKeySize);
		if (*srkKey == NULL) {
			destroy_key_refs(&srkKeyContainer);
			LogError("malloc of %u bytes failed.", *srkKeySize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		if (srkKeyContainer.authDataUsage != oldAuthDataUsage) {
			LogDebug("AuthDataUsage was changed by TPM.  Atmel Bug. Fixing it in PS");
			srkKeyContainer.authDataUsage = oldAuthDataUsage;
		}
		memcpy(*srkKey, &txBlob[10], *srkKeySize);

		memset(srkKeyContainer.pubKey.key, 0, srkKeyContainer.pubKey.keyLength);
		bugOffset = 0;
		LoadBlob_KEY(&bugOffset, newSRK, &srkKeyContainer);

		UnloadBlob_Auth(&offset, txBlob, ownerAuth);

#ifdef TSS_BUILD_PS
		/* Once the key file is created, it stays forever. There could be
		 * migratable keys in the hierarchy that are still useful to someone.
		 */
		result = ps_remove_key(&SRK_UUID);
		if (result != TSS_SUCCESS && result != TCSERR(TSS_E_PS_KEY_NOTFOUND)) {
			destroy_key_refs(&srkKeyContainer);
			LogError("Error removing SRK from key file.");
			goto done;
		}

		if ((result = ps_write_key(&SRK_UUID, &NULL_UUID, NULL, 0, newSRK, bugOffset))) {
			destroy_key_refs(&srkKeyContainer);
			LogError("Error writing SRK to disk");
			goto done;
		}
#endif
		result = mc_add_entry_srk(SRK_TPM_HANDLE, SRK_TPM_HANDLE, &srkKeyContainer);
		if (result != TSS_SUCCESS) {
			destroy_key_refs(&srkKeyContainer);
			LogError("Error creating SRK mem cache entry");
			*srkKeySize = 0;
			free(*srkKey);
		}
		destroy_key_refs(&srkKeyContainer);
	}
	LogResult("TakeOwnership", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_OwnerClear_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TPM_AUTH * ownerAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering OwnerClear");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Ownerclear", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

