
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsps.h"
#include "req_mgr.h"
#include "tcs_aik.h"


TSS_RESULT
TCSP_MakeIdentity_Internal(TCS_CONTEXT_HANDLE hContext,			/* in  */
			   TCPA_ENCAUTH identityAuth,			/* in */
			   TCPA_CHOSENID_HASH IDLabel_PrivCAHash,	/* in */
			   UINT32 idKeyInfoSize,			/* in */
			   BYTE * idKeyInfo,				/* in */
			   TPM_AUTH * pSrkAuth,				/* in, out */
			   TPM_AUTH * pOwnerAuth,			/* in, out */
			   UINT32 * idKeySize,				/* out */
			   BYTE ** idKey,				/* out */
			   UINT32 * pcIdentityBindingSize,		/* out */
			   BYTE ** prgbIdentityBinding,			/* out */
			   UINT32 * pcEndorsementCredentialSize,	/* out */
			   BYTE ** prgbEndorsementCredential,		/* out */
			   UINT32 * pcPlatformCredentialSize,		/* out */
			   BYTE ** prgbPlatformCredential,		/* out */
			   UINT32 * pcConformanceCredentialSize,	/* out */
			   BYTE ** prgbConformanceCredential)		/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY idKeyContainer;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (pSrkAuth != NULL) {
		LogDebug("SRK Auth Used");
		if ((result = auth_mgr_check(hContext, &pSrkAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No SRK Auth");
	}

	if ((result = auth_mgr_check(hContext, &pOwnerAuth->AuthHandle)))
		goto done;

	offset = 0;

	offset = 10;
	/*LoadBlob( &offset, idKeyInfoSize, txBlob, idKeyInfo);  */
	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob, identityAuth.authdata);
	/*LoadBlob_UINT32( &offset, 20, txBlob, "label size"); */
	LoadBlob(&offset, 20, txBlob, IDLabel_PrivCAHash.digest);
	LoadBlob(&offset, idKeyInfoSize, txBlob, idKeyInfo);
	if (pSrkAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, pSrkAuth);
		LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, offset, TPM_ORD_MakeIdentity, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_MakeIdentity, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		/* Call UnloadBlob_KEY to set the size of the key in &offset */
		if ((result = UnloadBlob_KEY(&offset, txBlob, &idKeyContainer)))
			goto done;

		destroy_key_refs(&idKeyContainer);
		*idKeySize = offset - 10;
		*idKey = calloc(1, *idKeySize);
		if (*idKey == NULL) {
			LogError("malloc of %d bytes failed.", *idKeySize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*idKey, &txBlob[10], *idKeySize);

		UnloadBlob_UINT32(&offset, pcIdentityBindingSize, txBlob);
		*prgbIdentityBinding = calloc(1, *pcIdentityBindingSize);
		if (*prgbIdentityBinding == NULL) {
			free(*idKey);
			*idKeySize = 0;
			LogError("malloc of %d bytes failed.", *pcIdentityBindingSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		UnloadBlob(&offset, *pcIdentityBindingSize, txBlob, *prgbIdentityBinding);

		/* If an error occurs, these will return NULL */
		get_credential(TR_PLATFORM_CREDENTIAL, pcPlatformCredentialSize,
			       prgbPlatformCredential);
		get_credential(TR_CONFORMANCE_CREDENTIAL, pcConformanceCredentialSize,
			       prgbConformanceCredential);
		get_credential(TR_ENDORSEMENT_CREDENTIAL, pcEndorsementCredentialSize,
			       prgbEndorsementCredential);

		if (pSrkAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, pSrkAuth);
		UnloadBlob_Auth(&offset, txBlob, pOwnerAuth);
	}
	LogResult("Make Identity", result);
done:
	auth_mgr_release_auth(pSrkAuth, pOwnerAuth, hContext);
	return result;
}

TSS_RESULT
TCSP_ActivateTPMIdentity_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE idKey,	/* in */
				  UINT32 blobSize,	/* in */
				  BYTE * blob,	/* in */
				  TPM_AUTH * idKeyAuth,	/* in, out */
				  TPM_AUTH * ownerAuth,	/* in, out */
				  UINT32 * SymmetricKeySize,	/* out */
				  BYTE ** SymmetricKey)	/* out */
{
	UINT64 offset, authOffset;
	TCPA_SYMMETRIC_KEY symKey;
	TSS_RESULT result;
	UINT32 paramSize;
	UINT32 keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("TCSP_ActivateTPMIdentity");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (idKeyAuth != NULL) {
		if ((result = auth_mgr_check(hContext, &idKeyAuth->AuthHandle)))
			goto done;
	}
	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	if ((result = ensureKeyIsLoaded(hContext, idKey, &keySlot)))
		goto done;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	LoadBlob_UINT32(&offset, blobSize, txBlob);
	LoadBlob(&offset, blobSize, txBlob, blob);
	if (idKeyAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, idKeyAuth);
		LoadBlob_Auth(&offset, txBlob, ownerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND,
				offset,
				TPM_ORD_ActivateIdentity, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, ownerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset,
				TPM_ORD_ActivateIdentity, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		/* We don't know what kind of key the symmetric key is, or how big it is.
		 * So, call UnloadBlob_SYMMETRIC_KEY to parse through the returned data
		 * and create the expanded TCPA_SYMMETRIC_KEY structure.  Then, serialize
		 * that data to pass back to the TSP. */
		offset = 10;
		if ((result = UnloadBlob_SYMMETRIC_KEY(&offset, txBlob, &symKey)))
			goto done;

		/* After parsing through the symmetric key, offset will point to the auth
		 * structure(s) */
		authOffset = offset;

		*SymmetricKey = calloc(1, offset - 10);
		if (*SymmetricKey == NULL) {
			free(symKey.data);
			LogError("malloc of %" PRIu64 " bytes failed.", offset - 10);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		*SymmetricKeySize = offset - 10;
		offset = 0;
		LoadBlob_SYMMETRIC_KEY(&offset, *SymmetricKey, &symKey);
		free(symKey.data);

		if (idKeyAuth != NULL) {
			UnloadBlob_Auth(&authOffset, txBlob, idKeyAuth);
		}
		UnloadBlob_Auth(&authOffset, txBlob, ownerAuth);
	}

done:
	auth_mgr_release_auth(idKeyAuth, ownerAuth, hContext);
	return result;
}

