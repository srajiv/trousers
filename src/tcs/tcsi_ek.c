
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
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

TSS_RESULT
TCSP_CreateEndorsementKeyPair_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCPA_NONCE antiReplay,	/* in */
				       UINT32 endorsementKeyInfoSize,	/* in */
				       BYTE * endorsementKeyInfo,	/* in */
				       UINT32 * endorsementKeySize,	/* out */
				       BYTE ** endorsementKey,	/* out */
				       TCPA_DIGEST * checksum)	/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_PUBKEY pubKey;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, antiReplay.nonce);
	LoadBlob(&offset, endorsementKeyInfoSize, txBlob, endorsementKeyInfo);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_CreateEndorsementKeyPair, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		if ((result = UnloadBlob_PUBKEY(&offset, txBlob, &pubKey)))
			goto done;
		free(pubKey.pubKey.key);
		free(pubKey.algorithmParms.parms);

		*endorsementKeySize = offset - 10;
		*endorsementKey = malloc(*endorsementKeySize);
		if (*endorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *endorsementKeySize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*endorsementKey, &txBlob[10], *endorsementKeySize);

		UnloadBlob(&offset, TCPA_DIGEST_SIZE, txBlob, checksum->digest);
	}
done:
	LogDebug("Leaving CreateEKPair with result: 0x%x", result);
	return result;
}

TSS_RESULT
TCSP_ReadPubek_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCPA_NONCE antiReplay,	/* in */
			UINT32 * pubEndorsementKeySize,	/* out */
			BYTE ** pubEndorsementKey,	/* out */
			TCPA_DIGEST * checksum)	/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_PUBKEY pubkey;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_ReadPubek, txBlob);
	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		if ((result = UnloadBlob_PUBKEY(&offset, txBlob, &pubkey)))
			goto done;
		free(pubkey.pubKey.key);
		free(pubkey.algorithmParms.parms);

		*pubEndorsementKeySize = (UINT32) (offset - 10);
		*pubEndorsementKey = malloc(*pubEndorsementKeySize);
		if (*pubEndorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *pubEndorsementKeySize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*pubEndorsementKey, &txBlob[10], *pubEndorsementKeySize);
		UnloadBlob(&offset, TCPA_DIGEST_SIZE, txBlob, checksum->digest);
	}
done:
	LogDebugFn("result: 0x%x", result);
	return result;
}

TSS_RESULT
TCSP_DisablePubekRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TPM_AUTH * ownerAuth)	/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("DisablePubekRead");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_DisablePubekRead, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_OwnerReadPubek_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			     TPM_AUTH * ownerAuth,	/* in, out */
			     UINT32 * pubEndorsementKeySize,	/* out */
			     BYTE ** pubEndorsementKey)	/* out */
{
	UINT32 paramSize;
	TSS_RESULT result;
	UINT64 offset;
	TCPA_PUBKEY container;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering OwnerReadPubek");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)))
		goto done;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerReadPubek, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		offset = 10;
		/* Call UnloadBlob to parse the data and set its size in &offset */
		if ((result = UnloadBlob_PUBKEY(&offset, txBlob, &container)))
			goto done;

		free(container.pubKey.key);
		free(container.algorithmParms.parms);

		*pubEndorsementKeySize = offset - 10;
		*pubEndorsementKey = malloc(*pubEndorsementKeySize);
		if (*pubEndorsementKey == NULL) {
			LogError("malloc of %u bytes failed.", *pubEndorsementKeySize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*pubEndorsementKey, &txBlob[10], *pubEndorsementKeySize);
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Owner Read Pubek", result);
done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

