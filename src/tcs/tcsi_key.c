
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
TCSP_LoadKeyByBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCS_KEY_HANDLE hUnwrappingKey,	/* in */
			    UINT32 cWrappedKeyBlobSize,		/* in */
			    BYTE * rgbWrappedKeyBlob,		/* in */
			    TPM_AUTH * pAuth,			/* in, out */
			    TCS_KEY_HANDLE * phKeyTCSI,		/* out */
			    TCS_KEY_HANDLE * phKeyHMAC)		/* out */
{
	UINT64 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	TCPA_KEY key;
	TCPA_KEY_HANDLE myKeySlot;
	TCS_KEY_HANDLE myTcsKeyHandle;
	TCPA_STORE_PUBKEY *parentPubKey = NULL;
	TCPA_KEY_HANDLE parentKeySlot;
	TSS_BOOL needToSendPacket = TRUE, canLoad;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebugFn("Enter");
	LogDebugUnrollKey(rgbWrappedKeyBlob);

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (pAuth != NULL) {
		LogDebug("Auth Used");
		if ((result = auth_mgr_check(hContext, pAuth->AuthHandle)))
			return result;
	} else {
		LogDebug("No Auth Used");
	}

	offset = 0;
	memset(&key, 0, sizeof(TCPA_KEY));
	if ((result = UnloadBlob_KEY(&offset, rgbWrappedKeyBlob, &key)))
		return result;
	cWrappedKeyBlobSize = offset;

	/*
	 * The first thing to make sure is that the parent is loaded.
	 * If the parentKeySlot is invalid, then it either wasn't found in the cache
	 * or it was evicted.  Then checking if it was ever in the cache by calling
	 * getParentPubByPub will tell us whether or not there is an error.  If this
	 * unregistered parent was never loaded by the user, then he's hosed and
	 * this is an error.  If there is knowledge, then the shim is called to load
	 * the parent by it's public key.
	 */

	/* Check the mem cache to see if there is a TPM handle associated with the
	 * parent's TCS handle */
	LogDebugFn("calling mc_get_slot_by_handle");
	if ((parentKeySlot = mc_get_slot_by_handle(hUnwrappingKey)) == NULL_TPM_HANDLE) {
		LogDebugFn("calling mc_get_pub_by_slot");
		parentPubKey = mc_get_pub_by_slot(hUnwrappingKey);
		if (parentPubKey == NULL) {
			result = TCSERR(TCS_E_KM_LOADFAILED);
			goto error;
		}
		LogDebugFn("calling LoadKeyShim");
		/* Otherwise, try to load it using the shim */
		if ((result = LoadKeyShim(hContext, parentPubKey, NULL, &parentKeySlot)))
			goto error;
	}
	/*******************************************
	 *Call LoadKeyShim
	 *If it passes, we had prior knowledge of this key and we can avoid redundant copies of it
	 *******************************************/

	/* If it's an authorized load, then assume that we brute-force load it every time */
	if (pAuth == NULL) {
		LogDebugFn("Checking if LoadKeyByBlob can be avoided by using"
			    " existing key");

		myTcsKeyHandle = mc_get_handle_by_pub(&key.pubKey, hUnwrappingKey);
		if (myTcsKeyHandle != NULL_TCS_HANDLE) {
			LogDebugFn("tcs key handle exists");

			myKeySlot = mc_get_slot_by_handle(myTcsKeyHandle);
			if (myKeySlot != NULL_TPM_HANDLE && isKeyLoaded(myKeySlot) == TRUE) {
				needToSendPacket = FALSE;
				LogDebugFn("Don't need to reload this key.");
				result = TSS_SUCCESS;
				goto add_cache_entry;
			}
		}
	}

	/******************************************
	 *Now we just have to check if there is enough room in the chip.
	 *********************************************/

	LogDebugFn("calling canILoadThisKey");
	if ((result = canILoadThisKey(&(key.algorithmParms), &canLoad)))
		goto error;

	if (canLoad == FALSE) {
		LogDebugFn("calling evictFirstKey");
		/* Evict a key that isn't the parent */
		if ((result = evictFirstKey(hUnwrappingKey)))
			goto error;
	}

	LogDebugFn("Entering LoadKey by blob");

	/****************************************
	 *	Now the parent is loaded and all of the info is ready.
	 *	Send the loadkey command.  If the auth is a NULL Pointer
	 *	then this represents a NoAuth load
	 ********************************************/

	offset = 10;
	LoadBlob_UINT32(&offset, parentKeySlot, txBlob);
	LoadBlob(&offset, cWrappedKeyBlobSize, txBlob, rgbWrappedKeyBlob);
	if (pAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, pAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_LoadKey, txBlob);
	} else
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_LoadKey, txBlob);

	LogDebugUnrollKey(rgbWrappedKeyBlob);
	LogDebugFn("Submitting request to the TPM");
	if ((result = req_mgr_submit_req(txBlob)))
		goto error;

	if (needToSendPacket == TRUE) {
		LogDebugFn("calling UnloadBlob_Header");
		if ((result = UnloadBlob_Header(txBlob, &paramSize))) {
			LogDebugFn("UnloadBlob_Header failed: rc=0x%x", result);
			goto error;
		}

		offset = 10;
		/*---	Finish unloading the stuff */
		UnloadBlob_UINT32(&offset, &myKeySlot, txBlob);
		if (pAuth != NULL) {
			UnloadBlob_Auth(&offset, txBlob, pAuth);
		}
	} else {
		LogDebugFn("Key slot is 0x%x", myKeySlot);
	}

	/***************************************
	 *See if a TCSKeyHandle already exists.
	 *	If it's 0, then it doesn't exist, and we need new knowledge of the key.
	 *	If it exists, then just register the new keySlot with that existing handle
	 *****************************************/

	LogDebugFn("calling mc_get_handle_by_pub");
add_cache_entry:
	if ((myTcsKeyHandle = mc_get_handle_by_pub(&key.pubKey, hUnwrappingKey))
	     == NULL_TCS_HANDLE) {
		LogDebugFn("No existing key handle for this key, need to create a new one");
		/* Get a new TCS Key Handle */
		myTcsKeyHandle = getNextTcsKeyHandle();
		LogDebugFn("calling mc_add_entry, TCS handle: 0x%x, TPM handle 0x%x",
			   myTcsKeyHandle, myKeySlot);
		if ((result = mc_add_entry(myTcsKeyHandle, myKeySlot, &key)))
			goto error;

		LogDebugFn("ctx_mark_key_loaded");
		if (ctx_mark_key_loaded(hContext, myTcsKeyHandle)) {
			LogError("Error marking key as loaded");
			result = TCSERR(TSS_E_INTERNAL_ERROR);
			goto error;
		}

		if ((result = mc_set_parent_by_handle(myTcsKeyHandle, hUnwrappingKey))) {
			LogError("setParentBlobByHandle failed.");
			goto error;
		}
	} else
		mc_set_slot_by_handle(myTcsKeyHandle, myKeySlot);

	result = TSS_SUCCESS;

	/* Setup the outHandles */
	*phKeyTCSI = myTcsKeyHandle;
	*phKeyHMAC = myKeySlot;

	LogDebugFn("Key handles for loadKeyByBlob slot:%.8X tcshandle:%.8X", myKeySlot,
		   myTcsKeyHandle);
error:
	destroy_key_refs(&key);
	auth_mgr_release_auth(pAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_EvictKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		       TCS_KEY_HANDLE hKey)		/* in */
{
	TSS_RESULT result;
	TCPA_KEY_HANDLE tpm_handle;

	if ((result = ctx_verify_context(hContext)))
		return result;

	tpm_handle = mc_get_slot_by_handle(hKey);
	if (tpm_handle == NULL_TPM_HANDLE)
		return TSS_SUCCESS;	/*let's call this success if the key is already evicted */

	if ((result = internal_EvictByKeySlot(tpm_handle)))
		return result;

	result = mc_set_slot_by_slot(tpm_handle, NULL_TPM_HANDLE);

	return result;
}

TSS_RESULT
TCSP_CreateWrapKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCS_KEY_HANDLE hWrappingKey,	/* in */
			    TCPA_ENCAUTH KeyUsageAuth,		/* in */
			    TCPA_ENCAUTH KeyMigrationAuth,	/* in */
			    UINT32 keyInfoSize,			/* in */
			    BYTE * keyInfo,			/* in */
			    UINT32 * keyDataSize,		/* out */
			    BYTE ** keyData,			/* out */
			    TPM_AUTH * pAuth)			/* in, out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY keyContainer;
	TCPA_KEY_HANDLE parentSlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Create Wrap Key");

	if ((result = ctx_verify_context(hContext)))
		goto done;

	if ((result = auth_mgr_check(hContext, pAuth->AuthHandle)))
		goto done;

	/* Since hWrappingKey must already be loaded, we can fail immediately if
	 * mc_get_slot_by_handle_lock() fails.*/
	parentSlot = mc_get_slot_by_handle_lock(hWrappingKey);
	if (parentSlot == NULL_TPM_HANDLE) {
		result = TCSERR(TSS_E_FAIL);
		goto done;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, parentSlot, txBlob);
	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob, KeyUsageAuth.authdata);
	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob, KeyMigrationAuth.authdata);
	LoadBlob(&offset, keyInfoSize, txBlob, keyInfo);
	LoadBlob_Auth(&offset, txBlob, pAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_CreateWrapKey, txBlob);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		/* First get the data from the packet */
		if ((result = UnloadBlob_KEY(&offset, txBlob, &keyContainer)))
			goto done;

		/* Here's how big it is */
		*keyDataSize = offset - 10;
		/* malloc the outBuffer */
		*keyData = calloc(1, *keyDataSize);
		if (*keyData == NULL) {
			LogError("malloc of %d bytes failed.", *keyDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			/* Reset the offset and load it into the outbuf */
			memcpy(*keyData, &txBlob[10], *keyDataSize);
		}

		UnloadBlob_Auth(&offset, txBlob, pAuth);

		destroy_key_refs(&keyContainer);
	}
	LogResult("Create Wrap Key", result);

done:
	auth_mgr_release_auth(pAuth, NULL, hContext);
	return result;
}

TSS_RESULT
TCSP_GetPubKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCS_KEY_HANDLE hKey,		/* in */
			TPM_AUTH * pAuth,		/* in, out */
			UINT32 * pcPubKeySize,		/* out */
			BYTE ** prgbPubKey)		/* out */
{
	UINT64 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_PUBKEY pubContainer;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];

	LogDebug("Entering Get pub key");
	if ((result = ctx_verify_context(hContext)))
		goto done;

	if (pAuth != NULL) {
		LogDebug("Auth Used");
		if ((result = auth_mgr_check(hContext, pAuth->AuthHandle)))
			goto done;
	} else {
		LogDebug("No Auth");
	}

	if (ensureKeyIsLoaded(hContext, hKey, &keySlot)) {
		result = TCSERR(TCS_E_KM_LOADFAILED);
		goto done;
	}

	LogDebug("GetPubKey: handle: 0x%x, slot: 0x%x", hKey, keySlot);
	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob);
	if (pAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, pAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_GetPubKey, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_GetPubKey, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		if ((result = UnloadBlob_PUBKEY(&offset, txBlob, &pubContainer)))
			goto done;
		free(pubContainer.pubKey.key);
		free(pubContainer.algorithmParms.parms);

		*pcPubKeySize = offset - 10;
		*prgbPubKey = calloc(1, *pcPubKeySize);
		if (*prgbPubKey == NULL) {
			LogError("malloc of %d bytes failed.", *pcPubKeySize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		memcpy(*prgbPubKey, &txBlob[10], *pcPubKeySize);

		if (pAuth != NULL) {
			UnloadBlob_Auth(&offset, txBlob, pAuth);
		}
	}
	LogResult("Get Public Key", result);
done:
	auth_mgr_release_auth(pAuth, NULL, hContext);
	return result;
}
