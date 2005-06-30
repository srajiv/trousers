
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
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

#include "atmel.h"

/*---	Kill audit */
#define AppendAudit( a, b, c )

TSS_RESULT
TCSP_SetOwnerInstall_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TSS_BOOL state	/* in  */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering SetOwnerInstall");
	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_BOOL(&offset, state, txBlob, "State");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_SetOwnerInstall,
			txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	offset = 10;
	AppendAudit(0, TPM_ORD_SetOwnerInstall, result);
	LogResult("SetOwnerInstall", result);
	return result;
}

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
			    BYTE ** srkKey	/*out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY srkKeyContainer;
	BYTE oldAuthDataUsage;
	UINT16 bugOffset;
	BYTE newSRK[1024];
	BYTE txBlob[TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	/*---	Check on the Atmel Bug Patch */
	offset = 0;
	UnloadBlob_KEY(&offset, srkInfo, &srkKeyContainer);
	oldAuthDataUsage = srkKeyContainer.authDataUsage;
	LogDebug("auth data usage is %.2X", oldAuthDataUsage);

	offset = 10;
	LoadBlob_UINT16(&offset, protocolID, txBlob, "prot id");
	LoadBlob_UINT32(&offset, encOwnerAuthSize, txBlob,
			"enc owner auth size");
	LoadBlob(&offset, encOwnerAuthSize, txBlob, encOwnerAuth,
			"enc owner auth");
	LoadBlob_UINT32(&offset, encSrkAuthSize, txBlob,
			"srk auth size");
	LoadBlob(&offset, encSrkAuthSize, txBlob, encSrkAuth,
			"srk auth");

	LoadBlob(&offset, srkInfoSize, txBlob, srkInfo, "srk");

	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_TakeOwnership, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	offset = 10;
	if (result == 0) {
		UnloadBlob_KEY(&offset, txBlob, &srkKeyContainer);
		*srkKeySize = offset - 10;
		*srkKey = getSomeMemory(*srkKeySize, hContext);	/*this is that memory leak problem */
		if (*srkKey == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if (srkKeyContainer.authDataUsage != oldAuthDataUsage) {
			LogDebug1("AuthDataUsage was changed by TPM.  Atmel Bug. Fixing it in PS");
			srkKeyContainer.authDataUsage = oldAuthDataUsage;
		}
		memcpy(*srkKey, &txBlob[10], *srkKeySize);
		bugOffset = 0;
		LoadBlob_KEY(&bugOffset, newSRK, &srkKeyContainer);

		UnloadBlob_Auth(&offset, txBlob, ownerAuth);

		/* Once the key file is created, it stays forever. There could be
		 * migratable keys in the hierarchy that are still useful to someone.
		 */
		result = removeRegisteredKey(&SRK_UUID);
		if (result != TSS_SUCCESS && result != TCSERR(TSS_E_PS_KEY_NOTFOUND)) {
			LogError1("Error removing SRK from key file.");
			return result;
		}

		if ((result = writeRegisteredKeyToFile(&SRK_UUID, &NULL_UUID, newSRK, bugOffset))) {
			LogError1("Error writing SRK to disk");
			return result;
		}
		result = add_mem_cache_entry_srk(SRK_TPM_HANDLE, SRK_TPM_HANDLE, &srkKeyContainer);
		if (result != TSS_SUCCESS)
			LogError1("Error creating mem cache entry");
	}
	LogResult("TakeOwnership", result);
	return result;
}

TSS_RESULT
TCSP_OIAP_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCS_AUTHHANDLE *authHandle,	/* out */
		   TCPA_NONCE *nonce0	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TCSI_OIAP");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_OIAP, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_UINT32(&offset, authHandle, txBlob, "authHandle");
		UnloadBlob(&offset, TCPA_NONCE_SIZE, txBlob,
				nonce0->nonce, "n0");
	}

	AppendAudit(0, TPM_ORD_OIAP, result);
	LogResult("OIAP", result);
	return result;
}

TSS_RESULT
TCSP_OSAP_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCPA_ENTITY_TYPE entityType,	/* in */
		   UINT32 entityValue,	/* in */
		   TCPA_NONCE nonceOddOSAP,	/* in */
		   TCS_AUTHHANDLE * authHandle,	/* out */
		   TCPA_NONCE * nonceEven,	/* out */
		   TCPA_NONCE * nonceEvenOSAP	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	UINT32 newEntValue = 0;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering OSAP");
	if ((result = ctx_verify_context(hContext)))
		return result;

	/* if ET is not KEYHANDLE or KEY, newEntValue is a don't care */
	if (entityType == TCPA_ET_KEYHANDLE || entityType == TCPA_ET_KEY) {
		if (ensureKeyIsLoaded(hContext, entityValue, &newEntValue))
			return TCSERR(TSS_E_FAIL);	/*tcs error */
	} else {
		newEntValue = entityValue;
	}

	offset = 10;
	LoadBlob_UINT16(&offset, entityType, txBlob, "entity type");
	LoadBlob_UINT32(&offset, newEntValue, txBlob, "entity value");
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonceOddOSAP.nonce, "nonce osap");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_OSAP, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, authHandle, txBlob, "auth handle");
		UnloadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonceEven->nonce, "n0");
		UnloadBlob(&offset, TCPA_NONCE_SIZE, txBlob, nonceEvenOSAP->nonce, "n0 osap");
	}
	AppendAudit(0, TPM_ORD_OSAP, result);
	LogResult("OSAP", result);

	return result;
}

TSS_RESULT
TCSP_ChangeAuth_Internal(TCS_CONTEXT_HANDLE contextHandle,	/* in */
			 TCS_KEY_HANDLE parentHandle,	/* in */
			 TCPA_PROTOCOL_ID protocolID,	/* in */
			 TCPA_ENCAUTH newAuth,	/* in */
			 TCPA_ENTITY_TYPE entityType,	/* in */
			 UINT32 encDataSize,	/* in */
			 BYTE *encData,	/* in */
			 TPM_AUTH *ownerAuth,	/* in, out */
			 TPM_AUTH *entityAuth,	/* in, out */
			 UINT32 *outDataSize,	/* out */
			 BYTE **outData	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	TCS_KEY_HANDLE tcsKeyHandleToEvict;
	TSS_UUID *uuidKeyToEvict;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Changeauth");
	if ((result = ctx_verify_context(contextHandle)))
		return result;

	if ((result = auth_mgr_check(contextHandle, ownerAuth->AuthHandle)))
		return result;
	if ((result = auth_mgr_check(contextHandle, entityAuth->AuthHandle)))
		return result;

	if ((result = ensureKeyIsLoaded(contextHandle, parentHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "handle");
	LoadBlob_UINT16(&offset, protocolID, txBlob, "prot ID");
	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob,
			newAuth.authdata, "encauth");
	LoadBlob_UINT16(&offset, entityType, txBlob, "entity type");
	LoadBlob_UINT32(&offset, encDataSize, txBlob, "enc data size");
	LoadBlob(&offset, encDataSize, txBlob, encData, "enc data");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Auth(&offset, txBlob, entityAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, offset,
			TPM_ORD_ChangeAuth, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);
	if (entityAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(entityAuth->AuthHandle);


	if (!result) {
		UnloadBlob_UINT32(&offset, outDataSize, txBlob,
				  "out data size");
		*outData = getSomeMemory(*outDataSize, contextHandle);
		if (*outData == NULL) {
			LogError("malloc of %d bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, *outDataSize, txBlob, *outData, "outdata");
		}
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
		UnloadBlob_Auth(&offset, txBlob, entityAuth);

		/* if the malloc above failed, terminate the 2 new auth handles and exit */
		if (result) {
			auth_mgr_release_auth(ownerAuth->AuthHandle);
			auth_mgr_release_auth(entityAuth->AuthHandle);
			return result;
		}

		/****************************************
		 *	Check if ET is a key.  If it is, we need to 
		 *		1 - Evict the key if loaded
		 *		2 - update the knowledge entries where applicable.
		 *		3 - Update the PS if applicable.
		 *		4 - Reload the key ( optional ) - Not doing it here
		 ****************************************/
		if (entityType == TCPA_ET_KEYHANDLE ||
		    entityType == TCPA_ET_KEY) {
			LogDebug1("entity type is a key.  Check if storage/knowledge must be updated");
			/*---	Compare the EncData against the TCS tables */

			/*---	Check PS */
			LogDebug1("Checking PS");
			uuidKeyToEvict = getUUIDByEncData(encData);
#if 0
			uuidKeyToEvict = getUUIDByEncData( *outData );	/* use the new encdata to search since above might change it  */
#endif
			if (uuidKeyToEvict != NULL) {
				LogDebug1("UUID is not NULL, replace storage");
				replaceEncData_PS(*uuidKeyToEvict, encData, *outData);
			}

			tcsKeyHandleToEvict = getTCSKeyHandleByEncData(encData); /*    always 2K for keys */
			LogDebug("tcsKeyHandle being evicted is %.8X", tcsKeyHandleToEvict);
			/*---	If it was found in knowledge, replace it */
			if (tcsKeyHandleToEvict != 0) {
				key_mgr_evict(contextHandle, tcsKeyHandleToEvict);
				replaceEncData_knowledge(encData, *outData);
			}

		}
	}
/*	AppendAudit(0, TPM_ORD_ChangeAuth, result);	 */
	LogResult("ChangeAuth", result);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthOwner_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_PROTOCOL_ID protocolID,	/* in */
			      TCPA_ENCAUTH newAuth,	/* in */
			      TCPA_ENTITY_TYPE entityType,	/* in */
			      TPM_AUTH * ownerAuth	/* in, out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering ChangeAuthOwner");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_UINT16(&offset, protocolID, txBlob, "prot id");
	LoadBlob(&offset, 20, txBlob, newAuth.authdata, "enc auth");
	LoadBlob_UINT16(&offset, entityType, txBlob, "entity type");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset, TPM_ORD_ChangeAuthOwner, txBlob);

	if ((result = req_mgr_submit_req(txBlob))) {
		auth_mgr_release_auth(ownerAuth->AuthHandle);
		return result;
	}

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	AppendAudit(0, TPM_ORD_ChangeAuthOwner, result);
	LogResult("ChangeAuthOwner", result);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthAsymStart_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE idHandle,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  UINT32 KeySizeIn,	/* in */
				  BYTE * KeyDataIn,	/* in */
				  TPM_AUTH * pAuth,	/* in, out */
				  UINT32 * KeySizeOut,	/* out */
				  BYTE ** KeyDataOut,	/* out */
				  UINT32 * CertifyInfoSize,	/* out */
				  BYTE ** CertifyInfo,	/* out */
				  UINT32 * sigSize,	/* out */
				  BYTE ** sig,	/* out */
				  TCS_KEY_HANDLE * ephHandle	/* out */
    )
{

	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	UINT32 keySlot;
	TCPA_CERTIFY_INFO certifyInfo;
	TCPA_KEY tempKey;
	UINT32 tempSize;
	TCPA_KEY_PARMS keyParmsContainer;
	TSS_BOOL canLoad;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering ChangeAuthAsymStart");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (pAuth != NULL) {
		LogDebug1("Auth Command");
		if ((result = auth_mgr_check(hContext, pAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}

	if ((result = ensureKeyIsLoaded(hContext, idHandle, &keySlot)))
		return result;

	LogDebug1("Checking for room to load the eph key");
	offset = 0;
	if ((result = UnloadBlob_KEY_PARMS(&offset, KeyDataIn, &keyParmsContainer)))
		return result;

	/* if we can't load the key, evict keys until we can */
	if ((result = canILoadThisKey(&keyParmsContainer, &canLoad)))
		return result;

	while (canLoad == FALSE) {
		/* Evict a key that isn't the parent */
		if ((result = evictFirstKey(idHandle)))
			return result;

		if ((result = canILoadThisKey(&keyParmsContainer, &canLoad)))
			return result;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "idhandle");
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, antiReplay.nonce, "nonce");
/*	LoadBlob_KEY_PARMS( &offset, txBlob, &tempKeyParms ); */
/*	LoadBlob_UINT32( &offset, KeySizeIn, txBlob, "temp key size" ); */
	LoadBlob(&offset, KeySizeIn, txBlob, KeyDataIn, "Temp Key");

	if (pAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, pAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
				TPM_ORD_ChangeAuthAsymStart, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_ChangeAuthAsymStart, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (result == 0) {
		UnloadBlob_CERTIFY_INFO(&offset, txBlob,
					&certifyInfo);
		*CertifyInfoSize = offset - 10;
		*CertifyInfo = getSomeMemory(*CertifyInfoSize, hContext);
		if (*CertifyInfo == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*CertifyInfo, &txBlob[offset - *CertifyInfoSize],
		       *CertifyInfoSize);
		UnloadBlob_UINT32(&offset, sigSize, txBlob, "sig size");
		*sig = getSomeMemory(*sigSize, hContext);
		if (*sig == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig, "sig");
		UnloadBlob_UINT32(&offset, ephHandle, txBlob, "eph handle");
		tempSize = offset;
		UnloadBlob_KEY(&offset, txBlob, &tempKey);
		*KeySizeOut = offset - tempSize;
		*KeyDataOut = getSomeMemory(*KeySizeOut, hContext);
		if (*KeyDataOut == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*KeyDataOut, &txBlob[offset - *KeySizeOut], *KeySizeOut);
		if (pAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, pAuth);
	}

/*	AppendAudit(0, TPM_ORD_ChangeAuthAsymStart, result); */
	LogResult("ChangeAuthAsymStart", result);
	return result;
}

TSS_RESULT
TCSP_ChangeAuthAsymFinish_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE parentHandle,	/* in */
				   TCS_KEY_HANDLE ephHandle,	/* in */
				   TCPA_ENTITY_TYPE entityType,	/* in */
				   TCPA_HMAC newAuthLink,	/* in */
				   UINT32 newAuthSize,	/* in */
				   BYTE * encNewAuth,	/* in */
				   UINT32 encDataSizeIn,	/* in */
				   BYTE * encDataIn,	/* in */
				   TPM_AUTH * ownerAuth,	/* in, out */
				   UINT32 * encDataSizeOut,	/* out */
				   BYTE ** encDataOut,	/* out */
				   TCPA_SALT_NONCE * saltNonce,	/* out */
				   TCPA_DIGEST * changeProof	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	UINT32 keySlot;
#if 0
	TCPA_CERTIFY_INFO certifyInfo;
	TCPA_KEY tempKey;
	UINT32 tempSize;
#endif
	TCS_KEY_HANDLE tcsKeyHandleToEvict;
	TSS_UUID *uuidKeyToEvict;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering ChangeAuthAsymFinish");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (ownerAuth != NULL) {
		LogDebug1("Auth used");
		if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}
	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "idhandle");
	LoadBlob_UINT32(&offset, ephHandle, txBlob, "ephHandle");
	LoadBlob_UINT16(&offset, entityType, txBlob, "entity Type");
	LoadBlob(&offset, 20, txBlob, newAuthLink.digest, "newAuthLink");
	LoadBlob_UINT32(&offset, newAuthSize, txBlob, "newAuthSize");
	LoadBlob(&offset, newAuthSize, txBlob, encNewAuth, "encNewauth");
	LoadBlob_UINT32(&offset, encDataSizeIn, txBlob, "encDatasize ");
	LoadBlob(&offset, encDataSizeIn, txBlob, encDataIn, "encDataIn");

	if (ownerAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, ownerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
				TPM_ORD_ChangeAuthAsymFinish, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_ChangeAuthAsymFinish, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, encDataSizeOut, txBlob,
				  "outDataSize");
		*encDataOut = getSomeMemory(*encDataSizeOut, hContext);
		if (*encDataOut == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *encDataSizeOut, txBlob,
			   *encDataOut, "outData");
		UnloadBlob(&offset, 20, txBlob, saltNonce->nonce, "salt Nonce");
		UnloadBlob(&offset, 20, txBlob, changeProof->digest,
			   "changeProof");
		if (ownerAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, ownerAuth);

		/****************************************
		 *	Check if ET is a key.  If it is, we need to 
		 *		1 - Evict the key if loaded
		 *		2 - update the knowledge entries where applicable.
		 *		3 - Update the PS if applicable.
		 *		4 - Reload the key ( optional ) - Not doing it here
		 ****************************************/
		if (entityType == TCPA_ET_KEYHANDLE ||
		    entityType == TCPA_ET_KEY) {
			/*---	Compare the EncData against the TCS tables */
			tcsKeyHandleToEvict = getTCSKeyHandleByEncData(encDataIn);	/*  always 2K for keys */

			/*---	Check PS */
			uuidKeyToEvict = getUUIDByEncData(encDataIn);
			if (uuidKeyToEvict != NULL) {
				replaceEncData_PS(*uuidKeyToEvict,
						  encDataIn, *encDataOut);
			}

			/*---	If it was found in knowledge, replace it */
			if (tcsKeyHandleToEvict != 0) {
				key_mgr_evict(hContext, tcsKeyHandleToEvict);
				replaceEncData_knowledge(encDataIn, *encDataOut);
			}
		}
	}

/*	AppendAudit(0, TPM_ORD_ChangeAuthAsymFinish, result); */
	LogResult("ChangeAuthAsymFinish", result);
	return result;
}

TSS_RESULT
internal_TerminateHandle(TCS_AUTHHANDLE handle)
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	offset = 10;
	LoadBlob_UINT32(&offset, handle, txBlob, "handle");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_Terminate_Handle, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	return UnloadBlob_Header(txBlob, &paramSize);
}

TSS_RESULT
TCSP_TerminateHandle_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCS_AUTHHANDLE handle	/* in */
    )
{
	TSS_RESULT result;

	LogDebug1("Entering TCSI_TerminateHandle");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, handle)))
		return result;

	result = auth_mgr_release_auth(handle);

	LogResult("Terminate Handle", result);
	AppendAudit(0, TPM_ORD_Terminate_Handle, result);
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
				  BYTE ** SymmetricKey	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	UINT32 keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("TCSP_ActivateTPMIdentity");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (idKeyAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, idKeyAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}
	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	if ((result = ensureKeyIsLoaded(hContext, idKey, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "id key handle");
	LoadBlob_UINT32(&offset, blobSize, txBlob, "blob size");
	LoadBlob(&offset, blobSize, txBlob, blob, "in blob");
	if (idKeyAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, idKeyAuth);
		LoadBlob_Auth(&offset, txBlob, ownerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND,
				offset,
				TPM_ORD_ActivateTPMIdentity, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, ownerAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset,
				TPM_ORD_ActivateTPMIdentity, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (idKeyAuth && idKeyAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(idKeyAuth->AuthHandle);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		offset += 6;
		UnloadBlob_UINT16(&offset, (UINT16 *) SymmetricKeySize,
				  txBlob, "used to calculate size of symkey");
		*SymmetricKeySize += 8;
		offset = 10;
		*SymmetricKey = getSomeMemory(*SymmetricKeySize, hContext);
		if (*SymmetricKey == NULL) {
			LogError1("Malloc Failure.");
			result = TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *SymmetricKeySize, txBlob, *SymmetricKey, "sym key");

		if (idKeyAuth != NULL) {
			if (result) {
				UnloadBlob_Auth(&offset, txBlob, idKeyAuth);
			}
		}
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
/*	AppendAudit(0, TPM_ORD_ActivateTPMIdentity, result); */
	return result;
}

TSS_RESULT
TCSP_Extend_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		     TCPA_PCRINDEX pcrNum,	/* in */
		     TCPA_DIGEST inDigest,	/* in */
		     TCPA_PCRVALUE * outDigest	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Extend");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (pcrNum > tpm_metrics.num_pcrs)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if (tcsd_options.kernel_pcrs & (1 << pcrNum)) {
		LogInfo("PCR %d is configured to be kernel controlled. Extend request denied.",
				pcrNum);
		return TCSERR(TSS_E_FAIL);
	}

	if (tcsd_options.firmware_pcrs & (1 << pcrNum)) {
		LogInfo("PCR %d is configured to be firmware controlled. Extend request denied.",
				pcrNum);
		return TCSERR(TSS_E_FAIL);
	}

	offset = 10;

	LoadBlob_UINT32(&offset, pcrNum, txBlob, "pcrNum");
	LoadBlob(&offset, TCPA_DIGEST_SIZE, txBlob, inDigest.digest,
		 "in digest");

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_Extend, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob(&offset, TCPA_DIGEST_SIZE, txBlob,
			   outDigest->digest, "digest");
	}
	AppendAudit(0, TPM_ORD_Extend, result);
	LogResult("Extend", result);
	return result;
}

TSS_RESULT
TCSP_PcrRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCPA_PCRINDEX pcrNum,	/* in */
		      TCPA_PCRVALUE * outDigest	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering PCRRead");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (pcrNum > tpm_metrics.num_pcrs)
		return TCSERR(TSS_E_BAD_PARAMETER);

	offset = 10;
	LoadBlob_UINT32(&offset, pcrNum, txBlob, "pcrnum");

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_PcrRead, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob(&offset, TCPA_DIGEST_SIZE, txBlob,
			   outDigest->digest, "digest");
	}
	AppendAudit(0, TPM_ORD_PcrRead, result);
	LogResult("PCR Read", result);
	return result;
}

TSS_RESULT
TCSP_Quote_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		    TCS_KEY_HANDLE keyHandle,	/* in */
		    TCPA_NONCE antiReplay,	/* in */
		    UINT32 pcrDataSizeIn,	/* in */
		    BYTE * pcrDataIn,	/* in */
		    TPM_AUTH * privAuth,	/* in, out */
		    UINT32 * pcrDataSizeOut,	/* out */
		    BYTE ** pcrDataOut,	/* out */
		    UINT32 * sigSize,	/* out */
		    BYTE ** sig	/* out */
    )
{

	UINT16 offset = 0;
	UINT32 paramSize;
	TSS_RESULT result;
	UINT32 keySlot;
	TCPA_PCR_COMPOSITE pcrComp;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering quote");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, privAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}
	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "key handle");
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, antiReplay.nonce, "anti nonce");
	LoadBlob(&offset, pcrDataSizeIn, txBlob, pcrDataIn, "Pcr Data");
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_Quote, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_Quote, txBlob);
	}
	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (privAuth && privAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(privAuth->AuthHandle);

	if (!result) {
		UnloadBlob_PCR_COMPOSITE(&offset, txBlob, &pcrComp);
		*pcrDataSizeOut = offset - 10;
		*pcrDataOut = getSomeMemory(*pcrDataSizeOut, hContext);
		if (*pcrDataOut == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*pcrDataOut, &txBlob[10], *pcrDataSizeOut);
		UnloadBlob_UINT32(&offset, sigSize, txBlob, "sigsize");
		*sig = getSomeMemory(*sigSize, hContext);
		if (*sig == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig, "sig");
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
/*	AppendAudit(0, TPM_ORD_Quote, result); */
	LogResult("Quote", result);
	return result;
}

TSS_RESULT
TCSP_DirWriteAuth_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_DIRINDEX dirIndex,	/* in */
			   TCPA_DIRVALUE newContents,	/* in */
			   TPM_AUTH * ownerAuth	/* in, out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering dirwriteauth");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	if (dirIndex > tpm_metrics.num_dirs) {
		result = TCSERR(TSS_E_BAD_PARAMETER);
		return result;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, dirIndex, txBlob, "dir index");
	LoadBlob(&offset, TCPA_DIRVALUE_SIZE, txBlob,
			newContents.digest, "new contents");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_DirWriteAuth, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

#if 0
	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);
#endif

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	AppendAudit(0, TPM_ORD_DirWriteAuth, result);
	LogResult("DirWriteAuth", result);
	return result;
}

TSS_RESULT
TCSP_DirRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCPA_DIRINDEX dirIndex,	/* in */
		      TCPA_DIRVALUE * dirValue	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering DirRead");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (dirValue == NULL)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if (dirIndex > tpm_metrics.num_dirs)
		return TCSERR(TSS_E_BAD_PARAMETER);

	offset = 10;
	LoadBlob_UINT32(&offset, dirIndex, txBlob, "dir index");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_DirRead, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob(&offset, TCPA_DIRVALUE_SIZE, txBlob,
			   dirValue->digest, "digest");
	}
	AppendAudit(0, TPM_ORD_DirRead, result);
	LogResult("DirRead", result);
	return result;
}

TSS_RESULT
TCSP_Seal_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCS_KEY_HANDLE keyHandle,	/* in */
		   TCPA_ENCAUTH encAuth,	/* in */
		   UINT32 pcrInfoSize,	/* in */
		   BYTE * PcrInfo,	/* in */
		   UINT32 inDataSize,	/* in */
		   BYTE * inData,	/* in */
		   TPM_AUTH * pubAuth,	/* in, out */
		   UINT32 * SealedDataSize,	/* out */
		   BYTE ** SealedData	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	TCPA_KEY_HANDLE keySlot;
	TCPA_STORED_DATA storedData;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Seal");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (pubAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, pubAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	if (keySlot == 0) {
		result = TCSERR(TSS_E_FAIL);
		return result;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "handle");
	LoadBlob(&offset, TCPA_ENCAUTH_SIZE, txBlob,
			encAuth.authdata, "encauth");
	LoadBlob_UINT32(&offset, pcrInfoSize, txBlob, "pcr info size");
	LoadBlob(&offset, pcrInfoSize, txBlob, PcrInfo, "pcr info");
	LoadBlob_UINT32(&offset, inDataSize, txBlob, "in data size");
	LoadBlob(&offset, inDataSize, txBlob, inData, "in data");

	if (pubAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, pubAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_Seal, txBlob);

	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_Seal, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (pubAuth && pubAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(pubAuth->AuthHandle);

	if (!result) {
		TSS_RESULT tmp_result;
		if ((tmp_result = UnloadBlob_STORED_DATA(&offset, txBlob, &storedData)))
			return tmp_result;
		*SealedDataSize = offset - 10;
/*		UnloadBlob_UINT32( &offset, SealedDataSize, txBlob, "sealed data size" ); */
		*SealedData = getSomeMemory(*SealedDataSize, hContext);
		if (*SealedData == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*SealedData, &txBlob[10], *SealedDataSize);
/*		LoadBlob_STORED_DATA( &offset, *SealedData, &storedData ); */
		if (pubAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, pubAuth);
	}
/*	AppendAudit(0, TPM_ORD_Seal, result); */
	LogResult("Seal", result);
	return result;
}

TSS_RESULT
TCSP_Unseal_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		     TCS_KEY_HANDLE parentHandle,	/* in */
		     UINT32 SealedDataSize,	/* in */
		     BYTE * SealedData,	/* in */
		     TPM_AUTH * parentAuth,	/* in, out */
		     TPM_AUTH * dataAuth,	/* in, out */
		     UINT32 * DataSize,	/* out */
		     BYTE ** Data	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Unseal");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (parentAuth != NULL) {
		LogDebug1("Auth used");
		if ((result = auth_mgr_check(hContext, parentAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}

	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keySlot)))
		return result;

	if (keySlot == 0) {
		result = TCSERR(TSS_E_FAIL);
		return result;
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "handle");
	LoadBlob(&offset, SealedDataSize, txBlob, SealedData, "data");
	if (parentAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, parentAuth);
		LoadBlob_Auth(&offset, txBlob, dataAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND,
				offset, TPM_ORD_Unseal, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, dataAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_Unseal, txBlob);
	}
	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (parentAuth && parentAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(parentAuth->AuthHandle);
	if (dataAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(dataAuth->AuthHandle);

	if (!result) {
		UnloadBlob_UINT32(&offset, DataSize, txBlob,
				  "sealed data size");
		*Data = getSomeMemory(*DataSize, hContext);
		if (*Data == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *DataSize, txBlob, *Data, "sealed data");
		if (parentAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, parentAuth);
		UnloadBlob_Auth(&offset, txBlob, dataAuth);
	}
/*	AppendAudit(0, TPM_ORD_Unseal, result); */
	LogResult("Unseal", result);
	return result;
}

TSS_RESULT
TCSP_UnBind_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		     TCS_KEY_HANDLE keyHandle,	/* in */
		     UINT32 inDataSize,	/* in */
		     BYTE * inData,	/* in */
		     TPM_AUTH * privAuth,	/* in, out */
		     UINT32 * outDataSize,	/* out */
		     BYTE ** outData	/* out */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	UINT16 offset;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TCSI_UnBind");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, privAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}
	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "key handle");
	LoadBlob_UINT32(&offset, inDataSize, txBlob, "data size");
	LoadBlob(&offset, inDataSize, txBlob, inData, "in data");
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_UnBind, txBlob);
	} else
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_UnBind, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (privAuth && privAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(privAuth->AuthHandle);

	if (!result) {
		UnloadBlob_UINT32(&offset, outDataSize, txBlob, "out data size");
		*outData = getSomeMemory(*outDataSize, hContext);
		if (*outData == NULL) {
			LogError("malloc of %d bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, (*outDataSize), txBlob, *outData, "out data");
		}
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
/*	AppendAudit(0, TPM_ORD_UnBind, result); */
	LogResult("UnBind", result);

	if (result) {
		if (privAuth != NULL)
			auth_mgr_release_auth(privAuth->AuthHandle);
	}

	return result;
}

TSS_RESULT
TCSP_CreateMigrationBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE parentHandle,	/* in */
				  TCPA_MIGRATE_SCHEME migrationType,	/* in */
#if 0
				  TCPA_MIGRATION_SCHEME migrationType,  /* in */
#endif
				  UINT32 MigrationKeyAuthSize,	/* in */
				  BYTE * MigrationKeyAuth,	/* in */
				  UINT32 encDataSize,	/* in */
				  BYTE * encData,	/* in */
				  TPM_AUTH * parentAuth,	/* in, out */
				  TPM_AUTH * entityAuth,	/* in, out */
				  UINT32 * randomSize,	/* out */
				  BYTE ** random,	/* out */
				  UINT32 * outDataSize,	/* out */
				  BYTE ** outData	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keyHandle;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering TPM_CreateMigrationBlob");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (parentAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, parentAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("no Auth");
	}

	if ((result = auth_mgr_check(hContext, entityAuth->AuthHandle)))
		return result;

	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keyHandle)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keyHandle, txBlob, "parent handle");
	LoadBlob_UINT16(&offset, migrationType, txBlob, "mig type");
	LoadBlob(&offset, MigrationKeyAuthSize, txBlob,
			MigrationKeyAuth, "mig key auth");
	LoadBlob_UINT32(&offset, encDataSize, txBlob, "enc size");
	LoadBlob(&offset, encDataSize, txBlob, encData, "enc data");
	if (parentAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, parentAuth);
		LoadBlob_Auth(&offset, txBlob, entityAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND,
				offset,
				TPM_ORD_CreateMigrationBlob, txBlob);
	} else {
		LoadBlob_Auth(&offset, txBlob, entityAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset,
				TPM_ORD_CreateMigrationBlob, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (parentAuth && parentAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(parentAuth->AuthHandle);
	if (entityAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(entityAuth->AuthHandle);

	if (result == 0) {
		UnloadBlob_UINT32(&offset, randomSize, txBlob, "random size");
		*random = getSomeMemory(*randomSize, hContext);
		UnloadBlob(&offset, *randomSize, txBlob, *random, "random");
		UnloadBlob_UINT32(&offset, outDataSize, txBlob, "out data size");
		*outData = getSomeMemory(*outDataSize, hContext);
		if (*outData == NULL) {
			LogError("malloc of %d bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, *outDataSize, txBlob, *outData, "out data");
		}
		if (parentAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, parentAuth);
		UnloadBlob_Auth(&offset, txBlob, entityAuth);

		if (result)
			auth_mgr_release_auth(entityAuth->AuthHandle);
	}
/*	AppendAudit(0, TPM_ORD_CreateMigrationBlob, result); */
	LogResult("TPM_CreateMigrationBlob", result);
	return result;
}

TSS_RESULT
TCSP_ConvertMigrationBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE parentHandle,	/* in */
				   UINT32 inDataSize,	/* in */
				   BYTE * inData,	/* in */
				   TPM_AUTH * parentAuth,	/* in, out */
				   UINT32 randomSize,	/* should be in */
				   BYTE * random,	/* should be in */
				   UINT32 * outDataSize,	/* out */
				   BYTE ** outData	/* out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("ConvertMigBlob");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (parentAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, parentAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}
	if ((result = ensureKeyIsLoaded(hContext, parentHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "parent handle");
	LoadBlob_UINT32(&offset, inDataSize, txBlob, "in data size");
	LoadBlob(&offset, inDataSize, txBlob, inData, "in data");
	LoadBlob_UINT32(&offset, randomSize, txBlob, "random size");
	LoadBlob(&offset, randomSize, txBlob, random, "random");
	if (parentAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, parentAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset,
				TPM_ORD_ConvertMigrationBlob, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_ConvertMigrationBlob, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (parentAuth && parentAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(parentAuth->AuthHandle);

	if (!result) {
		UnloadBlob_UINT32(&offset, outDataSize, txBlob,
				  "out data size");
		*outData = getSomeMemory(*outDataSize, hContext);
		if (*outData == NULL) {
			LogError("malloc of %d bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, *outDataSize, txBlob, *outData, "out data");
		}
		if (parentAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, parentAuth);

		if (result)
			auth_mgr_release_auth(parentAuth->AuthHandle);
	}
/*	AppendAudit(0, TPM_ORD_ConvertMigrationBlob, result); */
	LogResult("***Leaving ConvertMigrationBlob with result ", result);
	return result;
}

TSS_RESULT
TCSP_AuthorizeMigrationKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
				    UINT32 MigrationKeySize,	/* in */
				    BYTE * MigrationKey,	/* in */
				    TPM_AUTH * ownerAuth,	/* in, out */
				    UINT32 * MigrationKeyAuthSize,	/* out */
				    BYTE ** MigrationKeyAuth	/* out */
    )
{

	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	TCPA_MIGRATIONKEYAUTH container;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("TCSP_AuthorizeMigrationKey");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_UINT16(&offset, migrateScheme, txBlob, "migation scheme");
	LoadBlob(&offset, MigrationKeySize, txBlob, MigrationKey, "pubKey");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_AuthorizeMigrationKey, txBlob);
	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_MIGRATIONKEYAUTH(&offset, txBlob, &container);
		*MigrationKeyAuthSize = offset - 10;
		*MigrationKeyAuth = getSomeMemory(*MigrationKeyAuthSize, hContext);
		if (*MigrationKeyAuth == NULL) {
			LogError("malloc of %d bytes failed.", *MigrationKeyAuthSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			memcpy(*MigrationKeyAuth, &txBlob[10], *MigrationKeyAuthSize);
		}

		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
		if (result)
			auth_mgr_release_auth(ownerAuth->AuthHandle);
	}
	AppendAudit(0, TPM_ORD_AuthorizeMigrationKey, result);
	LogResult("TPM_AuthorizeMigrationKey", result);
	return result;

}

TSS_RESULT
TCSP_CertifyKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCS_KEY_HANDLE certHandle,	/* in */
			 TCS_KEY_HANDLE keyHandle,	/* in */
			 TCPA_NONCE antiReplay,	/* in */
			 TPM_AUTH * certAuth,	/* in, out */
			 TPM_AUTH * keyAuth,	/* in, out */
			 UINT32 * CertifyInfoSize,	/* out */
			 BYTE ** CertifyInfo,	/* out */
			 UINT32 * outDataSize,	/* out */
			 BYTE ** outData	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE certKeySlot, keySlot;
	TCPA_CERTIFY_INFO certifyContainer;
	UINT16 tag;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Certify Key");
	offset = 10;
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (certAuth != NULL) {
		LogDebug1("Auth Used for Cert signing key");
		if ((result = auth_mgr_check(hContext, certAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth used for Cert signing key");
	}

	if (keyAuth != NULL) {
		LogDebug1("Auth Used for Key being signed");
		if ((result = auth_mgr_check(hContext, keyAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth used for Key being signed");
	}

	if ((result = ensureKeyIsLoaded(hContext, certHandle, &certKeySlot)))
		return result;

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	LoadBlob_UINT32(&offset, certKeySlot, txBlob, "cert handle");
	LoadBlob_UINT32(&offset, keySlot, txBlob, "key handle");
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob,
			antiReplay.nonce, "anti replay");

	tag = TPM_TAG_RQU_COMMAND;
	if (certAuth != NULL) {
		tag++;
		LoadBlob_Auth(&offset, txBlob, certAuth);
	}
	if (keyAuth != NULL) {
		tag++;
		LoadBlob_Auth(&offset, txBlob, keyAuth);
	}
	LoadBlob_Header(tag, offset, TPM_ORD_CertifyKey, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_CERTIFY_INFO(&offset, txBlob,
					&certifyContainer);
		*CertifyInfoSize = offset - 10;
		*CertifyInfo = getSomeMemory(*CertifyInfoSize, hContext);
		if (*CertifyInfo == NULL) {
			LogError("malloc of %d bytes failed.", *CertifyInfoSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			memcpy(*CertifyInfo, &txBlob[10], *CertifyInfoSize);
		}

		UnloadBlob_UINT32(&offset, outDataSize, txBlob, "out data size");
		*outData = getSomeMemory(*outDataSize, hContext);
		if (*outData == NULL) {
			LogError("malloc of %d bytes failed.", *outDataSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, *outDataSize, txBlob, *outData, "out data");
		}

		if (certAuth != NULL) {
			UnloadBlob_Auth(&offset, txBlob, certAuth);
		}
		if (keyAuth != NULL) {
			UnloadBlob_Auth(&offset, txBlob, keyAuth);
		}
	}
	LogResult("Certify Key", result);
	return result;
}

TSS_RESULT
TCSP_Sign_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
		   TCS_KEY_HANDLE keyHandle,	/* in */
		   UINT32 areaToSignSize,	/* in */
		   BYTE * areaToSign,	/* in */
		   TPM_AUTH * privAuth,	/* in, out */
		   UINT32 * sigSize,	/* out */
		   BYTE ** sig	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Sign");
	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, privAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	offset = 10;

	LoadBlob_UINT32(&offset, keySlot, txBlob, "key handle");
	LoadBlob_UINT32(&offset, areaToSignSize, txBlob, "size");
	LoadBlob(&offset, areaToSignSize, txBlob, areaToSign,
			"area to sign");
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_Sign, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_Sign, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (privAuth && privAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(privAuth->AuthHandle);

	if (!result) {
		UnloadBlob_UINT32(&offset, sigSize, txBlob, "sig size");
		*sig = getSomeMemory(*sigSize, hContext);
		if (*sig == NULL) {
			LogError("malloc of %d bytes failed.", *sigSize);
			if (privAuth != NULL)
				auth_mgr_release_auth(privAuth->AuthHandle);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig, "sig");
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
/*	AppendAudit(0, TPM_ORD_Sign, result); */
	LogResult("sign", result);
	return result;
}

TSS_RESULT
TCSP_GetRandom_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			UINT32 * bytesRequested,	/* in, out */
			BYTE ** randomBytes	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering get random");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, *bytesRequested, txBlob, "requested");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_GetRandom, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, bytesRequested, txBlob, "random bytes size");
		*randomBytes = getSomeMemory(*bytesRequested, hContext);
		if (*randomBytes == NULL) {
			LogError("malloc of %d bytes failed.", *bytesRequested);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *bytesRequested, txBlob, *randomBytes, "random bytes");
	}
	AppendAudit(0, TPM_ORD_GetRandom, result);
	LogResult("get random", result);
	return result;
}

TSS_RESULT
TCSP_StirRandom_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 UINT32 inDataSize,	/* in */
			 BYTE * inData	/* in */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering stir random");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, inDataSize, txBlob, "in data size");
	LoadBlob(&offset, inDataSize, txBlob, inData, "in data");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_StirRandom,
			txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Stir random", result);
	AppendAudit(0, TPM_ORD_StirRandom, result);
	return result;
}

TSS_RESULT
internal_TCSGetCap(TCS_CONTEXT_HANDLE hContext,
		   TCPA_CAPABILITY_AREA capArea,
		   UINT32 subCapSize, BYTE * subCap,
		   UINT32 * respSize, BYTE ** resp)
{
	UINT32 tcsSubCapContainer;
	UINT16 offset;
	TSS_RESULT result;
	TCPA_VERSION tcsVersion = INTERNAL_CAP_TCS_VERSION;
	char mfg[4] = INTERNAL_CAP_TCS_MANUFACTURER;

	if ((result = ctx_verify_context(hContext)))
		return result;

	LogDebug1("Checking Software Cap of TCS");
	switch (capArea) {
	case TSS_TCSCAP_ALG:
		LogDebug1("TSS_TCSCAP_ALG");
		tcsSubCapContainer = Decode_UINT32(subCap);
		*respSize = 1;
		*resp = getSomeMemory(1, hContext);
		if (*resp == NULL) {
			LogError("malloc of %d bytes failed.", 1);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		switch (tcsSubCapContainer) {
		case TSS_ALG_RSA:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_RSA;
			break;
		case TSS_ALG_DES:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_DES;
			break;
		case TSS_ALG_3DES:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_3DES;
			break;
		case TSS_ALG_SHA:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_SHA;
			break;
		case TSS_ALG_AES:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_AES;
			break;
		case TSS_ALG_HMAC:
			(*resp)[0] = INTERNAL_CAP_TCS_ALG_HMAC;
			break;
		default:
			return TCSERR(TSS_E_FAIL);	/*tcs error */
		}
		break;
	case TSS_TCSCAP_VERSION:
		LogDebug1("TSS_TCSCAP_VERSION");
		*resp = getSomeMemory(4, hContext);
		if (*resp == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		offset = 0;
		LoadBlob_VERSION(&offset, *resp, &tcsVersion);
		*respSize = offset;
		break;
	case TSS_TCSCAP_PERSSTORAGE:
		LogDebug1("TSS_TCSCAP_PERSSTORAGE");
		*respSize = 1;
		*resp = getSomeMemory(1, hContext);
		if (*resp == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		(*resp)[0] = INTERNAL_CAP_TCS_PERSSTORAGE;
		break;

	case TSS_TCSCAP_CACHING:
		LogDebug1("TSS_TCSCAP_CACHINE");
		tcsSubCapContainer = Decode_UINT32(subCap);
		if (tcsSubCapContainer == TSS_TCSCAP_PROP_KEYCACHE) {
			LogDebug1("PROP_KEYCACHE");
			*respSize = 1;
			*resp = getSomeMemory(1, hContext);
			if (*resp == NULL) {
				LogError1("Malloc Failure.");
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			(*resp)[0] = INTERNAL_CAP_TCS_CACHING_KEYCACHE;
		} else if (tcsSubCapContainer == TSS_TCSCAP_PROP_AUTHCACHE) {
			LogDebug1("PROP_AUTHCACHE");
			*respSize = 1;
			*resp = getSomeMemory(1, hContext);
			if (*resp == NULL) {
				LogError1("Malloc Failure.");
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			(*resp)[0] = INTERNAL_CAP_TCS_CACHING_AUTHCACHE;
		} else {
			LogDebug1("Bad subcap");
			return TCSERR(TSS_E_FAIL);
		}
		break;
	case TSS_TCSCAP_MANUFACTURER:
		LogDebug1("TSS_TCSCAP_MANUFACTURER");
		*resp = getSomeMemory(4, hContext);
		if (*resp == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*resp, mfg, 4);
		*respSize = 4;
		break;
	default:
		LogDebug1("Bad subcap");
		return TCSERR(TSS_E_FAIL);
	}

	LogDebug1("Passed internal GetCap");
	return TCPA_SUCCESS;
}

TSS_RESULT
TCS_GetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_CAPABILITY_AREA capArea,	/* in */
			   UINT32 subCapSize,	/* in */
			   BYTE * subCap,	/* in */
			   UINT32 * respSize,	/* out */
			   BYTE ** resp	/* out */
    )
{
	TSS_RESULT result;

	if ((result = ctx_verify_context(hContext)))
		return result;

	return internal_TCSGetCap(hContext, capArea, subCapSize, subCap,
				  respSize, resp);
}

TSS_RESULT
TCSP_GetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCPA_CAPABILITY_AREA capArea,	/* in */
			    UINT32 subCapSize,	/* in */
			    BYTE * subCap,	/* in */
			    UINT32 * respSize,	/* out */
			    BYTE ** resp	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	LogDebug1("Entering Get Cap");
	offset = 10;
	LoadBlob_UINT32(&offset, capArea, txBlob, "capArea");
	LoadBlob_UINT32(&offset, subCapSize, txBlob, "sub cap size");
	LoadBlob(&offset, subCapSize, txBlob, subCap, "sub cap");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_GetCapability, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, respSize, txBlob, "resp size");
		*resp = getSomeMemory(*respSize, hContext);
		if (*resp == NULL) {
			LogError("malloc of %d bytes failed.", *respSize);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *respSize, txBlob, *resp, "resp");
	}
	LogResult("Get Cap", result);
	AppendAudit(0, TPM_ORD_GetCapability, result);
	return result;
}

TSS_RESULT
TCSP_GetCapabilitySigned_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE keyHandle,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  TCPA_CAPABILITY_AREA capArea,	/* in */
				  UINT32 subCapSize,	/* in */
				  BYTE * subCap,	/* in */
				  TPM_AUTH * privAuth,	/* in, out */
				  TCPA_VERSION * Version,	/* out */
				  UINT32 * respSize,	/* out */
				  BYTE ** resp,	/* out */
				  UINT32 * sigSize,	/* out */
				  BYTE ** sig	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, privAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}

	switch (capArea) {
		case TSS_TCSCAP_ALG:
		case TSS_TCSCAP_VERSION:
		case TSS_TCSCAP_PERSSTORAGE:
		case TSS_TCSCAP_CACHING:
			result = TCSERR(TSS_E_FAIL);	/*can't sign software cap's */
			break;
	}

	LogDebug1("Entering Get Cap Signed");
	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "key handle");
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce, "anti replay");
	LoadBlob_UINT32(&offset, capArea, txBlob, "cap area");
	LoadBlob_UINT32(&offset, subCapSize, txBlob, "sub cap size");
	LoadBlob(&offset, subCapSize, txBlob, subCap, "sub cap");
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset,
				TPM_ORD_GetCapabilitySigned, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_GetCapabilitySigned, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (privAuth && privAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(privAuth->AuthHandle);

	if (!result) {
		UnloadBlob_VERSION(&offset, txBlob, Version);
		UnloadBlob_UINT32(&offset, respSize, txBlob, "respSize");
		*resp = getSomeMemory(*respSize, hContext);
		if (*resp == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *respSize, txBlob, *resp, "resp");
		UnloadBlob_UINT32(&offset, sigSize, txBlob, "sig size");
		*sig = getSomeMemory(*sigSize, hContext);
		if (*sig == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig, "sig");
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
/*	AppendAudit(0, TPM_ORD_GetCapabilitySigned, result); */
	LogResult("Get Cap signed", result);
	return result;
}

TSS_RESULT
TCSP_GetCapabilityOwner_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TPM_AUTH * pOwnerAuth,	/* out */
				 TCPA_VERSION * pVersion,	/* out */
				 UINT32 * pNonVolatileFlags,	/* out */
				 UINT32 * pVolatileFlags	/* out */
    )
{
	UINT16 offset;
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Getcap owner");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, pOwnerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, pOwnerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_GetCapabilityOwner, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (pOwnerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(pOwnerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_VERSION(&offset, txBlob, pVersion);
		UnloadBlob_UINT32(&offset, pNonVolatileFlags, txBlob,
				  "nonvolflags");
		UnloadBlob_UINT32(&offset, pVolatileFlags, txBlob, "vol flags");
		UnloadBlob_Auth(&offset, txBlob, pOwnerAuth);
	}
	AppendAudit(0, TPM_ORD_GetCapabilityOwner, result);
	LogResult("GetCapowner", result);
	return result;
}

TSS_RESULT
TCSP_CreateEndorsementKeyPair_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCPA_NONCE antiReplay,	/* in */
				       UINT32 endorsementKeyInfoSize,	/* in */
				       BYTE * endorsementKeyInfo,	/* in */
				       UINT32 * endorsementKeySize,	/* out */
				       BYTE ** endorsementKey,	/* out */
				       TCPA_DIGEST * checksum	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_PUBKEY pubKey;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("\nEntering TCSI_CreateEKPair:");
	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob, antiReplay.nonce,
		 "anit replay");
	LoadBlob(&offset, endorsementKeyInfoSize, txBlob,
		 endorsementKeyInfo, "ek stuff");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_CreateEndorsementKeyPair, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_PUBKEY(&offset, txBlob, &pubKey);
		*endorsementKeySize = offset - 10;
		*endorsementKey = getSomeMemory(*endorsementKeySize, hContext);
		if (*endorsementKey == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*endorsementKey, &txBlob[10], *endorsementKeySize);

		UnloadBlob(&offset, TCPA_DIGEST_SIZE, txBlob,
			   checksum->digest, "digest");
	}
	LogData("Leaving CreateEKPair with result:", result);
/*	AppendAudit(0, TPM_ORD_CreateEndorsementKeyPair, result); */
	return result;
}

TSS_RESULT
TCSP_ReadPubek_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCPA_NONCE antiReplay,	/* in */
			UINT32 * pubEndorsementKeySize,	/* out */
			BYTE ** pubEndorsementKey,	/* out */
			TCPA_DIGEST * checksum	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_PUBKEY pubkey;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("\nEntering ReadPubek");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce, "anti replay");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset, TPM_ORD_ReadPubek, txBlob);
	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (!result) {
		UnloadBlob_PUBKEY(&offset, txBlob, &pubkey);
		*pubEndorsementKeySize = (UINT32) (offset - 10);
		*pubEndorsementKey = getSomeMemory(*pubEndorsementKeySize, hContext);
		if (*pubEndorsementKey == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*pubEndorsementKey, &txBlob[10], *pubEndorsementKeySize);
		UnloadBlob(&offset, TCPA_DIGEST_SIZE, txBlob,
			   checksum->digest, "digest");
	}
	LogResult("Read Pubek", result);
/*	LogData( "Leaving ReadPubek with result:", result ); */
/*	AppendAudit(0, TPM_ORD_ReadPubek, result); */
	return result;
}

TSS_RESULT
TCSP_DisablePubekRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TPM_AUTH * ownerAuth	/* in, out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("DisablePubekRead");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_DisablePubekRead, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	AppendAudit(0, TPM_ORD_DisablePubekRead, result);
	return result;
}

TSS_RESULT
TCSP_OwnerReadPubek_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			     TPM_AUTH * ownerAuth,	/* in, out */
			     UINT32 * pubEndorsementKeySize,	/* out */
			     BYTE ** pubEndorsementKey	/* out */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	UINT16 offset;
	TCPA_PUBKEY container;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering OwnerReadPubek");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerReadPubek, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		offset = 10;
		UnloadBlob_PUBKEY(&offset, txBlob, &container);
		*pubEndorsementKeySize = offset - 10;
		*pubEndorsementKey = getSomeMemory(*pubEndorsementKeySize, hContext);
		if (*pubEndorsementKey == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		memcpy(*pubEndorsementKey, &txBlob[10], *pubEndorsementKeySize);
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Owner Read Pubek", result);
	return result;
}

TSS_RESULT
TCSP_SelfTestFull_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Self Test Full");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A, TPM_ORD_SelfTestFull,
			txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Self Test Full", result);
	AppendAudit(0, TPM_ORD_SelfTestFull, result);
	return result;
}

TSS_RESULT
TCSP_CertifySelfTest_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCS_KEY_HANDLE keyHandle,	/* in */
			      TCPA_NONCE antiReplay,	/* in */
			      TPM_AUTH * privAuth,	/* in, out */
			      UINT32 * sigSize,	/* out */
			      BYTE ** sig	/* out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Certify Self Test");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = auth_mgr_check(hContext, privAuth->AuthHandle)))
			return result;
	} else {
		LogDebug1("No Auth");
	}

	if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
		return result;

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "key handle");
	LoadBlob(&offset, TCPA_NONCE_SIZE, txBlob,
			antiReplay.nonce, "nonoce");
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_CertifySelfTest,
				txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_CertifySelfTest, txBlob);
	}

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (privAuth && privAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(privAuth->AuthHandle);

	if (!result) {
		UnloadBlob_UINT32(&offset, sigSize, txBlob, "sig size");
		*sig = getSomeMemory(*sigSize, hContext);
		if (*sig == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *sigSize, txBlob, *sig, "sig");
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
/*	AppendAudit(0, TPM_ORD_CertifySelfTest, result); */
	LogResult("Certify Self Test", result);
	return result;
}

TSS_RESULT
TCSP_GetTestResult_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			    UINT32 * outDataSize,	/* out */
			    BYTE ** outData	/* out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Get Test Result");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A, TPM_ORD_GetTestResult, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		UnloadBlob_UINT32(&offset, outDataSize, txBlob, "data size");
		*outData = getSomeMemory(*outDataSize, hContext);
		if (*outData == NULL) {
			LogError1("Malloc Failure.");
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		UnloadBlob(&offset, *outDataSize, txBlob, *outData, "outdata");
		LogDebug1("outdata");
		LogBlob(*outDataSize, *outData);
	}
	LogResult("Get Test Result", result);
	AppendAudit(0, TPM_ORD_GetTestResult, result);
	return result;
}

TSS_RESULT
TCSP_OwnerSetDisable_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TSS_BOOL disableState,	/* in */
			      TPM_AUTH * ownerAuth	/* in, out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	offset = 10;

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	LoadBlob_BOOL(&offset, disableState, txBlob, "State");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerSetDisable, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	AppendAudit(0, TPM_ORD_OwnerSetDisable, result);
	return result;
}

TSS_RESULT
TCSP_OwnerClear_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TPM_AUTH * ownerAuth	/* in, out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering OwnerClear");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_OwnerClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Ownerclear", result);
	AppendAudit(0, TPM_ORD_OwnerClear, result);
	return result;
}

TSS_RESULT
TCSP_DisableOwnerClear_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				TPM_AUTH * ownerAuth	/* in, out */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering DisableownerClear");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if ((result = auth_mgr_check(hContext, ownerAuth->AuthHandle)))
		return result;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);
	LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, offset,
			TPM_ORD_DisableOwnerClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	offset = 10;
	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("DisableOwnerClear", result);
	AppendAudit(0, TPM_ORD_DisableOwnerClear, result);
	return result;
}

TSS_RESULT
TCSP_ForceClear_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Force Clear");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A, TPM_ORD_ForceClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	AppendAudit(0, TPM_ORD_ForceClear, result);
	LogResult("Force Clear", result);
	return result;
}

TSS_RESULT
TCSP_DisableForceClear_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Disable Force Clear");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_DisableForceClear, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Disable Force Clear", result);
	AppendAudit(0, TPM_ORD_DisableForceClear, result);
	return result;

}

TSS_RESULT
TCSP_PhysicalPresence_Internal(TCS_CONTEXT_HANDLE hContext, /* in */
			TCPA_PHYSICAL_PRESENCE fPhysicalPresence /* in */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result = TCSERR(TSS_E_NOTIMPL);
	BYTE txBlob[TPM_TXBLOB_SIZE];
	char runlevel;

	runlevel = platform_get_runlevel();

	if (runlevel != 's' && runlevel != 'S' && runlevel != '1') {
		LogInfo("Physical Presence command denied: Must be in single"
				" user mode.");
		return TCSERR(TSS_E_NOTIMPL);
	}

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_UINT16(&offset, fPhysicalPresence, txBlob, NULL);
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_PhysicalPresence, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	return UnloadBlob_Header(txBlob, &paramSize);
}

TSS_RESULT
TCSP_PhysicalDisable_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Physical Disable");
	if ((result = ctx_verify_context(hContext)))
		return result;

	/* XXX ooh, magic */
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_PhysicalDisable, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Physical Disable", result);
	AppendAudit(0, TPM_ORD_PhysicalDisable, result);

	return result;
}

TSS_RESULT
TCSP_PhysicalEnable_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Physical Enable");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_PhysicalEnable, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("Physical Enable", result);
	AppendAudit(0, TPM_ORD_PhysicalEnable, result);

	return result;
}

TSS_RESULT
TCSP_PhysicalSetDeactivated_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TSS_BOOL state	/* in */
    )
{
	UINT16 offset;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Physical Set Decativated");
	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_BOOL(&offset, state, txBlob, "State");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_PhysicalSetDeactivated, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("PhysicalSetDeactivated", result);
	AppendAudit(0, TPM_ORD_PhysicalSetDeactivated, result);
	return result;
}

TSS_RESULT
TCSP_SetTempDeactivated_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
    )
{
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Set Temp Deactivated");
	if ((result = ctx_verify_context(hContext)))
		return result;

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, 0x0A,
			TPM_ORD_SetTempDeactivated, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	LogResult("SetTempDeactivated", result);
	AppendAudit(0, TPM_ORD_SetTempDeactivated, result);

	return result;
}

TSS_RESULT
TCSP_FieldUpgrade_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			   UINT32 dataInSize,	/* in */
			   BYTE * dataIn,	/* in */
			   UINT32 * dataOutSize,	/* out */
			   BYTE ** dataOut,	/* out */
			   TPM_AUTH * ownerAuth	/* in, out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Field Upgrade");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	if (dataInSize != 0) {
		LoadBlob_UINT32(&offset, dataInSize, txBlob,
				"data size");
		LoadBlob(&offset, dataInSize, txBlob, dataIn, "data");
	}
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_FieldUpgrade, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		offset = 10;
		if (dataInSize != 0) {
			UnloadBlob_UINT32(&offset, dataOutSize, txBlob, "size");
			*dataOut = getSomeMemory(*dataOutSize, hContext);
			if (*dataOut == NULL) {
				LogError1("Malloc Failure.");
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			UnloadBlob(&offset, *dataOutSize, txBlob,
				   *dataOut, "data");
		}
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Field Upgrade", result);
	return result;
}

TSS_RESULT
TCSP_SetRedirection_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			     TCS_KEY_HANDLE keyHandle,	/* in */
			     UINT32 c1,	/* in */
			     UINT32 c2,	/* in */
			     TPM_AUTH * privAuth	/* in, out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	TCPA_KEY_HANDLE keySlot;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Set Redirection");

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (privAuth != NULL) {
		LogDebug1("Auth Used");
		if ((result = ensureKeyIsLoaded(hContext, keyHandle, &keySlot)))
			return TCSERR(TSS_E_FAIL);
	} else {
		keySlot = getSlotByHandle_lock(keyHandle);
		if (keySlot == NULL_TPM_HANDLE)
			return TCSERR(TSS_E_FAIL);
		LogDebug1("No Auth");
	}

	offset = 10;
	LoadBlob_UINT32(&offset, keySlot, txBlob, "key slot");
	LoadBlob_UINT32(&offset, c1, txBlob, "c1");
	LoadBlob_UINT32(&offset, c2, txBlob, "c2");
	if (privAuth != NULL) {
		LoadBlob_Auth(&offset, txBlob, privAuth);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND,
				offset, TPM_ORD_SetRedirection, txBlob);
	} else {
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
				TPM_ORD_SetRedirection, txBlob);
	}
	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (privAuth && privAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(privAuth->AuthHandle);

	if (!result) {
		offset = 10;
		if (privAuth != NULL)
			UnloadBlob_Auth(&offset, txBlob, privAuth);
	}
	LogResult("Set Redirection", result);
	return result;
}

TSS_RESULT
TCSP_CreateMaintenanceArchive_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TSS_BOOL generateRandom,	/* in */
				       TPM_AUTH * ownerAuth,	/* in, out */
				       UINT32 * randomSize,	/* out */
				       BYTE ** random,	/* out */
				       UINT32 * archiveSize,	/* out */
				       BYTE ** archive	/* out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Create Main Archive");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_BOOL(&offset, generateRandom, txBlob, "gen rand");
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_CreateMaintenanceArchive, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		offset = 10;
		UnloadBlob_UINT32(&offset, randomSize, txBlob, "random size");
		*random = getSomeMemory(*randomSize, hContext);
		if (*random == NULL) {
			LogError("malloc of %d bytes failed.", *randomSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, *randomSize, txBlob, *random, "random");
		}

		UnloadBlob_UINT32(&offset, archiveSize, txBlob, "archive size");
		*archive = getSomeMemory(*archiveSize, hContext);
		if (*archive == NULL) {
			LogError("malloc of %d bytes failed.", *archiveSize);
			result = TCSERR(TSS_E_OUTOFMEMORY);
		} else {
			UnloadBlob(&offset, *archiveSize, txBlob, *archive, "archive");
		}

		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
		if (result)
			auth_mgr_release_auth(ownerAuth->AuthHandle);
	}
	LogResult("Create Main Archive", result);
	return result;
}

TSS_RESULT
TCSP_LoadMaintenanceArchive_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				     UINT32 dataInSize,	/* in */
				     BYTE * dataIn,	/* in */
				     UINT32 * dataOutSize,	/* out */
				     BYTE ** dataOut,	/* out */
				     TPM_AUTH * ownerAuth	/* in, out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Load Maint Archive");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	if (dataInSize != 0) {
		LoadBlob_UINT32(&offset, dataInSize, txBlob,
				"vendor data size");
		LoadBlob(&offset, dataInSize, txBlob, dataIn,
				"vendor data");
	}
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_LoadMaintenanceArchive, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		offset = 10;
		if (dataInSize != 0) {
			UnloadBlob_UINT32(&offset, dataOutSize, txBlob, "vendor data size");
			*dataOut = getSomeMemory(*dataOutSize, hContext);
			if (*dataOut == NULL) {
				LogError1("Malloc Failure.");
				return TCSERR(TSS_E_OUTOFMEMORY);
			}
			UnloadBlob(&offset, *dataOutSize, txBlob,
				   *dataOut, "vendor data");
		}
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Load Maint Archive", result);
	return result;
}

TSS_RESULT
TCSP_KillMaintenanceFeature_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TPM_AUTH * ownerAuth	/* in, out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Kill Maint Feature");

	if ((result = ctx_verify_context(hContext)))
		return result;

	offset = 10;
	LoadBlob_Auth(&offset, txBlob, ownerAuth);

	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_KillMaintenanceFeature, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);

	if (ownerAuth->fContinueAuthSession == FALSE)
		auth_mgr_release_auth(ownerAuth->AuthHandle);

	if (!result) {
		offset = 10;
		UnloadBlob_Auth(&offset, txBlob, ownerAuth);
	}
	LogResult("Kill Maint Feature", result);
	return result;
}

TSS_RESULT
TCSP_LoadManuMaintPub_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCPA_NONCE antiReplay,	/* in */
			       UINT32 PubKeySize,	/* in */
			       BYTE * PubKey,	/* in */
			       TCPA_DIGEST * checksum	/* out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Load Manu Maint Pub");

	offset = 10;
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce, "checksum");
	LoadBlob(&offset, PubKeySize, txBlob, PubKey, "pubkey");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_LoadManuMaintPub, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		offset = 10;
		UnloadBlob(&offset, 20, txBlob, checksum->digest, "checksum");
	}
	LogResult("Load Manu Maint Pub", result);
	return result;
}

TSS_RESULT
TCSP_ReadManuMaintPub_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCPA_NONCE antiReplay,	/* in */
			       TCPA_DIGEST * checksum	/* out */
    )
{
	TSS_RESULT result;
	UINT32 paramSize;
	UINT16 offset;
	BYTE txBlob[TPM_TXBLOB_SIZE];

	LogDebug1("Entering Read Manu Maint Pub");

	offset = 10;
	LoadBlob(&offset, 20, txBlob, antiReplay.nonce, "checksum");
	LoadBlob_Header(TPM_TAG_RQU_COMMAND, offset,
			TPM_ORD_ReadManuMaintPub, txBlob);

	if ((result = req_mgr_submit_req(txBlob)))
		return result;

	result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
		offset = 10;
		UnloadBlob(&offset, 20, txBlob, checksum->digest, "checksum");
	}
	LogResult("Read Manu Maint Pub", result);
	return result;
}
