
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "hosttable.h"
#include "tsplog.h"
#include "trpctp.h"
#include "obj.h"

TSS_RESULT
TCS_OpenContext_RPC(BYTE *hostname, UINT32 *tcsContext, int type)
{
	TSS_RESULT result;
	struct host_table_entry *entry = NULL;

	entry = calloc(1, sizeof(struct host_table_entry));
	if (entry == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct host_table_entry));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	entry->hostname = hostname;
        entry->type = type;

	if (type == CONNECTION_TYPE_TCP_PERSISTANT) {
		/* lock all the way around the open context process. This will ensure that
		 * two sessions don't get opened with the same TCS and that then one has to
		 * be closed.
		 */
		pthread_mutex_lock(&(ht->lock));

		result = TCS_OpenContext_RPC_TP(entry, tcsContext);

		if (result == TSS_SUCCESS) {
			/* add_table_entry() will make sure an entry doesn't already exist
			 * for this tcs context */
			if ((result = add_table_entry(entry, *tcsContext))) {
				free(entry);
			}
		} else {
			free(entry);
		}

		pthread_mutex_unlock(&(ht->lock));

		return result;
	}

	free(entry);

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetRegisteredKeyByPublicInfo(TCS_CONTEXT_HANDLE tcsContext,
					     TCPA_ALGORITHM_ID algID, /* in */
					     UINT32 ulPublicInfoLength, /* in */
					     BYTE * rgbPublicInfo, /* in */
					     UINT32 * keySize, BYTE ** keyBlob
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(tcsContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetRegisteredKeyByPublicInfo_TP(entry,
							 tcsContext, algID,
							 ulPublicInfoLength,
							 rgbPublicInfo, keySize,
							 keyBlob);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_CloseContext(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		if ((result = TCS_CloseContext_TP(entry, hContext)) == TSS_SUCCESS) {
			close(entry->socket);
			remove_table_entry(hContext);
		}

		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_FreeMemory(TCS_CONTEXT_HANDLE hContext,	/* in */
			   BYTE * pMemory	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCS_FreeMemory_TP(entry, hContext, pMemory);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_LogPcrEvent(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TSS_PCR_EVENT Event,	/* in */
			    UINT32 * pNumber	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCS_LogPcrEvent_TP(entry, hContext, Event, pNumber);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_GetPcrEvent(TCS_CONTEXT_HANDLE hContext,	/* in */
			    UINT32 PcrIndex,	/* in */
			    UINT32 * pNumber,	/* in, out */
			    TSS_PCR_EVENT ** ppEvent	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_GetPcrEvent_TP(entry, hContext, PcrIndex,
				       pNumber, ppEvent);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_GetPcrEventsByPcr(TCS_CONTEXT_HANDLE hContext,	/* in */
				  UINT32 PcrIndex,	/* in */
				  UINT32 FirstEvent,	/* in */
				  UINT32 * pEventCount,	/* in,out */
				  TSS_PCR_EVENT ** ppEvents	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_GetPcrEventsByPcr_TP(entry, hContext,
					     PcrIndex, FirstEvent, pEventCount,
					     ppEvents);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_GetPcrEventLog(TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT32 * pEventCount,	/* out */
			       TSS_PCR_EVENT ** ppEvents	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_GetPcrEventLog_TP(entry, hContext,
					  pEventCount, ppEvents);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_RegisterKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TSS_UUID WrappingKeyUUID,	/* in */
			    TSS_UUID KeyUUID,	/* in */
			    UINT32 cKeySize,	/* in */
			    BYTE * rgbKey,	/* in */
			    UINT32 cVendorData,	/* in */
			    BYTE * gbVendorData	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_RegisterKey_TP(entry, hContext,
				       WrappingKeyUUID, KeyUUID, cKeySize,
				       rgbKey, cVendorData, gbVendorData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_UnregisterKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_UUID KeyUUID	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_UnregisterKey_TP(entry, hContext, KeyUUID);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_EnumRegisteredKeys(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TSS_UUID * pKeyUUID,	/* in */
				   UINT32 * pcKeyHierarchySize,	/* out */
				   TSS_KM_KEYINFO ** ppKeyHierarchy	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_EnumRegisteredKeys_TP(entry, hContext,
					      pKeyUUID, pcKeyHierarchySize,
					      ppKeyHierarchy);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_GetRegisteredKey(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TSS_UUID KeyUUID,	/* in */
				 TSS_KM_KEYINFO ** ppKeyInfo	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_GetRegisteredKey_TP(entry, hContext, KeyUUID,
					    ppKeyInfo);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_GetRegisteredKeyBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TSS_UUID KeyUUID,	/* in */
				     UINT32 * pcKeySize,	/* out */
				     BYTE ** prgbKey	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_GetRegisteredKeyBlob_TP(entry, hContext,
						KeyUUID, pcKeySize, prgbKey);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_LoadKeyByBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCS_KEY_HANDLE hUnwrappingKey,	/* in */
			       UINT32 cWrappedKeyBlobSize,	/* in */
			       BYTE * rgbWrappedKeyBlob,	/* in */
			       TPM_AUTH * pAuth,	/* in, out */
			       TCS_KEY_HANDLE * phKeyTCSI,	/* out */
			       TCS_KEY_HANDLE * phKeyHMAC	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_LoadKeyByBlob_TP(entry, hContext,
					  hUnwrappingKey, cWrappedKeyBlobSize,
					  rgbWrappedKeyBlob, pAuth, phKeyTCSI,
					  phKeyHMAC);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_LoadKeyByUUID(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_UUID KeyUUID,	/* in */
			       TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in, out */
			       TCS_KEY_HANDLE * phKeyTCSI	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_LoadKeyByUUID_TP(entry, hContext, KeyUUID,
					  pLoadKeyInfo, phKeyTCSI);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_EvictKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			  TCS_KEY_HANDLE hKey	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_EvictKey_TP(entry, hContext, hKey);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_CreateWrapKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCS_KEY_HANDLE hWrappingKey,	/* in */
			       TCPA_ENCAUTH KeyUsageAuth,	/* in */
			       TCPA_ENCAUTH KeyMigrationAuth,	/* in */
			       UINT32 keyInfoSize,	/* in */
			       BYTE * keyInfo,	/* in */
			       UINT32 * keyDataSize,	/* out */
			       BYTE ** keyData,	/* out */
			       TPM_AUTH * pAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_CreateWrapKey_TP(entry, hContext,
					  hWrappingKey, KeyUsageAuth,
					  KeyMigrationAuth, keyInfoSize,
					  keyInfo, keyDataSize, keyData, pAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetPubKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCS_KEY_HANDLE hKey,	/* in */
			   TPM_AUTH * pAuth,	/* in, out */
			   UINT32 * pcPubKeySize,	/* out */
			   BYTE ** prgbPubKey	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetPubKey_TP(entry, hContext, hKey, pAuth,
				      pcPubKeySize, prgbPubKey);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_MakeIdentity(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_ENCAUTH identityAuth,	/* in */
			      TCPA_CHOSENID_HASH IDLabel_PrivCAHash,	/* in */
			      UINT32 idKeyInfoSize,	/* in */
			      BYTE * idKeyInfo,	/* in */
			      TPM_AUTH * pSrkAuth,	/* in, out */
			      TPM_AUTH * pOwnerAuth,	/* in, out */
			      UINT32 * idKeySize,	/* out */
			      BYTE ** idKey,	/* out */
			      UINT32 * pcIdentityBindingSize,	/* out */
			      BYTE ** prgbIdentityBinding,	/* out */
			      UINT32 * pcEndorsementCredentialSize,	/* out */
			      BYTE ** prgbEndorsementCredential,	/* out */
			      UINT32 * pcPlatformCredentialSize,	/* out */
			      BYTE ** prgbPlatformCredential,	/* out */
			      UINT32 * pcConformanceCredentialSize,	/* out */
			      BYTE ** prgbConformanceCredential	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_MakeIdentity_TP(entry, hContext,
					 identityAuth, IDLabel_PrivCAHash,
					 idKeyInfoSize, idKeyInfo, pSrkAuth,
					 pOwnerAuth, idKeySize, idKey,
					 pcIdentityBindingSize,
					 prgbIdentityBinding,
					 pcEndorsementCredentialSize,
					 prgbEndorsementCredential,
					 pcPlatformCredentialSize,
					 prgbPlatformCredential,
					 pcConformanceCredentialSize,
					 prgbConformanceCredential);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_SetOwnerInstall(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TSS_BOOL state	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_SetOwnerInstall_TP(entry, hContext, state);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_TakeOwnership(TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT16 protocolID,	/* in */
/* UINT32					protocolID,		// in */
			       UINT32 encOwnerAuthSize,	/* in */
			       BYTE * encOwnerAuth,	/* in */
			       UINT32 encSrkAuthSize,	/* in */
			       BYTE * encSrkAuth,	/* in */
			       UINT32 srkInfoSize,	/* in */
			       BYTE * srkInfo,	/* in */
			       TPM_AUTH * ownerAuth,	/* in, out */
			       UINT32 * srkKeySize, BYTE ** srkKey) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_TakeOwnership_TP(entry, hContext,
					  protocolID, encOwnerAuthSize,
					  encOwnerAuth, encSrkAuthSize,
					  encSrkAuth, srkInfoSize, srkInfo,
					  ownerAuth, srkKeySize, srkKey);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_OIAP(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCS_AUTHHANDLE * authHandle,	/* out */
		      TCPA_NONCE * nonce0	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_OIAP_TP(entry, hContext, authHandle,
				 nonce0);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_OSAP(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCPA_ENTITY_TYPE entityType,	/* in */
		      UINT32 entityValue,	/* in */
		      TCPA_NONCE nonceOddOSAP,	/* in */
		      TCS_AUTHHANDLE * authHandle,	/* out */
		      TCPA_NONCE * nonceEven,	/* out */
		      TCPA_NONCE * nonceEvenOSAP	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_OSAP_TP(entry, hContext, entityType,
				 entityValue, nonceOddOSAP, authHandle,
				 nonceEven, nonceEvenOSAP);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ChangeAuth(TCS_CONTEXT_HANDLE contextHandle,	/* in */
			    TCS_KEY_HANDLE parentHandle,	/* in */
			    TCPA_PROTOCOL_ID protocolID,	/* in */
			    TCPA_ENCAUTH newAuth,	/* in */
			    TCPA_ENTITY_TYPE entityType,	/* in */
			    UINT32 encDataSize,	/* in */
			    BYTE * encData,	/* in */
			    TPM_AUTH * ownerAuth,	/* in, out */
			    TPM_AUTH * entityAuth,	/* in, out */
			    UINT32 * outDataSize,	/* out */
			    BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(contextHandle);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ChangeAuth_TP(entry, contextHandle,
				       parentHandle, protocolID, newAuth,
				       entityType, encDataSize, encData,
				       ownerAuth, entityAuth, outDataSize,
				       outData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ChangeAuthOwner(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_PROTOCOL_ID protocolID,	/* in */
				 TCPA_ENCAUTH newAuth,	/* in */
				 TCPA_ENTITY_TYPE entityType,	/* in */
				 TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ChangeAuthOwner_TP(entry, hContext,
					    protocolID, newAuth, entityType,
					    ownerAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ChangeAuthAsymStart(TCS_CONTEXT_HANDLE hContext,	/* in */
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
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ChangeAuthAsymStart_TP(entry, hContext,
						idHandle, antiReplay, KeySizeIn,
						KeyDataIn, pAuth, KeySizeOut,
						KeyDataOut, CertifyInfoSize,
						CertifyInfo, sigSize, sig,
						ephHandle);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ChangeAuthAsymFinish(TCS_CONTEXT_HANDLE hContext,	/* in */
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
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ChangeAuthAsymFinish_TP(entry, hContext,
						 parentHandle, ephHandle,
						 entityType, newAuthLink,
						 newAuthSize, encNewAuth,
						 encDataSizeIn, encDataIn,
						 ownerAuth, encDataSizeOut,
						 encDataOut, saltNonce,
						 changeProof);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_TerminateHandle(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_AUTHHANDLE handle	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_TerminateHandle_TP(entry, hContext, handle);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ActivateTPMIdentity(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE idKey,	/* in */
				     UINT32 blobSize,	/* in */
				     BYTE * blob,	/* in */
				     TPM_AUTH * idKeyAuth,	/* in, out */
				     TPM_AUTH * ownerAuth,	/* in, out */
				     UINT32 * SymmetricKeySize,	/* out */
				     BYTE ** SymmetricKey	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ActivateTPMIdentity_TP(entry, hContext,
						idKey, blobSize, blob,
						idKeyAuth, ownerAuth,
						SymmetricKeySize, SymmetricKey);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_Extend(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCPA_PCRINDEX pcrNum,	/* in */
			TCPA_DIGEST inDigest,	/* in */
			TCPA_PCRVALUE * outDigest	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_Extend_TP(entry, hContext, pcrNum, inDigest,
				   outDigest);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_PcrRead(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_PCRINDEX pcrNum,	/* in */
			 TCPA_PCRVALUE * outDigest	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_PcrRead_TP(entry, hContext, pcrNum,
				    outDigest);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_Quote(TCS_CONTEXT_HANDLE hContext,	/* in */
		       TCS_KEY_HANDLE keyHandle,	/* in */
		       TCPA_NONCE antiReplay,	/* in */
		       UINT32 pcrDataSizeIn,	/* in */
		       BYTE * pcrDataIn,	/* in */
		       TPM_AUTH * privAuth,	/* in, out */
		       UINT32 * pcrDataSizeOut,	/* out */
		       BYTE ** pcrDataOut,	/* out */
		       UINT32 * sigSize,	/* out */
		       BYTE ** sig	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_Quote_TP(entry, hContext, keyHandle,
				  antiReplay, pcrDataSizeIn, pcrDataIn,
				  privAuth, pcrDataSizeOut, pcrDataOut, sigSize,
				  sig);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_DirWriteAuth(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_DIRINDEX dirIndex,	/* in */
			      TCPA_DIRVALUE newContents,	/* in */
			      TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_DirWriteAuth_TP(entry, hContext, dirIndex,
					 newContents, ownerAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_DirRead(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_DIRINDEX dirIndex,	/* in */
			 TCPA_DIRVALUE * dirValue	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_DirRead_TP(entry, hContext, dirIndex,
				    dirValue);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_Seal(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCS_KEY_HANDLE keyHandle,	/* in */
		      TCPA_ENCAUTH encAuth,	/* in */
		      UINT32 pcrInfoSize,	/* in */
		      BYTE * PcrInfo,	/* in */
		      UINT32 inDataSize,	/* in */
		      BYTE * inData,	/* in */
		      TPM_AUTH * pubAuth,	/* in, out */
		      UINT32 * SealedDataSize,	/* out */
		      BYTE ** SealedData	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_Seal_TP(entry, hContext, keyHandle, encAuth,
				 pcrInfoSize, PcrInfo, inDataSize, inData,
				 pubAuth, SealedDataSize, SealedData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_Unseal(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCS_KEY_HANDLE parentHandle,	/* in */
			UINT32 SealedDataSize,	/* in */
			BYTE * SealedData,	/* in */
			TPM_AUTH * parentAuth,	/* in, out */
			TPM_AUTH * dataAuth,	/* in, out */
			UINT32 * DataSize,	/* out */
			BYTE ** Data	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_Unseal_TP(entry, hContext, parentHandle,
				   SealedDataSize, SealedData, parentAuth,
				   dataAuth, DataSize, Data);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_UnBind(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCS_KEY_HANDLE keyHandle,	/* in */
			UINT32 inDataSize,	/* in */
			BYTE * inData,	/* in */
			TPM_AUTH * privAuth,	/* in, out */
			UINT32 * outDataSize,	/* out */
			BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_UnBind_TP(entry, hContext, keyHandle,
				   inDataSize, inData, privAuth, outDataSize,
				   outData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_CreateMigrationBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE parentHandle,	/* in */
				     TCPA_MIGRATE_SCHEME migrationType,	/* in */
/* TCPA_MIGRATION_SCHEME	migrationType,				// in */
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
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_CreateMigrationBlob_TP(entry, hContext,
						parentHandle, migrationType,
						MigrationKeyAuthSize,
						MigrationKeyAuth, encDataSize,
						encData, parentAuth, entityAuth,
						randomSize, random, outDataSize,
						outData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ConvertMigrationBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
				      TCS_KEY_HANDLE parentHandle,	/* in */
				      UINT32 inDataSize,	/* in */
				      BYTE * inData,	/* in */
				      TPM_AUTH * parentAuth,	/* in, out */
				      UINT32 randomSize,	/*  should be in */
				      BYTE * random,	/*  should be in */
				      UINT32 * outDataSize,	/* out */
				      BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ConvertMigrationBlob_TP(entry, hContext,
						 parentHandle, inDataSize,
						 inData, parentAuth, randomSize,
						 random, outDataSize, outData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_AuthorizeMigrationKey(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
				       UINT32 MigrationKeySize,	/* in */
				       BYTE * MigrationKey,	/* in */
				       TPM_AUTH * ownerAuth,	/* in, out */
				       UINT32 * MigrationKeyAuthSize,	/* out */
				       BYTE ** MigrationKeyAuth	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_AuthorizeMigrationKey_TP(entry, hContext,
						  migrateScheme,
						  MigrationKeySize,
						  MigrationKey, ownerAuth,
						  MigrationKeyAuthSize,
						  MigrationKeyAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_CertifyKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCS_KEY_HANDLE certHandle,	/* in */
			    TCS_KEY_HANDLE keyHandle,	/* in */
			    TCPA_NONCE antiReplay,	/* in */
			    TPM_AUTH * certAuth,	/* in, out */
			    TPM_AUTH * keyAuth,	/* in, out */
			    UINT32 * CertifyInfoSize,	/* out */
			    BYTE ** CertifyInfo,	/* out */
			    UINT32 * outDataSize,	/* out */
			    BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_CertifyKey_TP(entry, hContext, certHandle,
				       keyHandle, antiReplay, certAuth, keyAuth,
				       CertifyInfoSize, CertifyInfo,
				       outDataSize, outData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_Sign(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCS_KEY_HANDLE keyHandle,	/* in */
		      UINT32 areaToSignSize,	/* in */
		      BYTE * areaToSign,	/* in */
		      TPM_AUTH * privAuth,	/* in, out */
		      UINT32 * sigSize,	/* out */
		      BYTE ** sig	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_Sign_TP(entry, hContext, keyHandle,
				 areaToSignSize, areaToSign, privAuth, sigSize,
				 sig);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetRandom(TCS_CONTEXT_HANDLE hContext,	/* in */
			   UINT32 bytesRequested,	/* in */
			   BYTE ** randomBytes	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);
	TSS_HCONTEXT tspContext;

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetRandom_TP(entry, hContext,
				      bytesRequested, randomBytes);

		if (result) {
			LogWarn("%s: TPM random generation failed. result=0x%x",
					__FUNCTION__, result);
			if ((tspContext = obj_lookupTspContext(hContext)) ==
							NULL_HCONTEXT) {
				LogError("TCS context not found: %x", hContext);
				return TSPERR(TSS_E_INTERNAL_ERROR);
			}
			result = get_local_random(tspContext, bytesRequested, randomBytes);
		}

		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_StirRandom(TCS_CONTEXT_HANDLE hContext,	/* in */
			    UINT32 inDataSize,	/* in */
			    BYTE * inData	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_StirRandom_TP(entry, hContext, inDataSize,
				       inData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCS_GetCapability(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_CAPABILITY_AREA capArea,	/* in */
			      UINT32 subCapSize,	/* in */
			      BYTE * subCap,	/* in */
			      UINT32 * respSize,	/* out */
			      BYTE ** resp	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCS_GetCapability_TP(entry, hContext, capArea,
					 subCapSize, subCap, respSize, resp);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetCapability(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCPA_CAPABILITY_AREA capArea,	/* in */
			       UINT32 subCapSize,	/* in */
			       BYTE * subCap,	/* in */
			       UINT32 * respSize,	/* out */
			       BYTE ** resp	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetCapability_TP(entry, hContext, capArea,
					  subCapSize, subCap, respSize, resp);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetCapabilitySigned(TCS_CONTEXT_HANDLE hContext,	/* in */
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
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetCapabilitySigned_TP(entry, hContext,
						keyHandle, antiReplay, capArea,
						subCapSize, subCap, privAuth,
						Version, respSize, resp,
						sigSize, sig);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetCapabilityOwner(TCS_CONTEXT_HANDLE hContext,	/* in */
				    TPM_AUTH * pOwnerAuth,	/* out */
				    TCPA_VERSION * pVersion,	/* out */
				    UINT32 * pNonVolatileFlags,	/* out */
				    UINT32 * pVolatileFlags	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetCapabilityOwner_TP(entry, hContext,
					       pOwnerAuth, pVersion,
					       pNonVolatileFlags,
					       pVolatileFlags);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_CreateEndorsementKeyPair(TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCPA_NONCE antiReplay,	/* in */
					  UINT32 endorsementKeyInfoSize,	/* in */
					  BYTE * endorsementKeyInfo,	/* in */
					  UINT32 * endorsementKeySize,	/* out */
					  BYTE ** endorsementKey,	/* out */
					  TCPA_DIGEST * checksum	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_CreateEndorsementKeyPair_TP(entry, hContext,
						     antiReplay,
						     endorsementKeyInfoSize,
						     endorsementKeyInfo,
						     endorsementKeySize,
						     endorsementKey, checksum);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ReadPubek(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_NONCE antiReplay,	/* in */
			   UINT32 * pubEndorsementKeySize,	/* out */
			   BYTE ** pubEndorsementKey,	/* out */
			   TCPA_DIGEST * checksum	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_ReadPubek_TP(entry, hContext, antiReplay,
				      pubEndorsementKeySize, pubEndorsementKey,
				      checksum);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_DisablePubekRead(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_DisablePubekRead_TP(entry, hContext,
					     ownerAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_OwnerReadPubek(TCS_CONTEXT_HANDLE hContext,	/* in */
				TPM_AUTH * ownerAuth,	/* in, out */
				UINT32 * pubEndorsementKeySize,	/* out */
				BYTE ** pubEndorsementKey	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_OwnerReadPubek_TP(entry, hContext,
					   ownerAuth, pubEndorsementKeySize,
					   pubEndorsementKey);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_SelfTestFull(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_SelfTestFull_TP(entry, hContext);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_CertifySelfTest(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_KEY_HANDLE keyHandle,	/* in */
				 TCPA_NONCE antiReplay,	/* in */
				 TPM_AUTH * privAuth,	/* in, out */
				 UINT32 * sigSize,	/* out */
				 BYTE ** sig	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_CertifySelfTest_TP(entry, hContext,
					    keyHandle, antiReplay, privAuth,
					    sigSize, sig);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetTestResult(TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT32 * outDataSize,	/* out */
			       BYTE ** outData	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_GetTestResult_TP(entry, hContext,
					  outDataSize, outData);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_OwnerSetDisable(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TSS_BOOL disableState,	/* in */
				 TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_OwnerSetDisable_TP(entry, hContext,
					    disableState, ownerAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_OwnerClear(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_OwnerClear_TP(entry, hContext, ownerAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_DisableOwnerClear(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_DisableOwnerClear_TP(entry, hContext,
					      ownerAuth);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ForceClear(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_ForceClear_TP(entry, hContext);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_DisableForceClear(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_DisableForceClear_TP(entry, hContext);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_PhysicalDisable(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_PhysicalDisable_TP(entry, hContext);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_PhysicalEnable(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_PhysicalEnable_TP(entry, hContext);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_PhysicalSetDeactivated(TCS_CONTEXT_HANDLE hContext,	/* in */
					TSS_BOOL state	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_PhysicalSetDeactivated_TP(entry, hContext,
						   state);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_PhysicalPresence(TCS_CONTEXT_HANDLE hContext,	/* in */
				TCPA_PHYSICAL_PRESENCE fPhysicalPresence	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result =
		    TCSP_PhysicalPresence_TP(entry, hContext, fPhysicalPresence);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_SetTempDeactivated(TCS_CONTEXT_HANDLE hContext	/* in */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = TCSP_SetTempDeactivated_TP(entry, hContext);
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_FieldUpgrade(TCS_CONTEXT_HANDLE hContext,	/* in */
			      UINT32 dataInSize,	/* in */
			      BYTE * dataIn,	/* in */
			      UINT32 * dataOutSize,	/* out */
			      BYTE ** dataOut,	/* out */
			      TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_SetRedirection(TCS_CONTEXT_HANDLE hContext,	/* in */
				TCS_KEY_HANDLE keyHandle,	/* in */
				UINT32 c1,	/* in */
				UINT32 c2,	/* in */
				TPM_AUTH * privAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_CreateMaintenanceArchive(TCS_CONTEXT_HANDLE hContext,	/* in */
					  TSS_BOOL generateRandom,	/* in */
					  TPM_AUTH * ownerAuth,	/* in, out */
					  UINT32 * randomSize,	/* out */
					  BYTE ** random,	/* out */
					  UINT32 * archiveSize,	/* out */
					  BYTE ** archive	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_LoadMaintenanceArchive(TCS_CONTEXT_HANDLE hContext,	/* in */
					UINT32 dataInSize,	/* in */
					BYTE * dataIn, /* in */
					TPM_AUTH * ownerAuth,	/* in, out */
					UINT32 * dataOutSize,	/* out */
					BYTE ** dataOut	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_KillMaintenanceFeature(TCS_CONTEXT_HANDLE hContext,	/* in */
					TPM_AUTH * ownerAuth	/* in, out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_LoadManuMaintPub(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  UINT32 PubKeySize,	/* in */
				  BYTE * PubKey,	/* in */
				  TCPA_DIGEST * checksum	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_ReadManuMaintPub(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  TCPA_DIGEST * checksum	/* out */
    ) {
	TSS_RESULT result;
	struct host_table_entry *entry = get_table_entry(hContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	if (entry->type == CONNECTION_TYPE_TCP_PERSISTANT) {
		result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);	/* function call */
		return result;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}
