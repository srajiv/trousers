
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
#include "rpc_tcstp_tsp.h"

TSS_RESULT
TCS_OpenContext_RPC(TSS_HCONTEXT tspContext, BYTE *hostname, int type)
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	struct host_table_entry *entry;

	/* add_table_entry() will make sure an entry doesn't already exist for this tsp context */
	if ((result = add_table_entry(tspContext, hostname, type, &entry)))
		return result;

	switch (type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			if ((result = TCS_OpenContext_RPC_TP(entry, &tcsContext)) == TSS_SUCCESS)
				entry->tcsContext = tcsContext;
			else
				remove_table_entry(tspContext);
			return result;
		default:
			break;
	}

	return TSPERR(TSS_E_INTERNAL_ERROR);
}

TSS_RESULT TCSP_GetRegisteredKeyByPublicInfo(TSS_HCONTEXT tspContext,
					     TCPA_ALGORITHM_ID algID, /* in */
					     UINT32 ulPublicInfoLength, /* in */
					     BYTE * rgbPublicInfo, /* in */
					     UINT32 * keySize, BYTE ** keyBlob)
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetRegisteredKeyByPublicInfo_TP(entry, algID,
								      ulPublicInfoLength,
								      rgbPublicInfo, keySize,
								      keyBlob);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_CloseContext(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			if ((result = TCS_CloseContext_TP(entry)) == TSS_SUCCESS) {
				close(entry->socket);
				remove_table_entry(tspContext);
			}
			break;
		default:
			break;
	}

	if (result != TSS_SUCCESS)
		put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_FreeMemory(TSS_HCONTEXT tspContext,	/* in */
			  BYTE * pMemory)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_FreeMemory_TP(entry, pMemory);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_LogPcrEvent(TSS_HCONTEXT tspContext,	/* in */
			   TSS_PCR_EVENT Event,	/* in */
			   UINT32 * pNumber)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_LogPcrEvent_TP(entry, Event, pNumber);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_GetPcrEvent(TSS_HCONTEXT tspContext,	/* in */
			   UINT32 PcrIndex,	/* in */
			   UINT32 * pNumber,	/* in, out */
			   TSS_PCR_EVENT ** ppEvent)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
		result =
			TCS_GetPcrEvent_TP(entry, PcrIndex, pNumber, ppEvent);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_GetPcrEventsByPcr(TSS_HCONTEXT tspContext,	/* in */
				 UINT32 PcrIndex,	/* in */
				 UINT32 FirstEvent,	/* in */
				 UINT32 * pEventCount,	/* in,out */
				 TSS_PCR_EVENT ** ppEvents)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_GetPcrEventsByPcr_TP(entry, PcrIndex, FirstEvent,
							  pEventCount, ppEvents);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_GetPcrEventLog(TSS_HCONTEXT tspContext,	/* in */
			      UINT32 * pEventCount,	/* out */
			      TSS_PCR_EVENT ** ppEvents)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_GetPcrEventLog_TP(entry, pEventCount, ppEvents);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_RegisterKey(TSS_HCONTEXT tspContext,	/* in */
			   TSS_UUID WrappingKeyUUID,	/* in */
			   TSS_UUID KeyUUID,	/* in */
			   UINT32 cKeySize,	/* in */
			   BYTE * rgbKey,	/* in */
			   UINT32 cVendorData,	/* in */
			   BYTE * gbVendorData)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_RegisterKey_TP(entry, WrappingKeyUUID, KeyUUID,
						    cKeySize, rgbKey, cVendorData, gbVendorData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_UnregisterKey(TSS_HCONTEXT tspContext,	/* in */
			      TSS_UUID KeyUUID)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_UnregisterKey_TP(entry, KeyUUID);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_EnumRegisteredKeys(TSS_HCONTEXT tspContext,	/* in */
				  TSS_UUID * pKeyUUID,	/* in */
				  UINT32 * pcKeyHierarchySize,	/* out */
				  TSS_KM_KEYINFO ** ppKeyHierarchy)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_EnumRegisteredKeys_TP(entry, pKeyUUID,
							   pcKeyHierarchySize, ppKeyHierarchy);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_GetRegisteredKey(TSS_HCONTEXT tspContext,	/* in */
				TSS_UUID KeyUUID,	/* in */
				TSS_KM_KEYINFO ** ppKeyInfo)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_GetRegisteredKey_TP(entry, KeyUUID, ppKeyInfo);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_GetRegisteredKeyBlob(TSS_HCONTEXT tspContext,	/* in */
				    TSS_UUID KeyUUID,	/* in */
				    UINT32 * pcKeySize,	/* out */
				    BYTE ** prgbKey)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_GetRegisteredKeyBlob_TP(entry, KeyUUID, pcKeySize,
							     prgbKey);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_LoadKeyByBlob(TSS_HCONTEXT tspContext,	/* in */
			      TCS_KEY_HANDLE hUnwrappingKey,	/* in */
			      UINT32 cWrappedKeyBlobSize,	/* in */
			      BYTE * rgbWrappedKeyBlob,	/* in */
			      TPM_AUTH * pAuth,	/* in, out */
			      TCS_KEY_HANDLE * phKeyTCSI,	/* out */
			      TCS_KEY_HANDLE * phKeyHMAC)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_LoadKeyByBlob_TP(entry, hUnwrappingKey,
						       cWrappedKeyBlobSize, rgbWrappedKeyBlob,
						       pAuth, phKeyTCSI, phKeyHMAC);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_LoadKeyByUUID(TSS_HCONTEXT tspContext,	/* in */
			      TSS_UUID KeyUUID,	/* in */
			      TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in, out */
			      TCS_KEY_HANDLE * phKeyTCSI)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_LoadKeyByUUID_TP(entry, KeyUUID, pLoadKeyInfo,
						       phKeyTCSI);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_EvictKey(TSS_HCONTEXT tspContext,	/* in */
			 TCS_KEY_HANDLE hKey)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_EvictKey_TP(entry, hKey);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_CreateWrapKey(TSS_HCONTEXT tspContext,	/* in */
			      TCS_KEY_HANDLE hWrappingKey,	/* in */
			      TCPA_ENCAUTH KeyUsageAuth,	/* in */
			      TCPA_ENCAUTH KeyMigrationAuth,	/* in */
			      UINT32 keyInfoSize,	/* in */
			      BYTE * keyInfo,	/* in */
			      UINT32 * keyDataSize,	/* out */
			      BYTE ** keyData,	/* out */
			      TPM_AUTH * pAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CreateWrapKey_TP(entry, hWrappingKey, KeyUsageAuth,
						       KeyMigrationAuth, keyInfoSize, keyInfo,
						       keyDataSize, keyData, pAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_GetPubKey(TSS_HCONTEXT tspContext,	/* in */
			   TCS_KEY_HANDLE hKey,	/* in */
			   TPM_AUTH * pAuth,	/* in, out */
			   UINT32 * pcPubKeySize,	/* out */
			   BYTE ** prgbPubKey)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetPubKey_TP(entry, hKey, pAuth, pcPubKeySize,
						   prgbPubKey);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_MakeIdentity(TSS_HCONTEXT tspContext,	/* in */
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
			     BYTE ** prgbConformanceCredential)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_MakeIdentity_TP(entry, identityAuth,
						      IDLabel_PrivCAHash, idKeyInfoSize, idKeyInfo,
						      pSrkAuth, pOwnerAuth, idKeySize, idKey,
						      pcIdentityBindingSize, prgbIdentityBinding,
						      pcEndorsementCredentialSize,
						      prgbEndorsementCredential,
						      pcPlatformCredentialSize,
						      prgbPlatformCredential,
						      pcConformanceCredentialSize,
						      prgbConformanceCredential);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_SetOwnerInstall(TSS_HCONTEXT tspContext,	/* in */
				TSS_BOOL state)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_SetOwnerInstall_TP(entry, state);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_TakeOwnership(TSS_HCONTEXT tspContext,	/* in */
			      UINT16 protocolID,	/* in */
			      UINT32 encOwnerAuthSize,	/* in */
			      BYTE * encOwnerAuth,	/* in */
			      UINT32 encSrkAuthSize,	/* in */
			      BYTE * encSrkAuth,	/* in */
			      UINT32 srkInfoSize,	/* in */
			      BYTE * srkInfo,	/* in */
			      TPM_AUTH * ownerAuth,	/* in, out */
			      UINT32 * srkKeySize,
			      BYTE ** srkKey)
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_TakeOwnership_TP(entry, protocolID,
						       encOwnerAuthSize, encOwnerAuth,
						       encSrkAuthSize, encSrkAuth, srkInfoSize,
						       srkInfo, ownerAuth, srkKeySize, srkKey);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_OIAP(TSS_HCONTEXT tspContext,	/* in */
		     TCS_AUTHHANDLE * authHandle,	/* out */
		     TCPA_NONCE * nonce0)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_OIAP_TP(entry, authHandle, nonce0);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_OSAP(TSS_HCONTEXT tspContext,	/* in */
		     TCPA_ENTITY_TYPE entityType,	/* in */
		     UINT32 entityValue,	/* in */
		     TCPA_NONCE nonceOddOSAP,	/* in */
		     TCS_AUTHHANDLE * authHandle,	/* out */
		     TCPA_NONCE * nonceEven,	/* out */
		     TCPA_NONCE * nonceEvenOSAP)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_OSAP_TP(entry, entityType, entityValue,
					      nonceOddOSAP, authHandle, nonceEven, nonceEvenOSAP);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ChangeAuth(TSS_HCONTEXT tspContext,	/* in */
			   TCS_KEY_HANDLE parentHandle,	/* in */
			   TCPA_PROTOCOL_ID protocolID,	/* in */
			   TCPA_ENCAUTH newAuth,	/* in */
			   TCPA_ENTITY_TYPE entityType,	/* in */
			   UINT32 encDataSize,	/* in */
			   BYTE * encData,	/* in */
			   TPM_AUTH * ownerAuth,	/* in, out */
			   TPM_AUTH * entityAuth,	/* in, out */
			   UINT32 * outDataSize,	/* out */
			   BYTE ** outData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ChangeAuth_TP(entry, parentHandle, protocolID,
						    newAuth, entityType, encDataSize, encData,
						    ownerAuth, entityAuth, outDataSize, outData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ChangeAuthOwner(TSS_HCONTEXT tspContext,	/* in */
				TCPA_PROTOCOL_ID protocolID,	/* in */
				TCPA_ENCAUTH newAuth,	/* in */
				TCPA_ENTITY_TYPE entityType,	/* in */
				TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ChangeAuthOwner_TP(entry, protocolID, newAuth,
							 entityType, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ChangeAuthAsymStart(TSS_HCONTEXT tspContext,	/* in */
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
				    TCS_KEY_HANDLE * ephHandle)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ChangeAuthAsymStart_TP(entry, idHandle, antiReplay,
							     KeySizeIn, KeyDataIn, pAuth,
							     KeySizeOut, KeyDataOut,
							     CertifyInfoSize, CertifyInfo, sigSize,
							     sig, ephHandle);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ChangeAuthAsymFinish(TSS_HCONTEXT tspContext,	/* in */
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
				     TCPA_DIGEST * changeProof)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ChangeAuthAsymFinish_TP(entry, parentHandle,
							      ephHandle, entityType, newAuthLink,
							      newAuthSize, encNewAuth,
							      encDataSizeIn, encDataIn, ownerAuth,
							      encDataSizeOut, encDataOut, saltNonce,
							      changeProof);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_TerminateHandle(TSS_HCONTEXT tspContext,	/* in */
				TCS_AUTHHANDLE handle)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_TerminateHandle_TP(entry, handle);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ActivateTPMIdentity(TSS_HCONTEXT tspContext,	/* in */
				    TCS_KEY_HANDLE idKey,	/* in */
				    UINT32 blobSize,	/* in */
				    BYTE * blob,	/* in */
				    TPM_AUTH * idKeyAuth,	/* in, out */
				    TPM_AUTH * ownerAuth,	/* in, out */
				    UINT32 * SymmetricKeySize,	/* out */
				    BYTE ** SymmetricKey)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ActivateTPMIdentity_TP(entry, idKey, blobSize, blob,
							     idKeyAuth, ownerAuth, SymmetricKeySize,
							     SymmetricKey);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_Extend(TSS_HCONTEXT tspContext,	/* in */
			TCPA_PCRINDEX pcrNum,	/* in */
			TCPA_DIGEST inDigest,	/* in */
			TCPA_PCRVALUE * outDigest)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_Extend_TP(entry, pcrNum, inDigest, outDigest);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_PcrRead(TSS_HCONTEXT tspContext,	/* in */
			TCPA_PCRINDEX pcrNum,	/* in */
			TCPA_PCRVALUE * outDigest)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_PcrRead_TP(entry, pcrNum, outDigest);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_PcrReset(TSS_HCONTEXT tspContext,	/* in */
			 UINT32 pcrDataSizeIn,		/* in */
			 BYTE * pcrDataIn)		/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_PcrReset_TP(entry, pcrDataSizeIn, pcrDataIn);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}


TSS_RESULT TCSP_Quote(TSS_HCONTEXT tspContext,	/* in */
		      TCS_KEY_HANDLE keyHandle,	/* in */
		      TCPA_NONCE antiReplay,	/* in */
		      UINT32 pcrDataSizeIn,	/* in */
		      BYTE * pcrDataIn,	/* in */
		      TPM_AUTH * privAuth,	/* in, out */
		      UINT32 * pcrDataSizeOut,	/* out */
		      BYTE ** pcrDataOut,	/* out */
		      UINT32 * sigSize,	/* out */
		      BYTE ** sig)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_Quote_TP(entry, keyHandle, antiReplay,
					       pcrDataSizeIn, pcrDataIn, privAuth, pcrDataSizeOut,
					       pcrDataOut, sigSize, sig);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_DirWriteAuth(TSS_HCONTEXT tspContext,	/* in */
			     TCPA_DIRINDEX dirIndex,	/* in */
			     TCPA_DIRVALUE newContents,	/* in */
			     TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DirWriteAuth_TP(entry, dirIndex, newContents,
						      ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_DirRead(TSS_HCONTEXT tspContext,	/* in */
			 TCPA_DIRINDEX dirIndex,	/* in */
			 TCPA_DIRVALUE * dirValue)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DirRead_TP(entry, dirIndex, dirValue);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_Seal(TSS_HCONTEXT tspContext,	/* in */
		     TCS_KEY_HANDLE keyHandle,	/* in */
		     TCPA_ENCAUTH encAuth,	/* in */
		     UINT32 pcrInfoSize,	/* in */
		     BYTE * PcrInfo,	/* in */
		     UINT32 inDataSize,	/* in */
		     BYTE * inData,	/* in */
		     TPM_AUTH * pubAuth,	/* in, out */
		     UINT32 * SealedDataSize,	/* out */
		     BYTE ** SealedData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_Seal_TP(entry, keyHandle, encAuth, pcrInfoSize,
					      PcrInfo, inDataSize, inData, pubAuth, SealedDataSize,
					      SealedData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_Unseal(TSS_HCONTEXT tspContext,	/* in */
		       TCS_KEY_HANDLE parentHandle,	/* in */
		       UINT32 SealedDataSize,	/* in */
		       BYTE * SealedData,	/* in */
		       TPM_AUTH * parentAuth,	/* in, out */
		       TPM_AUTH * dataAuth,	/* in, out */
		       UINT32 * DataSize,	/* out */
		       BYTE ** Data)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_Unseal_TP(entry, parentHandle, SealedDataSize,
						SealedData, parentAuth, dataAuth, DataSize, Data);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_UnBind(TSS_HCONTEXT tspContext,	/* in */
		       TCS_KEY_HANDLE keyHandle,	/* in */
		       UINT32 inDataSize,	/* in */
		       BYTE * inData,	/* in */
		       TPM_AUTH * privAuth,	/* in, out */
		       UINT32 * outDataSize,	/* out */
		       BYTE ** outData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_UnBind_TP(entry, keyHandle, inDataSize, inData,
						privAuth, outDataSize,
				   outData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_CreateMigrationBlob(TSS_HCONTEXT tspContext,	/* in */
				    TCS_KEY_HANDLE parentHandle,	/* in */
				    TCPA_MIGRATE_SCHEME migrationType,	/* in */
				    UINT32 MigrationKeyAuthSize,	/* in */
				    BYTE * MigrationKeyAuth,	/* in */
				    UINT32 encDataSize,	/* in */
				    BYTE * encData,	/* in */
				    TPM_AUTH * parentAuth,	/* in, out */
				    TPM_AUTH * entityAuth,	/* in, out */
				    UINT32 * randomSize,	/* out */
				    BYTE ** random,	/* out */
				    UINT32 * outDataSize,	/* out */
				    BYTE ** outData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CreateMigrationBlob_TP(entry, parentHandle,
							     migrationType, MigrationKeyAuthSize,
							     MigrationKeyAuth, encDataSize, encData,
							     parentAuth, entityAuth, randomSize,
							     random, outDataSize, outData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ConvertMigrationBlob(TSS_HCONTEXT tspContext,	/* in */
				     TCS_KEY_HANDLE parentHandle,	/* in */
				     UINT32 inDataSize,	/* in */
				     BYTE * inData,	/* in */
				     UINT32 randomSize,	/* in */
				     BYTE * random,	/* in */
				     TPM_AUTH * parentAuth,	/* in, out */
				     UINT32 * outDataSize,	/* out */
				     BYTE ** outData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ConvertMigrationBlob_TP(entry, parentHandle,
							      inDataSize, inData, randomSize,
							      random, parentAuth, outDataSize,
							      outData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_AuthorizeMigrationKey(TSS_HCONTEXT tspContext,	/* in */
				      TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
				      UINT32 MigrationKeySize,	/* in */
				      BYTE * MigrationKey,	/* in */
				      TPM_AUTH * ownerAuth,	/* in, out */
				      UINT32 * MigrationKeyAuthSize,	/* out */
				      BYTE ** MigrationKeyAuth)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_AuthorizeMigrationKey_TP(entry, migrateScheme,
							       MigrationKeySize, MigrationKey,
							       ownerAuth, MigrationKeyAuthSize,
							       MigrationKeyAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_CertifyKey(TSS_HCONTEXT tspContext,	/* in */
			   TCS_KEY_HANDLE certHandle,	/* in */
			   TCS_KEY_HANDLE keyHandle,	/* in */
			   TCPA_NONCE antiReplay,	/* in */
			   TPM_AUTH * certAuth,	/* in, out */
			   TPM_AUTH * keyAuth,	/* in, out */
			   UINT32 * CertifyInfoSize,	/* out */
			   BYTE ** CertifyInfo,	/* out */
			   UINT32 * outDataSize,	/* out */
			   BYTE ** outData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CertifyKey_TP(entry, certHandle, keyHandle,
						    antiReplay, certAuth, keyAuth, CertifyInfoSize,
						    CertifyInfo, outDataSize, outData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_Sign(TSS_HCONTEXT tspContext,	/* in */
		     TCS_KEY_HANDLE keyHandle,	/* in */
		     UINT32 areaToSignSize,	/* in */
		     BYTE * areaToSign,	/* in */
		     TPM_AUTH * privAuth,	/* in, out */
		     UINT32 * sigSize,	/* out */
		     BYTE ** sig)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_Sign_TP(entry, keyHandle, areaToSignSize,
					      areaToSign, privAuth, sigSize, sig);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_GetRandom(TSS_HCONTEXT tspContext,	/* in */
			  UINT32 bytesRequested,	/* in */
			  BYTE ** randomBytes)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetRandom_TP(entry, bytesRequested, randomBytes);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_StirRandom(TSS_HCONTEXT tspContext,	/* in */
			   UINT32 inDataSize,	/* in */
			   BYTE * inData)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_StirRandom_TP(entry, inDataSize, inData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCS_GetCapability(TSS_HCONTEXT tspContext,	/* in */
			     TCPA_CAPABILITY_AREA capArea,	/* in */
			     UINT32 subCapSize,	/* in */
			     BYTE * subCap,	/* in */
			     UINT32 * respSize,	/* out */
			     BYTE ** resp)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCS_GetCapability_TP(entry, capArea, subCapSize, subCap,
						      respSize, resp);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_SetCapability(TSS_HCONTEXT tspContext,	/* in */
			      TCPA_CAPABILITY_AREA capArea,	/* in */
			      UINT32 subCapSize,	/* in */
			      BYTE * subCap,	/* in */
			      UINT32 valueSize,	/* in */
			      BYTE * value,	/* in */
			      TPM_AUTH *ownerAuth) /* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_SetCapability_TP(entry, capArea, subCapSize, subCap,
						       valueSize, value, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_GetCapability(TSS_HCONTEXT tspContext,	/* in */
			      TCPA_CAPABILITY_AREA capArea,	/* in */
			      UINT32 subCapSize,	/* in */
			      BYTE * subCap,	/* in */
			      UINT32 * respSize,	/* out */
			      BYTE ** resp)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetCapability_TP(entry, capArea, subCapSize, subCap,
						       respSize, resp);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_GetCapabilitySigned(TSS_HCONTEXT tspContext,	/* in */
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
				    BYTE ** sig)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetCapabilitySigned_TP(entry, keyHandle, antiReplay,
							     capArea, subCapSize, subCap, privAuth,
							     Version, respSize, resp, sigSize, sig);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_GetCapabilityOwner(TSS_HCONTEXT tspContext,	/* in */
				    TPM_AUTH * pOwnerAuth,	/* out */
				    TCPA_VERSION * pVersion,	/* out */
				    UINT32 * pNonVolatileFlags,	/* out */
				    UINT32 * pVolatileFlags)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetCapabilityOwner_TP(entry, pOwnerAuth, pVersion,
							    pNonVolatileFlags, pVolatileFlags);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_CreateEndorsementKeyPair(TSS_HCONTEXT tspContext,	/* in */
					 TCPA_NONCE antiReplay,	/* in */
					 UINT32 endorsementKeyInfoSize,	/* in */
					 BYTE * endorsementKeyInfo,	/* in */
					 UINT32 * endorsementKeySize,	/* out */
					 BYTE ** endorsementKey,	/* out */
					 TCPA_DIGEST * checksum)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CreateEndorsementKeyPair_TP(entry, antiReplay,
								  endorsementKeyInfoSize,
								  endorsementKeyInfo,
								  endorsementKeySize,
								  endorsementKey, checksum);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ReadPubek(TSS_HCONTEXT tspContext,	/* in */
			  TCPA_NONCE antiReplay,	/* in */
			  UINT32 * pubEndorsementKeySize,	/* out */
			  BYTE ** pubEndorsementKey,	/* out */
			  TCPA_DIGEST * checksum)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ReadPubek_TP(entry, antiReplay,
						   pubEndorsementKeySize, pubEndorsementKey,
						   checksum);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_DisablePubekRead(TSS_HCONTEXT tspContext,	/* in */
				 TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DisablePubekRead_TP(entry, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_OwnerReadPubek(TSS_HCONTEXT tspContext,	/* in */
			       TPM_AUTH * ownerAuth,	/* in, out */
			       UINT32 * pubEndorsementKeySize,	/* out */
			       BYTE ** pubEndorsementKey)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_OwnerReadPubek_TP(entry, ownerAuth,
							pubEndorsementKeySize, pubEndorsementKey);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_SelfTestFull(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_SelfTestFull_TP(entry);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_CertifySelfTest(TSS_HCONTEXT tspContext,	/* in */
				TCS_KEY_HANDLE keyHandle,	/* in */
				TCPA_NONCE antiReplay,	/* in */
				TPM_AUTH * privAuth,	/* in, out */
				UINT32 * sigSize,	/* out */
				BYTE ** sig)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CertifySelfTest_TP(entry, keyHandle, antiReplay,
							 privAuth, sigSize, sig);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_GetTestResult(TSS_HCONTEXT tspContext,	/* in */
			      UINT32 * outDataSize,	/* out */
			      BYTE ** outData)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_GetTestResult_TP(entry, outDataSize, outData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_OwnerSetDisable(TSS_HCONTEXT tspContext,	/* in */
				TSS_BOOL disableState,	/* in */
				TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_OwnerSetDisable_TP(entry, disableState, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ResetLockValue(TSS_HCONTEXT tspContext,	/* in */
			       TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ResetLockValue_TP(entry, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_OwnerClear(TSS_HCONTEXT tspContext,	/* in */
			   TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_OwnerClear_TP(entry, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_DisableOwnerClear(TSS_HCONTEXT tspContext,	/* in */
				  TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DisableOwnerClear_TP(entry, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ForceClear(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ForceClear_TP(entry);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_DisableForceClear(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DisableForceClear_TP(entry);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_PhysicalDisable(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_PhysicalDisable_TP(entry);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_PhysicalEnable(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_PhysicalEnable_TP(entry);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_PhysicalSetDeactivated(TSS_HCONTEXT tspContext,	/* in */
				       TSS_BOOL state)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_PhysicalSetDeactivated_TP(entry, state);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_PhysicalPresence(TSS_HCONTEXT tspContext,	/* in */
				 TCPA_PHYSICAL_PRESENCE fPhysicalPresence)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_PhysicalPresence_TP(entry, fPhysicalPresence);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_SetTempDeactivated(TSS_HCONTEXT tspContext)	/* in */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_SetTempDeactivated_TP(entry);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_FieldUpgrade(TSS_HCONTEXT tspContext,	/* in */
			      UINT32 dataInSize,	/* in */
			      BYTE * dataIn,	/* in */
			      UINT32 * dataOutSize,	/* out */
			      BYTE ** dataOut,	/* out */
			      TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_SetRedirection(TSS_HCONTEXT tspContext,	/* in */
				TCS_KEY_HANDLE keyHandle,	/* in */
				UINT32 c1,	/* in */
				UINT32 c2,	/* in */
				TPM_AUTH * privAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = (UINT32) TSPERR(TSS_E_INTERNAL_ERROR);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_CreateMaintenanceArchive(TSS_HCONTEXT tspContext,	/* in */
					  TSS_BOOL generateRandom,	/* in */
					  TPM_AUTH * ownerAuth,	/* in, out */
					  UINT32 * randomSize,	/* out */
					  BYTE ** random,	/* out */
					  UINT32 * archiveSize,	/* out */
					  BYTE ** archive)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CreateMaintenanceArchive_TP(entry, generateRandom,
								  ownerAuth, randomSize, random,
								  archiveSize, archive);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_LoadMaintenanceArchive(TSS_HCONTEXT tspContext,	/* in */
					UINT32 dataInSize,	/* in */
					BYTE * dataIn, /* in */
					TPM_AUTH * ownerAuth,	/* in, out */
					UINT32 * dataOutSize,	/* out */
					BYTE ** dataOut)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_LoadMaintenanceArchive_TP(entry, dataInSize, dataIn,
								ownerAuth, dataOutSize, dataOut);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_KillMaintenanceFeature(TSS_HCONTEXT tspContext,	/* in */
					TPM_AUTH * ownerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_KillMaintenanceFeature_TP(entry, ownerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_LoadManuMaintPub(TSS_HCONTEXT tspContext,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  UINT32 PubKeySize,	/* in */
				  BYTE * PubKey,	/* in */
				  TCPA_DIGEST * checksum)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_LoadManuMaintPub_TP(entry, antiReplay, PubKeySize,
							  PubKey, checksum);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT TCSP_ReadManuMaintPub(TSS_HCONTEXT tspContext,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  TCPA_DIGEST * checksum)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ReadManuMaintPub_TP(entry, antiReplay, checksum);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_DaaJoin(TSS_HCONTEXT tspContext,	/* in */
	     TPM_HANDLE daa_session,		/* in */
	     BYTE stage,			/* in */
	     UINT32 inputSize0,			/* in */
	     BYTE* inputData0,			/* in */
	     UINT32 inputSize1,			/* in */
	     BYTE* inputData1,			/* in */
	     TPM_AUTH* ownerAuth,		/* in, out */
	     UINT32* outputSize,		/* out */
	     BYTE** outputData)			/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DaaJoin_TP(entry, daa_session, stage, inputSize0,
						 inputData0, inputSize1, inputData1, ownerAuth,
						 outputSize, outputData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;

}

TSS_RESULT
TCSP_DaaSign(TSS_HCONTEXT tspContext,	/* in */
	     TPM_HANDLE daa_session,		/* in */
	     BYTE stage,			/* in */
	     UINT32 inputSize0,			/* in */
	     BYTE* inputData0,			/* in */
	     UINT32 inputSize1,			/* in */
	     BYTE* inputData1,			/* in */
	     TPM_AUTH* ownerAuth,		/* in, out */
	     UINT32* outputSize,		/* out */
	     BYTE** outputData)			/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_DaaSign_TP(entry, daa_session, stage, inputSize0,
						 inputData0, inputSize1, inputData1, ownerAuth,
						 outputSize, outputData);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_ReadCounter(TSS_HCONTEXT       tspContext,		/* in */
		 TSS_COUNTER_ID     idCounter,		/* in */
		 TPM_COUNTER_VALUE* counterValue)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ReadCounter_TP(entry, idCounter, counterValue);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_CreateCounter(TSS_HCONTEXT       tspContext,	/* in */
		   UINT32             LabelSize,	/* in (=4) */
		   BYTE*              pLabel,		/* in */
		   TPM_ENCAUTH        CounterAuth,	/* in */
		   TPM_AUTH*          pOwnerAuth,	/* in, out */
		   TSS_COUNTER_ID*    idCounter,	/* out */
		   TPM_COUNTER_VALUE* counterValue)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_CreateCounter_TP(entry, LabelSize, pLabel, CounterAuth,
						       pOwnerAuth, idCounter, counterValue);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_IncrementCounter(TSS_HCONTEXT       tspContext,	/* in */
		      TSS_COUNTER_ID     idCounter,	/* in */
		      TPM_AUTH*          pCounterAuth,	/* in, out */
		      TPM_COUNTER_VALUE* counterValue)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_IncrementCounter_TP(entry, idCounter, pCounterAuth,
							  counterValue);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_ReleaseCounter(TSS_HCONTEXT   tspContext,		/* in */
		    TSS_COUNTER_ID idCounter,		/* in */
		    TPM_AUTH*      pCounterAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ReleaseCounter_TP(entry, idCounter, pCounterAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_ReleaseCounterOwner(TSS_HCONTEXT   tspContext,	/* in */
			 TSS_COUNTER_ID idCounter,	/* in */
			 TPM_AUTH*      pOwnerAuth)	/* in, out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ReleaseCounterOwner_TP(entry, idCounter, pOwnerAuth);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_ReadCurrentTicks(TSS_HCONTEXT tspContext,		/* in */
		      UINT32*      pulCurrentTime,	/* out */
		      BYTE**       prgbCurrentTime)	/* out */
{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_ReadCurrentTicks_TP(entry, pulCurrentTime, prgbCurrentTime);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}

TSS_RESULT
TCSP_TickStampBlob(TSS_HCONTEXT   tspContext,		/* in */
		   TCS_KEY_HANDLE hKey,			/* in */
		   TPM_NONCE*     antiReplay,		/* in */
		   TPM_DIGEST*    digestToStamp,	/* in */
		   TPM_AUTH*      privAuth,		/* in, out */
		   UINT32*        pulSignatureLength,	/* out */
		   BYTE**         prgbSignature,	/* out */
		   UINT32*        pulTickCountLength,	/* out */
		   BYTE**         prgbTickCount)	/* out */

{
	TSS_RESULT result = TSPERR(TSS_E_INTERNAL_ERROR);
	struct host_table_entry *entry = get_table_entry(tspContext);

	if (entry == NULL)
		return TSPERR(TSS_E_NO_CONNECTION);

	switch (entry->type) {
		case CONNECTION_TYPE_TCP_PERSISTANT:
			result = TCSP_TickStampBlob_TP(entry, hKey, antiReplay, digestToStamp,
						       privAuth, pulSignatureLength,
						       prgbSignature, pulTickCountLength,
						       prgbTickCount);
			break;
		default:
			break;
	}

	put_table_entry(entry);

	return result;
}
