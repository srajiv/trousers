
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#ifndef _RPC_TCSTP_H_
#define _RPC_TCSTP_H_

#include "hosttable.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

int setData(BYTE,int,void *,int,struct tsp_packet *);
int getData(BYTE,int,void *,int,struct tcsd_packet_hdr *);
TSS_RESULT sendTCSDPacket(struct host_table_entry *,TCS_CONTEXT_HANDLE,struct tsp_packet *,struct tcsd_packet_hdr **);
TSS_RESULT send_init(struct host_table_entry *,BYTE *,int,struct tcsd_packet_hdr **);
TSS_RESULT sendit(struct host_table_entry *,BYTE *,int,struct tcsd_packet_hdr **);
short get_port();

/* Context commands always included */
TSS_RESULT TCS_OpenContext_RPC_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE *);
TSS_RESULT TCS_CloseContext_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE);
TSS_RESULT TCS_FreeMemory_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,BYTE *);

#ifdef TSS_BUILD_AUTH
TSS_RESULT TCSP_OIAP_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_AUTHHANDLE *,TCPA_NONCE *);
TSS_RESULT TCSP_OSAP_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_ENTITY_TYPE,UINT32,TCPA_NONCE,TCS_AUTHHANDLE *,TCPA_NONCE *,TCPA_NONCE *);
#else
#define TCSP_OIAP_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_OSAP_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_PCR_EVENTS
TSS_RESULT TCS_LogPcrEvent_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_PCR_EVENT,UINT32 *);
TSS_RESULT TCS_GetPcrEvent_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32,UINT32 *,TSS_PCR_EVENT **);
TSS_RESULT TCS_GetPcrEventLog_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32 *,TSS_PCR_EVENT **);
TSS_RESULT TCS_GetPcrEventsByPcr_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32,UINT32,UINT32 *,TSS_PCR_EVENT **);
#else
#define TCS_LogPcrEvent_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_GetPcrEvent_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_GetPcrEventLog_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_GetPcrEventsByPcr_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_PS
TSS_RESULT TCSP_GetRegisteredKeyByPublicInfo_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE tcsContext,TCPA_ALGORITHM_ID algID,UINT32,BYTE *,UINT32 *,BYTE **);
TSS_RESULT TCS_RegisterKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_UUID,TSS_UUID,UINT32,BYTE *,UINT32,BYTE *);
TSS_RESULT TCSP_UnregisterKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_UUID);
TSS_RESULT TCS_EnumRegisteredKeys_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_UUID *,UINT32 *,TSS_KM_KEYINFO **);
TSS_RESULT TCS_GetRegisteredKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_UUID,TSS_KM_KEYINFO **);
TSS_RESULT TCS_GetRegisteredKeyBlob_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_UUID,UINT32 *,BYTE **);
TSS_RESULT TCSP_LoadKeyByUUID_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_UUID,TCS_LOADKEY_INFO *,TCS_KEY_HANDLE *);
#else
#define TCSP_GetRegisteredKeyByPublicInfo_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_RegisterKey_TP(...)				TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_UnregisterKey_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_EnumRegisteredKeys_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_GetRegisteredKey_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#define TCS_GetRegisteredKeyBlob_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_LoadKeyByUUID_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_KEY
TSS_RESULT TCSP_LoadKeyByBlob_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,BYTE *,TPM_AUTH *,TCS_KEY_HANDLE *,TCS_KEY_HANDLE *);
TSS_RESULT TCSP_EvictKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE);
TSS_RESULT TCSP_CreateWrapKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_ENCAUTH,TCPA_ENCAUTH,UINT32,BYTE *,UINT32 *,BYTE **,TPM_AUTH *);
TSS_RESULT TCSP_GetPubKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_TerminateHandle_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_AUTHHANDLE);
#else
#define TCSP_LoadKeyByBlob_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_EvictKey_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_CreateWrapKey_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_GetPubKey_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_TerminateHandle_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_AIK
TSS_RESULT TCSP_MakeIdentity_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_ENCAUTH,TCPA_CHOSENID_HASH,UINT32,BYTE *,TPM_AUTH *,TPM_AUTH *,UINT32 *,BYTE **,UINT32 *,BYTE **,UINT32 *,BYTE **,UINT32 *,BYTE **,UINT32 *,BYTE **);
TSS_RESULT TCSP_ActivateTPMIdentity_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,BYTE *,TPM_AUTH *,TPM_AUTH *,UINT32 *,BYTE **);
#else
#define TCSP_MakeIdentity_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ActivateTPMIdentity_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_ADMIN
TSS_RESULT TCSP_SetOwnerInstall_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_BOOL);
TSS_RESULT TCSP_DisableOwnerClear_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TPM_AUTH *);
TSS_RESULT TCSP_ForceClear_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE hContext);
TSS_RESULT TCSP_DisableForceClear_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE hContext);
TSS_RESULT TCSP_PhysicalDisable_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE hContext);
TSS_RESULT TCSP_PhysicalEnable_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE hContext);
TSS_RESULT TCSP_PhysicalSetDeactivated_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_BOOL);
TSS_RESULT TCSP_PhysicalPresence_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_PHYSICAL_PRESENCE);
TSS_RESULT TCSP_SetTempDeactivated_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE hContext);
TSS_RESULT TCSP_FieldUpgrade_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32,BYTE *,UINT32 *,BYTE **,TPM_AUTH *);
TSS_RESULT TCSP_SetRedirection_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,UINT32,TPM_AUTH *);
TSS_RESULT TCSP_OwnerSetDisable_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_BOOL,TPM_AUTH *);
#else
#define TCSP_SetOwnerInstall_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_DisableOwnerClear_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ForceClear_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_DisableForceClear_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_PhysicalDisable_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_PhysicalEnable_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_PhysicalSetDeactivated_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_PhysicalPresence_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_SetTempDeactivated_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_FieldUpgrade_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_SetRedirection_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_OwnerSetDisable_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_OWN
TSS_RESULT TCSP_TakeOwnership_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT16,UINT32,BYTE *,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_OwnerClear_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TPM_AUTH *);
#else
#define TCSP_TakeOwnership_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_OwnerClear_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_CHANGEAUTH
TSS_RESULT TCSP_ChangeAuth_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_PROTOCOL_ID,TCPA_ENCAUTH,TCPA_ENTITY_TYPE,UINT32,BYTE *,TPM_AUTH *,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_ChangeAuthOwner_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_PROTOCOL_ID,TCPA_ENCAUTH,TCPA_ENTITY_TYPE,TPM_AUTH *);
TSS_RESULT TCSP_ChangeAuthAsymStart_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_NONCE,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **,UINT32 *,BYTE **,UINT32 *,BYTE **,TCS_KEY_HANDLE *);
TSS_RESULT TCSP_ChangeAuthAsymFinish_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCS_KEY_HANDLE,TCPA_ENTITY_TYPE,TCPA_HMAC,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **,TCPA_SALT_NONCE *,TCPA_DIGEST *);
#else
#define TCSP_ChangeAuth_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ChangeAuthOwner_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ChangeAuthAsymStart_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ChangeAuthAsymFinish_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_PCR_EXTEND
TSS_RESULT TCSP_Extend_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_PCRINDEX,TCPA_DIGEST,TCPA_PCRVALUE *);
TSS_RESULT TCSP_PcrRead_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_PCRINDEX,TCPA_PCRVALUE *);
#else
#define TCSP_Extend_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_PcrRead_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_QUOTE
TSS_RESULT TCSP_Quote_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_NONCE,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **,UINT32 *,BYTE **);
#else
#define TCSP_Quote_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_DIR
TSS_RESULT TCSP_DirWriteAuth_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_DIRINDEX,TCPA_DIRVALUE,TPM_AUTH *);
TSS_RESULT TCSP_DirRead_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_DIRINDEX,TCPA_DIRVALUE *);
#else
#define TCSP_DirWriteAuth_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_DirRead_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_SEAL
TSS_RESULT TCSP_Seal_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_ENCAUTH,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_Unseal_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,BYTE *,TPM_AUTH *,TPM_AUTH *,UINT32 *,BYTE **);
#else
#define TCSP_Seal_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_Unseal_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_BIND
TSS_RESULT TCSP_UnBind_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
#else
#define TCSP_UnBind_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_MIGRATION
TSS_RESULT TCSP_CreateMigrationBlob_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_MIGRATE_SCHEME,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,TPM_AUTH *,UINT32 *,BYTE **,UINT32 *,BYTE **);
TSS_RESULT TCSP_ConvertMigrationBlob_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_AuthorizeMigrationKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_MIGRATE_SCHEME,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
#else
#define TCSP_CreateMigrationBlob_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ConvertMigrationBlob_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_AuthorizeMigrationKey_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_CERTIFY
TSS_RESULT TCSP_CertifyKey_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCS_KEY_HANDLE,TCPA_NONCE,TPM_AUTH *,TPM_AUTH *,UINT32 *,BYTE **,UINT32 *,BYTE **);
#else
#define TCSP_CertifyKey_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_SIGN
TSS_RESULT TCSP_Sign_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
#else
#define TCSP_Sign_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_RANDOM
TSS_RESULT TCSP_GetRandom_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32,BYTE **);
TSS_RESULT TCSP_StirRandom_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32,BYTE *);
#else
#define TCSP_GetRandom_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_StirRandom_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_CAPS_TPM
TSS_RESULT TCSP_GetCapability_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_CAPABILITY_AREA,UINT32,BYTE *,UINT32 *,BYTE **);
TSS_RESULT TCSP_GetCapabilitySigned_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_NONCE,TCPA_CAPABILITY_AREA,UINT32,BYTE *,TPM_AUTH *,TCPA_VERSION *,UINT32 *,BYTE **,UINT32 *,BYTE **);
TSS_RESULT TCSP_GetCapabilityOwner_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TPM_AUTH *,TCPA_VERSION *,UINT32 *,UINT32 *);
#else
#define TCSP_GetCapability_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_GetCapabilitySigned_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_GetCapabilityOwner_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_CAPS
TSS_RESULT TCS_GetCapability_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_CAPABILITY_AREA,UINT32,BYTE *,UINT32 *,BYTE **);
#else
#define TCS_GetCapability_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_EK
TSS_RESULT TCSP_CreateEndorsementKeyPair_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_NONCE,UINT32,BYTE *,UINT32 *,BYTE **,TCPA_DIGEST *);
TSS_RESULT TCSP_ReadPubek_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_NONCE,UINT32 *,BYTE **,TCPA_DIGEST *);
TSS_RESULT TCSP_OwnerReadPubek_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_DisablePubekRead_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TPM_AUTH *);
#else
#define TCSP_DisablePubekRead_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_CreateEndorsementKeyPair_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ReadPubek_TP(...)			TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_OwnerReadPubek_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_SELFTEST
TSS_RESULT TCSP_SelfTestFull_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE hContext);
TSS_RESULT TCSP_CertifySelfTest_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCS_KEY_HANDLE,TCPA_NONCE,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_GetTestResult_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32 *,BYTE **);
#else
#define TCSP_SelfTestFull_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_CertifySelfTest_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_GetTestResult_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_MAINT
TSS_RESULT TCSP_CreateMaintenanceArchive_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TSS_BOOL,TPM_AUTH *,UINT32 *,BYTE **,UINT32 *,BYTE **);
TSS_RESULT TCSP_LoadMaintenanceArchive_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_KillMaintenanceFeature_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TPM_AUTH *);
TSS_RESULT TCSP_LoadManuMaintPub_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_NONCE,UINT32,BYTE *,TCPA_DIGEST *);
TSS_RESULT TCSP_ReadManuMaintPub_TP(struct host_table_entry *,TCS_CONTEXT_HANDLE,TCPA_NONCE,TCPA_DIGEST *);
#else
#define TCSP_CreateMaintenanceArchive_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_LoadMaintenanceArchive_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_KillMaintenanceFeature_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_LoadManuMaintPub_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_ReadManuMaintPub_TP(...)		TSPERR(TSS_E_INTERNAL_ERROR)
#endif

#ifdef TSS_BUILD_DAA
TSS_RESULT TCSP_DaaJoin_TP(struct host_table_entry *hte,TCS_CONTEXT_HANDLE,TSS_HDAA,BYTE,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
TSS_RESULT TCSP_DaaSign_TP(struct host_table_entry *hte,TCS_CONTEXT_HANDLE,TSS_HDAA,BYTE,UINT32,BYTE *,UINT32,BYTE *,TPM_AUTH *,UINT32 *,BYTE **);
#else
#define TCSP_DaaJoin_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#define TCSP_DaaSign_TP(...)	TSPERR(TSS_E_INTERNAL_ERROR)
#endif
#endif
