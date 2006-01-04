
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
 *
 */

#ifndef _TROUSERS_TYPES_H_
#define _TROUSERS_TYPES_H_

typedef TCPA_NONCE		TCPA_SALT_NONCE;
#define TCPA_NONCE_SIZE		sizeof(TCPA_NONCE)
#define TCPA_DIGEST_SIZE	sizeof(TCPA_DIGEST)
#define TCPA_ENCAUTH_SIZE	sizeof(TCPA_ENCAUTH)
#define TCPA_DIRVALUE_SIZE	sizeof(TCPA_DIRVALUE)
#define TCPA_AUTHDATA_SIZE	sizeof(TCPA_AUTHDATA)

#define TSS_FLAG_MIGRATABLE	(migratable)
#define TSS_FLAG_VOLATILE	(volatileKey)
#define TSS_FLAG_REDIRECTION	(redirection)

/* return codes */
#define TCPA_E_INAPPROPRIATE_ENC	TCPA_E_NEED_SELFTEST

#define TSS_ERROR_LAYER(x)	(x & 0x3000)
#define TSS_ERROR_CODE(x)	(x & TSS_MAX_ERROR)

#define TSPERR(x)		(x | TSS_LAYER_TSP)
#define TCSERR(x)		(x | TSS_LAYER_TCS)
#define TDDLERR(x)		(x | TSS_LAYER_TDDL)

extern TSS_UUID	NULL_UUID;
extern TSS_UUID	SRK_UUID;

#define NULL_HOBJECT	0
#define NULL_HCONTEXT	NULL_HOBJECT
#define NULL_HPCRS	NULL_HOBJECT
#define NULL_HENCDATA	NULL_HOBJECT
#define NULL_HKEY	NULL_HOBJECT
#define NULL_HTPM	NULL_HOBJECT
#define NULL_HHASH	NULL_HOBJECT
#define NULL_HPOLICY	NULL_HOBJECT

#define TSS_OBJECT_TYPE_CONTEXT		(0x0e)
#define TSS_OBJECT_TYPE_TPM		(0x0f)

#define TSS_PS_TYPE_NO			(0)

/* ordinals */

#define TPM_ORD_OIAP				(TCPA_PROTECTED_ORDINAL + 10)
#define TPM_ORD_OSAP				(TCPA_PROTECTED_ORDINAL + 11)
#define TPM_ORD_ChangeAuth			(TCPA_PROTECTED_ORDINAL + 12)
#define TPM_ORD_TakeOwnership			(TCPA_PROTECTED_ORDINAL + 13)
#define TPM_ORD_ChangeAuthAsymStart		(TCPA_PROTECTED_ORDINAL + 14)
#define TPM_ORD_ChangeAuthAsymFinish		(TCPA_PROTECTED_ORDINAL + 15)
#define TPM_ORD_ChangeAuthOwner			(TCPA_PROTECTED_ORDINAL + 16)

#define TPM_ORD_Extend				(TCPA_PROTECTED_ORDINAL + 20)
#define TPM_ORD_PcrRead				(TCPA_PROTECTED_ORDINAL + 21)
#define TPM_ORD_Quote				(TCPA_PROTECTED_ORDINAL + 22)
#define TPM_ORD_Seal				(TCPA_PROTECTED_ORDINAL + 23)
#define TPM_ORD_Unseal				(TCPA_PROTECTED_ORDINAL + 24)
#define TPM_ORD_DirWriteAuth			(TCPA_PROTECTED_ORDINAL + 25)
#define TPM_ORD_DirRead				(TCPA_PROTECTED_ORDINAL + 26)

#define TPM_ORD_UnBind				(TCPA_PROTECTED_ORDINAL + 30)
#define TPM_ORD_CreateWrapKey			(TCPA_PROTECTED_ORDINAL + 31)
#define TPM_ORD_LoadKey				(TCPA_PROTECTED_ORDINAL + 32)
#define TPM_ORD_GetPubKey			(TCPA_PROTECTED_ORDINAL + 33)
#define TPM_ORD_EvictKey			(TCPA_PROTECTED_ORDINAL + 34)

#define TPM_ORD_CreateMigrationBlob		(TCPA_PROTECTED_ORDINAL + 40)
#define TPM_ORD_ReWrapKey			(TCPA_PROTECTED_ORDINAL + 41)
#define TPM_ORD_ConvertMigrationBlob		(TCPA_PROTECTED_ORDINAL + 42)
#define TPM_ORD_AuthorizeMigrationKey		(TCPA_PROTECTED_ORDINAL + 43)
#define TPM_ORD_CreateMaintenanceArchive	(TCPA_PROTECTED_ORDINAL + 44)
#define TPM_ORD_LoadMaintenanceArchive		(TCPA_PROTECTED_ORDINAL + 45)
#define TPM_ORD_KillMaintenanceFeature		(TCPA_PROTECTED_ORDINAL + 46)
#define TPM_ORD_LoadManuMaintPub		(TCPA_PROTECTED_ORDINAL + 47)
#define TPM_ORD_ReadManuMaintPub		(TCPA_PROTECTED_ORDINAL + 48)

#define TPM_ORD_CertifyKey			(TCPA_PROTECTED_ORDINAL + 50)

#define TPM_ORD_Sign				(TCPA_PROTECTED_ORDINAL + 60)

#define TPM_ORD_GetRandom			(TCPA_PROTECTED_ORDINAL + 70)
#define TPM_ORD_StirRandom			(TCPA_PROTECTED_ORDINAL + 71)

#define TPM_ORD_SelfTestFull			(TCPA_PROTECTED_ORDINAL + 80)
#define TPM_ORD_SelfTestStartup			(TCPA_PROTECTED_ORDINAL + 81)
#define TPM_ORD_CertifySelfTest			(TCPA_PROTECTED_ORDINAL + 82)
#define TPM_ORD_ContinueSelfTest		(TCPA_PROTECTED_ORDINAL + 83)
#define TPM_ORD_GetTestResult			(TCPA_PROTECTED_ORDINAL + 84)
#define TPM_ORD_Reset				(TCPA_PROTECTED_ORDINAL + 90)
#define TPM_ORD_OwnerClear			(TCPA_PROTECTED_ORDINAL + 91)
#define TPM_ORD_DisableOwnerClear		(TCPA_PROTECTED_ORDINAL + 92)
#define TPM_ORD_ForceClear			(TCPA_PROTECTED_ORDINAL + 93)
#define TPM_ORD_DisableForceClear		(TCPA_PROTECTED_ORDINAL + 94)

#define TPM_ORD_GetCapabilitySigned		(TCPA_PROTECTED_ORDINAL + 100)
#define TPM_ORD_GetCapability			(TCPA_PROTECTED_ORDINAL + 101)
#define TPM_ORD_GetCapabilityOwner		(TCPA_PROTECTED_ORDINAL + 102)

#define TPM_ORD_OwnerSetDisable			(TCPA_PROTECTED_ORDINAL + 110)
#define TPM_ORD_PhysicalEnable			(TCPA_PROTECTED_ORDINAL + 111)
#define TPM_ORD_PhysicalDisable			(TCPA_PROTECTED_ORDINAL + 112)
#define TPM_ORD_SetOwnerInstall			(TCPA_PROTECTED_ORDINAL + 113)
#define TPM_ORD_PhysicalSetDeactivated		(TCPA_PROTECTED_ORDINAL + 114)
#define TPM_ORD_SetTempDeactivated		(TCPA_PROTECTED_ORDINAL + 115)

#define TPM_ORD_CreateEndorsementKeyPair	(TCPA_PROTECTED_ORDINAL + 120)
#define TPM_ORD_MakeIdentity			(TCPA_PROTECTED_ORDINAL + 121)
#define TPM_ORD_ActivateTPMIdentity		(TCPA_PROTECTED_ORDINAL + 122)
#define TPM_ORD_ReadPubek			(TCPA_PROTECTED_ORDINAL + 124)
#define TPM_ORD_OwnerReadPubek			(TCPA_PROTECTED_ORDINAL + 125)
#define TPM_ORD_DisablePubekRead		(TCPA_PROTECTED_ORDINAL + 126)

#define TPM_ORD_GetAuditEvent			(TCPA_PROTECTED_ORDINAL + 130)
#define TPM_ORD_GetAuditEventSigned		(TCPA_PROTECTED_ORDINAL + 131)

#define TPM_ORD_GetOrdinalAuditStatus		(TCPA_PROTECTED_ORDINAL + 140)
#define TPM_ORD_SetOrdinalAuditStatus		(TCPA_PROTECTED_ORDINAL + 141)

#define TPM_ORD_Terminate_Handle		(TCPA_PROTECTED_ORDINAL + 150)
#define TPM_ORD_Init				(TCPA_PROTECTED_ORDINAL + 151)
#define TPM_ORD_SaveState			(TCPA_PROTECTED_ORDINAL + 152)
#define TPM_ORD_Startup				(TCPA_PROTECTED_ORDINAL + 153)
#define TPM_ORD_SetRedirection			(TCPA_PROTECTED_ORDINAL + 154)

#define TPM_ORD_SHA1Start			(TCPA_PROTECTED_ORDINAL + 160)
#define TPM_ORD_SHA1Update			(TCPA_PROTECTED_ORDINAL + 161)
#define TPM_ORD_SHA1Complete			(TCPA_PROTECTED_ORDINAL + 162)
#define TPM_ORD_SHA1CompleteExtend		(TCPA_PROTECTED_ORDINAL + 163)

#define TPM_ORD_FieldUpgrade			(TCPA_PROTECTED_ORDINAL + 170)

#define TPM_ORD_SaveKeyContext			(TCPA_PROTECTED_ORDINAL + 180)
#define TPM_ORD_LoadKeyContext			(TCPA_PROTECTED_ORDINAL + 181)
#define TPM_ORD_SaveAuthContext			(TCPA_PROTECTED_ORDINAL + 182)
#define TPM_ORD_LoadAuthContext			(TCPA_PROTECTED_ORDINAL + 183)

#define TPM_ORD_PhysicalPresence		(TCPA_CONNECTION_ORDINAL + 10)


/* TSS 1.2 stuff needed for backporting its functionality */

#define TPM_VERSION_BYTE	BYTE
typedef struct tdTPM_VERSION {
	TPM_VERSION_BYTE major;
	TPM_VERSION_BYTE minor;
	BYTE revMajor;
	BYTE revMinor;
} TPM_VERSION;

/* use these to detect a 1.2 TPM, support to follow */
#define TPM_CAP_PROP_MAX_AUTHSESS	0x0000010D
#define TPM_CAP_VERSION_VAL		0x0000001A
#define TPM_CAP_PROPERTY		TCPA_CAP_PROPERTY

/* XXX end 1.2 stuff */

typedef struct tdTCPA_PERSISTENT_DATA{
	BYTE revMajor;
	BYTE revMinor;
	TCPA_NONCE tpmProof;
	TCPA_PUBKEY manuMaintPub;
	TCPA_KEY endorsementKey;
	TCPA_SECRET ownerAuth;
	TCPA_KEY srk;
	TCPA_DIRVALUE* dir;
	BYTE* rngState;
	BYTE ordinalAuditStatus;
} TCPA_PERSISTENT_DATA;

typedef struct tdTCPA_PERSISTENT_FLAGS{
	TSS_BOOL disable;
	TSS_BOOL ownership;
	TSS_BOOL deactivated;
	TSS_BOOL readPubek;
	TSS_BOOL disableOwnerClear;
	TSS_BOOL allowMaintenance;
	TSS_BOOL physicalPresenceLifetimeLock;
	TSS_BOOL physicalPresenceHWEnable;
	TSS_BOOL physicalPresenceCMDEnable;
	TSS_BOOL CEKPUsed;
	TSS_BOOL TPMpost;
	TSS_BOOL TPMpostLock;
} TCPA_PERSISTENT_FLAGS;

typedef struct tdTCPA_VOLATILE_FLAGS{
	TSS_BOOL deactivated;
	TSS_BOOL disableForceClear;
	TSS_BOOL physicalPresence;
	TSS_BOOL physicalPresenceLock;
	TSS_BOOL postInitialise;
} TCPA_VOLATILE_FLAGS;

typedef struct tdTCPA_CHANGEAUTH_VALIDATE {
	TCPA_SECRET newAuthSecret;
	TCPA_NONCE n1;
} TCPA_CHANGEAUTH_VALIDATE;

typedef struct tdTCPA_AUDIT_EVENT {
	TCPA_COMMAND_CODE ordinal;
	TCPA_RESULT returncode;
} TCPA_AUDIT_EVENT;

typedef struct tdTCPA_EVENT_CERT {
	TCPA_DIGEST certificateHash;
	TCPA_DIGEST entityDigest;
	TSS_BOOL digestChecked;
	TSS_BOOL digestVerified;
	UINT32 issuerSize;
	BYTE *issuer;
} TCPA_EVENT_CERT;

typedef struct tdTCPA_BOUND_DATA {
	TCPA_VERSION ver;
	TCPA_PAYLOAD_TYPE payload;
	BYTE *payloadData;
} TCPA_BOUND_DATA;

typedef struct tdTCPA_MIGRATE_ASYMKEY {
	TCPA_PAYLOAD_TYPE payload;
	TCPA_SECRET usageAuth;
	TCPA_DIGEST pubDataDigest;
	UINT32 partPrivKeyLen;
	TCPA_STORE_PRIVKEY partPrivKey;
} TCPA_MIGRATE_ASYMKEY;

typedef struct tdTCPA_PRIVKEY {
	UINT32 Privlen;
	BYTE *Privkey;
} TCPA_PRIVKEY;

/***********************************************
Derived Types
************************************************/
#define TSS_MIGRATION_SCHEME	TSS_MIGRATE_SCHEME

#endif
