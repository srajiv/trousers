
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _TCPA_LITERALS_H_
#define _TCPA_LITERALS_H_

/* These will indicate a vendor specific return from the chip */
#define TCPA_Vendor_Specific32	0x00000400
#define TCPA_Vendor_Specific8	0x80

/* Return codes we may get from the chip (v1.1) */
#define TCPA_BASE		0x0
#define TCPA_SUCCESS		TCPA_BASE
#define TCPA_VENDOR_ERROR	TCPA_Vendor_Specific32
#define TCPA_NON_FATAL		0x00000800
#define TCPA_AUTHFAIL		(TCPA_BASE + 1)
#define TCPA_BADINDEX		(TCPA_BASE + 2)
#define TCPA_BADPARAMETER	(TCPA_BASE + 3)
#define TCPA_AUDITFAILURE	(TCPA_BASE + 4)
#define TCPA_CLEAR_DISABLED	(TCPA_BASE + 5)
#define TCPA_DEACTIVATED	(TCPA_BASE + 6)
#define TCPA_DISABLED		(TCPA_BASE + 7)
#define TCPA_DISABLED_CMD	(TCPA_BASE + 8)
#define TCPA_FAIL		(TCPA_BASE + 9)
#define TCPA_BAD_ORDINAL	(TCPA_BASE + 10)
#define TCPA_INSTALL_DISABLED	(TCPA_BASE + 11)
#define TCPA_INVALID_KEYHANDLE	(TCPA_BASE + 12)
#define TCPA_KEYNOTFOUND	(TCPA_BASE + 13)
#define TCPA_INAPPROPRIATE_ENC	(TCPA_BASE + 14)
#define TCPA_MIGRATE_FAIL	(TCPA_BASE + 15)
#define TCPA_INVALID_PCR_INFO	(TCPA_BASE + 16)
#define TCPA_NOSPACE		(TCPA_BASE + 17)
#define TCPA_NOSRK		(TCPA_BASE + 18)
#define TCPA_NOTSEALED_BLOB	(TCPA_BASE + 19)
#define TCPA_OWNER_SET		(TCPA_BASE + 20)
#define TCPA_RESOURCES		(TCPA_BASE + 21)
#define TCPA_SHORTRANDOM	(TCPA_BASE + 22)
#define TCPA_SIZE		(TCPA_BASE + 23)
#define TCPA_WRONGPCRVAL	(TCPA_BASE + 24)
#define TCPA_BAD_PARAM_SIZE	(TCPA_BASE + 25)
#define TCPA_SHA_THREAD		(TCPA_BASE + 26)
#define TCPA_SHA_ERROR		(TCPA_BASE + 27)
#define TCPA_FAILEDSELFTEST	(TCPA_BASE + 28)
#define TCPA_AUTH2FAIL		(TCPA_BASE + 29)
#define TCPA_BADTAG		(TCPA_BASE + 30)
#define TCPA_IOERROR		(TCPA_BASE + 31)
#define TCPA_ENCRYPT_ERROR	(TCPA_BASE + 32)
#define TCPA_DECRYPT_ERROR	(TCPA_BASE + 33)
#define TCPA_INVALID_AUTHHANDLE	(TCPA_BASE + 34)
#define TCPA_NO_ENDORSEMENT	(TCPA_BASE + 35)
#define TCPA_INVALID_KEYUSAGE	(TCPA_BASE + 36)
#define TCPA_WRONG_ENTITYTYPE	(TCPA_BASE + 37)
#define TCPA_INVALID_POSTINIT	(TCPA_BASE + 38)
#define TCPA_INAPPRORIATE_SIG	(TCPA_BASE + 39)
#define TCPA_BAD_KEY_PROPERTY	(TCPA_BASE + 40)
#define TCPA_BAD_MIGRATION	(TCPA_BASE + 41)
#define TCPA_BAD_SCHEME		(TCPA_BASE + 42)
#define TCPA_BAD_DATASIZE	(TCPA_BASE + 43)
#define TCPA_BAD_MODE		(TCPA_BASE + 44)
#define TCPA_BAD_PRESENCE	(TCPA_BASE + 45)
#define TCPA_BAD_VERSION	(TCPA_BASE + 46)

#define TCPA_RETRY		(TCPA_BASE + TCPA_NON_FATAL)

/*===================================================== */
/*		ATMEL Error Codes */
/*==================================================== */

#define TCPA_ATMEL_BASE		0x00000400
#define TCPA_BAD_STATEID	TCPA_ATMEL_BASE + 1
#define TCPA_BADWRITE		TCPA_ATMEL_BASE + 2
#define TCPA_BADREAD		TCPA_ATMEL_BASE + 3
#define TCPA_TAMPER_DETECT	TCPA_ATMEL_BASE + 4
#define TCPA_LOCKED_OUT		TCPA_ATMEL_BASE + 5
#define TCPA_BAD_ID		TCPA_ATMEL_BASE + 6
#define TCPA_NO_ID		TCPA_ATMEL_BASE + 7
#define TCPA_INT_ERROR		TCPA_ATMEL_BASE + 8
#define TCPA_VERIF_FAIL		TCPA_ATMEL_BASE + 9

/*============================================================= */
/*				Ordinals			*/
/*============================================================= */
							/* Audit */
/*#define TPM_ORD_GetState				0x20000003 */
/*#define TPM_ORD_ResetChip				0x2000000c */
#define TPM_ORD_PhysicalPresence			0x4000000a
/*#define	TPM_ORD_OwnerSetState			0x20000002 */
#define TPM_ORD_OIAP				10
#define TPM_ORD_OSAP				11
#define TPM_ORD_ChangeAuth			12
#define TPM_ORD_TakeOwnership			13	/* x */
#define TPM_ORD_ChangeAuthAsymStart		14
#define TPM_ORD_ChangeAuthAsymFinish		15
#define TPM_ORD_ChangeAuthOwner			16	/* x */

#define TPM_ORD_Extend				20
#define TPM_ORD_PcrRead				21
#define TPM_ORD_Quote				22
#define TPM_ORD_Seal				23	/* x */
#define TPM_ORD_Unseal				24
#define TPM_ORD_DirWriteAuth			25	/* x */
#define TPM_ORD_DirRead				26

#define TPM_ORD_UnBind				30
#define TPM_ORD_CreateWrapKey			31	/* x */
#define TPM_ORD_LoadKey				32
#define TPM_ORD_GetPubKey			33
#define TPM_ORD_EvictKey			34

#define TPM_ORD_CreateMigrationBlob		40	/* x */
#define TPM_ORD_ReWrapKey			41
#define TPM_ORD_ConvertMigrationBlob		42	/* x */
#define TPM_ORD_AuthorizeMigrationKey		43	/* x */
#define TPM_ORD_CreateMaintenanceArchive	44	/* x */
#define TPM_ORD_LoadMaintenanceArchive		45	/* x */
#define TPM_ORD_KillMaintenanceFeature		46	/* x */
#define TPM_ORD_LoadManuMaintPub		47	/* x */
#define TPM_ORD_ReadManuMaintPub		48	/* x */

#define TPM_ORD_CertifyKey			50

#define TPM_ORD_Sign				60

#define TPM_ORD_GetRandom			70
#define TPM_ORD_StirRandom			71

#define TPM_ORD_SelfTestFull			80
#define TPM_ORD_SelfTestStartup			81
#define TPM_ORD_CertifySelfTest			82
#define TPM_ORD_ContinueSelfTest		83
#define TPM_ORD_GetTestResult			84

#define TPM_ORD_Reset				90	/* x */
#define TPM_ORD_OwnerClear			91	/* x */
#define TPM_ORD_DisableOwnerClear		92	/* x */
#define TPM_ORD_ForceClear			93	/* x */
#define TPM_ORD_DisableForceClear		94	/* x */

#define TPM_ORD_GetCapabilitySigned		100
#define TPM_ORD_GetCapability			101
#define TPM_ORD_GetCapabilityOwner		102

#define TPM_ORD_OwnerSetDisable			110	/* x */
#define TPM_ORD_PhysicalEnable			111	/* x */
#define TPM_ORD_PhysicalDisable			112	/* x */
#define TPM_ORD_SetOwnerInstall			113	/* x */
#define TPM_ORD_PhysicalSetDeactivated		114	/* x */
#define TPM_ORD_SetTempDeactivated		115	/* x */

#define TPM_ORD_CreateEndorsementKeyPair	120	/* x */
#define TPM_ORD_MakeIdentity			121	/* x */
#define TPM_ORD_ActivateTPMIdentity		122	/* x */
#define TPM_ORD_ReadPubek			124	/* x */
#define TPM_ORD_OwnerReadPubek			125	/* x */
#define TPM_ORD_DisablePubekRead		126	/* x */

#define TPM_ORD_GetAuditEvent			130	/* x */
#define TPM_ORD_GetAuditEventSigned		131	/* x */

#define TPM_ORD_GetOrdinalAuditStatus		140
#define TPM_ORD_SetOrdinalAuditStatus		141	/* x */

#define TPM_ORD_Terminate_Handle		150
#define TPM_ORD_Init				151	/* x */
#define TPM_ORD_SaveState			152	/* x */
#define TPM_ORD_Startup				153	/* x */
#define TPM_ORD_SetRedirection			154	/* x */

#define TPM_ORD_SHA1Start			160
#define TPM_ORD_SHA1Update			161
#define TPM_ORD_SHA1Complete			162
#define TPM_ORD_SHA1CompleteExtend		163

#define TPM_ORD_FieldUpgrade			170

#define TPM_ORD_SaveKeyContext			180
#define TPM_ORD_LoadKeyContext			181
#define TPM_ORD_SaveAuthContext			182
#define TPM_ORD_LoadAuthContext			183

/*======================================== */
/*		Commands */
/*======================================== */
#define TPM_TAG_RQU_COMMAND		0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND	0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND	0x00C3
#define TPM_TAG_RSP_COMMAND		0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND	0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND	0x00C6

/***************************************
4.10	TCPA_KEY_USAGE values
************************************************/
#define TPM_KEY_SIGNING		0x0010
#define TPM_KEY_STORAGE		0x0011
#define TPM_KEY_IDENTITY	0x0012
#define TPM_KEY_AUTHCHANGE	0X0013
#define TPM_KEY_BIND		0x0014
#define TPM_KEY_LEGACY		0x0015

/***************************************
4.11	TCPA_AUTH_DATA_USAGE values
************************************************/
#define TPM_AUTH_NEVER	0x00
#define TPM_AUTH_ALWAYS	0x01

/***************************************
4.12	TCPA_KEY_FLAGS
************************************************/
#define redirection		0x00000001
#define migratable		0x00000002
#define volatileKey		0x00000004
#define FLAG_REDIRECTION	0x00000001
#define FLAG_MIGRATABLE		0x00000002
#define FLAG_VOLATILE		0x00000004

/*********************************************
TCPA_PAYLOAD_TYPE Values
*************************************************/
#define TCPA_PT_ASYM		0x01
#define TCPA_PT_BIND		0x02
#define TCPA_PT_MIGRATE		0x03
#define TCPA_PT_MAINT		0x04
#define TCPA_PT_SEAL		0x05

/*********************************************
4.15	TCPA_ENTITY_TYPE
***************************************************/
#define TCPA_ET_KEYHANDLE	0x0001
#define TCPA_ET_OWNER		0x0002
#define TCPA_ET_DATA		0x0003
#define TCPA_ET_SRK		0x0004
#define TCPA_ET_KEY		0x0005

/*********************************************
	4.16	TCPA_STARTUP_TYPE
***************************************************/
#define TCPA_ST_CLEAR			0x0001
#define TCPA_ST_STATE			0x0002
#define TCPA_ST_DEACTIVATED		0x0003

/**************************************************
	TCPA_PROTOCOL_ID Values
**********************************************************/
#define TCPA_PID_OIAP		0x0001
#define TCPA_PID_OSAP		0x0002
#define TCPA_PID_ADIP		0x0003
#define TCPA_PID_ADCP		0x0004
#define TCPA_PID_OWNER		0x0005

/************************************************
	4.18	TCPA_ALGORITHM_ID
***************************************************/
#define TCPA_ALG_RSA	0x00000001
#define TCPA_ALG_DES	0x00000002
#define TCPA_ALG_3DES	0x00000003
#define TCPA_ALG_SHA	0x00000004
#define TCPA_ALG_HMAC	0x00000005
#define TCPA_ALG_AES	0x00000006

/********************************************************
4.19	TCPA_PHYSICAL_PRESENCE
*********************************************/
#define TCPA_PHYSICAL_PRESENCE_LIFETIME_LOCK	0x0080
#define TCPA_PHYSICAL_PRESENCE_HW_ENABLE	0x0040
#define TCPA_PHYSICAL_PRESENCE_CMD_ENABLE	0x0020
#define TCPA_PHYSICAL_PRESENCE_NOTPRESENT	0x0010
#define TCPA_PHYSICAL_PRESENCE_PRESENT		0x0008
#define TCPA_PHYSICAL_PRESENCE_LOCK		0x0004

/**************************************************
4.22	TCPA_MIGRATE_SCHEME
*******************************************************/
#define TCPA_MS_MIGRATE	0x0001
#define TCPA_MS_REWRAP	0x0002
#define TCPA_MS_MAINT	0x0003

/*************************************************************
4.31	TCPA_CAPABILITY_AREA
**********************************************************************/
#define TCPA_CAP_ORD			0x00000001
#define TCPA_CAP_ALG			0x00000002
#define TCPA_CAP_PID			0x00000003
#define TCPA_CAP_FLAG			0x00000004
#define TCPA_CAP_PROPERTY		0x00000005
#define TCPA_CAP_VERSION		0x00000006
#define TCPA_CAP_KEY_HANDLE		0x00000007
#define TCPA_CAP_CHECK_LOADED		0x00000008

/* use these to detect a 1.2 TPM, support to follow */
#define TPM_CAP_PROP_MAX_AUTHSESS	0x0000010D
#define TPM_CAP_VERSION_VAL		0x0000001A
#define TPM_CAP_PROPERTY		TCPA_CAP_PROPERTY

#define TCPA_CAP_PROP_PCR		0x00000101
#define TCPA_CAP_PROP_DIR		0x00000102
#define TCPA_CAP_PROP_MANUFACTURER	0x00000103
#define TCPA_CAP_PROP_SLOTS		0x00000104

#define TCPA_ES_NONE			0x0001
#define TCPA_ES_RSAESPKCSv15		0x0002
#define TCPA_ES_RSAESOAEP_SHA1_MGF1	0x0003

#define TCPA_SS_NONE			0x0001
#define TCPA_SS_RSASSAPKCS1v15_SHA1	0x0002
#define TCPA_SS_RSASSAPKCS1v15_DER	0x0003

#endif
