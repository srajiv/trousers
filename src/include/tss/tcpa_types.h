
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TCPA_TYPES_H_
#define _TCPA_TYPES_H_

/***********************************************
Basic Types: 
There are some new types for 64-bit systems that were derived from the basic C-language integer and long types, so they work in existing code. 
Type	Definition
************************************************/
#define DWORD32		unsigned __int32	/*32-bit unsigned integer. */
#define DWORD64		unsigned __int16	/*64-bit unsigned integer. */
#define INT16		short	/*16-bit signed integer. */
#define INT32		__int32	/*32-bit signed integer. */
#define INT64		__int64	/*64-bit signed integer. */
#define LONG32		__int32	/*32-bit signed integer. */
#define LONG64		__int64	/*64-bit signed integer. */
#define UINT16		unsigned short	/*Unsigned INT16 */
#define UINT32		unsigned int	/*Unsigned INT32. */
#define UINT64		unsigned __int64	/*Unsigned INT64. */
#define ULONG32		unsigned LONG32	/*Unsigned LONG32. */
#define ULONG64		unsigned LONG64	/*Unsigned LONG64. */
#define BYTE		unsigned char	/*Unsigned character */
#define BOOL		int
#define TSS_BOOL	BOOL
#define UNICODE	wchar_t	/*UNICODE character */

#ifndef PVOID
#define PVOID void*
#endif

/***********************************************
Boolean types
************************************************/
#ifndef TRUE
#define TRUE		0x01	/*Assertion */
#define FALSE		0x00	/*Contradiction */
#endif
#define MAX_RPC_WAIT	180

typedef struct tdTCPA_DIGEST {
	BYTE digest[20];
} TCPA_DIGEST;

typedef struct tdTCPA_NONCE {
	BYTE nonce[20];
} TCPA_NONCE;

typedef BYTE TCPA_AUTHDATA[20];

typedef UINT32 TSS_FLAGS;
typedef UINT32 TSS_RESULT;
typedef UINT32 TCPA_RESULT;

typedef UINT32 TCS_AUTHHANDLE;
typedef UINT32 TCS_CONTEXT_HANDLE;	/*    32-bit or 64-bit pointer        Basic context handle */
typedef UINT32 TCS_KEY_HANDLE;	/*32-bit or 64-bit pointer      Basic key handle */

typedef UINT32 TCPA_KEY_HANDLE;
typedef UINT16 TCPA_ENC_SCHEME;
typedef UINT16 TCPA_SIG_SCHEME;
typedef UINT32 TCPA_ALGORITHM_ID;
typedef UINT16 TCPA_KEY_USAGE;
typedef UINT16 TCPA_ENTITY_TYPE;

typedef UINT32 TCPA_PCRINDEX;	/*Index to a PCR register */
typedef UINT32 TCPA_DIRINDEX;	/*Index to a DIR register */
typedef UINT32 TCPA_AUTHHANDLE;	/*Handle to an authorization session */
typedef UINT32 TSS_HASHHANDLE;	/*Handle to a hash session */
typedef UINT32 TSS_HMACHHANDLE;	/*Handle to a HMAC session */
typedef UINT32 TCPA_ENCHANDLE;	/*Handle to a encryption/decryption session */
/*typedef UINT32	TCPA_KEY_HANDLE;		//The area where a key is held assigned by the TPM. */

#if 0
typedef struct tdTCPA_KEY_FLAGS {
	unsigned int redirection:1;
	unsigned int migratable:1;
	unsigned int volatileKey:1;
	unsigned int unused:29;
} TCPA_KEY_FLAGS;
#else
typedef UINT32 TCPA_KEY_FLAGS;
#endif

typedef BOOL TCPA_AUTH_DATA_USAGE;

typedef struct tdTCPA_SECRET {
	BYTE secret[20];
} TCPA_SECRET;

typedef UINT16 TCPA_MIGRATE_SCHEME;
typedef UINT32 TCPA_COMMAND_CODE;
typedef UINT32 TCPA_EVENTTYPE;
typedef UINT32 TCPA_CAPABILITY_AREA;

typedef struct tdTCPA_AUTH {
	TCPA_AUTHHANDLE AuthHandle;
	TCPA_NONCE NonceOdd;	/* system */
	TCPA_NONCE NonceEven;	/* TPM */
	BYTE fContinueAuthSession;
	TCPA_AUTHDATA HMAC;
} TPM_AUTH;

typedef struct tdTCPA_ENCAUTH {
	BYTE encauth[20];
} TCPA_ENCAUTH;

typedef TCPA_NONCE TCPA_SALT_NONCE;

typedef TCPA_DIGEST TCPA_PCRVALUE;
typedef TCPA_DIGEST TCPA_COMPOSITE_HASH;
typedef TCPA_DIGEST TCPA_CHOSENID_HASH;
typedef TCPA_DIGEST TCPA_HMAC;
typedef TCPA_DIGEST TCPA_DIRVALUE;

typedef struct tdTCPA_STORE_PUBKEY {
	UINT32 keyLength;
	BYTE *key;
} TCPA_STORE_PUBKEY;

typedef struct tdTCPA_KEY_PARMS {
	TCPA_ALGORITHM_ID algorithmID;
	TCPA_ENC_SCHEME encScheme;
	TCPA_SIG_SCHEME sigScheme;
	UINT32 parmSize;
	BYTE *parms;
} TCPA_KEY_PARMS;

typedef struct tdTCPA_PUBKEY {
	TCPA_KEY_PARMS algorithmParms;
	TCPA_STORE_PUBKEY pubKey;
} TCPA_PUBKEY;

typedef struct tdTCPA_VERSION {
	BYTE major;
	BYTE minor;
	BYTE revMajor;
	BYTE revMinor;
} TCPA_VERSION;

typedef struct tdTCPA_KEY_HANDLE_LIST {
	UINT16 loaded;
	TCPA_KEY_HANDLE *handle;
} TCPA_KEY_HANDLE_LIST;

typedef struct tdTCPA_KEY {
	TCPA_VERSION ver;
	TCPA_KEY_USAGE keyUsage;
	TCPA_KEY_FLAGS keyFlags;
	TCPA_AUTH_DATA_USAGE authDataUsage;
	TCPA_KEY_PARMS algorithmParms;
	UINT32 PCRInfoSize;
	BYTE *PCRInfo;
	TCPA_STORE_PUBKEY pubKey;
	UINT32 encSize;
	BYTE *encData;
} TCPA_KEY;

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
	BOOL disable;
	BOOL ownership;
	BOOL deactivated;
	BOOL readPubek;
	BOOL disableOwnerClear;
	BOOL allowMaintenance;
	BOOL physicalPresenceLifetimeLock;
	BOOL physicalPresenceHWEnable;
	BOOL physicalPresenceCMDEnable;
	BOOL CEKPUsed;
	BOOL TPMpost;
	BOOL TPMpostLock;
} TCPA_PERSISTENT_FLAGS;

typedef struct tdTCPA_VOLATILE_FLAGS{
	BOOL deactivated;
	BOOL disableForceClear;
	BOOL physicalPresence;
	BOOL physicalPresenceLock;
	BOOL postInitialise;
} TCPA_VOLATILE_FLAGS;

typedef unsigned char TCPA_PAYLOAD_TYPE;

typedef UINT16 TCPA_PROTOCOL_ID;

typedef struct tdTCPA_RSA_KEY_PARMS {
	UINT32 keyLength;
	UINT32 numPrimes;
	UINT32 exponentSize;
	BYTE *exponent;
} TCPA_RSA_KEY_PARMS;

typedef struct tdTCPA_CHANGEAUTH_VALIDATE {
	TCPA_SECRET newAuthSecret;
	TCPA_NONCE n1;
} TCPA_CHANGEAUTH_VALIDATE;

typedef struct tdTCPA_MIGRATIONKEYAUTH {
	TCPA_PUBKEY migrationKey;
	TCPA_MIGRATE_SCHEME migrationScheme;
	TCPA_DIGEST digest;
} TCPA_MIGRATIONKEYAUTH;
typedef struct tdTCPA_AUDIT_EVENT {
	TCPA_COMMAND_CODE ordinal;
	TCPA_RESULT returncode;
} TCPA_AUDIT_EVENT;

typedef struct tdTCPA_EVENT_CERT {
	TCPA_DIGEST certificateHash;
	TCPA_DIGEST entityDigest;
	BOOL digestChecked;
	BOOL digestVerified;
	UINT32 issuerSize;
	BYTE *issuer;
} TCPA_EVENT_CERT;

typedef struct tdTCPA_PCR_SELECTION {
	UINT16 sizeOfSelect;
	BYTE *pcrSelect;
} TCPA_PCR_SELECTION;

typedef struct tdTCPA_PCR_COMPOSITE {
	TCPA_PCR_SELECTION select;
	UINT32 valueSize;
	TCPA_PCRVALUE *pcrValue;
} TCPA_PCR_COMPOSITE;

typedef struct tdTCPA_PCR_INFO {
	TCPA_PCR_SELECTION pcrSelection;
	TCPA_COMPOSITE_HASH digestAtRelease;
	TCPA_COMPOSITE_HASH digestAtCreation;
} TCPA_PCR_INFO;

typedef struct tdTCPA_STORED_DATA {
	TCPA_VERSION ver;
	UINT32 sealInfoSize;
	BYTE *sealInfo;
	UINT32 encDataSize;
	BYTE *encData;
} TCPA_STORED_DATA;

typedef struct tdTCPA_SEALED_DATA {
	TCPA_PAYLOAD_TYPE payload;
	TCPA_SECRET authData;
	TCPA_NONCE tpmProof;
	TCPA_DIGEST storedDigest;
	UINT32 dataSize;
	BYTE *data;
} TCPA_SEALED_DATA;

typedef struct tdTCPA_SYMMETRIC_KEY {
	TCPA_ALGORITHM_ID algId;
	TCPA_ENC_SCHEME encScheme;
	UINT16 size;
	BYTE *data;
} TCPA_SYMMETRIC_KEY;

typedef struct tdTCPA_BOUND_DATA {
	TCPA_VERSION ver;
	TCPA_PAYLOAD_TYPE payload;
	BYTE *payloadData;
} TCPA_BOUND_DATA;

typedef struct tdTCPA_STORE_PRIVKEY {
	UINT32 keyLength;
	BYTE *key;
} TCPA_STORE_PRIVKEY;

typedef struct tdTCPA_STORE_ASYMKEY {
	TCPA_PAYLOAD_TYPE payload;
	TCPA_SECRET usageAuth;
	TCPA_SECRET migrationAuth;
	TCPA_DIGEST pubDataDigest;
	TCPA_STORE_PRIVKEY privKey;
} TCPA_STORE_ASYMKEY;

typedef struct tdTCPA_MIGRATE_ASYMKEY {
	TCPA_PAYLOAD_TYPE payload;
	TCPA_SECRET usageAuth;
	TCPA_DIGEST pubDataDigest;
	UINT32 partPrivKeyLen;
	TCPA_STORE_PRIVKEY partPrivKey;
} TCPA_MIGRATE_ASYMKEY;

typedef struct tdTCPA_CERTIFY_INFO {
	TCPA_VERSION version;
	TCPA_KEY_USAGE keyUsage;
	TCPA_KEY_FLAGS keyFlags;
	TCPA_AUTH_DATA_USAGE authDataUsage;
	TCPA_KEY_PARMS algorithmParms;
	TCPA_DIGEST pubkeyDigest;
	TCPA_NONCE data;
	BOOL parentPCRStatus;
	UINT32 PCRInfoSize;
	BYTE *PCRInfo;
} TCPA_CERTIFY_INFO;

typedef struct tdTCPA_QUOTE_INFO {
	TCPA_VERSION version;
	BYTE fixed[4];
	TCPA_COMPOSITE_HASH digestValue;
	TCPA_NONCE externalData;
} TCPA_QUOTE_INFO;

typedef struct tdTCPA_IDENTITY_CONTENTS {
	TCPA_VERSION ver;
	UINT32 ordinal;
	TCPA_CHOSENID_HASH labelPrivCADigest;
	TCPA_PUBKEY identityPubKey;
} TCPA_IDENTITY_CONTENTS;

typedef struct tdTCPA_ASYM_CA_CONTENTS {
	TCPA_SYMMETRIC_KEY sessionKey;
	TCPA_DIGEST idDigest;
} TCPA_ASYM_CA_CONTENTS;

typedef struct tdTCPA_PRIVKEY {
	UINT32 Privlen;
	BYTE *Privkey;
} TCPA_PRIVKEY;

/***********************************************
Derived Types
************************************************/
#define TSS_FLAG		UINT32	/*Object attributes. */
#define TSS_HOBJECT		UINT32	/*32-bit or 64-bit pointer      Basic object handle. */
#define TSS_ALGORITHM_ID	UINT32	/*Type of TSS Algorithm IDs */
#define TSS_MIGRATION_SCHEME	UINT16	/*Type of TSS Migration Scheme IDs */
#define TSS_KEY_USAGE_ID	UINT32	/*Type of TSS Key Usage IDs */
#define TSS_KEY_ENC_SCHEME	UINT16	/*Type of TSS Encryption Scheme IDs */
#define TSS_KEY_SIG_SCHEME	UINT16	/*Type of TSS Signature Scheme IDs */
#define TSS_EVENTTYPE		UINT32	/*Type of TSS event */
/********************************************
Object Types
********************************************/
#define TSS_HCONTEXT	TSS_HOBJECT	/*Context object handle. */
#define TSS_HPOLICY	TSS_HOBJECT	/*Policy object handle. */
#define TSS_HTPM	TSS_HOBJECT	/*TPM object handle. */
#define TSS_HKEY	TSS_HOBJECT	/*Key object handle. */
#define TSS_HENCDATA	TSS_HOBJECT	/*Encrypted data object handle. */
#define TSS_HPCRS	TSS_HOBJECT	/*PCR composite object handle. */
#define TSS_HHASH	TSS_HOBJECT	/*Hash object handle. */

typedef struct tdTSS_VERSION {
	BYTE bMajor;
	BYTE bMinor;
	BYTE bRevMajor;
	BYTE bRevMinor;
} TSS_VERSION;

typedef struct tdTSS_PCR_EVENT {
	TSS_VERSION versionInfo;
	UINT32 ulPcrIndex;
	TSS_EVENTTYPE eventType;
	UINT32 ulPcrValueLength;
	BYTE *rgbPcrValue;
	UINT32 ulEventLength;
	BYTE *rgbEvent;
} TSS_PCR_EVENT;

typedef struct tdTSS_EVENT_CERT {
	TSS_VERSION versionInfo;
	UINT32 ulCertificateHashLength;
	BYTE *rgbCertificateHash;
	UINT32 ulEntityDigestLength;
	BYTE *rgbentityDigest;
	BOOL fDigestChecked;
	BOOL fDigestVerified;
	UINT32 ulIssuerLength;
	BYTE *rgbIssuer;
} TSS_EVENT_CERT;

typedef struct tdTSS_UUID {
	UINT32 ulTimeLow;
	UINT16 usTimeMid;
	UINT16 usTimeHigh;
	BYTE bClockSeqHigh;
	BYTE bClockSeqLow;
	BYTE rgbNode[6];
} TSS_UUID;

typedef struct tdTSS_KM_KEYINFO {
	TSS_VERSION versionInfo;
	TSS_UUID keyUUID;
	TSS_UUID parentKeyUUID;
	BYTE bAuthDataUsage;
	BOOL fIsLoaded;		/* TRUE: actually loaded in TPM */
	UINT32 ulVendorDataLength;	/* may be 0 */
	BYTE *rgbVendorData;	/* may be NULL */
} TSS_KM_KEYINFO;

typedef struct tdTSS_VALIDATION {
	TSS_VERSION versionInfo;
	UINT32 ulExternalDataLength;	/* in */
	BYTE *rgbExternalData;	/* in */
	UINT32 ulDataLength;	/* out */
	BYTE *rgbData;		/* out */
	UINT32 ulValidationLength;	/* out */
	BYTE *rgbValidationData;	/* out  */
} TSS_VALIDATION;

#if 0
typedef struct tdTSS_AUTH {
	TSS_AUTHHANDLE AuthHandle;
	TCPA_NONCE NonceOdd;	/* system        */
	TCPA_NONCE NonceEven;	/* TPM   */
	BOOL fContinueAuthSession;
	TCPA_AUTHDATA HMAC;
} TSS_AUTH;
#endif

/*--	moved */
typedef struct tdTCS_AUTH {
	TCS_AUTHHANDLE AuthHandle;
	TCPA_NONCE NonceOdd;	/* system        */
	TCPA_NONCE NonceEven;	/* TPM   */
	BOOL fContinueAuthSession;
	TCPA_AUTHDATA HMAC;
} TCS_AUTH;

typedef struct tdTCS_LOADKEY_INFO {
	TSS_UUID keyUUID;
	TSS_UUID parentKeyUUID;
	TCPA_DIGEST paramDigest;/* SHA1 digest of the TPM_LoadKey
				 * Command input parameters
				 * As defined in TCPA Main
				 * Specification */
	TPM_AUTH authData;	/* Data regarding a valid auth
				 * Session including the
				 * HMAC digest */
} TCS_LOADKEY_INFO;

typedef struct tdTCPA_PCR_OBJECT {
	TCPA_PCR_SELECTION select;
	TCPA_PCRVALUE pcrs[32];	/* hard coded */
	TCPA_PCRVALUE compositeHash;
} TCPA_PCR_OBJECT;

typedef struct tdTCPA_HASH_OBJECT {
	UINT32 hashType;
	BYTE *hashData;
	UINT32 hashSize;
	UINT32 hashUpdateSize;
	BYTE *hashUpdateBuffer;
} TCPA_HASH_OBJECT;

typedef struct tdTCPA_ENCDATA_OBJECT {
	TSS_HPOLICY usagePolicy;
	TSS_HPOLICY migPolicy;
	UINT32 encryptedDataLength;
	BYTE encryptedData[512];
	TCPA_PCR_INFO pcrInfo;
	BOOL usePCRs;
	UINT32 encType;
} TCPA_ENCDATA_OBJECT;

typedef struct tdTCPA_TPM_OBJECT {
	TSS_HPOLICY policy;
} TCPA_TPM_OBJECT;

typedef struct tdTCPA_POLICY_OBJECT {
	BYTE SecretLifetime;	/* 0->Always, 1->Use Counter 2-> Use Timer */
	UINT32 SecretMode;
	UINT32 SecretCounter;
	UINT32 SecretTimer;	/* in seconds */
	UINT32 SecretSize;
	BYTE Secret[20];
	UINT32 PolicyType;
	UNICODE popupString[256];
	UINT32 popupStringLength;
} TCPA_POLICY_OBJECT;

typedef struct tdTCPA_CONTEXT_OBJECT {
	TSS_FLAG silentMode;
	TSS_HPOLICY policy;
	TCS_CONTEXT_HANDLE tcsHandle;
	UNICODE machineName[256];
	UINT32 machineNameLength;
} TCPA_CONTEXT_OBJECT;

typedef struct tdTCPA_RSAKEY_OBJECT {
	TCPA_KEY tcpaKey;
	TSS_HPOLICY usagePolicy;
	TSS_HPOLICY migPolicy;
	TSS_FLAG persStorageType;
	TSS_UUID uuid;
	TCPA_PRIVKEY privateKey;
	BOOL usesAuth;
} TCPA_RSAKEY_OBJECT;

#endif
