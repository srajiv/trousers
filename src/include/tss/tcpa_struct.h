/*++

  TPM structures basically extracted from  TCPA Main Specification V1.1b

*/

#ifndef __TCPA_STRUCT_H__
#define __TCPA_STRUCT_H__

//--------------------------------------------------------------------

//********************************************************************
// structures

//-------------------------------------------------------------------
// section 4.5
typedef struct tdTCPA_VERSION
{
	BYTE   major;
	BYTE   minor;
	BYTE   revMajor;
	BYTE   revMinor;
} TCPA_VERSION;


//-------------------------------------------------------------------
// section 4.6
// digest size is 20 or greater

typedef struct tdTCPA_DIGEST
{
	BYTE  digest[TCPA_SHA1_160_HASH_LEN];
} TCPA_DIGEST;

//-------------------------------------------------------------------
typedef TCPA_DIGEST  TCPA_PCRVALUE;
typedef TCPA_DIGEST  TCPA_COMPOSITE_HASH;
typedef TCPA_DIGEST  TCPA_DIRVALUE;
typedef TCPA_DIGEST  TCPA_HMAC;
typedef TCPA_DIGEST  TCPA_CHOSENID_HASH;

//-------------------------------------------------------------------
// section 4.7
typedef struct tdTCPA_NONCE
{
	BYTE  nonce[TCPA_SHA1BASED_NONCE_LEN];
} TCPA_NONCE;

typedef struct tdTCPA_AUTHDATA
{
	BYTE  authdata[TCPA_SHA1_160_HASH_LEN];
} TCPA_AUTHDATA;

typedef TCPA_AUTHDATA TCPA_SECRET;
typedef TCPA_AUTHDATA TCPA_ENCAUTH;

//-------------------------------------------------------------------
// section 4.9
typedef struct tdTCPA_KEY_HANDLE_LIST
{
	UINT16  loaded;
#ifdef __midl
	[size_is(loaded)]
#endif
	TCPA_KEY_HANDLE* handle;
} TCPA_KEY_HANDLE_LIST;

//-------------------------------------------------------------------
// section 4.12

// TPM_KEY_FLAGS has been moved to tpm_typedef.h

//-------------------------------------------------------------------
// section 4.20
typedef struct tdTCPA_KEY_PARMS
{
	TCPA_ALGORITHM_ID  algorithmID;
	TCPA_ENC_SCHEME    encScheme;
	TCPA_SIG_SCHEME    sigScheme;
	UINT32             parmSize;
#ifdef __midl
	[size_is(parmSize)]
#endif
	BYTE*              parms;
} TCPA_KEY_PARMS;

typedef struct tdTCPA_RSA_KEY_PARMS
{
	UINT32   keyLength;
	UINT32   numPrimes;
	UINT32   exponentSize;
#ifdef __midl
	[size_is(exponentSize)]
#endif
	BYTE*    exponent;
} TCPA_RSA_KEY_PARMS;

//-------------------------------------------------------------------
// section 4.25

typedef struct tdTCPA_PCR_SELECTION
{
	UINT16   sizeOfSelect;
#ifdef __midl
	[size_is(sizeOfSelect)]
#endif
		BYTE*    pcrSelect;
} TCPA_PCR_SELECTION;

typedef struct tdTCPA_PCR_COMPOSITE
{
	TCPA_PCR_SELECTION select;
	UINT32             valueSize;
#ifdef __midl
	[size_is(valueSize)]
#endif
	TCPA_PCRVALUE*      pcrValue;
} TCPA_PCR_COMPOSITE;

typedef struct tdTCPA_PCR_INFO
{
	TCPA_PCR_SELECTION  pcrSelection;
	TCPA_COMPOSITE_HASH digestAtRelease;
	TCPA_COMPOSITE_HASH digestAtCreation;
}  TCPA_PCR_INFO;

//-------------------------------------------------------------------
// section 4.26
typedef struct tdTCPA_STORED_DATA
{
	TCPA_VERSION  ver;
	UINT32   sealInfoSize;
#ifdef __midl
	[size_is(sealInfoSize)]
#endif
	BYTE*    sealInfo;
	UINT32   encDataSize;
#ifdef __midl
	[size_is(encDataSize)]
#endif
		BYTE*    encData;
} TCPA_STORED_DATA;

typedef struct tdTCPA_SEALED_DATA
{
	TCPA_PAYLOAD_TYPE  payload;
	TCPA_SECRET        authData;
	TCPA_NONCE         tpmProof;
	TCPA_DIGEST        storedDigest;
	UINT32             dataSize;
#ifdef __midl
	[size_is(dataSize)]
#endif
		BYTE*              data;
} TCPA_SEALED_DATA;

typedef struct tdTCPA_SYMMETRIC_KEY
{
	TCPA_ALGORITHM_ID  algId;
	TCPA_ENC_SCHEME    encScheme;
	UINT16             size;
#ifdef __midl
	[size_is(size)]
#endif
		BYTE*              data;
} TCPA_SYMMETRIC_KEY;

//-------------------------------------------------------------------
// section 4.27
typedef struct tdTCPA_STORE_PUBKEY
{
	UINT32   keyLength;
#ifdef __midl
	[size_is(keyLength)]
#endif
	BYTE*    key;
} TCPA_STORE_PUBKEY;

typedef struct tdTCPA_PUBKEY
{
	TCPA_KEY_PARMS     algorithmParms;
	TCPA_STORE_PUBKEY  pubKey;
} TCPA_PUBKEY;

typedef struct tdTCPA_STORE_PRIVKEY
{
	UINT32   keyLength;
#ifdef __midl
	[size_is(keyLength)]
#endif
		BYTE*    key;
} TCPA_STORE_PRIVKEY;

typedef struct tdTCPA_STORE_ASYMKEY
{
	TCPA_PAYLOAD_TYPE  payload;
	TCPA_SECRET        usageAuth;
	TCPA_SECRET        migrationAuth;
	TCPA_DIGEST        pubDataDigest;
	TCPA_STORE_PRIVKEY privKey;
} TCPA_STORE_ASYMKEY;

typedef struct tdTCPA_KEY
{
	TCPA_VERSION         ver;
	TCPA_KEY_USAGE       keyUsage;
	TCPA_KEY_FLAGS       keyFlags;
	TCPA_AUTH_DATA_USAGE authDataUsage;
	TCPA_KEY_PARMS       algorithmParms;
	UINT32               PCRInfoSize;
#ifdef __midl
	[size_is(PCRInfoSize)]
#endif
	BYTE*                PCRInfo;
	TCPA_STORE_PUBKEY    pubKey;
	UINT32               encSize;
#ifdef __midl
	[size_is(encSize)]
#endif
	BYTE*                encData;
} TCPA_KEY;

//-------------------------------------------------------------------
// section 4.28
typedef struct tdTCPA_CERTIFY_INFO
{
	TCPA_VERSION         version;
	TCPA_KEY_USAGE       keyUsage;
	TCPA_KEY_FLAGS       keyFlags;
	TCPA_AUTH_DATA_USAGE authDataUsage;
	TCPA_KEY_PARMS       algorithmParms;
	TCPA_DIGEST          pubkeyDigest;
	TCPA_NONCE           data;
	TSS_BOOL             parentPCRStatus;
	UINT32               PCRInfoSize;
#ifdef __midl
	[size_is(PCRInfoSize)]
#endif
		BYTE*                PCRInfo;
} TCPA_CERTIFY_INFO;

//-------------------------------------------------------------------
// section 4.23
typedef struct tdTCPA_MIGRATIONKEYAUTH
{
	TCPA_PUBKEY          migrationKey;
	TCPA_MIGRATE_SCHEME  migrationScheme;
	TCPA_DIGEST          digest;
} TCPA_MIGRATIONKEYAUTH;

//-------------------------------------------------------------------
// section 4.30.2
typedef struct tdTCPA_IDENTITY_REQ
{
	UINT32          asymSize;
	UINT32          symSize;
	TCPA_KEY_PARMS  asymAlgorithm;
	TCPA_KEY_PARMS  symAlgorithm;
#ifdef __midl
	[size_is(asymSize)]
#endif
		BYTE*           asymBlob;
#ifdef __midl
	[size_is(symSize)]
#endif
		BYTE*           symBlob;
} TCPA_IDENTITY_REQ;

// Errata: Where is TCPA_IDENTITY_CONTENTS?

//-------------------------------------------------------------------
// section 4.29
typedef struct tdTCPA_QUOTE_INFO
{
	TCPA_VERSION         version;
	BYTE                 fixed[4]; // Shall always be the ASCII string 'QUOT'
	TCPA_COMPOSITE_HASH  compositeHash;
	TCPA_NONCE           externalData;
} TCPA_QUOTE_INFO;

#endif // __TCPA_STRUCT_H__

