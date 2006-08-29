/*++

  TSS structures for TSS

*/

#ifndef __TSS_STRUCTS_H__
#define __TSS_STRUCTS_H__

typedef struct tdTSS_VERSION
{
	BYTE   bMajor;
	BYTE   bMinor;
	BYTE   bRevMajor;
	BYTE   bRevMinor;
} TSS_VERSION;

typedef struct tdTSS_PCR_EVENT
{
	TSS_VERSION  versionInfo;
	UINT32  ulPcrIndex;
	TSS_EVENTTYPE eventType;
	UINT32  ulPcrValueLength;
#ifdef __midl
	[size_is(ulPcrValueLength)]
#endif
	BYTE*      rgbPcrValue;
	UINT32  ulEventLength;
#ifdef __midl
	[size_is(ulEventLength)]
#endif
	BYTE*      rgbEvent;
} TSS_PCR_EVENT;


typedef struct tdTSS_EVENT_CERT
{
	TSS_VERSION       versionInfo;
	UINT32  ulCertificateHashLength;
	BYTE*   rgbCertificateHash;
	UINT32  ulEntityDigestLength;
#ifdef __midl
	[size_is(ulEntityDigestLength)]
#endif
	BYTE*   rgbentityDigest;
	TSS_BOOL  fDigestChecked;
	TSS_BOOL  fDigestVerified;
	UINT32  ulIssuerLength;
#ifdef __midl
	[size_is(ulIssuerLength)]
#endif
	BYTE*   rgbIssuer;
} TSS_EVENT_CERT;

typedef struct tdTSS_UUID
{
	UINT32  ulTimeLow;
	UINT16  usTimeMid;
	UINT16  usTimeHigh;
	BYTE   bClockSeqHigh;
	BYTE   bClockSeqLow;
	BYTE   rgbNode[6];
} TSS_UUID;

typedef struct tdTSS_KM_KEYINFO
{
	TSS_VERSION  versionInfo;
	TSS_UUID  keyUUID;
	TSS_UUID  parentKeyUUID;
	BYTE   bAuthDataUsage;
	TSS_BOOL  fIsLoaded;    // TRUE: actually loaded in TPM
	UINT32  ulVendorDataLength;  // may be 0
#ifdef __midl
	[size_is(ulVendorDataLength)]
#endif
	BYTE*   rgbVendorData;   // may be NULL
} TSS_KM_KEYINFO;

#if 0 // TSS 1.1 Header file Errata 1 removed this struct
typedef struct tdTSS_VALIDATION
{
	TCPA_NONCE    ExternalData;
	UINT32    DataLength;
#ifdef __midl
	[size_is(DataLength)]
#endif
	BYTE*     Data;
	UINT32    ValidationDataLength;
#ifdef __midl
	[size_is(ValidationDataLength)]
#endif
	BYTE*     ValidationData;
} TSS_VALIDATION;
#else
typedef struct tdTSS_VALIDATION
{
	TSS_VERSION  versionInfo;
	UINT32       ulExternalDataLength;
#ifdef __midl
	[size_is(ulExternalDataLength)]
#endif
	BYTE*        rgbExternalData;
	UINT32       ulDataLength;
#ifdef __midl
	[size_is(ulDataLength)]
#endif
	BYTE*     rgbData;
	UINT32    ulValidationDataLength;
#ifdef __midl
	[size_is(ulValidationDataLength)]
#endif
	BYTE*     rgbValidationData;
} TSS_VALIDATION;
#endif

/* TSS_CALLBACK has been imported from the TSS 1.2 header files in order to
 * support TSS 1.2 style callbacks in Trousers 0.2.X.  This will enable 64bit
 * apps to take advanatage of callbacks on TPM 1.1 hardware */
typedef struct tdTSS_CALLBACK
{
	PVOID            callback;
	PVOID            appData;
	TSS_ALGORITHM_ID alg;
} TSS_CALLBACK;


#endif // __TSS_STRUCTS_H__

