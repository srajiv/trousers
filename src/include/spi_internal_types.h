
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _SPI_INTERNAL_TYPES_H_
#define _SPI_INTERNAL_TYPES_H_

typedef struct tdAnObject {
	void *memPointer;
	UINT32 objectSize;
	UINT32 objectHandle;
	UINT32 tspContext;
	UINT32 tcsContext;
	UINT32 objectType;
	struct tdAnObject *next;
} AnObject;

typedef struct tdTSPKeyHandleContainer {
	TSS_HKEY tspKeyHandle;
	struct tdTSPKeyHandleContainer *next;
} TSPKeyHandleContainer;

typedef struct tdTCSKeyHandleContainer {
	TCS_KEY_HANDLE tcsKeyHandle;
	struct tdTSPKeyHandleContainer *tspHandles;
	struct tdTCSKeyHandleContainer *next;
} TCSKeyHandleContainer;

struct TSP_INTERNAL_POLICY_CB {
	TSS_RESULT (*Tspicb_CallbackHMACAuth)(
			PVOID lpAppData,
			TSS_HOBJECT hAuthorizedObject,
			TSS_BOOL ReturnOrVerify,
			UINT32 ulPendingFunction,
			TSS_BOOL ContinueUse,
			UINT32 ulSizeNonces,
			BYTE *rgbNonceEven,
			BYTE *rgbNonceOdd,
			BYTE *rgbNonceEvenOSAP,
			BYTE *rgbNonceOddOSAP,
			UINT32 ulSizeDigestHmac,
			BYTE *rgbParamDigest,
			BYTE *rgbHmacData);
	TSS_RESULT (*Tspicb_CallbackXorEnc)(
			PVOID lpAppData,
			TSS_HOBJECT hOSAPObject,
			TSS_HOBJECT hObject,
			TSS_FLAG PurposeSecret,
			UINT32 ulSizeNonces,
			BYTE *rgbNonceEven,
			BYTE *rgbNonceOdd,
			BYTE *rgbNonceEvenOSAP,
			BYTE *rgbNonceOddOSAP,
			UINT32 ulSizeEncAuth,
			BYTE *rgbEncAuthUsage,
			BYTE *rgbEncAuthMigration);
	TSS_RESULT (*Tspicb_CallbackTakeOwnership)(
			PVOID lpAppData,
			TSS_HOBJECT hObject,
			TSS_HKEY hObjectPubKey,
			UINT32 ulSizeEncAuth,
			BYTE *rgbEncAuth);
	TSS_RESULT (*Tspicb_CallbackChangeAuthAsym)(
			PVOID lpAppData,
			TSS_HOBJECT hObject,
			TSS_HKEY hObjectPubKey,
			UINT32 ulSizeEncAuth,
			UINT32 ulSizeAithLink,
			BYTE *rgbEncAuth,
			BYTE *rgbAuthLink);
	TSS_RESULT (*Tspicb_CollateIdentity)(
			PVOID lpAppData,
			UINT32 ulTCPAPlainIdentityProofLength,
			BYTE *rgbTCPAPlainIdentityProof,
			TSS_ALGORITHM_ID algID,
			UINT32 ulSessionKeyLength,
			BYTE *rgbSessionKey,
			UINT32 *pulTCPAIdentityProofLength,
			BYTE *rgbTCPAIdentityProof);
	TSS_RESULT (*Tspicb_ActivateIdentity)(
			PVOID lpAppData,
			UINT32 ulSessionKeyLength,
			BYTE *rgbSessionKey,
			UINT32 ulSymCAAttestationBlobLength,
			BYTE *rgbSymCAAttestationBlob,
			UINT32 *pulCredentialLength,
			BYTE *rgbCredential);
};

typedef struct tdTSP_INTERNAL_POLICY_OBJECT {
	TCPA_POLICY_OBJECT p;
	struct TSP_INTERNAL_POLICY_CB cb;
} TSP_INTERNAL_POLICY_OBJECT;

#endif
