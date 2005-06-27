#if !defined( _TSPI_H_ )
#define _TSPI_H_


#if !defined( EXTERN_C )
#if defined ( __cplusplus )
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif //__cplusplus
#endif //EXTERN_C

#if !defined( TSPICALL )
#define TSPICALL EXTERN_C TSS_RESULT
#endif //TSPICALL

TSPICALL Tspi_SetAttribUint32
(
 TSS_HOBJECT      hObject,      // in
 TSS_FLAG         attribFlag,   // in
 TSS_FLAG         subFlag,      // in
 UINT32           ulAttrib      // in
);

TSPICALL Tspi_GetAttribUint32
(
 TSS_HOBJECT      hObject,     // in
 TSS_FLAG         attribFlag,  // in
 TSS_FLAG         subFlag,     // in
 UINT32*          pulAttrib    // out
);

TSPICALL Tspi_SetAttribData
(
 TSS_HOBJECT      hObject,            // in
 TSS_FLAG         attribFlag,         // in
 TSS_FLAG         subFlag,            // in
 UINT32           ulAttribDataSize,   // in
 BYTE*            rgbAttribData       // in
);

TSPICALL Tspi_GetAttribData
(
 TSS_HOBJECT      hObject,               // in
 TSS_FLAG         attribFlag,            // in
 TSS_FLAG         subFlag,               // in
 UINT32*          pulAttribDataSize,     // out
 BYTE**           prgbAttribData         // out
);


TSPICALL Tspi_ChangeAuth
(
 TSS_HOBJECT      hObjectToChange,   // in
 TSS_HOBJECT      hParentObject,     // in
 TSS_HPOLICY      hNewPolicy         // in
);


TSPICALL Tspi_ChangeAuthAsym
(
 TSS_HOBJECT      hObjectToChange,   // in
 TSS_HOBJECT      hParentObject,     // in
 TSS_HKEY         hIdentKey,         // in
 TSS_HPOLICY      hNewPolicy         // in
);

TSPICALL Tspi_GetPolicyObject
(
 TSS_HOBJECT      hObject,      // in
 TSS_FLAG         policyType,   // in
 TSS_HPOLICY*     phPolicy      // out
);


TSPICALL Tspi_Context_Create
(
 TSS_HCONTEXT*    phContext   // out
);

TSPICALL Tspi_Context_Close
(
 TSS_HCONTEXT     hContext    // in
);


TSPICALL Tspi_Context_Connect
(
 TSS_HCONTEXT     hContext,        // in
 UNICODE*         wszDestination   // in
);

TSPICALL Tspi_Context_FreeMemory
(
 TSS_HCONTEXT     hContext,    // in
 BYTE*            rgbMemory    // in
);


TSPICALL Tspi_Context_GetDefaultPolicy
(
 TSS_HCONTEXT     hContext,    // in
 TSS_HPOLICY*     phPolicy     // out
);

TSPICALL Tspi_Context_CreateObject
(
 TSS_HCONTEXT     hContext,     // in
 TSS_FLAG         objectType,   // in
 TSS_FLAG         initFlags,    // in
 TSS_HOBJECT*     phObject      // out
);

TSPICALL Tspi_Context_CloseObject
(
 TSS_HCONTEXT     hContext,    // in
 TSS_HOBJECT      hObject      // in
);

TSPICALL Tspi_Context_GetCapability
(
 TSS_HCONTEXT     hContext,            // in
 TSS_FLAG         capArea,             // in
 UINT32           ulSubCapLength,      // in
 BYTE*            rgbSubCap,           // in
 UINT32*          pulRespDataLength,   // out
 BYTE**           prgbRespData         // out
);


TSPICALL Tspi_Context_GetTpmObject
(
 TSS_HCONTEXT     hContext,     // in
 TSS_HTPM*        phTPM         // out
);

TSPICALL Tspi_Context_LoadKeyByBlob
(
 TSS_HCONTEXT     hContext,         // in
 TSS_HKEY         hUnwrappingKey,   // in
 UINT32           ulBlobLength,     // in
 BYTE*            rgbBlobData,      // in
 TSS_HKEY*        phKey             // out
);


TSPICALL Tspi_Context_LoadKeyByUUID
(
 TSS_HCONTEXT     hContext,                // in
 TSS_FLAG         persistentStorageType,   // in
 TSS_UUID         uuidData,                // in
 TSS_HKEY*        phKey                    // out
);

TSPICALL Tspi_Context_RegisterKey
(
 TSS_HCONTEXT     hContext,                      // in
 TSS_HKEY         hKey,                          // in
 TSS_FLAG         persistentStorageType,         // in
 TSS_UUID         uuidKey,                       // in
 TSS_FLAG         persistentStorageTypeParent,   // in
 TSS_UUID         uuidParentKey                  // in
);

TSPICALL Tspi_Context_UnregisterKey
(
 TSS_HCONTEXT     hContext,                // in
 TSS_FLAG         persistentStorageType,   // in
 TSS_UUID         uuidKey,                 // in
 TSS_HKEY*	  phkey			   // out
);

TSPICALL Tspi_Context_GetKeyByUUID
(
 TSS_HCONTEXT     hContext,                // in
 TSS_FLAG         persistentStorageType,   // in
 TSS_UUID         uuidData,                // in
 TSS_HKEY*        phKey                    // out
);

TSPICALL Tspi_Context_GetKeyByPublicInfo
(
 TSS_HCONTEXT     hContext,                // in
 TSS_FLAG         persistentStorageType,   // in
 TSS_ALGORITHM_ID algID,                   // in
 UINT32           ulPublicInfoLength,      // in
 BYTE*            rgbPublicInfo,           // in
 TSS_HKEY*        phKey                    // out
);

TSPICALL Tspi_Context_GetRegisteredKeysByUUID
(
 TSS_HCONTEXT     hContext,                // in
 TSS_FLAG         persistentStorageType,   // in
 TSS_UUID*        pGuidData,               // in
 UINT32*          pulKeyHierarchySize,     // out
 TSS_KM_KEYINFO** ppKeyHierarchy           // out
);

TSPICALL Tspi_Policy_SetSecret
(
 TSS_HPOLICY      hPolicy,           // in
 TSS_FLAG         secretMode,        // in
 UINT32           ulSecretLength,    // in
 BYTE*            rgbSecret          // in
);

TSPICALL Tspi_Policy_FlushSecret
(
 TSS_HPOLICY      hPolicy    // in
);

TSPICALL Tspi_Policy_AssignToObject
(
 TSS_HPOLICY      hPolicy,   // in
 TSS_HOBJECT      hObject    // in
);

TSPICALL Tspi_TPM_CreateEndorsementKey
(
 TSS_HTPM         hTPM,               // in
 TSS_HKEY         hKey,               // in
 TSS_VALIDATION*  pValidationData     // in, out
);

TSPICALL Tspi_TPM_GetPubEndorsementKey
(
 TSS_HTPM         hTPM,                  // in
 TSS_BOOL         fOwnerAuthorized,      // in
 TSS_VALIDATION*  pValidationData,       // in, out
 TSS_HKEY*        phEndorsementPubKey    // out
);

TSPICALL Tspi_TPM_TakeOwnership
(
 TSS_HTPM         hTPM,                  // in
 TSS_HKEY         hKeySRK,               // in
 TSS_HKEY         hEndorsementPubKey     // in
);


TSPICALL Tspi_TPM_CollateIdentityRequest
(
 TSS_HTPM         hTPM,                       // in
 TSS_HKEY         hKeySRK,                    // in
 TSS_HKEY         hCAPubKey,                  // in
 UINT32           ulIdentityLabelLength,      // in
 BYTE*            rgbIdentityLabelData,       // in
 TSS_HKEY         hIdentityKey,               // in
 TSS_ALGORITHM_ID algid,				// in
 UINT32*          pulTcpaIdentityReqLength,   // out
 BYTE**           prgbTcpaIdentityReq         // out
);


TSPICALL Tspi_TPM_ActivateIdentity
(
 TSS_HTPM         hTPM,                         // in
 TSS_HKEY         hIdentKey,                    // in
 UINT32           ulAsymCAContentsBlobLength,   // in
 BYTE*            rgbAsymCAContentsBlob,        // in
 UINT32           ulSymCAAttestationBlobLength, // in
 BYTE*            rgbSymCAAttestationBlob,      // in
 UINT32*          pulCredentialLength,          // out
 BYTE**           prgbCredential                // out
);


TSPICALL Tspi_TPM_ClearOwner
(
 TSS_HTPM         hTPM,            // in
 TSS_BOOL         fForcedClear     // in
);


TSPICALL Tspi_TPM_SetStatus
(
 TSS_HTPM         hTPM,         // in
 TSS_FLAG         statusFlag,   // in
 TSS_BOOL         fTpmState     // in
);

TSPICALL Tspi_TPM_GetStatus
(
 TSS_HTPM         hTPM,         // in
 TSS_FLAG         statusFlag,   // in
 TSS_BOOL*        pfTpmState    // out
);

TSPICALL Tspi_TPM_SelfTestFull
(
 TSS_HTPM         hTPM   // in
);

TSPICALL Tspi_TPM_CertifySelfTest
(
 TSS_HTPM         hTPM,               // in
 TSS_HKEY         hKey,               // in
 TSS_VALIDATION*  pValidationData     // in, out
);

TSPICALL Tspi_TPM_GetTestResult
(
 TSS_HTPM         hTPM,                  // in
 UINT32*          pulTestResultLength,   // out
 BYTE**           prgbTestResult         // out
);

TSPICALL Tspi_TPM_GetCapability
(
 TSS_HTPM         hTPM,                // in
 TSS_FLAG         capArea,             // in
 UINT32           ulSubCapLength,      // in
 BYTE*            rgbSubCap,           // in
 UINT32*          pulRespDataLength,   // out
 BYTE**           prgbRespData         // out
);

TSPICALL Tspi_TPM_GetCapabilitySigned
(
 TSS_HTPM         hTPM,                // in
 TSS_HTPM         hKey,                // in
 TSS_FLAG         capArea,             // in
 UINT32           ulSubCapLength,      // in
 BYTE*            rgbSubCap,           // in
 TSS_VALIDATION*  pValidationData,     // in, out
 UINT32*          pulRespDataLength,   // out
 BYTE**           prgbRespData         // out
);

TSPICALL Tspi_TPM_CreateMaintenanceArchive
(
 TSS_HTPM         hTPM,                   // in
 TSS_BOOL         fGenerateRndNumber,     // in
 UINT32*          pulRndNumberLength,     // out
 BYTE**           prgbRndNumber,          // out
 UINT32*          pulArchiveDataLength,   // out
 BYTE**           prgbArchiveData         // out
);

TSPICALL Tspi_TPM_KillMaintenanceFeature
(
 TSS_HTPM         hTPM    // in
);

TSPICALL Tspi_TPM_LoadMaintenancePubKey
(
 TSS_HTPM         hTPM,               // in
 TSS_HKEY         hMaintenanceKey,    // in
 TSS_VALIDATION*  pValidationData     // in, out
);

TSPICALL Tspi_TPM_CheckMaintenancePubKey
(
 TSS_HTPM         hTPM,              // in
 TSS_HKEY         hMaintenanceKey,   // in
 TSS_VALIDATION*  pValidationData    // in, out
);

TSPICALL Tspi_TPM_GetRandom
(
 TSS_HTPM         hTPM,                  // in
 UINT32           ulRandomDataLength,    // in
 BYTE**           prgbRandomData         // out
);

TSPICALL Tspi_TPM_StirRandom
(
 TSS_HTPM         hTPM,                  // in
 UINT32           ulEntropyDataLength,   // in
 BYTE*            rgbEntropyData         // in
);

TSPICALL Tspi_TPM_AuthorizeMigrationTicket
(
 TSS_HTPM            hTPM,                // in
 TSS_HKEY            hMigrationKey,       // in
 TSS_MIGRATE_SCHEME  migrationScheme,     // in
 UINT32*             pulMigTicketLength,  // out
 BYTE**              prgbMigTicket        // out
);


TSPICALL Tspi_TPM_GetEvent
(
 TSS_HTPM         hTPM,            // in
 UINT32           ulPcrIndex,      // in
 UINT32           ulEventNumber,   // in
 TSS_PCR_EVENT*   pPcrEvent        // out
);

TSPICALL Tspi_TPM_GetEvents
(
 TSS_HTPM         hTPM,             // in
 UINT32           ulPcrIndex,       // in
 UINT32           ulStartNumber,    // in
 UINT32*          pulEventNumber,   // in, out
 TSS_PCR_EVENT**  prgPcrEvents      // out
);


TSPICALL Tspi_TPM_GetEventLog
(
 TSS_HTPM         hTPM,               // in
 UINT32*          pulEventNumber,     // out
 TSS_PCR_EVENT**  prgPcrEvents        // out
);

TSPICALL Tspi_TPM_Quote
(
 TSS_HTPM         hTPM,               // in
 TSS_HKEY         hIdentKey,          // in
 TSS_HPCRS        hPcrComposite,      // in
 TSS_VALIDATION*  pValidationData     // in, out
);

TSPICALL Tspi_TPM_PcrExtend
(
 TSS_HTPM	hTPM,			// in
 UINT32		ulPcrIndex,		// in
 UINT32		ulPcrDataLength,	// in
 BYTE*		pbPcrData,		// in
 TSS_PCR_EVENT*	pPcrEvent,		// in
 UINT32*	pulPcrValueLength,	// out
 BYTE**		prgbPcrValue		// out
);

TSPICALL Tspi_TPM_PcrRead
(
 TSS_HTPM         hTPM,                // in
 UINT32           ulPcrIndex,          // in
 UINT32*          pulPcrValueLength,   // out
 BYTE**           prgbPcrValue         // out
);


TSPICALL Tspi_TPM_DirWrite
(
 TSS_HTPM         hTPM,              // in
 UINT32           ulDirIndex,        // in
 UINT32           ulDirDataLength,   // in
 BYTE*            rgbDirData         // in
);


TSPICALL Tspi_TPM_DirRead
(
 TSS_HTPM         hTPM,               // in
 UINT32           ulDirIndex,         // in
 UINT32*          pulDirDataLength,   // out
 BYTE**           prgbDirData         // out
);


TSPICALL Tspi_Key_LoadKey
(
 TSS_HKEY         hKey,            // in
 TSS_HKEY         hUnwrappingKey   // in
);

TSPICALL Tspi_Key_UnloadKey
(
 TSS_HKEY         hKey            // in
);


TSPICALL Tspi_Key_GetPubKey
(
 TSS_HKEY         hKey,             // in
 UINT32*          pulPubKeyLength,  // out
 BYTE**           prgbPubKey        // out
);


TSPICALL Tspi_Key_CertifyKey
(
 TSS_HKEY         hKey,             // in
 TSS_HKEY         hCertifyingKey,   // in
 TSS_VALIDATION*  pValidationData   // in, out
);

TSPICALL Tspi_Key_CreateKey
(
 TSS_HKEY         hKey,           // in
 TSS_HKEY         hWrappingKey,   // in
 TSS_HPCRS        hPcrComposite   // in, may be NULL
);

TSPICALL Tspi_Key_WrapKey
(
 TSS_HKEY         hKey,           // in
 TSS_HKEY         hWrappingKey,   // in
 TSS_HPCRS        hPcrComposite   // in, may be NULL
);

TSPICALL Tspi_Key_CreateMigrationBlob
(
 TSS_HKEY         hKeyToMigrate,            // in
 TSS_HKEY         hParentKey,               // in
 UINT32           ulMigTicketLength,        // in
 BYTE*            rgbMigTicket   ,          // in
 UINT32*          pulRandomLength,          // out
 BYTE**           prgbRandom,               // out
 UINT32*          pulMigrationBlobLength,   // out
 BYTE**           prgbMigrationBlob         // out
);

TSPICALL Tspi_Key_ConvertMigrationBlob
(
 TSS_HKEY         hKeyToMigrate,           // in
 TSS_HKEY         hParentKey,              // in
 UINT32           ulRandomLength,          // in
 BYTE*            rgbRandom,               // in
 UINT32           ulMigrationBlobLength,   // in
 BYTE*            rgbMigrationBlob         // in
);

TSPICALL Tspi_Hash_Sign
(
 TSS_HHASH        hHash,                // in
 TSS_HKEY         hKey,                 // in
 UINT32*          pulSignatureLength,   // out
 BYTE**           prgbSignature         // out
);

TSPICALL Tspi_Hash_VerifySignature
(
 TSS_HHASH        hHash,               // in
 TSS_HKEY         hKey,                // in
 UINT32           ulSignatureLength,   // in
 BYTE*            rgbSignature         // in
);

TSPICALL Tspi_Hash_SetHashValue
(
 TSS_HHASH        hHash,               // in
 UINT32           ulHashValueLength,   // in
 BYTE*            rgbHashValue         // in
);

TSPICALL Tspi_Hash_GetHashValue
(
 TSS_HHASH        hHash,                // in
 UINT32*          pulHashValueLength,   // out
 BYTE**           prgbHashValue         // out
);

TSPICALL Tspi_Hash_UpdateHashValue
(
 TSS_HHASH        hHash,          // in
 UINT32           ulDataLength,   // in
 BYTE*            rgbData         // in
);


TSPICALL Tspi_Data_Bind
(
 TSS_HENCDATA     hEncData,       // in
 TSS_HKEY         hEncKey,        // in
 UINT32           ulDataLength,   // in
 BYTE*            rgbDataToBind   // in
);

TSPICALL Tspi_Data_Unbind
(
 TSS_HENCDATA     hEncData,               // in
 TSS_HKEY         hKey,                   // in
 UINT32*          pulUnboundDataLength,   // out
 BYTE**           prgbUnboundData         // out
);

TSPICALL Tspi_Data_Seal
(
 TSS_HENCDATA     hEncData,        // in
 TSS_HKEY         hEncKey,         // in
 UINT32           ulDataLength,    // in
 BYTE*            rgbDataToSeal,   // in
 TSS_HPCRS        hPcrComposite    // in
);

TSPICALL Tspi_Data_Unseal
(
 TSS_HENCDATA     hEncData,                // in
 TSS_HKEY         hKey,                    // in
 UINT32*          pulUnsealedDataLength,   // out
 BYTE**           prgbUnsealedData         // out
);

TSPICALL Tspi_PcrComposite_SelectPcrIndex
(
 TSS_HPCRS        hPcrComposite,   // in
 UINT32           ulPcrIndex       // in
);

TSPICALL Tspi_PcrComposite_SetPcrValue
(
 TSS_HPCRS        hPcrComposite,      // in
 UINT32           ulPcrIndex,         // in
 UINT32           ulPcrValueLength,   // in
 BYTE*            rgbPcrValue         // in
);

TSPICALL Tspi_PcrComposite_GetPcrValue
(
 TSS_HPCRS        hPcrComposite,       // in
 UINT32           ulPcrIndex,          // in
 UINT32*          pulPcrValueLength,   // out
 BYTE**           prgbPcrValue         // out
);

/******/
TSPICALL Tspicb_CallbackHMACAuth
(
 PVOID            lpAppData,          // in
 TSS_HOBJECT      hAuthorizedObject,  // in
 TSS_BOOL         ReturnOrVerify,     // in
 UINT32           ulPendingFunction,  // in
 TSS_BOOL         ContinueUse,        // in
 UINT32           ulSizeNonces,       // in
 BYTE*            rgbNonceEven,       // in
 BYTE*            rgbNonceOdd,        // in
 BYTE*            rgbNonceEvenOSAP,   // in
 BYTE*            rgbNonceOddOSAP,    // in
 UINT32           ulSizeDigestHmac,   // in
 BYTE*            rgbParamDigest,     // in
 BYTE*            rgbHmacData         // in, out
);


TSPICALL Tspicb_CallbackXorEnc
(
 PVOID            lpAppData,            // in
 TSS_HOBJECT      hOSAPObject,          // in
 TSS_HOBJECT      hObject,              // in
 TSS_FLAG         PurposeSecret,        // in
 UINT32           ulSizeNonces,         // in
 BYTE*            rgbNonceEven,         // in
 BYTE*            rgbNonceOdd,          // in
 BYTE*            rgbNonceEvenOSAP,     // in
 BYTE*            rgbNonceOddOSAP,      // in
 UINT32           ulSizeEncAuth,        // in
 BYTE*            rgbEncAuthUsage,      // out
 BYTE*            rgbEncAuthMigration   // out
);


TSPICALL Tspicb_CallbackTakeOwnership
(
 PVOID            lpAppData,         // in
 TSS_HOBJECT      hObject,           // in
 TSS_HKEY         hObjectPubKey,     // in
 UINT32           ulSizeEncAuth,     // in
 BYTE*            rgbEncAuth	     // out
);


TSPICALL Tspicb_CallbackChangeAuthAsym
(
 PVOID            lpAppData,        // in
 TSS_HOBJECT      hObject,          // in
 TSS_HKEY         hObjectPubKey,    // in
 UINT32           ulSizeEncAuth,    // in
 UINT32           ulSizeAuthLink,   // in
 BYTE*            rgbEncAuth,       // out
 BYTE*            rgbAuthLink       // out
);

TSPICALL Tspicb_CollateIdentity
(
 PVOID			lpAppData,			  // in
 UINT32			ulTCPAPlainIdentityProofLength,   // in
 BYTE*			rgbTCPAPlainIdentityProof,	  // in
 TSS_ALGORITHM_ID	algID,				  // in
 UINT32			ulSessionKeyLength,		  // out
 BYTE*			rgbSessionKey,			  // out
 UINT32*		pulTCPAIdentityProofLength,	  // out
 BYTE*			rgbTCPAIdentityProof		  // out
);


TSPICALL Tspicb_ActivateIdentity
(
 PVOID            lpAppData,                    // in
 UINT32           ulSessionKeyLength,           // in
 BYTE*            rgbSessionKey,                // in
 UINT32           ulSymCAAttestationBlobLength, // in
 BYTE*            rgbSymCAAttestationBlob,      // in
 UINT32*          pulCredentialLength,          // out
 BYTE*            rgbCredential                 // out
);

#endif //_TSPI_H_

