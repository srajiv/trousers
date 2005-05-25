
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TCS_EXPORTS_H_
#define _TCS_EXPORTS_H_

TSS_RESULT TSC_PhysicalPresence(UINT16 physPres);

/*---	Atmel Commands */
TSS_RESULT Atmel_TPM_SetState(TCS_CONTEXT_HANDLE hContext, BYTE stateID, UINT32 sizeState,
			       BYTE * stateValue);
TSS_RESULT Atmel_TPM_OwnerSetState(TCS_CONTEXT_HANDLE hContext, BYTE stateID, UINT32 sizeState,
				    BYTE * stateValue, TCS_AUTH * ownerAuth);
TSS_RESULT Atmel_TPM_GetState(TCS_CONTEXT_HANDLE hContext, BYTE stateID, UINT32 * sizeState,
			       BYTE ** stateValue);

/*---	Proposed Commands */

TSS_RESULT TCSP_GetRegisteredKeyByPublicInfo(TCS_CONTEXT_HANDLE tcsContext, TCPA_ALGORITHM_ID algID,	/* in */
					      UINT32 ulPublicInfoLength,	/* in */
					      BYTE * rgbPublicInfo,	/* in */
					      UINT32 * keySize, BYTE ** keyBlob);

/*---	New command */

TSS_RESULT TCS_GetCapability(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_CAPABILITY_AREA capArea,	/* in */
			      UINT32 subCapSize,	/* in */
			      BYTE * subCap,	/* in */
			      UINT32 * respSize,	/* out */
			      BYTE ** resp	/* out */
    );

/*===	This file should only contain exports from the main spec */

TSS_RESULT TCS_OpenContext(TCS_CONTEXT_HANDLE * hContext	/* out  */
    );

TSS_RESULT TCS_CloseContext(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCS_FreeMemory(TCS_CONTEXT_HANDLE hContext,	/* in */
			   BYTE * pMemory	/* in */
    );

TSS_RESULT TCS_LogPcrEvent(TCS_CONTEXT_HANDLE hContext,	/* in    */
			    TSS_PCR_EVENT Event,	/* in  */
			    UINT32 * pNumber	/* out */
    );

TSS_RESULT TCS_GetPcrEvent(TCS_CONTEXT_HANDLE hContext,	/* in  */
			    UINT32 PcrIndex,	/* in */
			    UINT32 * pNumber,	/* in, out */
			    TSS_PCR_EVENT ** ppEvent	/* out */
    );

TSS_RESULT TCS_GetPcrEventsByPcr(TCS_CONTEXT_HANDLE hContext,	/* in */
				  UINT32 PcrIndex,	/* in */
				  UINT32 FirstEvent,	/* in */
				  UINT32 * pEventCount,	/* in,out */
				  TSS_PCR_EVENT ** ppEvents	/* out */
    );

TSS_RESULT TCS_GetPcrEventLog(TCS_CONTEXT_HANDLE hContext,	/* in  */
			       UINT32 * pEventCount,	/* out */
			       TSS_PCR_EVENT ** ppEvents	/* out */
    );

TSS_RESULT TCS_RegisterKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TSS_UUID WrappingKeyUUID,	/* in */
			    TSS_UUID KeyUUID,	/* in  */
			    UINT32 cKeySize,	/* in */
			    BYTE * rgbKey,	/* in */
			    UINT32 cVendorData,	/* in */
			    BYTE * gbVendorData	/* in */
    );

TSS_RESULT TCSP_UnregisterKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_UUID KeyUUID	/* in  */
    );

TSS_RESULT TCS_EnumRegisteredKeys(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TSS_UUID * pKeyUUID,	/* in    */
				   UINT32 * pcKeyHierarchySize,	/* out */
				   TSS_KM_KEYINFO ** ppKeyHierarchy	/* out */
    );

TSS_RESULT TCS_GetRegisteredKey(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TSS_UUID KeyUUID,	/* in */
				 TSS_KM_KEYINFO ** ppKeyInfo	/* out */
    );

TSS_RESULT TCS_GetRegisteredKeyBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TSS_UUID KeyUUID,	/* in */
				     UINT32 * pcKeySize,	/* out */
				     BYTE ** prgbKey	/* out */
    );

TSS_RESULT TCSP_LoadKeyByBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCS_KEY_HANDLE hUnwrappingKey,	/* in */
			       UINT32 cWrappedKeyBlobSize,	/* in */
			       BYTE * rgbWrappedKeyBlob,	/* in */
			       TCS_AUTH * pAuth,	/* in, out */
			       TCS_KEY_HANDLE * phKeyTCSI,	/* out */
			       TCS_KEY_HANDLE * phKeyHMAC	/* out */
    );

TSS_RESULT TCSP_LoadKeyByUUID(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TSS_UUID KeyUUID,	/* in */
			       TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in, out */
			       TCS_KEY_HANDLE * phKeyTCSI	/* out */
    );

TSS_RESULT TCSP_EvictKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			  TCS_KEY_HANDLE hKey	/* in */
    );

TSS_RESULT TCSP_CreateWrapKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCS_KEY_HANDLE hWrappingKey,	/* in */
			       TCPA_ENCAUTH KeyUsageAuth,	/* in */
			       TCPA_ENCAUTH KeyMigrationAuth,	/* in */
			       UINT32 keyInfoSize,	/* in */
			       BYTE * keyInfo,	/* in */
			       UINT32 * keyDataSize,	/* out */
			       BYTE ** keyData,	/* out */
			       TCS_AUTH * pAuth	/* in, out */
    );

TSS_RESULT TCSP_GetPubKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCS_KEY_HANDLE hKey,	/* in */
			   TCS_AUTH * pAuth,	/* in, out */
			   UINT32 * pcPubKeySize,	/* out */
			   BYTE ** prgbPubKey	/* out */
    );
TSS_RESULT TCSP_MakeIdentity(TCS_CONTEXT_HANDLE hContext,	/* in  */
			      TCPA_ENCAUTH identityAuth,	/* in */
			      TCPA_CHOSENID_HASH IDLabel_PrivCAHash,	/* in */
			      UINT32 idKeyInfoSize,	/*in */
			      BYTE * idKeyInfo,	/*in */
			      TCS_AUTH * pSrkAuth,	/* in, out */
			      TCS_AUTH * pOwnerAuth,	/* in, out */
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
    );

TSS_RESULT TCSP_SetOwnerInstall(TCS_CONTEXT_HANDLE hContext,	/* in */
				 BOOL state	/* in  */
    );
TSS_RESULT TCSP_TakeOwnership(TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT16 protocolID,	/* in */
			       UINT32 encOwnerAuthSize,	/* in  */
			       BYTE * encOwnerAuth,	/* in */
			       UINT32 encSrkAuthSize,	/* in */
			       BYTE * encSrkAuth,	/* in */
			       UINT32 srkInfoSize,	/*in */
			       BYTE * srkInfo,	/*in */
			       TCS_AUTH * ownerAuth,	/* in, out */
			       UINT32 * srkKeySize,	/*out */
			       BYTE ** srkKey	/*out */
    );

TSS_RESULT TCSP_OIAP(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCS_AUTHHANDLE * authHandle,	/* out  */
		      TCPA_NONCE * nonce0	/* out */
    );

TSS_RESULT TCSP_OSAP(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCPA_ENTITY_TYPE entityType,	/* in */
		      UINT32 entityValue,	/* in */
		      TCPA_NONCE nonceOddOSAP,	/* in */
		      TCS_AUTHHANDLE * authHandle,	/* out  */
		      TCPA_NONCE * nonceEven,	/* out */
		      TCPA_NONCE * nonceEvenOSAP	/* out */
    );

TSS_RESULT TCSP_ChangeAuth(TCS_CONTEXT_HANDLE contextHandle,	/* in */
			    TCS_KEY_HANDLE parentHandle,	/* in */
			    TCPA_PROTOCOL_ID protocolID,	/* in */
			    TCPA_ENCAUTH newAuth,	/* in */
			    TCPA_ENTITY_TYPE entityType,	/* in */
			    UINT32 encDataSize,	/* in */
			    BYTE * encData,	/* in */
			    TCS_AUTH * ownerAuth,	/* in, out */
			    TCS_AUTH * entityAuth,	/* in, out       */
			    UINT32 * outDataSize,	/* out */
			    BYTE ** outData	/* out */
    );

TSS_RESULT TCSP_ChangeAuthOwner(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_PROTOCOL_ID protocolID,	/* in */
				 TCPA_ENCAUTH newAuth,	/* in */
				 TCPA_ENTITY_TYPE entityType,	/* in */
				 TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_ChangeAuthAsymStart(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE idHandle,	/* in */
				     TCPA_NONCE antiReplay,	/* in */
				     UINT32 KeySizeIn,	/* in */
				     BYTE * KeyDataIn,	/* in */
				     TCS_AUTH * pAuth,	/* in, out */
				     UINT32 * KeySizeOut,	/* out */
				     BYTE ** KeyDataOut,	/* out */
				     UINT32 * CertifyInfoSize,	/* out */
				     BYTE ** CertifyInfo,	/* out */
				     UINT32 * sigSize,	/* out */
				     BYTE ** sig,	/* out */
				     TCS_KEY_HANDLE * ephHandle	/* out */
    );

TSS_RESULT TCSP_ChangeAuthAsymFinish(TCS_CONTEXT_HANDLE hContext,	/* in */
				      TCS_KEY_HANDLE parentHandle,	/* in */
				      TCS_KEY_HANDLE ephHandle,	/* in */
				      TCPA_ENTITY_TYPE entityType,	/* in */
				      TCPA_HMAC newAuthLink,	/* in */
				      UINT32 newAuthSize,	/* in */
				      BYTE * encNewAuth,	/* in */
				      UINT32 encDataSizeIn,	/* in */
				      BYTE * encDataIn,	/* in */
				      TCS_AUTH * ownerAuth,	/* in, out */
				      UINT32 * encDataSizeOut,	/* out */
				      BYTE ** encDataOut,	/* out */
				      TCPA_SALT_NONCE * saltNonce,	/* out */
				      TCPA_DIGEST * changeProof	/* out */
    );

TSS_RESULT TCSP_TerminateHandle(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_AUTHHANDLE handle	/* in */
    );

TSS_RESULT TCSP_ActivateTPMIdentity(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE idKey,	/* in */
				     UINT32 blobSize,	/* in */
				     BYTE * blob,	/* in */
				     TCS_AUTH * idKeyAuth,	/* in, out */
				     TCS_AUTH * ownerAuth,	/* in, out */
				     UINT32 * SymmetricKeySize,	/* out */
				     BYTE ** SymmetricKey	/* out */
    );

TSS_RESULT TCSP_Extend(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCPA_PCRINDEX pcrNum,	/* in */
			TCPA_DIGEST inDigest,	/* in */
			TCPA_PCRVALUE * outDigest	/* out */
    );

TSS_RESULT TCSP_PcrRead(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_PCRINDEX pcrNum,	/* in */
			 TCPA_PCRVALUE * outDigest	/* out */
    );

TSS_RESULT TCSP_Quote(TCS_CONTEXT_HANDLE hContext,	/* in */
		       TCS_KEY_HANDLE keyHandle,	/* in */
		       TCPA_NONCE antiReplay,	/* in */
		       UINT32 pcrDataSizeIn,	/* in */
		       BYTE * pcrDataIn,	/* in */
		       TCS_AUTH * privAuth,	/* in, out */
		       UINT32 * pcrDataSizeOut,	/* out */
		       BYTE ** pcrDataOut,	/* out */
		       UINT32 * sigSize,	/* out */
		       BYTE ** sig	/* out */
    );

TSS_RESULT TCSP_DirWriteAuth(TCS_CONTEXT_HANDLE hContext,	/* in */
			      TCPA_DIRINDEX dirIndex,	/* in */
			      TCPA_DIRVALUE newContents,	/* in */
			      TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_DirRead(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TCPA_DIRINDEX dirIndex,	/* in */
			 TCPA_DIRVALUE * dirValue	/* out */
    );

TSS_RESULT TCSP_Seal(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCS_KEY_HANDLE keyHandle,	/* in */
		      TCPA_ENCAUTH encAuth,	/* in */
		      UINT32 pcrInfoSize,	/* in */
		      BYTE * PcrInfo,	/* in */
		      UINT32 inDataSize,	/* in */
		      BYTE * inData,	/* in */
		      TCS_AUTH * pubAuth,	/* in, out */
		      UINT32 * SealedDataSize,	/* out */
		      BYTE ** SealedData	/* out */
    );

TSS_RESULT TCSP_Unseal(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCS_KEY_HANDLE parentHandle,	/* in */
			UINT32 SealedDataSize,	/* in */
			BYTE * SealedData,	/* in */
			TCS_AUTH * parentAuth,	/* in, out */
			TCS_AUTH * dataAuth,	/* in, out */
			UINT32 * DataSize,	/* out */
			BYTE ** Data	/* out */
    );

TSS_RESULT TCSP_UnBind(TCS_CONTEXT_HANDLE hContext,	/* in */
			TCS_KEY_HANDLE keyHandle,	/* in */
			UINT32 inDataSize,	/* in */
			BYTE * inData,	/* in */
			TCS_AUTH * privAuth,	/* in, out */
			UINT32 * outDataSize,	/* out */
			BYTE ** outData	/* out */
    );

TSS_RESULT TCSP_CreateMigrationBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE parentHandle,	/* in */
				     TCPA_MIGRATE_SCHEME migrationType,	/* in */
/*TCPA_MIGRATION_SCHEME	migrationType,				// in */
				     UINT32 MigrationKeyAuthSize,	/* in */
				     BYTE * MigrationKeyAuth,	/* in */
				     UINT32 encDataSize,	/* in */
				     BYTE * encData,	/* in */
				     TCS_AUTH * parentAuth,	/* in, out */
				     TCS_AUTH * entityAuth,	/* in, out */
				     UINT32 * randomSize,	/* out */
				     BYTE ** random,	/* out */
				     UINT32 * outDataSize,	/* out */
				     BYTE ** outData	/* out */
    );

TSS_RESULT TCSP_ConvertMigrationBlob(TCS_CONTEXT_HANDLE hContext,	/* in */
				      TCS_KEY_HANDLE parentHandle,	/* in */
				      UINT32 inDataSize,	/* in */
				      BYTE * inData,	/* in */
				      TCS_AUTH * parentAuth,	/* in, out */
				      UINT32 randomSize,	/* should be in */
				      BYTE * random,	/* should be in */
				      UINT32 * outDataSize,	/* out */
				      BYTE ** outData	/* out */
    );

TSS_RESULT TCSP_AuthorizeMigrationKey(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
				       UINT32 MigrationKeySize,	/* in */
				       BYTE * MigrationKey,	/* in */
				       TCS_AUTH * ownerAuth,	/* in, out */
				       UINT32 * MigrationKeyAuthSize,	/* out */
				       BYTE ** MigrationKeyAuth	/* out */
    );

TSS_RESULT TCSP_CertifyKey(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCS_KEY_HANDLE certHandle,	/* in */
			    TCS_KEY_HANDLE keyHandle,	/* in */
			    TCPA_NONCE antiReplay,	/* in */
			    TCS_AUTH * certAuth,	/* in, out */
			    TCS_AUTH * keyAuth,	/* in, out */
			    UINT32 * CertifyInfoSize,	/* out */
			    BYTE ** CertifyInfo,	/* out */
			    UINT32 * outDataSize,	/* out */
			    BYTE ** outData	/* out */
    );

TSS_RESULT TCSP_Sign(TCS_CONTEXT_HANDLE hContext,	/* in */
		      TCS_KEY_HANDLE keyHandle,	/* in */
		      UINT32 areaToSignSize,	/* in */
		      BYTE * areaToSign,	/* in */
		      TCS_AUTH * privAuth,	/* in, out */
		      UINT32 * sigSize,	/* out */
		      BYTE ** sig	/* out */
    );

TSS_RESULT TCSP_GetRandom(TCS_CONTEXT_HANDLE hContext,	/* in */
			   UINT32 bytesRequested,	/* in */
			   BYTE ** randomBytes	/* out */
    );

TSS_RESULT TCSP_StirRandom(TCS_CONTEXT_HANDLE hContext,	/* in */
			    UINT32 inDataSize,	/* in */
			    BYTE * inData	/* in */
    );

TSS_RESULT TCSP_GetCapability(TCS_CONTEXT_HANDLE hContext,	/* in */
			       TCPA_CAPABILITY_AREA capArea,	/* in */
			       UINT32 subCapSize,	/* in */
			       BYTE * subCap,	/* in */
			       UINT32 * respSize,	/* out */
			       BYTE ** resp	/* out */
    );

TSS_RESULT TCSP_GetCapabilitySigned(TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE keyHandle,	/* in */
				     TCPA_NONCE antiReplay,	/* in */
				     TCPA_CAPABILITY_AREA capArea,	/* in */
				     UINT32 subCapSize,	/* in */
				     BYTE * subCap,	/* in */
				     TCS_AUTH * privAuth,	/* in, out */
				     TCPA_VERSION * Version,	/* out */
				     UINT32 * respSize,	/* out */
				     BYTE ** resp,	/* out */
				     UINT32 * sigSize,	/* out */
				     BYTE ** sig	/* out */
    );

TSS_RESULT TCSP_GetCapabilityOwner(TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCS_AUTH * pOwnerAuth,	/* out */
				    TCPA_VERSION * pVersion,	/* out */
				    UINT32 * pNonVolatileFlags,	/* out */
				    UINT32 * pVolatileFlags	/* out */
    );

TSS_RESULT TCSP_CreateEndorsementKeyPair(TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCPA_NONCE antiReplay,	/* in */
					  UINT32 endorsementKeyInfoSize,	/* in */
					  BYTE * endorsementKeyInfo,	/* in */
					  UINT32 * endorsementKeySize,	/* out */
					  BYTE ** endorsementKey,	/* out */
					  TCPA_DIGEST * checksum	/* out */
    );

TSS_RESULT TCSP_ReadPubek(TCS_CONTEXT_HANDLE hContext,	/* in */
			   TCPA_NONCE antiReplay,	/* in */
			   UINT32 * pubEndorsementKeySize,	/* out */
			   BYTE ** pubEndorsementKey,	/* out */
			   TCPA_DIGEST * checksum	/* out */
    );

TSS_RESULT TCSP_DisablePubekRead(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_OwnerReadPubek(TCS_CONTEXT_HANDLE hContext,	/* in */
				TCS_AUTH * ownerAuth,	/* in, out */
				UINT32 * pubEndorsementKeySize,	/* out */
				BYTE ** pubEndorsementKey	/* out */
    );

TSS_RESULT TCSP_SelfTestFull(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCSP_CertifySelfTest(TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_KEY_HANDLE keyHandle,	/* in */
				 TCPA_NONCE antiReplay,	/* in */
				 TCS_AUTH * privAuth,	/* in, out */
				 UINT32 * sigSize,	/* out */
				 BYTE ** sig	/* out */
    );

TSS_RESULT TCSP_GetTestResult(TCS_CONTEXT_HANDLE hContext,	/* in */
			       UINT32 * outDataSize,	/* out */
			       BYTE ** outData	/* out */
    );

TSS_RESULT TCSP_OwnerSetDisable(TCS_CONTEXT_HANDLE hContext,	/* in */
				 BOOL disableState,	/* in */
				 TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_OwnerClear(TCS_CONTEXT_HANDLE hContext,	/* in */
			    TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_DisableOwnerClear(TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_ForceClear(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCSP_DisableForceClear(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCSP_PhysicalDisable(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCSP_PhysicalEnable(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCSP_PhysicalSetDeactivated(TCS_CONTEXT_HANDLE hContext,	/* in */
					BOOL state	/* in */
    );

TSS_RESULT TCSP_PhysicalPresence(TCS_CONTEXT_HANDLE hContext,  /*  in */
		TCPA_PHYSICAL_PRESENCE fPhysicalPresence        /*  in */
    );

TSS_RESULT TCSP_SetTempDeactivated(TCS_CONTEXT_HANDLE hContext	/* in */
    );

TSS_RESULT TCSP_FieldUpgrade(TCS_CONTEXT_HANDLE hContext,	/* in */
			      UINT32 dataInSize,	/* in */
			      BYTE * dataIn,	/* in */
			      UINT32 * dataOutSize,	/* out */
			      BYTE ** dataOut,	/* out */
			      TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_SetRedirection(TCS_CONTEXT_HANDLE hContext,	/* in */
				TCS_KEY_HANDLE keyHandle,	/* in */
				UINT32 c1,	/* in */
				UINT32 c2,	/* in */
				TCS_AUTH * privAuth	/* in, out */
    );

TSS_RESULT TCSP_CreateMaintenanceArchive(TCS_CONTEXT_HANDLE hContext,	/* in */
					  BOOL generateRandom,	/* in */
					  TPM_AUTH * ownerAuth,	/* in, out */
					  UINT32 * randomSize,	/* out */
					  BYTE ** random,	/* out */
					  UINT32 * archiveSize,	/* out */
					  BYTE ** archive	/* out */
    );

TSS_RESULT TCSP_LoadMaintenanceArchive(TCS_CONTEXT_HANDLE hContext,	/* in */
					UINT32 dataInSize,	/* in */
					BYTE * dataIn,	/* in */
					TPM_AUTH * ownerAuth,	/* in, out */
					UINT32 * dataOutSize,	/* out */
					BYTE ** dataOut	/* out */
    );

TSS_RESULT TCSP_KillMaintenanceFeature(TCS_CONTEXT_HANDLE hContext,	/* in */
					TCS_AUTH * ownerAuth	/* in, out */
    );

TSS_RESULT TCSP_LoadManuMaintPub(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  UINT32 PubKeySize,	/* in */
				  BYTE * PubKey,	/* in */
				  TCPA_DIGEST * checksum	/* out */
    );

TSS_RESULT TCSP_ReadManuMaintPub(TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  TCPA_DIGEST * checksum	/* out */
    );

UINT32 TCS_OpenContext_RPC(UNICODE * hostName, UINT32 * tcsContext, int);

#endif
