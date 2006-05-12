
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TRPCTP_H_
#define _TRPCTP_H_

	TCPA_RESULT TCS_OpenContext_RPC_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE *);
	TCPA_RESULT TCSP_GetRegisteredKeyByPublicInfo_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE tcsContext, TCPA_ALGORITHM_ID algID,	/* in */
							 UINT32 ulPublicInfoLength,	/* in */
							 BYTE * rgbPublicInfo,	/* in */
							 UINT32 * keySize,
							 BYTE ** keyBlob);

	TCPA_RESULT TCS_CloseContext_TP(struct host_table_entry *,
					TCS_CONTEXT_HANDLE hContext);
	TCPA_RESULT TCS_FreeMemory_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				      BYTE * pMemory	/* in */
	    );
	TCPA_RESULT TCS_LogPcrEvent_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				       TSS_PCR_EVENT Event,	/* in */
				       UINT32 * pNumber	/* out */
	    );
	TCPA_RESULT TCS_GetPcrEvent_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				       UINT32 PcrIndex,	/* in */
				       UINT32 * pNumber,	/* in, out */
				       TSS_PCR_EVENT ** ppEvent	/* out */
	    );

	TCPA_RESULT TCS_GetPcrEventsByPcr_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					     UINT32 PcrIndex,	/* in */
					     UINT32 FirstEvent,	/* in */
					     UINT32 * pEventCount,	/* in ,out */
					     TSS_PCR_EVENT ** ppEvents	/* out */
	    );

	TCPA_RESULT TCS_GetPcrEventLog_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  UINT32 * pEventCount,	/* out */
					  TSS_PCR_EVENT ** ppEvents	/* out */
	    );

	TCPA_RESULT TCS_RegisterKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				       TSS_UUID WrappingKeyUUID,	/* in */
				       TSS_UUID KeyUUID,	/* in */
				       UINT32 cKeySize,	/* in */
				       BYTE * rgbKey,	/* in */
				       UINT32 cVendorData,	/* in */
				       BYTE * gbVendorData	/* in */
	    );

	TCPA_RESULT TCSP_UnregisterKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TSS_UUID KeyUUID	/* in */
	    );

	TCPA_RESULT TCS_EnumRegisteredKeys_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					      TSS_UUID * pKeyUUID,	/* in */
					      UINT32 * pcKeyHierarchySize,	/* out */
					      TSS_KM_KEYINFO ** ppKeyHierarchy	/* out */
	    );

	TCPA_RESULT TCS_GetRegisteredKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					    TSS_UUID KeyUUID,	/* in */
					    TSS_KM_KEYINFO ** ppKeyInfo	/* out */
	    );

	TCPA_RESULT TCS_GetRegisteredKeyBlob_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						TSS_UUID KeyUUID,	/* in */
						UINT32 * pcKeySize,	/* out */
						BYTE ** prgbKey	/* out */
	    );

	TCPA_RESULT TCSP_LoadKeyByBlob_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCS_KEY_HANDLE hUnwrappingKey,	/* in */
					  UINT32 cWrappedKeyBlobSize,	/* in */
					  BYTE * rgbWrappedKeyBlob,	/* in */
					  TPM_AUTH * pAuth,	/* in , out */
					  TCS_KEY_HANDLE * phKeyTCSI,	/* out */
					  TCS_KEY_HANDLE * phKeyHMAC	/* out */
	    );

	TCPA_RESULT TCSP_LoadKeyByUUID_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TSS_UUID KeyUUID,	/* in */
					  TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in , out */
					  TCS_KEY_HANDLE * phKeyTCSI	/* out */
	    );

	TCPA_RESULT TCSP_EvictKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				     TCS_KEY_HANDLE hKey	/* in */
	    );

	TCPA_RESULT TCSP_CreateWrapKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCS_KEY_HANDLE hWrappingKey,	/* in */
					  TCPA_ENCAUTH KeyUsageAuth,	/* in */
					  TCPA_ENCAUTH KeyMigrationAuth,	/* in */
					  UINT32 keyInfoSize,	/* in */
					  BYTE * keyInfo,	/* in */
					  UINT32 * keyDataSize,	/* out */
					  BYTE ** keyData,	/* out */
					  TPM_AUTH * pAuth	/* in , out */
	    );

	TCPA_RESULT TCSP_GetPubKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				      TCS_KEY_HANDLE hKey,	/* in */
				      TPM_AUTH * pAuth,	/* in , out */
				      UINT32 * pcPubKeySize,	/* out */
				      BYTE ** prgbPubKey	/* out */
	    );

	TCPA_RESULT TCSP_MakeIdentity_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCPA_ENCAUTH identityAuth,	/* in */
					 TCPA_CHOSENID_HASH IDLabel_PrivCAHash,	/* in */
					 UINT32 idKeyInfoSize,	/* in */
					 BYTE * idKeyInfo,	/* in */
					 TPM_AUTH * pSrkAuth,	/* in , out */
					 TPM_AUTH * pOwnerAuth,	/* in , out */
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

	TCPA_RESULT TCSP_SetOwnerInstall_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					    TSS_BOOL state	/* in */
	    );

	TCPA_RESULT TCSP_TakeOwnership_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  UINT16 protocolID,	/* in */
					  UINT32 encOwnerAuthSize,	/* in */
					  BYTE * encOwnerAuth,	/* in */
					  UINT32 encSrkAuthSize,	/* in */
					  BYTE * encSrkAuth,	/* in */
					  UINT32 srkInfoSize,	/* in */
					  BYTE * srkInfo,	/* in */
					  TPM_AUTH * ownerAuth,	/* in , out */
					  UINT32 * srkKeySize, BYTE ** srkKey);

	TCPA_RESULT TCSP_OIAP_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_AUTHHANDLE * authHandle,	/* out */
				 TCPA_NONCE * nonce0	/* out */
	    );

	TCPA_RESULT TCSP_OSAP_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCPA_ENTITY_TYPE entityType,	/* in */
				 UINT32 entityValue,	/* in */
				 TCPA_NONCE nonceOddOSAP,	/* in */
				 TCS_AUTHHANDLE * authHandle,	/* out */
				 TCPA_NONCE * nonceEven,	/* out */
				 TCPA_NONCE * nonceEvenOSAP	/* out */
	    );

	TCPA_RESULT TCSP_ChangeAuth_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE contextHandle,	/* in */
				       TCS_KEY_HANDLE parentHandle,	/* in */
				       TCPA_PROTOCOL_ID protocolID,	/* in */
				       TCPA_ENCAUTH newAuth,	/* in */
				       TCPA_ENTITY_TYPE entityType,	/* in */
				       UINT32 encDataSize,	/* in */
				       BYTE * encData,	/* in */
				       TPM_AUTH * ownerAuth,	/* in , out */
				       TPM_AUTH * entityAuth,	/* in , out */
				       UINT32 * outDataSize,	/* out */
				       BYTE ** outData	/* out */
	    );

	TCPA_RESULT TCSP_ChangeAuthOwner_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					    TCPA_PROTOCOL_ID protocolID,	/* in */
					    TCPA_ENCAUTH newAuth,	/* in */
					    TCPA_ENTITY_TYPE entityType,	/* in */
					    TPM_AUTH * ownerAuth	/* in , out */
	    );

	TCPA_RESULT TCSP_ChangeAuthAsymStart_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						TCS_KEY_HANDLE idHandle,	/* in */
						TCPA_NONCE antiReplay,	/* in */
						UINT32 KeySizeIn,	/* in */
						BYTE * KeyDataIn,	/* in */
						TPM_AUTH * pAuth,	/* in , out */
						UINT32 * KeySizeOut,	/* out */
						BYTE ** KeyDataOut,	/* out */
						UINT32 * CertifyInfoSize,	/* out */
						BYTE ** CertifyInfo,	/* out */
						UINT32 * sigSize,	/* out */
						BYTE ** sig,	/* out */
						TCS_KEY_HANDLE * ephHandle	/* out */
	    );

	TCPA_RESULT TCSP_ChangeAuthAsymFinish_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						 TCS_KEY_HANDLE parentHandle,	/* in */
						 TCS_KEY_HANDLE ephHandle,	/* in */
						 TCPA_ENTITY_TYPE entityType,	/* in */
						 TCPA_HMAC newAuthLink,	/* in */
						 UINT32 newAuthSize,	/* in */
						 BYTE * encNewAuth,	/* in */
						 UINT32 encDataSizeIn,	/* in */
						 BYTE * encDataIn,	/* in */
						 TPM_AUTH * ownerAuth,	/* in , out */
						 UINT32 * encDataSizeOut,	/* out */
						 BYTE ** encDataOut,	/* out */
						 TCPA_SALT_NONCE * saltNonce,	/* out */
						 TCPA_DIGEST * changeProof	/* out */
	    );

	TCPA_RESULT TCSP_TerminateHandle_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					    TCS_AUTHHANDLE handle	/* in */
	    );

	TCPA_RESULT TCSP_ActivateTPMIdentity_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						TCS_KEY_HANDLE idKey,	/* in */
						UINT32 blobSize,	/* in */
						BYTE * blob,	/* in */
						TPM_AUTH * idKeyAuth,	/* in , out */
						TPM_AUTH * ownerAuth,	/* in , out */
						UINT32 * SymmetricKeySize,	/* out */
						BYTE ** SymmetricKey	/* out */
	    );

	TCPA_RESULT TCSP_Extend_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCPA_PCRINDEX pcrNum,	/* in */
				   TCPA_DIGEST inDigest,	/* in */
				   TCPA_PCRVALUE * outDigest	/* out */
	    );

	TCPA_RESULT TCSP_PcrRead_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCPA_PCRINDEX pcrNum,	/* in */
				    TCPA_PCRVALUE * outDigest	/* out */
	    );

	TCPA_RESULT TCSP_Quote_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				  TCS_KEY_HANDLE keyHandle,	/* in */
				  TCPA_NONCE antiReplay,	/* in */
				  UINT32 pcrDataSizeIn,	/* in */
				  BYTE * pcrDataIn,	/* in */
				  TPM_AUTH * privAuth,	/* in , out */
				  UINT32 * pcrDataSizeOut,	/* out */
				  BYTE ** pcrDataOut,	/* out */
				  UINT32 * sigSize,	/* out */
				  BYTE ** sig	/* out */
	    );

	TCPA_RESULT TCSP_DirWriteAuth_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCPA_DIRINDEX dirIndex,	/* in */
					 TCPA_DIRVALUE newContents,	/* in */
					 TPM_AUTH * ownerAuth	/* in , out */
	    );

	TCPA_RESULT TCSP_DirRead_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				    TCPA_DIRINDEX dirIndex,	/* in */
				    TCPA_DIRVALUE * dirValue	/* out */
	    );

	TCPA_RESULT TCSP_Seal_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_KEY_HANDLE keyHandle,	/* in */
				 TCPA_ENCAUTH encAuth,	/* in */
				 UINT32 pcrInfoSize,	/* in */
				 BYTE * PcrInfo,	/* in */
				 UINT32 inDataSize,	/* in */
				 BYTE * inData,	/* in */
				 TPM_AUTH * pubAuth,	/* in , out */
				 UINT32 * SealedDataSize,	/* out */
				 BYTE ** SealedData	/* out */
	    );

	TCPA_RESULT TCSP_Unseal_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE parentHandle,	/* in */
				   UINT32 SealedDataSize,	/* in */
				   BYTE * SealedData,	/* in */
				   TPM_AUTH * parentAuth,	/* in , out */
				   TPM_AUTH * dataAuth,	/* in , out */
				   UINT32 * DataSize,	/* out */
				   BYTE ** Data	/* out */
	    );

	TCPA_RESULT TCSP_UnBind_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				   TCS_KEY_HANDLE keyHandle,	/* in */
				   UINT32 inDataSize,	/* in */
				   BYTE * inData,	/* in */
				   TPM_AUTH * privAuth,	/* in , out */
				   UINT32 * outDataSize,	/* out */
				   BYTE ** outData	/* out */
	    );

	TCPA_RESULT TCSP_CreateMigrationBlob_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						TCS_KEY_HANDLE parentHandle,	/* in */
						TCPA_MIGRATE_SCHEME migrationType,	/* in */
						UINT32 MigrationKeyAuthSize,	/* in */
						BYTE * MigrationKeyAuth,	/* in */
						UINT32 encDataSize,	/* in */
						BYTE * encData,	/* in */
						TPM_AUTH * parentAuth,	/* in , out */
						TPM_AUTH * entityAuth,	/* in , out */
						UINT32 * randomSize,	/* out */
						BYTE ** random,	/* out */
						UINT32 * outDataSize,	/* out */
						BYTE ** outData	/* out */
	    );

	TCPA_RESULT TCSP_ConvertMigrationBlob_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						 TCS_KEY_HANDLE parentHandle,	/* in */
						 UINT32 inDataSize,	/* in */
						 BYTE * inData,	/* in */
						 UINT32 randomSize,	/* in */
						 BYTE * random,	/* in */
						 TPM_AUTH * parentAuth,	/* in , out */
						 UINT32 * outDataSize,	/* out */
						 BYTE ** outData	/* out */
	    );

	TCPA_RESULT TCSP_AuthorizeMigrationKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						  TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
						  UINT32 MigrationKeySize,	/* in */
						  BYTE * MigrationKey,	/* in */
						  TPM_AUTH * ownerAuth,	/* in, out */
						  UINT32 * MigrationKeyAuthSize,	/* out */
						  BYTE ** MigrationKeyAuth	/* out */
	    );

	TCPA_RESULT TCSP_CertifyKey_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCS_KEY_HANDLE certHandle,	/* in */
				       TCS_KEY_HANDLE keyHandle,	/* in */
				       TCPA_NONCE antiReplay,	/* in */
				       TPM_AUTH * certAuth,	/* in, out */
				       TPM_AUTH * keyAuth,	/* in, out */
				       UINT32 * CertifyInfoSize,	/* out */
				       BYTE ** CertifyInfo,	/* out */
				       UINT32 * outDataSize,	/* out */
				       BYTE ** outData	/* out */
	    );

	TCPA_RESULT TCSP_Sign_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				 TCS_KEY_HANDLE keyHandle,	/* in */
				 UINT32 areaToSignSize,	/* in */
				 BYTE * areaToSign,	/* in */
				 TPM_AUTH * privAuth,	/* in, out */
				 UINT32 * sigSize,	/* out */
				 BYTE ** sig	/* out */
	    );

	TCPA_RESULT TCSP_GetRandom_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				      UINT32 bytesRequested,	/* in */
				      BYTE ** randomBytes	/* out */
	    );

	TCPA_RESULT TCSP_StirRandom_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				       UINT32 inDataSize,	/* in */
				       BYTE * inData	/* in */
	    );

	TCPA_RESULT TCS_GetCapability_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCPA_CAPABILITY_AREA capArea,	/* in */
					 UINT32 subCapSize,	/* in */
					 BYTE * subCap,	/* in */
					 UINT32 * respSize,	/* out */
					 BYTE ** resp	/* out */
	    );

	TCPA_RESULT TCSP_GetCapability_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCPA_CAPABILITY_AREA capArea,	/* in */
					  UINT32 subCapSize,	/* in */
					  BYTE * subCap,	/* in */
					  UINT32 * respSize,	/* out */
					  BYTE ** resp	/* out */
	    );

	TCPA_RESULT TCSP_GetCapabilitySigned_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
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
						BYTE ** sig	/* out */
	    );

	TCPA_RESULT TCSP_GetCapabilityOwner_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					       TPM_AUTH * pOwnerAuth,	/* out */
					       TCPA_VERSION * pVersion,	/* out */
					       UINT32 * pNonVolatileFlags,	/* out */
					       UINT32 * pVolatileFlags	/* out */
	    );

	TCPA_RESULT TCSP_CreateEndorsementKeyPair_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						     TCPA_NONCE antiReplay,	/* in */
						     UINT32 endorsementKeyInfoSize,	/* in */
						     BYTE * endorsementKeyInfo,	/* in */
						     UINT32 * endorsementKeySize,	/* out */
						     BYTE ** endorsementKey,	/* out */
						     TCPA_DIGEST * checksum	/* out */
	    );

	TCPA_RESULT TCSP_ReadPubek_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				      TCPA_NONCE antiReplay,	/* in */
				      UINT32 * pubEndorsementKeySize,	/* out */
				      BYTE ** pubEndorsementKey,	/* out */
				      TCPA_DIGEST * checksum	/* out */
	    );

	TCPA_RESULT TCSP_DisablePubekRead_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					     TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_OwnerReadPubek_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					   TPM_AUTH * ownerAuth,	/* in, out */
					   UINT32 * pubEndorsementKeySize,	/* out */
					   BYTE ** pubEndorsementKey	/* out */
	    );

	TCPA_RESULT TCSP_SelfTestFull_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TCPA_RESULT TCSP_CertifySelfTest_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					    TCS_KEY_HANDLE keyHandle,	/* in */
					    TCPA_NONCE antiReplay,	/* in */
					    TPM_AUTH * privAuth,	/* in, out */
					    UINT32 * sigSize,	/* out */
					    BYTE ** sig	/* out */
	    );

	TCPA_RESULT TCSP_GetTestResult_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					  UINT32 * outDataSize,	/* out */
					  BYTE ** outData	/* out */
	    );

	TCPA_RESULT TCSP_OwnerSetDisable_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					    TSS_BOOL disableState,	/* in */
					    TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_OwnerClear_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
				       TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_DisableOwnerClear_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					      TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_ForceClear_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TCPA_RESULT TCSP_DisableForceClear_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TCPA_RESULT TCSP_PhysicalDisable_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TCPA_RESULT TCSP_PhysicalEnable_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TCPA_RESULT TCSP_PhysicalSetDeactivated_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						   TSS_BOOL state	/* in */
	    );

	TCPA_RESULT TCSP_PhysicalPresence_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						   TCPA_PHYSICAL_PRESENCE fPhysicalPresence	/* in */
	    );

	TCPA_RESULT TCSP_SetTempDeactivated_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TCPA_RESULT TCSP_FieldUpgrade_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					 UINT32 dataInSize,	/* in */
					 BYTE * dataIn,	/* in */
					 UINT32 * dataOutSize,	/* out */
					 BYTE ** dataOut,	/* out */
					 TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_SetRedirection_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					   TCS_KEY_HANDLE keyHandle,	/* in */
					   UINT32 c1,	/* in */
					   UINT32 c2,	/* in */
					   TPM_AUTH * privAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_CreateMaintenanceArchive_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						     TSS_BOOL generateRandom,	/* in */
						     TPM_AUTH * ownerAuth,	/* in, out */
						     UINT32 * randomSize,	/* out */
						     BYTE ** random,	/* out */
						     UINT32 archiveSize,	/* out */
						     BYTE ** archive	/* out */
	    );

	TCPA_RESULT TCSP_LoadMaintenanceArchive_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						   UINT32 * pcDataSize,	/* in, out */
						   BYTE ** prgbData,	/* in, out */
						   TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_KillMaintenanceFeature_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
						   TPM_AUTH * ownerAuth	/* in, out */
	    );

	TCPA_RESULT TCSP_LoadManuMaintPub_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					     TCPA_NONCE antiReplay,	/* in */
					     UINT32 PubKeySize,	/* in */
					     BYTE * PubKey,	/* in */
					     TCPA_DIGEST * checksum	/* out */
	    );

	TCPA_RESULT TCSP_ReadManuMaintPub_TP(struct host_table_entry *, TCS_CONTEXT_HANDLE hContext,	/* in */
					     TCPA_NONCE antiReplay,	/* in */
					     TCPA_DIGEST * checksum	/* out */
	    );

#endif
