
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TCS_UTILS_H_
#define _TCS_UTILS_H_

#include <assert.h>
#include <pthread.h>

struct key_mem_cache
{
	TCPA_KEY_HANDLE tpm_handle;
	TCS_KEY_HANDLE tcs_handle;
	UINT16 flags;
	int ref_cnt;
	UINT32 time_stamp;
	TSS_UUID uuid;
	TSS_UUID p_uuid;
	TCPA_KEY *blob;
	struct key_mem_cache *parent;
	struct key_mem_cache *next, *prev;
};

extern struct key_mem_cache *key_mem_cache_head;
extern pthread_mutex_t mem_cache_lock;

struct tpm_properties
{
	UINT32 num_pcrs;
	UINT32 num_dirs;
	UINT32 num_keys;
	UINT32 num_auths;
	TSS_BOOL authctx_swap;
	TSS_BOOL keyctx_swap;
	TCPA_VERSION version;
	BYTE manufacturer[16];
};

extern struct tpm_properties tpm_metrics;

#define TPM_VERSION(maj, min) \
	((tpm_metrics.version.major == maj) && (tpm_metrics.version.minor == min))

#define MIN(a,b) ((a) < (b) ? (a) : (b))

#ifdef TSS_DEBUG
#define DBG_ASSERT(x)	assert(x)
#else
#define DBG_ASSERT(x)
#endif

TSS_RESULT get_tpm_metrics(struct tpm_properties *);

TSS_RESULT auth_mgr_init();
TSS_RESULT auth_mgr_final();
TSS_RESULT auth_mgr_check(TCS_CONTEXT_HANDLE, TCS_AUTHHANDLE);
TSS_RESULT auth_mgr_release_auth(TCS_AUTHHANDLE);
TSS_RESULT auth_mgr_oiap(TCS_CONTEXT_HANDLE, TCS_AUTHHANDLE *, TCPA_NONCE *);
TSS_RESULT auth_mgr_osap(TCS_CONTEXT_HANDLE, TCPA_ENTITY_TYPE, UINT32, TCPA_NONCE,
			 TCS_AUTHHANDLE *, TCPA_NONCE *, TCPA_NONCE *);
TSS_RESULT auth_mgr_close_context(TCS_CONTEXT_HANDLE);

TSS_RESULT event_log_init();
TSS_RESULT event_log_final();

#define TPM_TXBLOB_SIZE		4096
#define MAX_AUTHS_CAP		1024

#define next( x ) x = x->next

/* platform.c */

char platform_get_runlevel();

/*---	cache.c */

void key_mgr_ref_count();
TSS_RESULT key_mgr_dec_ref_count(TCS_KEY_HANDLE);
TSS_RESULT key_mgr_inc_ref_count(TCS_KEY_HANDLE);
TSS_RESULT key_mgr_load_by_uuid(TCS_CONTEXT_HANDLE, TSS_UUID *, TCS_LOADKEY_INFO *,
				TCS_KEY_HANDLE *);
TSS_RESULT key_mgr_load_by_blob(TCS_CONTEXT_HANDLE, TCS_KEY_HANDLE, UINT32, BYTE *,
				TCS_AUTH *, TCS_KEY_HANDLE *, TCS_KEY_HANDLE *);
TSS_RESULT key_mgr_evict(TCS_CONTEXT_HANDLE, TCS_KEY_HANDLE);


extern TCS_CONTEXT_HANDLE InternalContext;
//extern KeyCacheEntry *glKeyCacheEntry;

void initKeyFile(TCS_CONTEXT_HANDLE hContext);
//TSS_RESULT initCache();
TSS_RESULT refreshTimeStampBySlot(TCPA_KEY_HANDLE keySlot);
TCS_KEY_HANDLE getNextTcsKeyHandle();
TCPA_STORE_PUBKEY *getParentPubBySlot(TCPA_KEY_HANDLE slot);
TCPA_STORE_PUBKEY *getPubBySlot(TCPA_KEY_HANDLE slot);
TCPA_STORE_PUBKEY *getPubByHandle(TCS_KEY_HANDLE tcsKeyHandle);
TSS_UUID *getUuidByPub(TCPA_STORE_PUBKEY *pub);
TSS_UUID *getUUIDByEncData(BYTE *encData);
TCS_KEY_HANDLE getTCSKeyHandleByEncData(BYTE *encData);
TSS_RESULT initDiskCache(void);
void closeDiskCache(void);

TSS_RESULT
replaceEncData_knowledge(BYTE *encData, BYTE *newEncData);

void
replaceEncData_PS(TSS_UUID, BYTE *encData, BYTE *newEncData);

TCPA_STORE_PUBKEY *getPubByUuid(TSS_UUID *);
TSS_RESULT add_mem_cache_entry(TCS_KEY_HANDLE, TCPA_KEY_HANDLE, TCPA_KEY *);
TSS_RESULT add_mem_cache_entry_srk(TCS_KEY_HANDLE, TCPA_KEY_HANDLE, TCPA_KEY *);
TSS_RESULT remove_mem_cache_entry(TCS_KEY_HANDLE tcs_handle);
TSS_RESULT setSlotBySlot(TCPA_KEY_HANDLE, TCPA_KEY_HANDLE);
TSS_RESULT setSlotByHandle(TCS_KEY_HANDLE, TCPA_KEY_HANDLE);
//void removeCacheEntryByHandle(TCS_KEY_HANDLE);
//void setUuidsByPub(TCPA_STORE_PUBKEY *, TSS_UUID *, TSS_UUID *);
TCPA_KEY_HANDLE getSlotByHandle(TCS_KEY_HANDLE);
TCPA_KEY_HANDLE getSlotByHandle_lock(TCS_KEY_HANDLE);
TCPA_KEY_HANDLE getSlotByPub(TCPA_STORE_PUBKEY *);
TCS_KEY_HANDLE getTCSKeyHandleByPub(TCPA_STORE_PUBKEY *);
TCPA_STORE_PUBKEY *getParentPubByPub(TCPA_STORE_PUBKEY *);
BOOL isKeyRegistered(TCPA_STORE_PUBKEY *);
TSS_RESULT getBlobByPub(TCPA_STORE_PUBKEY *, TCPA_KEY **);
//TSS_RESULT setParentPubByPub(TCPA_STORE_PUBKEY *, TCPA_STORE_PUBKEY *);
TCS_KEY_HANDLE getAnyHandleBySlot(TCPA_KEY_HANDLE);
//TCS_KEY_HANDLE getKeyHandleByUuid(TSS_UUID *);
TSS_RESULT evictFirstKey(TCS_KEY_HANDLE);
TSS_RESULT getParentUUIDByUUID(TSS_UUID *, TSS_UUID **);
TSS_RESULT removeRegisteredKeyFromFile(TSS_UUID *);
/*TSS_RESULT removeRegisteredKeyNode(TSS_UUID *);*/
TSS_RESULT getRegisteredKeyByUUID(TSS_UUID *, BYTE *, UINT16 *);
TSS_RESULT isPubRegistered(TCPA_STORE_PUBKEY *);
TSS_RESULT getRegisteredUuidByPub(TCPA_STORE_PUBKEY *, TSS_UUID **);
BOOL isKeyLoaded(TCPA_KEY_HANDLE);
TSS_RESULT LoadKeyShim(TCS_CONTEXT_HANDLE, TCPA_STORE_PUBKEY *, TSS_UUID *,TCPA_KEY_HANDLE *);
TSS_RESULT writeRegisteredKeyToFile(TSS_UUID *, TSS_UUID *, BYTE *, UINT32);
BOOL isKeyInMemCache(TCS_KEY_HANDLE);
TSS_RESULT setParentByHandle(TCS_KEY_HANDLE, TCS_KEY_HANDLE);
TSS_RESULT isUUIDRegistered(TSS_UUID *, BOOL *);
TSS_RESULT destroyKeyFile(void);
void destroy_key_refs(TCPA_KEY *);
TSS_RESULT getKeyByCacheEntry(struct key_disk_cache *, BYTE *, UINT16 *);

#if 0
int KM_GetHierarchy(TSS_UUID *, KMNode **);
void KM_DestroyKMList(struct tdKMList *list);
void KM_DestroyKMNode(KMNode * list);
#endif

/*******************************************************************************************************/
/*---	cxt.c */

TSS_RESULT freeSomeMemory(TCS_CONTEXT_HANDLE, void *);
void *getSomeMemory(unsigned long, TCS_CONTEXT_HANDLE);
TSS_RESULT context_close_auth(TCS_CONTEXT_HANDLE);
TSS_RESULT checkContextForAuth(TCS_CONTEXT_HANDLE, TCS_AUTHHANDLE);
TSS_RESULT addContextForAuth(TCS_CONTEXT_HANDLE, TCS_AUTHHANDLE);
TSS_RESULT ctx_verify_context(TCS_CONTEXT_HANDLE);
pthread_cond_t *ctx_get_cond_var(TCS_CONTEXT_HANDLE);
TSS_RESULT ctx_mark_key_loaded(TCS_CONTEXT_HANDLE, TCS_KEY_HANDLE);

TCS_CONTEXT_HANDLE make_context();
void destroy_context(TCS_CONTEXT_HANDLE);


/*******************************************************************************************************/
/*---	tcs_utils.c */

TSS_RESULT get_current_version(TCPA_VERSION *);
TSS_RESULT fill_key_info(struct key_disk_cache *, struct key_mem_cache *, TSS_KM_KEYINFO *);

void setCorruptParamSize(BOOL);
TSS_RESULT ensureKeyIsLoaded(TCS_CONTEXT_HANDLE, TCS_KEY_HANDLE, TCPA_KEY_HANDLE *);
UINT16 getVendor(TCS_CONTEXT_HANDLE);

void showBlob(BYTE * blob, char *string);
void LogData(char *string, UINT32 data);
void LogArray(char *string, BYTE * data, UINT32 length);
void LogResult(char *string, TSS_RESULT result);
void setLogging(BYTE b);
void purgeLog();
TSS_RESULT canILoadThisKey(TCPA_KEY_PARMS *parms, BOOL *);
TSS_RESULT internal_EvictByKeySlot(TCPA_KEY_HANDLE slot);

TSS_RESULT clearKeysFromChip(TCS_CONTEXT_HANDLE hContext);
TSS_RESULT clearUnknownKeys(TCS_CONTEXT_HANDLE);

UINT16 Decode_UINT16(BYTE * in);
void UINT32ToArray(UINT32 i, BYTE * out);
void UINT16ToArray(UINT16 i, BYTE * out);
UINT32 Decode_UINT32(BYTE * y);
void LoadBlob_UINT32(UINT16 * offset, UINT32 in, BYTE * blob, char *);
void LoadBlob_UINT16(UINT16 * offset, UINT16 in, BYTE * blob, char *);
void UnloadBlob_UINT32(UINT16 * offset, UINT32 * out, BYTE * blob, char *);
void UnloadBlob_UINT16(UINT16 * offset, UINT16 * out, BYTE * blob, char *);
void LoadBlob_BYTE(UINT16 * offset, BYTE data, BYTE * blob, char *);
void UnloadBlob_BYTE(UINT16 * offset, BYTE * dataOut, BYTE * blob, char *);
void LoadBlob_BOOL(UINT16 * offset, BOOL data, BYTE * blob, char *);
void UnloadBlob_BOOL(UINT16 * offset, BOOL * dataOut, BYTE * blob, char *);
void LoadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object, char *);
void UnloadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object, char *);
void LoadBlob_Header(UINT16 tag, UINT32 paramSize, UINT32 ordinal, BYTE * blob);
TSS_RESULT UnloadBlob_Header(BYTE * blob, UINT32 * size);
void LoadBlob_MIGRATIONKEYAUTH(UINT16 * offset, BYTE * blob, TCPA_MIGRATIONKEYAUTH * mkAuth);
void UnloadBlob_MIGRATIONKEYAUTH(UINT16 * offset, BYTE * blob,
				 TCPA_MIGRATIONKEYAUTH * mkAuth);
void LoadBlob_Auth(UINT16 * offset, BYTE * blob, TCS_AUTH * auth);
void UnloadBlob_Auth(UINT16 * offset, BYTE * blob, TCS_AUTH * auth);
void LoadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyInfo);
TSS_RESULT UnloadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyParms);
TSS_RESULT UnloadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store);
void LoadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store);
void UnloadBlob_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out);
void LoadBlob_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * ver);
TSS_RESULT UnloadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key);
void LoadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key);
void LoadBlob_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_PUBKEY * key);
TSS_RESULT UnloadBlob_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_PUBKEY * key);
TSS_RESULT UnloadBlob_SYMMETRIC_KEY(UINT16 * offset, BYTE * blob, TCPA_SYMMETRIC_KEY * key);
TSS_RESULT UnloadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION * pcr);
void LoadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION pcr);
TSS_RESULT UnloadBlob_PCR_COMPOSITE(UINT16 * offset, BYTE * blob, TCPA_PCR_COMPOSITE * out);
void LoadBlob_PCR_INFO(UINT16 * offset, BYTE * blob, TCPA_PCR_INFO * pcr);
TSS_RESULT UnloadBlob_PCR_INFO(UINT16 * offset, BYTE * blob, TCPA_PCR_INFO * pcr);
TSS_RESULT UnloadBlob_STORED_DATA(UINT16 * offset, BYTE * blob, TCPA_STORED_DATA * data);
void LoadBlob_STORED_DATA(UINT16 * offset, BYTE * blob, TCPA_STORED_DATA * data);
void LoadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags);
void UnloadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags);
TSS_RESULT UnloadBlob_CERTIFY_INFO(UINT16 * offset, BYTE * blob, TCPA_CERTIFY_INFO * certify);
TSS_RESULT UnloadBlob_KEY_HANDLE_LIST(UINT16 * offset, BYTE * blob,
				TCPA_KEY_HANDLE_LIST * list);
void LoadBlob_UUID(UINT16 * offset, BYTE * outBlob, TSS_UUID uuid);
void UnloadBlob_UUID(UINT16 * offset, BYTE * inBlob, TSS_UUID * outUuid);

TSS_RESULT internal_TerminateHandle(TCS_AUTHHANDLE handle);

UINT32 get_pcr_event_size(TSS_PCR_EVENT *);

#if 1
	TSS_RESULT TSC_PhysicalPresence_Internal(UINT16 physPres);

	TSS_RESULT Atmel_TPM_SetState_Internal(TCS_CONTEXT_HANDLE hContext, BYTE stateID,
						UINT32 sizeState, BYTE * stateValue);
	TSS_RESULT Atmel_TPM_OwnerSetState_Internal(TCS_CONTEXT_HANDLE hContext, BYTE stateID,
						     UINT32 sizeState, BYTE * stateValue,
						     TCS_AUTH * ownerAuth);
	TSS_RESULT Atmel_TPM_GetState_Internal(TCS_CONTEXT_HANDLE hContext, BYTE stateID,
						UINT32 * sizeState, BYTE ** stateValue);

/*---	Proposed Commands */
	TSS_RESULT TCSP_GetRegisteredKeyByPublicInfo_Internal(TCS_CONTEXT_HANDLE tcsContext, TCPA_ALGORITHM_ID algID,	/* in */
							       UINT32 ulPublicInfoLength,	/* in */
							       BYTE * rgbPublicInfo,	/* in */
							       UINT32 * keySize, BYTE ** keyBlob);
/*---	end proposed */

	TSS_RESULT TCS_OpenContext_Internal(TCS_CONTEXT_HANDLE * hContext	/* out  */
	    );

	TSS_RESULT TCS_CloseContext_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCS_FreeMemory_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					    BYTE * pMemory	/* in */
	    );

	TSS_RESULT TCS_LogPcrEvent_Internal(TCS_CONTEXT_HANDLE hContext,	/* in    */
					     TSS_PCR_EVENT Event,	/* in  */
					     UINT32 * pNumber	/* out */
	    );

	TSS_RESULT TCS_GetPcrEvent_Internal(TCS_CONTEXT_HANDLE hContext,	/* in  */
					     UINT32 PcrIndex,	/* in */
					     UINT32 * pNumber,	/* in, out */
					     TSS_PCR_EVENT ** ppEvent	/* out */
	    );

	TSS_RESULT TCS_GetPcrEventsByPcr_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						   UINT32 PcrIndex,	/* in */
						   UINT32 FirstEvent,	/* in */
						   UINT32 * pEventCount,	/* in,out */
						   TSS_PCR_EVENT ** ppEvents	/* out */
	    );

	TSS_RESULT TCS_GetPcrEventLog_Internal(TCS_CONTEXT_HANDLE hContext,	/* in  */
						UINT32 * pEventCount,	/* out */
						TSS_PCR_EVENT ** ppEvents	/* out */
	    );

	TSS_RESULT TCS_RegisterKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					     TSS_UUID *WrappingKeyUUID,	/* in */
					     TSS_UUID *KeyUUID,	/* in  */
					     UINT32 cKeySize,	/* in */
					     BYTE * rgbKey,	/* in */
					     UINT32 cVendorData,	/* in */
					     BYTE * gbVendorData	/* in */
	    );

	TSS_RESULT TCSP_UnregisterKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						TSS_UUID KeyUUID	/* in  */
	    );

	TSS_RESULT TCS_EnumRegisteredKeys_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						    TSS_UUID * pKeyUUID,	/* in    */
						    UINT32 * pcKeyHierarchySize,	/* out */
						    TSS_KM_KEYINFO ** ppKeyHierarchy	/* out */
	    );

	TSS_RESULT TCS_GetRegisteredKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						  TSS_UUID *KeyUUID,	/* in */
						  TSS_KM_KEYINFO ** ppKeyInfo	/* out */
	    );

	TSS_RESULT TCS_GetRegisteredKeyBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						      TSS_UUID *KeyUUID,	/* in */
/*TCS_KEY_HANDLE*			hKey,	//out		//my proposal...shot down */
						      UINT32 * pcKeySize,	/* out */
						      BYTE ** prgbKey	/* out */
	    );

	TSS_RESULT TCSP_LoadKeyByBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						TCS_KEY_HANDLE hUnwrappingKey,	/* in */
						UINT32 cWrappedKeyBlobSize,	/* in */
						BYTE * rgbWrappedKeyBlob,	/* in */
						TCS_AUTH * pAuth,	/* in, out */
						TCS_KEY_HANDLE * phKeyTCSI,	/* out */
						TCS_KEY_HANDLE * phKeyHMAC	/* out */
	    );

	TSS_RESULT TCSP_LoadKeyByUUID_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						TSS_UUID *KeyUUID,	/* in */
						TCS_LOADKEY_INFO * pLoadKeyInfo,	/* in, out */
						TCS_KEY_HANDLE * phKeyTCSI	/* out */
	    );

	TSS_RESULT TCSP_EvictKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					   TCS_KEY_HANDLE hKey	/* in */
	    );

	TSS_RESULT TCSP_CreateWrapKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						TCS_KEY_HANDLE hWrappingKey,	/* in */
						TCPA_ENCAUTH KeyUsageAuth,	/* in */
						TCPA_ENCAUTH KeyMigrationAuth,	/* in */
						UINT32 keyInfoSize,	/* in */
						BYTE * keyInfo,	/* in */
						UINT32 * keyDataSize,	/* out */
						BYTE ** keyData,	/* out */
						TCS_AUTH * pAuth	/* in, out */
	    );

	TSS_RESULT TCSP_GetPubKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					    TCS_KEY_HANDLE hKey,	/* in */
					    TCS_AUTH * pAuth,	/* in, out */
					    UINT32 * pcPubKeySize,	/* out */
					    BYTE ** prgbPubKey	/* out */
	    );
	TSS_RESULT TCSP_MakeIdentity_Internal(TCS_CONTEXT_HANDLE hContext,	/* in  */
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

	TSS_RESULT TCSP_SetOwnerInstall_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						  BOOL state	/* in  */
	    );
	TSS_RESULT TCSP_TakeOwnership_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_OIAP_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCS_AUTHHANDLE * authHandle,	/* out  */
				       TCPA_NONCE * nonce0	/* out */
	    );

	TSS_RESULT TCSP_OSAP_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCPA_ENTITY_TYPE entityType,	/* in */
				       UINT32 entityValue,	/* in */
				       TCPA_NONCE nonceOddOSAP,	/* in */
				       TCS_AUTHHANDLE * authHandle,	/* out  */
				       TCPA_NONCE * nonceEven,	/* out */
				       TCPA_NONCE * nonceEvenOSAP	/* out */
	    );

	TSS_RESULT TCSP_ChangeAuth_Internal(TCS_CONTEXT_HANDLE contextHandle,	/* in */
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

	TSS_RESULT TCSP_ChangeAuthOwner_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						  TCPA_PROTOCOL_ID protocolID,	/* in */
						  TCPA_ENCAUTH newAuth,	/* in */
						  TCPA_ENTITY_TYPE entityType,	/* in */
						  TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_ChangeAuthAsymStart_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_ChangeAuthAsymFinish_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_TerminateHandle_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						  TCS_AUTHHANDLE handle	/* in */
	    );

	TSS_RESULT TCSP_ActivateTPMIdentity_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						      TCS_KEY_HANDLE idKey,	/* in */
						      UINT32 blobSize,	/* in */
						      BYTE * blob,	/* in */
						      TCS_AUTH * idKeyAuth,	/* in, out */
						      TCS_AUTH * ownerAuth,	/* in, out */
						      UINT32 * SymmetricKeySize,	/* out */
						      BYTE ** SymmetricKey	/* out */
	    );

	TSS_RESULT TCSP_Extend_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCPA_PCRINDEX pcrNum,	/* in */
					 TCPA_DIGEST inDigest,	/* in */
					 TCPA_PCRVALUE * outDigest	/* out */
	    );

	TSS_RESULT TCSP_PcrRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCPA_PCRINDEX pcrNum,	/* in */
					  TCPA_PCRVALUE * outDigest	/* out */
	    );

	TSS_RESULT TCSP_Quote_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_DirWriteAuth_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					       TCPA_DIRINDEX dirIndex,	/* in */
					       TCPA_DIRVALUE newContents,	/* in */
					       TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_DirRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					  TCPA_DIRINDEX dirIndex,	/* in */
					  TCPA_DIRVALUE * dirValue	/* out */
	    );

	TSS_RESULT TCSP_Seal_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_Unseal_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCS_KEY_HANDLE parentHandle,	/* in */
					 UINT32 SealedDataSize,	/* in */
					 BYTE * SealedData,	/* in */
					 TCS_AUTH * parentAuth,	/* in, out */
					 TCS_AUTH * dataAuth,	/* in, out */
					 UINT32 * DataSize,	/* out */
					 BYTE ** Data	/* out */
	    );

	TSS_RESULT TCSP_UnBind_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					 TCS_KEY_HANDLE keyHandle,	/* in */
					 UINT32 inDataSize,	/* in */
					 BYTE * inData,	/* in */
					 TCS_AUTH * privAuth,	/* in, out */
					 UINT32 * outDataSize,	/* out */
					 BYTE ** outData	/* out */
	    );
	TSS_RESULT TCSP_CreateMigrationBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_ConvertMigrationBlob_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						       TCS_KEY_HANDLE parentHandle,	/* in */
						       UINT32 inDataSize,	/* in */
						       BYTE * inData,	/* in */
						       TCS_AUTH * parentAuth,	/* in, out */
						       UINT32 randomSize,	/* should be in */
						       BYTE * random,	/* should be in */
						       UINT32 * outDataSize,	/* out */
						       BYTE ** outData	/* out */
	    );

	TSS_RESULT TCSP_AuthorizeMigrationKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
							TCPA_MIGRATE_SCHEME migrateScheme,	/* in */
							UINT32 MigrationKeySize,	/* in */
							BYTE * MigrationKey,	/* in */
							TCS_AUTH * ownerAuth,	/* in, out */
							UINT32 * MigrationKeyAuthSize,	/* out */
							BYTE ** MigrationKeyAuth	/* out */
	    );

	TSS_RESULT TCSP_CertifyKey_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_Sign_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				       TCS_KEY_HANDLE keyHandle,	/* in */
				       UINT32 areaToSignSize,	/* in */
				       BYTE * areaToSign,	/* in */
				       TCS_AUTH * privAuth,	/* in, out */
				       UINT32 * sigSize,	/* out */
				       BYTE ** sig	/* out */
	    );

	TSS_RESULT TCSP_GetRandom_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					    UINT32 * bytesRequested,	/* in, out */
					    BYTE ** randomBytes	/* out */
	    );

	TSS_RESULT TCSP_StirRandom_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					     UINT32 inDataSize,	/* in */
					     BYTE * inData	/* in */
	    );

	TSS_RESULT TCS_GetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					       TCPA_CAPABILITY_AREA capArea,	/* in */
					       UINT32 subCapSize,	/* in */
					       BYTE * subCap,	/* in */
					       UINT32 * respSize,	/* out */
					       BYTE ** resp	/* out */
	    );

	TSS_RESULT TCSP_GetCapability_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						TCPA_CAPABILITY_AREA capArea,	/* in */
						UINT32 subCapSize,	/* in */
						BYTE * subCap,	/* in */
						UINT32 * respSize,	/* out */
						BYTE ** resp	/* out */
	    );

	TSS_RESULT TCSP_GetCapabilitySigned_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
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

	TSS_RESULT TCSP_GetCapabilityOwner_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						     TCS_AUTH * pOwnerAuth,	/* out */
						     TCPA_VERSION * pVersion,	/* out */
						     UINT32 * pNonVolatileFlags,	/* out */
						     UINT32 * pVolatileFlags	/* out */
	    );

	TSS_RESULT TCSP_CreateEndorsementKeyPair_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
							   TCPA_NONCE antiReplay,	/* in */
							   UINT32 endorsementKeyInfoSize,	/* in */
							   BYTE * endorsementKeyInfo,	/* in */
							   UINT32 * endorsementKeySize,	/* out */
							   BYTE ** endorsementKey,	/* out */
							   TCPA_DIGEST * checksum	/* out */
	    );

	TSS_RESULT TCSP_ReadPubek_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					    TCPA_NONCE antiReplay,	/* in */
					    UINT32 * pubEndorsementKeySize,	/* out */
					    BYTE ** pubEndorsementKey,	/* out */
					    TCPA_DIGEST * checksum	/* out */
	    );

	TSS_RESULT TCSP_DisablePubekRead_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						   TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_OwnerReadPubek_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						 TCS_AUTH * ownerAuth,	/* in, out */
						 UINT32 * pubEndorsementKeySize,	/* out */
						 BYTE ** pubEndorsementKey	/* out */
	    );

	TSS_RESULT TCSP_SelfTestFull_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCSP_CertifySelfTest_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						  TCS_KEY_HANDLE keyHandle,	/* in */
						  TCPA_NONCE antiReplay,	/* in */
						  TCS_AUTH * privAuth,	/* in, out */
						  UINT32 * sigSize,	/* out */
						  BYTE ** sig	/* out */
	    );

	TSS_RESULT TCSP_GetTestResult_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						UINT32 * outDataSize,	/* out */
						BYTE ** outData	/* out */
	    );

	TSS_RESULT TCSP_OwnerSetDisable_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						  BOOL disableState,	/* in */
						  TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_OwnerClear_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					     TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_DisableOwnerClear_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						    TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_ForceClear_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCSP_DisableForceClear_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCSP_PhysicalPresence_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						TCPA_PHYSICAL_PRESENCE fPhysicalPresence /* in */
	    );

	TSS_RESULT TCSP_PhysicalDisable_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCSP_PhysicalEnable_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCSP_PhysicalSetDeactivated_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
							 BOOL state	/* in */
	    );

	TSS_RESULT TCSP_SetTempDeactivated_Internal(TCS_CONTEXT_HANDLE hContext	/* in */
	    );

	TSS_RESULT TCSP_FieldUpgrade_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
					       UINT32 dataInSize,	/* in */
					       BYTE * dataIn,	/* in */
					       UINT32 * dataOutSize,	/* out */
					       BYTE ** dataOut,	/* out */
					       TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_SetRedirection_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						 TCS_KEY_HANDLE keyHandle,	/* in */
						 UINT32 c1,	/* in */
						 UINT32 c2,	/* in */
						 TCS_AUTH * privAuth	/* in, out */
	    );

	TSS_RESULT TCSP_CreateMaintenanceArchive_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
							   BOOL generateRandom,	/* in */
							   TCS_AUTH * ownerAuth,	/* in, out */
							   UINT32 * randomSize,	/* out */
							   BYTE ** random,	/* out */
							   UINT32 * archiveSize,	/* out */
							   BYTE ** archive	/* out */
	    );

	TSS_RESULT TCSP_LoadMaintenanceArchive_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
							 UINT32 dataInSize,	/* in */
							 BYTE * dataIn,	/* in */
							 UINT32 * dataOutSize,	/* out */
							 BYTE ** dataOut,	/* out */
							 TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_KillMaintenanceFeature_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
							 TCS_AUTH * ownerAuth	/* in, out */
	    );

	TSS_RESULT TCSP_LoadManuMaintPub_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						   TCPA_NONCE antiReplay,	/* in */
						   UINT32 PubKeySize,	/* in */
						   BYTE * PubKey,	/* in */
						   TCPA_DIGEST * checksum	/* out */
	    );

	TSS_RESULT TCSP_ReadManuMaintPub_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
						   TCPA_NONCE antiReplay,	/* in */
						   TCPA_DIGEST * checksum	/* out */
	    );
#else

	TSS_RESULT TSC_PhysicalPresence(UINT16 physPres);

	TSS_RESULT Atmel_TPM_SetState(TCS_CONTEXT_HANDLE hContext, BYTE stateID,
						UINT32 sizeState, BYTE * stateValue);
	TSS_RESULT Atmel_TPM_OwnerSetState(TCS_CONTEXT_HANDLE hContext, BYTE stateID,
						     UINT32 sizeState, BYTE * stateValue,
						     TCS_AUTH * ownerAuth);
	TSS_RESULT Atmel_TPM_GetState(TCS_CONTEXT_HANDLE hContext, BYTE stateID,
						UINT32 * sizeState, BYTE ** stateValue);

/*---	Proposed Commands */
	TSS_RESULT TCSP_GetRegisteredKeyByPublicInfo(TCS_CONTEXT_HANDLE tcsContext, TCPA_ALGORITHM_ID algID,	/* in */
							       UINT32 ulPublicInfoLength,	/* in */
							       BYTE * rgbPublicInfo,	/* in */
							       UINT32 * keySize, BYTE ** keyBlob);
/*---	end proposed */

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
/*TCS_AUTH*				pAuth		// in, out */
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
/*TCS_KEY_HANDLE*			hKey,	//out		//my proposal...shot down */
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

	TSS_RESULT TCS_GetCapability(TCS_CONTEXT_HANDLE hContext,	/* in */
					       TCPA_CAPABILITY_AREA capArea,	/* in */
					       UINT32 subCapSize,	/* in */
					       BYTE * subCap,	/* in */
					       UINT32 * respSize,	/* out */
					       BYTE ** resp	/* out */
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


#endif
#endif /*_TCS_UTILS_H_ */
