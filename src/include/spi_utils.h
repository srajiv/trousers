
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _SPI_UTILS_H_
#define _SPI_UTILS_H_

#include <pthread.h>

struct key_mem_cache
{
	TCS_KEY_HANDLE tcs_handle;
	TSS_HKEY tsp_handle;
	UINT16 flags;
	UINT32 time_stamp;
	TSS_UUID uuid;
	TSS_UUID p_uuid;
	TCPA_KEY *blob;
	struct key_mem_cache *parent;
	struct key_mem_cache *next;
};

extern struct key_mem_cache *key_mem_cache_head;
extern pthread_mutex_t mem_cache_lock;

#define MIN(a,b) ((a) < (b) ? (a) : (b))
extern TSS_VERSION FIXED_TSP_VERSION;

UINT32 UnicodeToArray(BYTE * bytes, UNICODE * wchars);
UINT32 ArrayToUnicode(BYTE * bytes, UINT32 howManyBytes, UNICODE * wchars);
UINT32 StringToUnicodeArray(char *message, BYTE * array);

TSS_RESULT internal_GetRandomNonce(TCS_CONTEXT_HANDLE hContext, TCPA_NONCE * nonce);

void *calloc_tspi(TCS_CONTEXT_HANDLE, UINT32);
TSS_RESULT free_tspi(TCS_CONTEXT_HANDLE, void *);
//BOOL isThisPointerSPI(TCS_CONTEXT_HANDLE tcsContext, void *memPointer);
void destroy_key_refs(TCPA_KEY *);

void try_FreeMemory(void *pointer);

/*---	keyReg.c */
void keyreg_SetUUIDOfKeyObject(TSS_HKEY hKey, TSS_UUID uuid, TSS_FLAG psType);
BOOL keyreg_IsKeyAlreadyRegistered(UINT32 keyBlobSize, BYTE * keyBlob);
TSS_RESULT keyreg_WriteKeyToFile(TSS_UUID *, TSS_UUID *, UINT32, UINT32, BYTE *);
TSS_RESULT keyreg_RemoveKey(TCS_CONTEXT_HANDLE, TSS_UUID *);
TSS_RESULT keyreg_GetKeyByUUID(TCS_CONTEXT_HANDLE, TSS_UUID *, UINT32 *, BYTE **);
TSS_RESULT keyreg_GetParentUUIDByUUID(TSS_UUID *, TSS_UUID *);
TSS_RESULT keyreg_GetParentPSTypeByUUID(TSS_UUID *, UINT32 *);
TSS_RESULT keyreg_replaceEncData_PS(BYTE *, BYTE *);

/*---	secrets.c */

TSS_RESULT policy_UsesAuth(TSS_HPOLICY hPolicy, BOOL *);

TSS_RESULT secret_PerformAuth_OIAP(TSS_HPOLICY hPolicy, TCPA_DIGEST hashDigest, TCS_AUTH * auth);
TSS_RESULT secret_ValidateAuth_OIAP(TSS_HPOLICY hPolicy, TCPA_DIGEST hashDigest, TCS_AUTH * auth);
TSS_RESULT secret_PerformXOR_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy, TSS_HPOLICY hMigPolicy,
				  TSS_HOBJECT hKey, UINT16 osapType, UINT32 osapData,
				  TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig,
				  BYTE sharedSecret[20], TCS_AUTH * auth, TCPA_NONCE * nonceEvenOSAP);
TSS_RESULT secret_PerformAuth_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy, TSS_HPOLICY hMigPolicy,
				   TSS_HOBJECT hKey, BYTE sharedSecret[20], TCS_AUTH * auth,
				   BYTE * hashDigest, TCPA_NONCE nonceEvenOSAP);

TSS_RESULT secret_ValidateAuth_OSAP(TSS_HPOLICY hPolicy, TSS_HPOLICY hUsagePolicy,
				    TSS_HPOLICY hMigPolicy, BYTE sharedSecret[20], TCS_AUTH * auth,
				    BYTE * hashDigest, TCPA_NONCE nonceEvenOSAP);

TSS_RESULT secret_TakeOwnership(TSS_HKEY hEndorsementPubKey,
				TSS_HTPM hTPM,
				TSS_HKEY hKeySRK,
				TCS_AUTH * auth,
				UINT32 * encOwnerAuthLength,
				BYTE * encOwnerAuth, UINT32 * encSRKAuthLength, BYTE * encSRKAuth);

#define next( x )	x = x->next

UINT16 getMaxPCRs(TCS_CONTEXT_HANDLE);
TCPA_PCRVALUE *getPcrFromComposite(TCPA_PCR_COMPOSITE comp, UINT32 which);

#define UI_MAX_SECRET_STRING_LENGTH	256
#define UI_MAX_POPUP_STRING_LENGTH	256
TSS_RESULT DisplayPINWindow(char *, UNICODE *);
TSS_RESULT DisplayNewPINWindow(char *, UNICODE *);

int pin_mem(void *, size_t);
int unpin_mem(void *, size_t);

#define TCSD_DEFAULT_PORT	30003
short get_port(void);

#define AUTH_RETRY_NANOSECS	500000000
#define AUTH_RETRY_COUNT	5

/*===	Object Stuff */
void removeObject(UINT32 objectHandle);
/*void destroyObject( AnObject* object ); */
UINT32 getObjectTypeByHandle(TSS_HOBJECT objectHandle);
TSS_RESULT obj_getTpmObject(UINT32 context, TSS_HOBJECT * out);
TCS_CONTEXT_HANDLE obj_getContextForObject(UINT32 objectHandle);
TSS_HOBJECT obj_GetPolicyOfObject(UINT32 objectHandle, UINT32 policyType);
TSS_RESULT setObject(UINT32 objectHandle, void *buffer, UINT32 sizeOfBuffer);
TSS_RESULT getObject(UINT32 objectHandle, void **outBuffer, UINT32 * outSize);
TSS_HOBJECT addObject(UINT32 context, UINT32 objectType);
void destroyObjectsByContext(UINT32 contextHandle);

AnObject *getAnObjectByHandle(UINT32 oHandle);
BOOL anyPopupPolicies(TSS_HCONTEXT context);

TSS_RESULT internal_GetContextForContextObject(TSS_HCONTEXT hContext, TCS_CONTEXT_HANDLE * tcsContext);
TSS_RESULT internal_GetContextObjectForContext(TCS_CONTEXT_HANDLE tcsContext, TSS_HCONTEXT * tspContext);
TSS_RESULT internal_CheckContext_1(TSS_HOBJECT object1, TCS_CONTEXT_HANDLE * tcsContext);
TSS_RESULT internal_CheckContext_2(TSS_HOBJECT object1, TSS_HOBJECT object2,
				   TCS_CONTEXT_HANDLE * tcsContext);
TSS_RESULT internal_CheckContext_3(TSS_HOBJECT object1, TSS_HOBJECT object2, TSS_HOBJECT object3,
				   TCS_CONTEXT_HANDLE * tcsContext);
TSS_RESULT internal_CheckObjectType_1(TSS_HOBJECT object, UINT32 objectType);
TSS_RESULT internal_CheckObjectType_2(TSS_HOBJECT object1, UINT32 objectType1, TSS_HOBJECT object2,
				      UINT32 objectType2);
TSS_RESULT internal_CheckObjectType_3(TSS_HOBJECT object1, UINT32 objectType1, TSS_HOBJECT object2,
				      UINT32 objectType2, TSS_HOBJECT object3, UINT32 objectType3);

/*---	These funcs should be called to handle the TSS_HKEY <--> TCS_KEY_HANDLE issues */

void addKeyHandle(TCS_KEY_HANDLE tcsHandle, TSS_HKEY tspHandle);
void removeTSPKeyHandle(TSS_HKEY tspHandle);
void removeTCSKeyHandle(TCS_KEY_HANDLE tcsHandle);
TCS_KEY_HANDLE getTCSKeyHandle(TSS_HKEY tspHandle);

/*---------------------------------------------------------------------------------------- */

TCPA_VERSION *getCurrentVersion(TSS_HCONTEXT hContext);

TSS_RESULT Init_AuthNonce(TCS_CONTEXT_HANDLE hContext, TCS_AUTH * auth);
BOOL validateReturnAuth(BYTE * secret, BYTE * hash, TCS_AUTH * auth);
void HMAC_Auth(BYTE * secret, BYTE * Digest, TCS_AUTH * auth);
TSS_RESULT OSAP_Calc(TCS_CONTEXT_HANDLE hContext, UINT16 EntityType, UINT32 EntityValue,
		     BYTE * authSecret, BYTE * usageSecret, BYTE * migSecret,
		     TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig, BYTE * sharedSecret,
		     TCS_AUTH * auth);

TSS_RESULT internal_GetSecret(TSS_HPOLICY, TCPA_SECRET *, BOOL);
TSS_RESULT internal_SetSecret(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size, BYTE * data,
			      BOOL hashDataForMe);
TSS_RESULT internal_FlushSecret(TSS_HPOLICY hPolicy);
TSS_RESULT internal_CopySecrets(TSS_HPOLICY dest, TSS_HPOLICY source);

void LoadBlob_PCR_COMPOSITE(UINT16 * offset, BYTE * outBlob, TCPA_PCR_COMPOSITE comp);
void UnloadBlob_PCR_COMPOSITE(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * inBlob,
			      TCPA_PCR_COMPOSITE * comp);

TSS_RESULT calculateCompositeHash(TCPA_PCR_COMPOSITE comp, TCPA_DIGEST * digest);
TSS_RESULT calcCompositeHash(TCPA_PCR_SELECTION select, TCPA_PCRVALUE * arrayOfPcrs,
			     TCPA_DIGEST * digestOut);
TSS_RESULT generateCompositeFromTPM(TSS_HCONTEXT hContext, TCPA_PCR_SELECTION select,
				    TCPA_DIGEST * digest);

UINT16 Decode_UINT16(BYTE * in);
void UINT32ToArray(UINT32 i, BYTE * out);
void UINT16ToArray(UINT16 i, BYTE * out);
UINT32 Decode_UINT32(BYTE * y);
void LoadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object);
void UnloadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object);
void LoadBlob_UINT32(UINT16 * offset, UINT32 in, BYTE * blob);
void LoadBlob_UINT16(UINT16 * offset, UINT16 in, BYTE * blob);
void LoadBlob_BYTE(UINT16 * offset, BYTE data, BYTE * blob);
void UnloadBlob_BYTE(UINT16 * offset, BYTE * dataOut, BYTE * blob);
void LoadBlob_BOOL(UINT16 * offset, BOOL data, BYTE * blob);
void UnloadBlob_BOOL(UINT16 * offset, BOOL * dataOut, BYTE * blob);
void UnloadBlob_UINT32(UINT16 * offset, UINT32 * out, BYTE * blob);
void UnloadBlob_UINT16(UINT16 * offset, UINT16 * out, BYTE * blob);
void LoadBlob_RSA_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_RSA_KEY_PARMS * parms);
void UnloadBlob_TSS_VERSION(UINT16 * offset, BYTE * blob, TSS_VERSION * out);
void UnloadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out);
void LoadBlob_BOUND_DATA(UINT16 * offset, TCPA_BOUND_DATA bd, UINT32 payloadLength, BYTE * blob);
void LoadBlob_TSS_VERSION(UINT16 * offset, BYTE * blob, TSS_VERSION version);
void LoadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION version);
void LoadBlob_PCR_INFO(UINT16 * offset, BYTE * blob, TCPA_PCR_INFO * pcr);
TSS_RESULT UnloadBlob_PCR_INFO(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
			 TCPA_PCR_INFO * pcr);
TSS_RESULT UnloadBlob_PCR_SELECTION(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
			      TCPA_PCR_SELECTION * pcr);
void LoadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION pcr);
TSS_RESULT UnloadBlob_STORED_DATA(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
			    TCPA_STORED_DATA * data);
void LoadBlob_STORED_DATA(UINT16 * offset, BYTE * blob, TCPA_STORED_DATA * data);
void LoadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key);
/*void LoadBlob_VERSION( UINT16* offset, BYTE* blob,  TCPA_VERSION* ver ); */
void LoadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags);
void UnloadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags);
void LoadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyInfo);
void LoadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store);
void LoadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID uuid);
void UnloadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID * uuid);
TSS_RESULT UnloadBlob_KEY_PARMS(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
			  TCPA_KEY_PARMS * keyParms);
/*void UnloadBlob_VERSION( UINT16* offset,  BYTE* blob, TCPA_VERSION* out ); */
TSS_RESULT UnloadBlob_KEY(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
		    TCPA_KEY * key);
/*void UnloadBlob_VERSION( UINT16* offset,  BYTE* blob, TCPA_VERSION* out ); */
TSS_RESULT UnloadBlob_STORE_PUBKEY(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
			     TCPA_STORE_PUBKEY * store);
void LoadBlob_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_PUBKEY pubKey);
void LoadBlob_CERTIFY_INFO(UINT16 * offset, BYTE * blob, TCPA_CERTIFY_INFO * certify);
void LoadBlob_STORE_ASYMKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_ASYMKEY * store);
void LoadBlob_KEY_ForHash(UINT16 * offset, BYTE * blob, TCPA_KEY * key);

TSS_RESULT EncryptStoreAsymKey(TCS_CONTEXT_HANDLE hContext, TCPA_PAYLOAD_TYPE payload,
			       UINT32 privModLength, BYTE * privMod, BYTE * usageAuth, BYTE * migAuth,
			       TCPA_RSAKEY_OBJECT * keyObject, BYTE * pubkey, UINT32 pubKeyLength);
void UnloadBlob_TCPA_EVENT_CERT(UINT16 * offset, BYTE * blob, TCPA_EVENT_CERT * cert);
void UnloadBlob_DIGEST(UINT16 * offset, BYTE * blob, TCPA_DIGEST digest);
TSS_RESULT UnloadBlob_PUBKEY(TCS_CONTEXT_HANDLE hContext, UINT16 * offset, BYTE * blob,
		       TCPA_PUBKEY * pubKey);

void UnloadBlob_MigrationKeyAuth(TCS_CONTEXT_HANDLE hContext, UINT16 * offset,
				 TCPA_MIGRATIONKEYAUTH * migAuth, BYTE * blob);
void LoadBlob_CHANGEAUTH_VALIDATE(UINT16 * offset, BYTE * blob, TCPA_CHANGEAUTH_VALIDATE * caValidate);
TSS_RESULT popup_GetSecret(UINT32, UNICODE *, void *);

BOOL check_flagset_collision(TSS_FLAG, UINT32);

#endif
