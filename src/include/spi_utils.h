
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
#include <netinet/in.h> // for endian routines

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

UINT32 UnicodeToArray(BYTE * bytes, UNICODE * wchars);
UINT32 ArrayToUnicode(BYTE * bytes, UINT32 howManyBytes, UNICODE * wchars);
UINT32 StringToUnicodeArray(char *message, BYTE * array);

TSS_RESULT internal_GetRandomNonce(TCS_CONTEXT_HANDLE hContext, TCPA_NONCE * nonce);

void *calloc_tspi(TSS_HCONTEXT, UINT32);
TSS_RESULT free_tspi(TSS_HCONTEXT, void *);

/*---	keyReg.c */
void keyreg_SetUUIDOfKeyObject(TSS_HKEY hKey, TSS_UUID uuid, TSS_FLAG psType);
BOOL keyreg_IsKeyAlreadyRegistered(TSS_HCONTEXT, UINT32, BYTE *);
TSS_RESULT keyreg_WriteKeyToFile(TSS_UUID *, TSS_UUID *, UINT32, UINT32, BYTE *);
TSS_RESULT keyreg_RemoveKey(TSS_UUID *);
TSS_RESULT keyreg_GetKeyByUUID(TSS_UUID *, UINT32 *, BYTE **);
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

short get_port(void);

#define AUTH_RETRY_NANOSECS	500000000
#define AUTH_RETRY_COUNT	5

#define endian32(x)	htonl(x)
#define endian16(x)	htons(x)

/*===	Object Stuff */
void removeObject(UINT32 objectHandle);
/*void destroyObject( AnObject* object ); */
UINT32 getObjectTypeByHandle(TSS_HOBJECT objectHandle);
TSS_RESULT setObject(UINT32 objectHandle, void *buffer, UINT32 sizeOfBuffer);
TSS_RESULT getObject(UINT32 objectHandle, void **outBuffer, UINT32 * outSize);
TSS_HOBJECT addObject(UINT32 context, UINT32 objectType);

AnObject *getAnObjectByHandle(UINT32 oHandle);
BOOL anyPopupPolicies(TSS_HCONTEXT context);

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
TSS_RESULT internal_SetSecret(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size, BYTE * data);
TSS_RESULT internal_FlushSecret(TSS_HPOLICY hPolicy);
TSS_RESULT internal_CopySecrets(TSS_HPOLICY dest, TSS_HPOLICY source);

TSS_RESULT calculateCompositeHash(TCPA_PCR_COMPOSITE comp, TCPA_DIGEST * digest);
TSS_RESULT calcCompositeHash(TCPA_PCR_SELECTION select, TCPA_PCRVALUE * arrayOfPcrs,
			     TCPA_DIGEST * digestOut);
TSS_RESULT generateCompositeFromTPM(TSS_HCONTEXT hContext, TCPA_PCR_SELECTION select,
				    TCPA_DIGEST * digest);

UINT16 Decode_UINT16(BYTE * in);
void UINT32ToArray(UINT32 i, BYTE * out);
void UINT16ToArray(UINT16 i, BYTE * out);
UINT32 Decode_UINT32(BYTE * y);

TSS_RESULT EncryptStoreAsymKey(TCS_CONTEXT_HANDLE hContext, TCPA_PAYLOAD_TYPE payload,
			       UINT32 privModLength, BYTE * privMod, BYTE * usageAuth, BYTE * migAuth,
			       TCPA_RSAKEY_OBJECT * keyObject, BYTE * pubkey, UINT32 pubKeyLength);

TSS_RESULT popup_GetSecret(UINT32, UNICODE *, void *);

BOOL check_flagset_collision(TSS_FLAG, UINT32);
TSS_RESULT get_tpm_flags(TCS_CONTEXT_HANDLE, TSS_HTPM, UINT32 *, UINT32 *);

void LoadBlob_AUTH(UINT16 * offset, BYTE * blob, TCS_AUTH * auth);
void UnloadBlob_AUTH(UINT16 * offset, BYTE * blob, TCS_AUTH * auth);
void LoadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info);
void UnloadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info);

#endif
