
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "tss_crypto.h"

TSS_UUID NULL_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };

int
pin_mem(void *addr, size_t len)
{
	/* only root can lock pages into RAM */
	if (getuid() != (uid_t)0) {
		LogWarn1("Not pinning secrets in memory due to insufficient perms.");
		return 0;
	}

	if (mlock(addr, len) == -1) {
		LogError("mlock: %s", strerror(errno));
		return 1;
	}

	return 0;
}

int
unpin_mem(void *addr, size_t len)
{
	/* only root can lock pages into RAM */
	if (getuid() != (uid_t)0) {
		return 0;
	}

	if (munlock(addr, len) == -1) {
		LogError("mlock: %s", strerror(errno));
		return 1;
	}

	return 0;
}

short
get_port(void)
{
	char *env_port;
	int port = 0;

	env_port = getenv("TSS_TCSD_PORT");

	if (env_port == NULL)
		return TCSD_DEFAULT_PORT;

	port = atoi(env_port);

	if (port == 0 || port > 65535)
		return TCSD_DEFAULT_PORT;

	return (short)port;
}

BOOL
check_flagset_collision(TSS_FLAG flagset, UINT32 flags)
{
	UINT32 on_flags = flagset & flags;
	int i, one_bits = 0;

	/* if more than 1 bit is set, there's a collision */
	for (i = 0; i < (int)(sizeof(UINT32) * 8); i++) {
		if (on_flags & 1)
			one_bits++;
		on_flags >>= 1;
	}

	return (one_bits > 1 ? TRUE : FALSE);
}

TSS_RESULT
internal_CheckContext_1(TSS_HOBJECT object1, TCS_CONTEXT_HANDLE * tcsContext)
{
	TCS_CONTEXT_HANDLE tcsContext1;

	LogDebug1("Checking Context 1");

	tcsContext1 = obj_getContextForObject(object1);
	if (tcsContext1 == 0) {
		LogDebug1("Failed context 1");
		return TSS_E_INVALID_HANDLE;
	}

	*tcsContext = tcsContext1;
	LogDebug1("Passed Context check");

	return TSS_SUCCESS;
}

TSS_RESULT
internal_CheckContext_2(TSS_HOBJECT object1, TSS_HOBJECT object2, TCS_CONTEXT_HANDLE * tcsContext)
{
	TCS_CONTEXT_HANDLE tcsContext1;
	TCS_CONTEXT_HANDLE tcsContext2;

	LogDebug1("Checking Context 2");

	tcsContext1 = obj_getContextForObject(object1);
	if (tcsContext1 == 0) {
		LogDebug1("Failed on first object");
		return TSS_E_INVALID_HANDLE;
	}

	tcsContext2 = obj_getContextForObject(object2);
	if (tcsContext2 == 0) {
		LogDebug1("Failed on second object");
		return TSS_E_INVALID_HANDLE;
	}

	if (tcsContext1 != tcsContext2) {
		LogDebug1("First and second mismatch");
		return TSS_E_INVALID_HANDLE;
	}

	*tcsContext = tcsContext1;

	LogDebug1("Passed Context check");

	return TSS_SUCCESS;
}

TSS_RESULT
internal_CheckContext_3(TSS_HOBJECT object1, TSS_HOBJECT object2,
			TSS_HOBJECT object3, TCS_CONTEXT_HANDLE * tcsContext)
{
	TCS_CONTEXT_HANDLE tcsContext1;
	TCS_CONTEXT_HANDLE tcsContext2;
	TCS_CONTEXT_HANDLE tcsContext3;

	LogDebug1("Checking context 3");

	tcsContext1 = obj_getContextForObject(object1);
	if (tcsContext1 == 0) {
		LogDebug1("Failed check 1");
		return TSS_E_INVALID_HANDLE;
	}

	tcsContext2 = obj_getContextForObject(object2);
	if (tcsContext2 == 0) {
		LogDebug1("Failed check 2");
		return TSS_E_INVALID_HANDLE;
	}

	tcsContext3 = obj_getContextForObject(object3);
	if (tcsContext3 == 0) {
		LogDebug1("Failed check 3");
		return TSS_E_INVALID_HANDLE;
	}

	if (tcsContext1 != tcsContext2 || tcsContext1 != tcsContext3) {
		LogDebug1("Context Mismatch");
		return -1; 
	}

	*tcsContext = tcsContext1;

	LogDebug1("Passed Context check");
	return TSS_SUCCESS;
}

TSS_RESULT
internal_CheckObjectType_1(TSS_HOBJECT object, UINT32 objectType)
{
	AnObject *anObject;

	LogDebug1("Check object 1");
	anObject = getAnObjectByHandle(object);

	if (anObject == NULL) {
		LogDebug1("Can't find object");
		return TSS_E_INVALID_HANDLE;
	}

	if (anObject->objectType != objectType) {
		LogDebug1("Object type does not match");
		return TSS_E_INVALID_HANDLE;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
internal_CheckObjectType_2(TSS_HOBJECT object1, UINT32 objectType1,
			   TSS_HOBJECT object2, UINT32 objectType2)
{
	AnObject *anObject;

	LogDebug1("Check object 2");
	anObject = getAnObjectByHandle(object1);

	if (anObject == NULL) {
		LogDebug1("Can't find object 1");
		return TSS_E_INVALID_HANDLE;
	}

	if (anObject->objectType != objectType1) {
		LogDebug1("Object 1 type does not match");
		return TSS_E_INVALID_HANDLE;
	}

	anObject = getAnObjectByHandle(object2);
	if (anObject == NULL) {
		LogDebug1("Can't find object 2");
		return TSS_E_INVALID_HANDLE;
	}

	if (anObject->objectType != objectType2) {
		LogDebug1("Object 2 type does not match object 1");
		return TSS_E_INVALID_HANDLE;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
internal_CheckObjectType_3(TSS_HOBJECT object1, UINT32 objectType1,
			   TSS_HOBJECT object2, UINT32 objectType2,
			   TSS_HOBJECT object3, UINT32 objectType3)
{
	AnObject *anObject;

	LogDebug1("Check object 3");
	anObject = getAnObjectByHandle(object1);
	if (anObject == NULL) {
		LogDebug1("Can't find object 1");
		return TSS_E_INVALID_HANDLE;
	}

	if (anObject->objectType != objectType1) {
		LogDebug1("Object 1 type does not match");
		return TSS_E_INVALID_HANDLE;
	}

	anObject = getAnObjectByHandle(object2);
	if (anObject == NULL) {
		LogDebug1("Can't find object 2");
		return TSS_E_INVALID_HANDLE;
	}

	if (anObject->objectType != objectType2) {
		LogDebug1("Object 2 type does not match");
		return TSS_E_INVALID_HANDLE;
	}

	anObject = getAnObjectByHandle(object3);
	if (anObject == NULL) {
		LogDebug1("Can't find object 3");
		return TSS_E_INVALID_HANDLE;
	}

	if (anObject->objectType != objectType3) {
		LogDebug1("Object 3 type does not match");
		return TSS_E_INVALID_HANDLE;
	}

	return TSS_SUCCESS;
}

#if 0
/* ---	Converts true unicode to a TSS defined byte array of unicode data */
UINT32
UnicodeToArray(BYTE * bytes, UNICODE * wchars)
{
	UINT32 i, w;
	for (i = 0, w = 0; wchars[w] != 0; i += 2, w++) {
		bytes[i] = ((wchars[w] >> 8) & 0x00FF);
		bytes[i + 1] = (wchars[w] & 0x00FF);
	}
	bytes[i] = 0;
	bytes[i + 1] = 0;

	i += 2;
	return i;
}

/* ---	converts TSS defined byte array of unicode characters to unicode */
UINT32
ArrayToUnicode(BYTE * bytes, UINT32 howManyBytes, UNICODE * wchars)
{
	UINT32 i;
	UINT16 temp;
	for (i = 0; i < howManyBytes; i += 2) {
		temp = (bytes[i] << 8);
		temp |= bytes[i + 1];
		wchars[i >> 1] = temp;
	}
	wchars[i >> 1] = 0;

	i += 2;
	return (i >> 1);
}

/* ---	Converts SBCS to TSS defined unicode array */
UINT32
StringToUnicodeArray(char *message, BYTE * array)
{
	UINT32 i, w;
	for (i = 0, w = 0; message[i] != 0; i++, w += 2) {
		array[w] = 0;
		array[w + 1] = message[i];
	}
	array[w++] = 0;
	array[w++] = 0;

	return w;
}
#endif

TSS_RESULT
internal_GetRandomNonce(TCS_CONTEXT_HANDLE hContext, TCPA_NONCE * nonce)
{
	TSS_RESULT result;
	UINT32 twenty = 20;
	BYTE *random;

	if ((result = TCSP_GetRandom(hContext, &twenty, &random)))
		return TSS_E_INTERNAL_ERROR;

	memcpy(nonce->nonce, random, 20);

	if ((result = TCS_FreeMemory(hContext, random)))
		return result;

	return TSS_SUCCESS;
}

void
UnloadBlob_DIGEST(UINT16 * offset, BYTE * blob, TCPA_DIGEST digest)
{
	UnloadBlob(offset, 20, blob, digest.digest);
}

TSS_RESULT
UnloadBlob_PUBKEY(TCS_CONTEXT_HANDLE hContext, UINT16 * offset,
		  BYTE * blob, TCPA_PUBKEY * pubKey)
{
	TSS_RESULT result;

	if ((result = UnloadBlob_KEY_PARMS(hContext, offset, blob, &pubKey->algorithmParms)))
		return result;
	return UnloadBlob_STORE_PUBKEY(hContext, offset, blob, &pubKey->pubKey);
}

void
UnloadBlob_MigrationKeyAuth(TCS_CONTEXT_HANDLE hContext,
			    UINT16 * offset, TCPA_MIGRATIONKEYAUTH * migAuth, BYTE * blob)
{
	UnloadBlob_PUBKEY(hContext, offset, blob, &migAuth->migrationKey);
	UnloadBlob_UINT16(offset, &migAuth->migrationScheme, blob);
	UnloadBlob_DIGEST(offset, blob, migAuth->digest);
}

#if 0
void
LoadBlob_STORE_PRIVKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PRIVKEY * store)
{
	LoadBlob_UINT32(offset, store->keyLength, blob);
	LoadBlob(offset, store->keyLength, blob, store->key);
}

void
LoadBlob_STORE_ASYMKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_ASYMKEY * store)
{
	blob[(*offset)++] = store->payload;
	LoadBlob(offset, 20, blob, store->usageAuth.secret);
	LoadBlob(offset, 20, blob, store->migrationAuth.secret);
	LoadBlob(offset, 20, blob, store->pubDataDigest.digest);
	LoadBlob_STORE_PRIVKEY(offset, blob, &store->privKey);
}
#endif

void
LoadBlob_KEY_ForHash(UINT16 * offset, BYTE * blob, TCPA_KEY * key)
{
	LoadBlob_TCPA_VERSION(offset, blob, key->ver);
	LoadBlob_UINT16(offset, key->keyUsage, blob);
	LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	blob[(*offset)++] = key->authDataUsage;
	LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);
	LoadBlob_UINT32(offset, key->PCRInfoSize, blob);
	LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
}

#if 0
TSS_RESULT
EncryptStoreAsymKey(TCS_CONTEXT_HANDLE hContext, TCPA_PAYLOAD_TYPE payload,
		    UINT32 privModLength, BYTE * privMod, BYTE * usageAuth,
		    BYTE * migAuth, TCPA_RSAKEY_OBJECT * keyObject,
		    BYTE * pubkey, UINT32 pubKeyLength)
{
	UINT16 offset;
	BYTE blob[1000];
	BYTE seed[20];
	TCPA_STORE_ASYMKEY storeAsymkey;
/* 	UINT32 rc; */
	UINT32 bytesRequested;
	BYTE *randomBytes;
	TSS_RESULT result;

	bytesRequested = 20;
	if ((result = TCSP_GetRandom(hContext,	/*  in */
				    &bytesRequested,	/*  in, out */
				    &randomBytes	/*  out */
	    )))
		return result;
	memset(seed, *randomBytes, 20);

	/* generate storeAsymkey structure */
	storeAsymkey.payload = TCPA_PT_ASYM;
	storeAsymkey.privKey.keyLength = privModLength;
	storeAsymkey.privKey.key = getSPIMemory(hContext, privModLength);
/* 	storeAsymkey.privKey.key = malloc(privModLength); */
	memcpy(storeAsymkey.privKey.key, privMod, storeAsymkey.privKey.keyLength);
	memcpy(storeAsymkey.migrationAuth.secret, migAuth, 20);
	memcpy(storeAsymkey.usageAuth.secret, usageAuth, 20);

	offset = 0;
	LoadBlob_KEY_ForHash(&offset, blob, &keyObject->tcpaKey);

	TSS_Hash(TSS_HASH_SHA1, offset, blob, storeAsymkey.pubDataDigest.digest);

	offset = 0;
	LoadBlob_STORE_ASYMKEY(&offset, blob, &storeAsymkey);

	if ((result = TSS_RSA_Encrypt(blob,
				    offset,
				    keyObject->tcpaKey.encData,
				    &keyObject->tcpaKey.encSize,
				    pubkey, pubKeyLength)))
		return result;

	return TSS_SUCCESS;

}
#endif

TCPA_PCRVALUE *
getPcrFromComposite(TCPA_PCR_COMPOSITE comp, UINT32 which)
{
	UINT32 i, j, valueOffset;

	valueOffset = 0;
	for (j = 0; j < comp.select.sizeOfSelect; j++) {
		for (i = 0; i < 8; i++) {
			if (comp.select.pcrSelect[j] & (1 << i)) {
				if (j == (which >> 3) && i == (which & 0x07)) {
					return &comp.pcrValue[valueOffset];
				} else
					valueOffset++;
			}
		}
	}
	return NULL;
}

BOOL firstPCRCheck = 1;
UINT16
getMaxPCRs(TCS_CONTEXT_HANDLE hContext)
{
	TSS_RESULT result;
	static UINT16 ret;
	BYTE subCap[4];
	UINT32 respSize;
	BYTE *resp;

	LogDebug1("getMaxPCRs");
	if (firstPCRCheck == 0) {
		LogDebug("Already ran it, maxPcrs=0x%.4X", ret);
		return ret;
	}

	/* ===  Make this call the getCap( PROP_PCR ) to find out how many pcr's it supports */
	UINT32ToArray(TCPA_CAP_PROP_PCR, subCap);

	if ((result = TCSP_GetCapability(hContext, TCPA_CAP_PROPERTY, 4, subCap, &respSize, &resp)))
		return 0;

	ret = (UINT16) Decode_UINT32(resp);
/* 	Tspi_Context_FreeMemory( hContext, resp ); */
	TCS_FreeMemory(hContext, resp);
	firstPCRCheck = 0;
	LogDebug("maxPcrs=0x%.4X", ret);

	return ret;
}

BOOL firstVersionCheck = 1;
TCPA_VERSION *
getCurrentVersion(TSS_HCONTEXT hContext)
{
	static TCPA_VERSION version;
	/* TCS_CONTEXT_HANDLE hContext; */
	TCPA_CAPABILITY_AREA capArea = TCPA_CAP_VERSION;
	UINT32 respSize;
	BYTE *resp;
	TCPA_RESULT result = 0;
	UINT16 offset;
	TCS_CONTEXT_HANDLE tcsContext;
#if 0
	AnObject *anObject;
#endif

	if (firstVersionCheck) {
		if ((result = internal_CheckContext_1(hContext, &tcsContext)))
			return NULL;
#if 0
		/* call getCap and fill the version */
		anObject = getAnObjectByHandle(hContext);
		if (anObject == NULL)
			return NULL;
#endif
		result = TCSP_GetCapability(tcsContext,	/*  in */
					    capArea,	/*  in */
					    0,	/*  in */
					    NULL, /* in */
					    &respSize,	/*  out */
					    &resp);	/*  out */
		if (!result) {
			offset = 0;
			UnloadBlob_TCPA_VERSION(&offset, resp, &version);
			free(resp);
			firstVersionCheck = 0;
		}
	}

	if (!result)
		return &version;
	else
		return NULL;
}

TSS_RESULT
Init_AuthNonce(TCS_CONTEXT_HANDLE hContext, TCS_AUTH * auth)
{
	TSS_RESULT result;

	auth->fContinueAuthSession = 0x00;
	if ((result = internal_GetRandomNonce(hContext, &auth->NonceOdd))) {
		LogError1("Failed creating random nonce");
		return TSS_E_INTERNAL_ERROR;
	}

	return TSS_SUCCESS;
}

BOOL
validateReturnAuth(BYTE *secret, BYTE *hash, TCS_AUTH *auth)
{
	BYTE digest[20];
	/* ===  auth is expected to have both nonces and the digest from the TPM */
	memcpy(digest, auth->HMAC, 20);
	HMAC_Auth(secret, hash, auth);

	return (BOOL) memcmp(digest, auth->HMAC, 20);
}

void
HMAC_Auth(BYTE * secret, BYTE * Digest, TCS_AUTH * auth)
{
	UINT16 offset;
	BYTE Blob[61];

	offset = 0;
	LoadBlob(&offset, 20, Blob, Digest);
	LoadBlob(&offset, 20, Blob, auth->NonceEven.nonce);
	LoadBlob(&offset, 20, Blob, auth->NonceOdd.nonce);
	Blob[offset++] = auth->fContinueAuthSession;

	TSS_HMAC(TSS_HASH_SHA1, 20, secret, offset, Blob, auth->HMAC);
	return;
}

TSS_RESULT
OSAP_Calc(TCS_CONTEXT_HANDLE hContext, UINT16 EntityType, UINT32 EntityValue,
	  BYTE * authSecret, BYTE * usageSecret, BYTE * migSecret,
	  TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig,
	  BYTE * sharedSecret, TCS_AUTH * auth)
{

	TSS_RESULT rc;
/* 	BYTE		*random; */
/* 	UINT32		bytesReturned = 20; */
	TCPA_NONCE nonceEvenOSAP;
	UINT16 offset;
	BYTE hmacBlob[0x200];
	BYTE hashBlob[0x200];
	BYTE xorUsageAuth[20];
	BYTE xorMigAuth[20];
	UINT32 i;

	if ((rc = internal_GetRandomNonce(hContext, &auth->NonceOdd))) {
		LogError1("Failed creating random nonce");
		return TSS_E_INTERNAL_ERROR;
	}
	auth->fContinueAuthSession = 0x00;
#if 0
	//Generate the Odd Nonce
//      if( rc = TCSP_GetRandom(
//              hContext,
//              &bytesReturned,
//              &random ))
//              return rc | TSS_E_INTERNAL_ERROR;

//      memcpy(auth->NonceOdd.nonce,random,20);
//      TCS_FreeMemory( hContext, random );
#endif

	if ((rc = TCSP_OSAP(hContext, EntityType, EntityValue, auth->NonceOdd,
				&auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP))) {
		if (rc == TCPA_RESOURCES) {
			int retry = 0;
			do {
				/* POSIX sleep time, { secs, nanosecs } */
				struct timespec t = { 0, AUTH_RETRY_NANOSECS };

				nanosleep(&t, NULL);

				rc = TCSP_OSAP(hContext, EntityType, EntityValue, auth->NonceOdd,
						   &auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP);
			} while (rc == TCPA_RESOURCES && ++retry < AUTH_RETRY_COUNT);
		}

		if (rc)
			return rc;
	}

	/* ---- */
	offset = 0;
	LoadBlob(&offset, 20, hmacBlob, nonceEvenOSAP.nonce);
	LoadBlob(&offset, 20, hmacBlob, auth->NonceOdd.nonce);

	TSS_HMAC(TSS_HASH_SHA1, 20, authSecret, offset, hmacBlob, sharedSecret);

	/* ---- */
	offset = 0;
	LoadBlob(&offset, 20, hashBlob, sharedSecret);
	LoadBlob(&offset, 20, hashBlob, auth->NonceEven.nonce);

	TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, xorUsageAuth);

	/* ---- */
	offset = 0;
	LoadBlob(&offset, 20, hashBlob, sharedSecret);
	LoadBlob(&offset, 20, hashBlob, auth->NonceOdd.nonce);
	TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, xorMigAuth);

	/* ---- */
	for (i = 0; i < 20; i++)
		encAuthUsage->encauth[i] = usageSecret[i] ^ xorUsageAuth[i];
	for (i = 0; i < 20; i++)
		encAuthMig->encauth[i] = migSecret[i] ^ xorMigAuth[i];

	return TSS_SUCCESS;
}

TSS_RESULT
internal_GetSecret(TSS_HPOLICY hPolicy, TCPA_SECRET * secret, BOOL forHMACUse)
{

	AnObject *object = NULL;
	TSP_INTERNAL_POLICY_OBJECT *pObj;

	object = getAnObjectByHandle(hPolicy);
	if (object == 0)
		return TSS_E_INVALID_HANDLE;

	pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

	memcpy(secret->secret, &pObj->p.Secret, 20);

	return TSS_SUCCESS;
}

TSS_RESULT
internal_CopySecrets(TSS_HPOLICY dest, TSS_HPOLICY source)
{
	AnObject *object = NULL;
	TCPA_SECRET tempSecret;
	TSP_INTERNAL_POLICY_OBJECT *pObj;

	object = getAnObjectByHandle(source);
	if (object == 0)
		return TSS_E_INVALID_HANDLE;

	pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

	memcpy(tempSecret.secret, &pObj->p.Secret, 20);
	return internal_SetSecret(dest, pObj->p.SecretMode, 20, tempSecret.secret, FALSE);

}

TSS_RESULT
internal_SetSecret(TSS_HPOLICY hPolicy, TSS_FLAG mode, UINT32 size, BYTE * data,
		   BOOL hashSecretForMe)
{
	AnObject *object = NULL;
	TSP_INTERNAL_POLICY_OBJECT *pObj = NULL;

	object = getAnObjectByHandle(hPolicy);
	if (object == 0)
		return TSS_E_INVALID_HANDLE;

	if (object->memPointer == NULL) {
		LogError("internal mem pointer for object 0x%x is invalid", hPolicy);
		return TSS_E_INTERNAL_ERROR;
	}

	pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

	if (size && data && (mode != TSS_SECRET_MODE_CALLBACK)) {
		if (hashSecretForMe) {
			TSS_Hash(TSS_HASH_SHA1, size, data, (BYTE *)&pObj->p.Secret);
		} else {
			if (size != 20)
				return TSS_E_BAD_PARAMETER;
			memcpy(&pObj->p.Secret, data, size);
		}
	} else if (mode == TSS_SECRET_MODE_POPUP) {
		/* TRUE will force the confirmation of popup entry data dialog to appear */
		if(popup_GetSecret(TRUE, pObj->p.popupString, &pObj->p.Secret))
			return TSS_E_INTERNAL_ERROR;
	}
	pObj->p.SecretMode = mode;
	pObj->p.SecretSize = 20;

	return TSS_SUCCESS;
}

TSS_RESULT
internal_FlushSecret(TSS_HPOLICY hPolicy)
{
	AnObject *object = NULL;
	TSP_INTERNAL_POLICY_OBJECT *pObj = NULL;

	object = getAnObjectByHandle(hPolicy);
	if (object == 0)
		return TSS_E_INVALID_HANDLE;

	if (object->memPointer == NULL) {
		LogError("internal mem pointer for object 0x%x is invalid", hPolicy);
		return TSS_E_INTERNAL_ERROR;
	}

	pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

	if (pObj->p.Secret != NULL)
		memset(&pObj->p.Secret, 0, pObj->p.SecretSize);	/* required by spec */

	pObj->p.SecretSize = 0;

	return TSS_SUCCESS;
}

#if 0
void
LoadBlob_PCR_COMPOSITE(UINT16 * offset, BYTE * outBlob, TCPA_PCR_COMPOSITE comp)
{
	UINT32 i;
	LoadBlob_PCR_SELECTION(offset, outBlob, comp.select);
	LoadBlob_UINT32(offset, comp.valueSize, outBlob);
	for (i = 0; i < comp.valueSize / 20; i++)
		LoadBlob(offset, 20, outBlob, comp.pcrValue[i].digest);
}

void
UnloadBlob_PCR_COMPOSITE(TCS_CONTEXT_HANDLE hContext,
			 UINT16 * offset, BYTE * inBlob, TCPA_PCR_COMPOSITE * comp)
{
	UINT32 i;
	UnloadBlob_PCR_SELECTION(hContext, offset, inBlob, &comp->select);
	UnloadBlob_UINT32(offset, &comp->valueSize, inBlob);
	if (hContext == 0)
		comp->pcrValue = malloc(20 * comp->valueSize);
	else
		comp->pcrValue = getSPIMemory(hContext, 20 * comp->valueSize);
	for (i = 0; i < comp->valueSize / 20; i++)
		UnloadBlob(offset, 20, inBlob, comp->pcrValue[i].digest);
}

TSS_RESULT
calculateCompositeHash( TCPA_PCR_COMPOSITE comp, TCPA_DIGEST* digest )
{
	BYTE hashBlob[1024];
	UINT16 blobOffset = 0;
	LoadBlob_PCR_COMPOSITE( &blobOffset, hashBlob, comp );
	TSS_Hash( TSS_HASH_SHA1, blobOffset, hashBlob, digest->digest );
	return TSS_SUCCESS;
}
#endif

TSS_RESULT
calcCompositeHash(TCPA_PCR_SELECTION select, TCPA_PCRVALUE * arrayOfPcrs, TCPA_DIGEST * digestOut)
{
	int size;
	int index;
	BYTE mask;
	BYTE temp[1024];
	UINT32 numPCRs = 0;
	UINT16 offset = 0;
	UINT16 sizeOffset = 0;

	sizeOffset = 0;
	LoadBlob_PCR_SELECTION(&sizeOffset, temp, select);
	offset = sizeOffset + 4;

	for (size = 0; size < select.sizeOfSelect; size++) {
		for (index = 0, mask = 1; index < 8; index++, mask = mask << 1) {
			if (select.pcrSelect[size] & mask) {
				memcpy(&temp[(numPCRs * 20) + offset],
				       arrayOfPcrs[numPCRs].digest, 20);
				numPCRs++;
			}
		}
	}

	offset += (numPCRs * 20);
	UINT32ToArray(numPCRs * 20, &temp[sizeOffset]);

	TSS_Hash(TSS_HASH_SHA1, offset, temp, digestOut->digest);
	return 0;
}

TSS_RESULT
generateCompositeFromTPM(TSS_HCONTEXT hContext, TCPA_PCR_SELECTION select, TCPA_DIGEST * digest)
{
	UINT32 i, j;
	BYTE hashBlob[1024];
	BYTE mask;
	TCPA_PCRVALUE pcrVal;
/* 	TCS_CONTEXT_HANDLE hContext; */
	UINT16 blobOffset;
	TCPA_RESULT result;
	UINT16 count = 0;
	UINT32 blah;

	/* TCS_OpenContext( &hContext ); */

	blobOffset = 0;
	LoadBlob_PCR_SELECTION(&blobOffset, hashBlob, select);
	blah = blobOffset;
	blobOffset += 4;
	for (i = 0; i < select.sizeOfSelect; i++) {
		for (j = 0; j < 8; j++) {
			mask = (1 << j);
			if (select.pcrSelect[i] & mask) {
				count++;
				if ((result = TCSP_PcrRead(hContext, (i << 3) + j, &pcrVal)))
					return result;
				LoadBlob(&blobOffset, 20, hashBlob, pcrVal.digest);
/* 				memcpy( &hashBlob[blobOffset], pcrVal.digest, 20 ); */
/* 				blobOffset += 20; */
			}

		}
	}
	UINT32ToArray(count * 20, &hashBlob[blah]);
	TSS_Hash(TSS_HASH_SHA1, blobOffset, hashBlob, digest->digest);

	/* TCS_CloseContext( hContext ); */
	return TSS_SUCCESS;
}

/* --------------------------------------------------------------------------------------------------- */
UINT16
Decode_UINT16(BYTE * in)
{
	UINT16 temp = 0;
	temp = (in[1] & 0xFF);
	temp |= (in[0] << 8);
	return temp;
}

void
UINT32ToArray(UINT32 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 24) & 0xFF);
	out[1] = (BYTE) ((i >> 16) & 0xFF);
	out[2] = (BYTE) ((i >> 8) & 0xFF);
	out[3] = (BYTE) i & 0xFF;
}

void
UINT16ToArray(UINT16 i, BYTE * out)
{
	out[0] = ((i >> 8) & 0xFF);
	out[1] = i & 0xFF;
}

UINT32
Decode_UINT32(BYTE * y)
{
	UINT32 x = 0;

	x = y[0];
	x = ((x << 8) | (y[1] & 0xFF));
	x = ((x << 8) | (y[2] & 0xFF));
	x = ((x << 8) | (y[3] & 0xFF));

	return x;
}

void
LoadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object)
{
	if (size == 0)
		return;
	memcpy(&container[(*offset)], object, size);
	(*offset) += (UINT16) size;
}

void
UnloadBlob(UINT16 * offset, UINT32 size, BYTE * container, BYTE * object)
{
	if (size == 0)
		return;
	memcpy(object, &container[(*offset)], size);
	(*offset) += (UINT16) size;
}

void
LoadBlob_BYTE(UINT16 * offset, BYTE data, BYTE * blob)
{
	blob[*offset] = data;
	(*offset)++;
}

void
UnloadBlob_BYTE(UINT16 * offset, BYTE * dataOut, BYTE * blob)
{
	*dataOut = blob[*offset];
	(*offset)++;
}

void
LoadBlob_BOOL(UINT16 * offset, BOOL data, BYTE * blob)
{
	blob[*offset] = (BYTE) data;
	(*offset)++;
}

void
UnloadBlob_BOOL(UINT16 * offset, BOOL * dataOut, BYTE * blob)
{
	*dataOut = blob[*offset];
	(*offset)++;
}

void
LoadBlob_UINT32(UINT16 * offset, UINT32 in, BYTE * blob)
{
	UINT32ToArray(in, &blob[*offset]);
	*offset += 4;
}

void
LoadBlob_UINT16(UINT16 * offset, UINT16 in, BYTE * blob)
{
	UINT16ToArray(in, &blob[*offset]);
	*offset += 2;
}

void
UnloadBlob_UINT32(UINT16 * offset, UINT32 * out, BYTE * blob)
{
	*out = Decode_UINT32(&blob[*offset]);
	*offset += 4;
}

void
UnloadBlob_UINT16(UINT16 * offset, UINT16 * out, BYTE * blob)
{
	*out = Decode_UINT16(&blob[*offset]);
	*offset += 2;
}

void
LoadBlob_RSA_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_RSA_KEY_PARMS * parms)
{
	LoadBlob_UINT32(offset, parms->keyLength, blob);
	LoadBlob_UINT32(offset, parms->numPrimes, blob);
	LoadBlob_UINT32(offset, parms->exponentSize, blob);
	LoadBlob(offset, parms->exponentSize, blob, parms->exponent);
	return;
}

#if 0
void
UnloadBlob_TSS_VERSION(UINT16 * offset, BYTE * blob, TSS_VERSION * out)
{
	out->bMajor = blob[(*offset)++];
	out->bMinor = blob[(*offset)++];
	out->bRevMajor = blob[(*offset)++];
	out->bRevMinor = blob[(*offset)++];
	return;
}
#endif

void
LoadBlob_TSS_VERSION(UINT16 * offset, BYTE * blob, TSS_VERSION version)
{
	blob[(*offset)++] = version.bMajor;
	blob[(*offset)++] = version.bMinor;
	blob[(*offset)++] = version.bRevMajor;
	blob[(*offset)++] = version.bRevMinor;
	return;
}

void
UnloadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION * out)
{
	out->major = blob[(*offset)++];
	out->minor = blob[(*offset)++];
	out->revMajor = blob[(*offset)++];
	out->revMinor = blob[(*offset)++];
	return;
}

void
LoadBlob_TCPA_VERSION(UINT16 * offset, BYTE * blob, TCPA_VERSION version)
{
	blob[(*offset)++] = version.major;
	blob[(*offset)++] = version.minor;
	blob[(*offset)++] = version.revMajor;
	blob[(*offset)++] = version.revMinor;
	return;
}

void
LoadBlob_BOUND_DATA(UINT16 * offset, TCPA_BOUND_DATA bd,
		    UINT32 payloadLength, BYTE * blob)
{
	LoadBlob_TCPA_VERSION(offset, blob, bd.ver);
	LoadBlob(offset, 1, blob, &bd.payload);
	LoadBlob(offset, payloadLength, blob, bd.payloadData);
}

#if 0
void
LoadBlob_PCR_INFO(UINT16 * offset, BYTE * blob, TCPA_PCR_INFO * pcr)
{
	LoadBlob_PCR_SELECTION(offset, blob, pcr->pcrSelection);
	LoadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtRelease.digest);
	LoadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtCreation.digest);
	return;
}
#endif

TSS_RESULT
UnloadBlob_PCR_INFO(TCS_CONTEXT_HANDLE hContext, UINT16 * offset,
		    BYTE * blob, TCPA_PCR_INFO * pcr)
{
	TSS_RESULT result;

	if ((result = UnloadBlob_PCR_SELECTION(hContext, offset, blob, &pcr->pcrSelection)))
		return result;
	UnloadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtRelease.digest);
	UnloadBlob(offset, TPM_DIGEST_SIZE, blob, pcr->digestAtCreation.digest);
	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_STORED_DATA(TCS_CONTEXT_HANDLE hContext, UINT16 * offset,
		       BYTE * blob, TCPA_STORED_DATA * data)
{
	UnloadBlob_TCPA_VERSION(offset, blob, &data->ver);
	UnloadBlob_UINT32(offset, &data->sealInfoSize, blob);

	if (data->sealInfoSize > 0) {
		if (hContext == 0)
			data->sealInfo = malloc(data->sealInfoSize);
		else
			data->sealInfo = calloc_tspi(hContext, data->sealInfoSize);

		if (data->sealInfo == NULL) {
			LogError("malloc of %d bytes failed.", data->sealInfoSize);
			return TSS_E_OUTOFMEMORY;
		}
		UnloadBlob(offset, data->sealInfoSize, blob, data->sealInfo);
	} else {
		data->sealInfo = NULL;
	}

	UnloadBlob_UINT32(offset, &data->encDataSize, blob);

	if (data->encDataSize > 0) {
		if (hContext == 0)
			data->encData = malloc(data->encDataSize);
		else
			data->encData = calloc_tspi(hContext, data->encDataSize);

		if (data->encData == NULL) {
			LogError("malloc of %d bytes failed.", data->encDataSize);
			return TSS_E_OUTOFMEMORY;
		}

		UnloadBlob(offset, data->encDataSize, blob, data->encData);
	} else {
		data->encData = NULL;
	}

	return TSS_SUCCESS;
}

void
LoadBlob_STORED_DATA(UINT16 * offset, BYTE * blob, TCPA_STORED_DATA * data)
{
	LoadBlob_TCPA_VERSION(offset, blob, data->ver);
	LoadBlob_UINT32(offset, data->sealInfoSize, blob);
	LoadBlob(offset, data->sealInfoSize, blob, data->sealInfo);
	LoadBlob_UINT32(offset, data->encDataSize, blob);
	LoadBlob(offset, data->encDataSize, blob, data->encData);
}

TSS_RESULT
UnloadBlob_PCR_SELECTION(TCS_CONTEXT_HANDLE hContext,
			 UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION * pcr)
{
	UINT16 i;

	pcr->sizeOfSelect = Decode_UINT16(&blob[*offset]);

	if (pcr->sizeOfSelect > 0) {
		*offset += 2;
		if (hContext == 0)
			pcr->pcrSelect = malloc(pcr->sizeOfSelect);
		else
			pcr->pcrSelect = calloc_tspi(hContext, pcr->sizeOfSelect);

		if (pcr->pcrSelect == NULL) {
			LogError("malloc of %d bytes failed.", pcr->sizeOfSelect);
			return TSS_E_OUTOFMEMORY;
		}

		for (i = 0; i < pcr->sizeOfSelect; i++, (*offset)++)
			pcr->pcrSelect[i] = blob[*offset];
	} else {
		pcr->pcrSelect = NULL;
	}

	return TSS_SUCCESS;
}

void
LoadBlob_PCR_SELECTION(UINT16 * offset, BYTE * blob, TCPA_PCR_SELECTION pcr)
{
	UINT16 i;

	UINT16ToArray(pcr.sizeOfSelect, &blob[*offset]);
	*offset += 2;
	for (i = 0; i < pcr.sizeOfSelect; i++, (*offset)++)
		blob[*offset] = pcr.pcrSelect[i];
	return;

}

void
LoadBlob_KEY(UINT16 * offset, BYTE * blob, TCPA_KEY * key)
{

/* 	UINT32 i; */

	LoadBlob_TCPA_VERSION(offset, blob, key->ver);
	LoadBlob_UINT16(offset, key->keyUsage, blob);
	LoadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	blob[(*offset)++] = key->authDataUsage;
	LoadBlob_KEY_PARMS(offset, blob, &key->algorithmParms);
	LoadBlob_UINT32(offset, key->PCRInfoSize, blob);
/* 	for( i = 0 ; i < key->PCRInfoSize ; i++, (*offset)++ ) */
/* 		blob[*offset] = key->PCRInfo[i]; */
	LoadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	LoadBlob_STORE_PUBKEY(offset, blob, &key->pubKey);
	LoadBlob_UINT32(offset, key->encSize, blob);
	LoadBlob(offset, key->encSize, blob, key->encData);

	return;
}

void
LoadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;

	if (*flags & migratable)
		tempFlag |= FLAG_MIGRATABLE;
	if (*flags & redirection)
		tempFlag |= FLAG_REDIRECTION;
	if (*flags & volatileKey)
		tempFlag |= FLAG_VOLATILE;
	LoadBlob_UINT32(offset, tempFlag, blob);
}

void
UnloadBlob_KEY_FLAGS(UINT16 * offset, BYTE * blob, TCPA_KEY_FLAGS * flags)
{
	UINT32 tempFlag = 0;
	memset(flags, 0x00, sizeof(TCPA_KEY_FLAGS));

	UnloadBlob_UINT32(offset, &tempFlag, blob);

	if (tempFlag & FLAG_REDIRECTION)
		*flags |= redirection;
	if (tempFlag & FLAG_MIGRATABLE)
		*flags |= migratable;
	if (tempFlag & FLAG_VOLATILE)
		*flags |= volatileKey;
}

void
LoadBlob_KEY_PARMS(UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyInfo)
{
	LoadBlob_UINT32(offset, keyInfo->algorithmID, blob);
	LoadBlob_UINT16(offset, keyInfo->encScheme, blob);
	LoadBlob_UINT16(offset, keyInfo->sigScheme, blob);
	LoadBlob_UINT32(offset, keyInfo->parmSize, blob);
	LoadBlob(offset, keyInfo->parmSize, blob, keyInfo->parms);
}

void
LoadBlob_STORE_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store)
{
	LoadBlob_UINT32(offset, store->keyLength, blob);
	LoadBlob(offset, store->keyLength, blob, store->key);
}

void
LoadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID uuid)
{
	LoadBlob_UINT32(offset, uuid.ulTimeLow, blob);
	LoadBlob_UINT16(offset, uuid.usTimeMid, blob);
	LoadBlob_UINT16(offset, uuid.usTimeHigh, blob);
	LoadBlob_BYTE(offset, uuid.bClockSeqHigh, blob);
	LoadBlob_BYTE(offset, uuid.bClockSeqLow, blob);
	LoadBlob(offset, 6, blob, uuid.rgbNode);
}

void
UnloadBlob_UUID(UINT16 * offset, BYTE * blob, TSS_UUID * uuid)
{
	memset(uuid, 0, sizeof(TSS_UUID));
	UnloadBlob_UINT32(offset, &uuid->ulTimeLow, blob);
	UnloadBlob_UINT16(offset, &uuid->usTimeMid, blob);
	UnloadBlob_UINT16(offset, &uuid->usTimeHigh, blob);
	UnloadBlob_BYTE(offset, &uuid->bClockSeqHigh, blob);
	UnloadBlob_BYTE(offset, &uuid->bClockSeqLow, blob);
	UnloadBlob(offset, 6, blob, uuid->rgbNode);
}

TSS_RESULT
UnloadBlob_KEY_PARMS(TCS_CONTEXT_HANDLE hContext,
		     UINT16 * offset, BYTE * blob, TCPA_KEY_PARMS * keyParms)
{

	UnloadBlob_UINT32(offset, &keyParms->algorithmID, blob);
	UnloadBlob_UINT16(offset, &keyParms->encScheme, blob);
	UnloadBlob_UINT16(offset, &keyParms->sigScheme, blob);
	UnloadBlob_UINT32(offset, &keyParms->parmSize, blob);

	if (keyParms->parmSize > 0) {
		if (hContext == 0)
			keyParms->parms = malloc(keyParms->parmSize);
		else
			keyParms->parms = calloc_tspi(hContext, keyParms->parmSize);

		if (keyParms->parms == NULL) {
			LogError("malloc of %d bytes failed.", keyParms->parmSize);
			return TSS_E_OUTOFMEMORY;
		}
		UnloadBlob(offset, keyParms->parmSize, blob, keyParms->parms);
	} else {
		keyParms->parms = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_KEY(TCS_CONTEXT_HANDLE hContext, UINT16 * offset,
	       BYTE * blob, TCPA_KEY * key)
{
	TSS_RESULT result;

	UnloadBlob_TCPA_VERSION(offset, blob, &key->ver);
	UnloadBlob_UINT16(offset, &key->keyUsage, blob);
	UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	key->authDataUsage = blob[(*offset)++];
	if ((result = UnloadBlob_KEY_PARMS(hContext, offset, (BYTE *) blob, &key->algorithmParms)))
		return result;
	UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob);

	if (key->PCRInfoSize > 0) {
		if (hContext == 0)
			key->PCRInfo = malloc(key->PCRInfoSize);
		else
			key->PCRInfo = calloc_tspi(hContext, key->PCRInfoSize);

		if (key->PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", key->PCRInfoSize);
			return TSS_E_OUTOFMEMORY;
		}
		UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	} else {
		key->PCRInfo = NULL;
	}

	if ((result = UnloadBlob_STORE_PUBKEY(hContext, offset, blob, &key->pubKey)))
		return result;
	UnloadBlob_UINT32(offset, &key->encSize, blob);

	if (key->encSize > 0) {
		if (hContext == 0)
			key->encData = malloc(key->encSize);
		else
			key->encData = calloc_tspi(hContext, key->encSize);

		if (key->encData == NULL) {
			LogError("malloc of %d bytes failed.", key->encSize);
			return TSS_E_OUTOFMEMORY;
		}
		UnloadBlob(offset, key->encSize, blob, key->encData);
	} else {
		key->encData = NULL;
	}

	return result;
}

/*
void UnloadBlob_VERSION( UINT16* offset,  BYTE* blob, TCPA_VERSION* out ){

	out->major = blob[(*offset)++];
	out->minor = blob[(*offset)++];
	out->revMajor = blob[(*offset)++];
	out->revMinor = blob[(*offset)++];

	return;
}
*/

TSS_RESULT
UnloadBlob_STORE_PUBKEY(TCS_CONTEXT_HANDLE hContext,
			UINT16 * offset, BYTE * blob, TCPA_STORE_PUBKEY * store)
{

	UnloadBlob_UINT32(offset, &store->keyLength, blob);

	if (store->keyLength > 0) {
		if (hContext == 0)
			store->key = malloc(store->keyLength);
		else
			store->key = calloc_tspi(hContext, store->keyLength);

		if (store->key == NULL) {
			LogError("malloc of %d bytes failed.", store->keyLength);
			return TSS_E_OUTOFMEMORY;
		}
		UnloadBlob(offset, store->keyLength, blob, store->key);
	} else {
		store->key = NULL;
	}

	return TSS_SUCCESS;
}

#if 0
void
LoadBlob_PUBKEY(UINT16 * offset, BYTE * blob, TCPA_PUBKEY pubKey)
{

	LoadBlob_KEY_PARMS(offset, blob, &pubKey.algorithmParms);
	LoadBlob_UINT32(offset, pubKey.pubKey.keyLength, blob);
	LoadBlob(offset, pubKey.pubKey.keyLength, blob, pubKey.pubKey.key);

	return;
}

void
LoadBlob_CERTIFY_INFO(UINT16 * offset, BYTE * blob, TCPA_CERTIFY_INFO * certify)
{

	LoadBlob_TCPA_VERSION(offset, blob, certify->version);
	LoadBlob_UINT16(offset, certify->keyUsage, blob);
	LoadBlob_KEY_FLAGS(offset, blob, &certify->keyFlags);
	LoadBlob_BYTE(offset, (BYTE) certify->authDataUsage, blob);
	LoadBlob_KEY_PARMS(offset, blob, &certify->algorithmParms);
	LoadBlob(offset, 20, blob, certify->pubkeyDigest.digest);
	LoadBlob(offset, 20, blob, certify->data.nonce);
	LoadBlob_BYTE(offset, (BYTE) certify->parentPCRStatus, blob);
	LoadBlob_UINT32(offset, certify->PCRInfoSize, blob);
	LoadBlob(offset, certify->PCRInfoSize, blob, certify->PCRInfo);
	return;
}
#endif

void
UnloadBlob_TCPA_EVENT_CERT(UINT16 * offset, BYTE * blob, TCPA_EVENT_CERT * cert)
{
	UnloadBlob(offset, 20, blob, cert->certificateHash.digest);
	UnloadBlob(offset, 20, blob, cert->entityDigest.digest);
	cert->digestChecked = blob[(*offset)++];
	cert->digestVerified = blob[(*offset)++];
	UnloadBlob_UINT32(offset, &cert->issuerSize, blob);
	UnloadBlob(offset, cert->issuerSize, blob, cert->issuer);
}

void
LoadBlob_CHANGEAUTH_VALIDATE(UINT16 * offset, BYTE * blob,
			     TCPA_CHANGEAUTH_VALIDATE * caValidate)
{
	LoadBlob(offset, 20, blob, caValidate->newAuthSecret.secret);
	LoadBlob(offset, 20, blob, caValidate->n1.nonce);
	return;
}

/* free any pointers this key may have and zero out the respective areas. */
void
destroy_key_refs(TCPA_KEY *key)
{
	free(key->algorithmParms.parms);
	key->algorithmParms.parms = NULL;
	key->algorithmParms.parmSize = 0;

	free(key->pubKey.key);
	key->pubKey.key = NULL;
	key->pubKey.keyLength = 0;

	free(key->encData);
	key->encData = NULL;
	key->encSize = 0;
}

UINT32
get_pcr_event_size(TSS_PCR_EVENT *e)
{
	return (sizeof(TSS_PCR_EVENT) + e->ulEventLength + e->ulPcrValueLength);
}
