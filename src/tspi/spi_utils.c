
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
#include "tsplog.h"
#include "obj.h"
#include "tss/trousers.h"

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
internal_GetRandomNonce(TCS_CONTEXT_HANDLE tcsContext, TCPA_NONCE * nonce)
{
	TSS_RESULT result;
	UINT32 twenty = 20;
	BYTE *random;

	if ((result = TCSP_GetRandom(tcsContext, &twenty, &random)))
		return TSS_E_INTERNAL_ERROR;

	memcpy(nonce->nonce, random, 20);

	free(random);
	return TSS_SUCCESS;
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
	Trspi_LoadBlob_KEY_ForHash(&offset, blob, &keyObject->tcpaKey);

	Trspi_Hash(TSS_HASH_SHA1, offset, blob, storeAsymkey.pubDataDigest.digest);

	offset = 0;
	Trspi_LoadBlob_STORE_ASYMKEY(&offset, blob, &storeAsymkey);

	if ((result = Trspi_RSA_Encrypt(blob,
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

#if 0
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
#endif

//BOOL firstVersionCheck = 1;
TCPA_VERSION *
getCurrentVersion(TSS_HCONTEXT hContext)
{
	static TCPA_VERSION version = { 1, 1, 0, 0 };
#if 0
	/* No use case for getCurrentVersion has convinced me that the version
	 * info from the TCS is the right answer. Just return a 1.1.0.0
	 * answer all the time. - KEY
	 */
	/* TCS_CONTEXT_HANDLE hContext; */
	TCPA_CAPABILITY_AREA capArea = TCPA_CAP_VERSION;
	UINT32 respSize;
	BYTE *resp;
	TCPA_RESULT result = 0;
	UINT16 offset;
	TCS_CONTEXT_HANDLE tcsContext;

	if (firstVersionCheck) {
		if ((result = obj_isConnected_1(hContext, &tcsContext)))
			return &version;

		result = TCSP_GetCapability(tcsContext,	/*  in */
					    capArea,	/*  in */
					    0,	/*  in */
					    NULL, /* in */
					    &respSize,	/*  out */
					    &resp);	/*  out */
		if (!result) {
			offset = 0;
			Trspi_UnloadBlob_TCPA_VERSION(&offset, resp, &version);
			free(resp);
			firstVersionCheck = 0;
		}
	}
#endif
	return &version;
}

TSS_RESULT
Init_AuthNonce(TCS_CONTEXT_HANDLE tcsContext, TCS_AUTH * auth)
{
	TSS_RESULT result;

	auth->fContinueAuthSession = 0x00;
	if ((result = internal_GetRandomNonce(tcsContext, &auth->NonceOdd))) {
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
	Trspi_LoadBlob(&offset, 20, Blob, Digest);
	Trspi_LoadBlob(&offset, 20, Blob, auth->NonceEven.nonce);
	Trspi_LoadBlob(&offset, 20, Blob, auth->NonceOdd.nonce);
	Blob[offset++] = auth->fContinueAuthSession;

	Trspi_HMAC(TSS_HASH_SHA1, 20, secret, offset, Blob, auth->HMAC);
	return;
}

TSS_RESULT
OSAP_Calc(TCS_CONTEXT_HANDLE tcsContext, UINT16 EntityType, UINT32 EntityValue,
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

	if ((rc = internal_GetRandomNonce(tcsContext, &auth->NonceOdd))) {
		LogError1("Failed creating random nonce");
		return TSS_E_INTERNAL_ERROR;
	}
	auth->fContinueAuthSession = 0x00;
#if 0
	//Generate the Odd Nonce
//      if( rc = TCSP_GetRandom(
//              tcsContext,
//              &bytesReturned,
//              &random ))
//              return rc | TSS_E_INTERNAL_ERROR;

//      memcpy(auth->NonceOdd.nonce,random,20);
//      TCS_FreeMemory( tcsContext, random );
#endif

	if ((rc = TCSP_OSAP(tcsContext, EntityType, EntityValue, auth->NonceOdd,
				&auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP))) {
		if (rc == TCPA_RESOURCES) {
			int retry = 0;
			do {
				/* POSIX sleep time, { secs, nanosecs } */
				struct timespec t = { 0, AUTH_RETRY_NANOSECS };

				nanosleep(&t, NULL);

				rc = TCSP_OSAP(tcsContext, EntityType, EntityValue, auth->NonceOdd,
						   &auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP);
			} while (rc == TCPA_RESOURCES && ++retry < AUTH_RETRY_COUNT);
		}

		if (rc)
			return rc;
	}

	/* ---- */
	offset = 0;
	Trspi_LoadBlob(&offset, 20, hmacBlob, nonceEvenOSAP.nonce);
	Trspi_LoadBlob(&offset, 20, hmacBlob, auth->NonceOdd.nonce);

	Trspi_HMAC(TSS_HASH_SHA1, 20, authSecret, offset, hmacBlob, sharedSecret);

	/* ---- */
	offset = 0;
	Trspi_LoadBlob(&offset, 20, hashBlob, sharedSecret);
	Trspi_LoadBlob(&offset, 20, hashBlob, auth->NonceEven.nonce);

	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, xorUsageAuth);

	/* ---- */
	offset = 0;
	Trspi_LoadBlob(&offset, 20, hashBlob, sharedSecret);
	Trspi_LoadBlob(&offset, 20, hashBlob, auth->NonceOdd.nonce);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, xorMigAuth);

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
	if (object == NULL)
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
	if (object == NULL)
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
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;

	if (object->memPointer == NULL) {
		LogError("internal mem pointer for object 0x%x is invalid", hPolicy);
		return TSS_E_INTERNAL_ERROR;
	}

	pObj = (TSP_INTERNAL_POLICY_OBJECT *)object->memPointer;

	if (size && data && (mode != TSS_SECRET_MODE_CALLBACK)) {
		if (hashSecretForMe) {
			Trspi_Hash(TSS_HASH_SHA1, size, data, (BYTE *)&pObj->p.Secret);
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
	if (object == NULL)
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
TSS_RESULT
calculateCompositeHash( TCPA_PCR_COMPOSITE comp, TCPA_DIGEST* digest )
{
	BYTE hashBlob[1024];
	UINT16 blobOffset = 0;
	Trspi_LoadBlob_PCR_COMPOSITE( &blobOffset, hashBlob, comp );
	Trspi_Hash( TSS_HASH_SHA1, blobOffset, hashBlob, digest->digest );
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
	Trspi_LoadBlob_PCR_SELECTION(&sizeOffset, temp, select);
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

	Trspi_Hash(TSS_HASH_SHA1, offset, temp, digestOut->digest);
	return 0;
}

TSS_RESULT
generateCompositeFromTPM(TSS_HCONTEXT tcsContext, TCPA_PCR_SELECTION select, TCPA_DIGEST * digest)
{
	UINT32 i, j;
	BYTE hashBlob[1024];
	BYTE mask;
	TCPA_PCRVALUE pcrVal;
/* 	TCS_CONTEXT_HANDLE tcsContext; */
	UINT16 blobOffset;
	TCPA_RESULT result;
	UINT16 count = 0;
	UINT32 blah;

	/* TCS_OpenContext( &tcsContext ); */

	blobOffset = 0;
	Trspi_LoadBlob_PCR_SELECTION(&blobOffset, hashBlob, select);
	blah = blobOffset;
	blobOffset += 4;
	for (i = 0; i < select.sizeOfSelect; i++) {
		for (j = 0; j < 8; j++) {
			mask = (1 << j);
			if (select.pcrSelect[i] & mask) {
				count++;
				if ((result = TCSP_PcrRead(tcsContext, (i << 3) + j, &pcrVal)))
					return result;
				Trspi_LoadBlob(&blobOffset, 20, hashBlob, pcrVal.digest);
/* 				memcpy( &hashBlob[blobOffset], pcrVal.digest, 20 ); */
/* 				blobOffset += 20; */
			}

		}
	}
	UINT32ToArray(count * 20, &hashBlob[blah]);
	Trspi_Hash(TSS_HASH_SHA1, blobOffset, hashBlob, digest->digest);

	/* TCS_CloseContext( tcsContext ); */
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

UINT32
get_pcr_event_size(TSS_PCR_EVENT *e)
{
	return (sizeof(TSS_PCR_EVENT) + e->ulEventLength + e->ulPcrValueLength);
}

void
LoadBlob_AUTH(UINT16 * offset, BYTE * blob, TCS_AUTH * auth)
{
	Trspi_LoadBlob_UINT32(offset, auth->AuthHandle, blob);
	Trspi_LoadBlob(offset, 20, blob, auth->NonceOdd.nonce);
	Trspi_LoadBlob_BOOL(offset, auth->fContinueAuthSession, blob);
	Trspi_LoadBlob(offset, 20, blob, auth->HMAC);
}

void
UnloadBlob_AUTH(UINT16 * offset, BYTE * blob, TCS_AUTH * auth)
{
	Trspi_UnloadBlob(offset, 20, blob, auth->NonceEven.nonce);
	Trspi_UnloadBlob_BOOL(offset, &auth->fContinueAuthSession, blob);
	Trspi_UnloadBlob(offset, 20, blob, auth->HMAC);
}

void
LoadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	Trspi_LoadBlob_UUID(offset, blob, info->keyUUID);
	Trspi_LoadBlob_UUID(offset, blob, info->parentKeyUUID);
	Trspi_LoadBlob(offset, TPM_DIGEST_SIZE, blob, info->paramDigest.digest);
	LoadBlob_AUTH(offset, blob, &info->authData);
}

void
UnloadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	Trspi_UnloadBlob_UUID(offset, blob, &info->keyUUID);
	Trspi_UnloadBlob_UUID(offset, blob, &info->parentKeyUUID);
	Trspi_UnloadBlob(offset, TPM_DIGEST_SIZE, info->paramDigest.digest, blob);
	UnloadBlob_AUTH(offset, blob, &info->authData);
}


TSS_RESULT
get_tpm_flags(TCS_CONTEXT_HANDLE tcsContext, TSS_HTPM hTPM,
		UINT32 *volFlags, UINT32 *nonVolFlags)
{
	BYTE hashBlob[128];
	TCPA_DIGEST digest;
	TCS_AUTH auth;
	TCPA_VERSION version;
	TSS_RESULT result;
	UINT16 offset;
	TSS_HPOLICY hPolicy;

	if ((result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	/* do an owner authorized get capability call */
	UINT32ToArray(TPM_ORD_GetCapabilityOwner, hashBlob);
	Trspi_Hash(TSS_HASH_SHA1, sizeof(UINT32), hashBlob, digest.digest);

	if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth)))
		return result;

	if ((result = TCSP_GetCapabilityOwner(tcsContext,       /*  in */
					&auth,     /*  out */
					&version,  /*  out */
					nonVolFlags,      /*  out */
					volFlags  /*  out */
					)))
		return result;

	offset = 0;
	Trspi_LoadBlob_UINT32(&offset, result, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, TPM_ORD_GetCapabilityOwner, hashBlob);
	Trspi_LoadBlob_TCPA_VERSION(&offset, hashBlob, version);
	Trspi_LoadBlob_UINT32(&offset, *nonVolFlags, hashBlob);
	Trspi_LoadBlob_UINT32(&offset, *volFlags, hashBlob);

	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

	return secret_ValidateAuth_OIAP(hPolicy, digest, &auth);
}

