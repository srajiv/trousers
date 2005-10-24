
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

TSS_UUID NULL_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };

TSS_VERSION VERSION_1_1 = { 1, 1, 0, 0 };

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

TSS_BOOL
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
internal_GetRandomNonce(TCS_CONTEXT_HANDLE tcsContext, TCPA_NONCE * nonce)
{
	TSS_RESULT result;
	BYTE *random;
	TSS_HCONTEXT tspContext;

	if ((tspContext = obj_lookupTspContext(tcsContext)) == NULL_HCONTEXT)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	if ((result = TCSP_GetRandom(tcsContext, sizeof(TCPA_NONCE), &random)))
		return TSPERR(TSS_E_INTERNAL_ERROR);

	memcpy(nonce->nonce, random, sizeof(TCPA_NONCE));
	free_tspi(tspContext, random);

	return TSS_SUCCESS;
}

UINT16
get_num_pcrs(TCS_CONTEXT_HANDLE hContext)
{
	TSS_RESULT result;
	static UINT16 ret = 0;
	UINT32 subCap;
	UINT32 respSize;
	BYTE *resp;

	if (ret != 0)
		return ret;

	subCap = endian32(TPM_CAP_PROP_PCR);
	if ((result = TCSP_GetCapability(hContext, TCPA_CAP_PROPERTY, sizeof(UINT32),
					 (BYTE *)&subCap, &respSize, &resp))) {
		if ((resp = getenv("TSS_DEFAULT_NUM_PCRS")) == NULL)
			return TSS_DEFAULT_NUM_PCRS;

		/* don't set ret here, next time we may be connected */
		return atoi(resp);
	}

	ret = (UINT16)Decode_UINT32(resp);
	free_tspi(hContext, resp);

	return ret;
}

TSS_RESULT
Init_AuthNonce(TCS_CONTEXT_HANDLE tcsContext, TPM_AUTH * auth)
{
	TSS_RESULT result;

	auth->fContinueAuthSession = 0x00;
	if ((result = internal_GetRandomNonce(tcsContext, &auth->NonceOdd))) {
		LogError1("Failed creating random nonce");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

TSS_BOOL
validateReturnAuth(BYTE *secret, BYTE *hash, TPM_AUTH *auth)
{
	BYTE digest[20];
	/* auth is expected to have both nonces and the digest from the TPM */
	memcpy(digest, &auth->HMAC, 20);
	HMAC_Auth(secret, hash, auth);

	return (TSS_BOOL) memcmp(digest, &auth->HMAC, 20);
}

void
HMAC_Auth(BYTE * secret, BYTE * Digest, TPM_AUTH * auth)
{
	UINT16 offset;
	BYTE Blob[61];

	offset = 0;
	Trspi_LoadBlob(&offset, 20, Blob, Digest);
	Trspi_LoadBlob(&offset, 20, Blob, auth->NonceEven.nonce);
	Trspi_LoadBlob(&offset, 20, Blob, auth->NonceOdd.nonce);
	Blob[offset++] = auth->fContinueAuthSession;

	Trspi_HMAC(TSS_HASH_SHA1, 20, secret, offset, Blob, (BYTE *)&auth->HMAC);
}

TSS_RESULT
OSAP_Calc(TCS_CONTEXT_HANDLE tcsContext, UINT16 EntityType, UINT32 EntityValue,
	  BYTE * authSecret, BYTE * usageSecret, BYTE * migSecret,
	  TCPA_ENCAUTH * encAuthUsage, TCPA_ENCAUTH * encAuthMig,
	  BYTE * sharedSecret, TPM_AUTH * auth)
{

	TSS_RESULT rc;
	TCPA_NONCE nonceEvenOSAP;
	UINT16 offset;
	BYTE hmacBlob[0x200];
	BYTE hashBlob[0x200];
	BYTE xorUsageAuth[20];
	BYTE xorMigAuth[20];
	UINT32 i;

	if ((rc = internal_GetRandomNonce(tcsContext, &auth->NonceOdd))) {
		LogError1("Failed creating random nonce");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	auth->fContinueAuthSession = 0x00;

	if ((rc = TCSP_OSAP(tcsContext, EntityType, EntityValue, auth->NonceOdd,
				&auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP))) {
		if (rc == TCPA_E_RESOURCES) {
			int retry = 0;
			do {
				/* POSIX sleep time, { secs, nanosecs } */
				struct timespec t = { 0, AUTH_RETRY_NANOSECS };

				nanosleep(&t, NULL);

				rc = TCSP_OSAP(tcsContext, EntityType, EntityValue, auth->NonceOdd,
						   &auth->AuthHandle, &auth->NonceEven, &nonceEvenOSAP);
			} while (rc == TCPA_E_RESOURCES && ++retry < AUTH_RETRY_COUNT);
		}

		if (rc)
			return rc;
	}

	offset = 0;
	Trspi_LoadBlob(&offset, 20, hmacBlob, nonceEvenOSAP.nonce);
	Trspi_LoadBlob(&offset, 20, hmacBlob, auth->NonceOdd.nonce);

	Trspi_HMAC(TSS_HASH_SHA1, 20, authSecret, offset, hmacBlob, sharedSecret);

	offset = 0;
	Trspi_LoadBlob(&offset, 20, hashBlob, sharedSecret);
	Trspi_LoadBlob(&offset, 20, hashBlob, auth->NonceEven.nonce);

	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, xorUsageAuth);

	offset = 0;
	Trspi_LoadBlob(&offset, 20, hashBlob, sharedSecret);
	Trspi_LoadBlob(&offset, 20, hashBlob, auth->NonceOdd.nonce);
	Trspi_Hash(TSS_HASH_SHA1, offset, hashBlob, xorMigAuth);

	for (i = 0; i < sizeof(TCPA_ENCAUTH); i++)
		encAuthUsage->authdata[i] = usageSecret[i] ^ xorUsageAuth[i];
	for (i = 0; i < sizeof(TCPA_ENCAUTH); i++)
		encAuthMig->authdata[i] = migSecret[i] ^ xorMigAuth[i];

	return TSS_SUCCESS;
}

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
LoadBlob_AUTH(UINT16 * offset, BYTE * blob, TPM_AUTH * auth)
{
	Trspi_LoadBlob_UINT32(offset, auth->AuthHandle, blob);
	Trspi_LoadBlob(offset, 20, blob, auth->NonceOdd.nonce);
	Trspi_LoadBlob_BOOL(offset, auth->fContinueAuthSession, blob);
	Trspi_LoadBlob(offset, 20, blob, (BYTE *)&auth->HMAC);
}

void
UnloadBlob_AUTH(UINT16 * offset, BYTE * blob, TPM_AUTH * auth)
{
	Trspi_UnloadBlob(offset, 20, blob, auth->NonceEven.nonce);
	Trspi_UnloadBlob_BOOL(offset, &auth->fContinueAuthSession, blob);
	Trspi_UnloadBlob(offset, 20, blob, (BYTE *)&auth->HMAC);
}

void
LoadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	Trspi_LoadBlob_UUID(offset, blob, info->keyUUID);
	Trspi_LoadBlob_UUID(offset, blob, info->parentKeyUUID);
	Trspi_LoadBlob(offset, TCPA_DIGEST_SIZE, blob, info->paramDigest.digest);
	LoadBlob_AUTH(offset, blob, &info->authData);
}

void
UnloadBlob_LOADKEY_INFO(UINT16 *offset, BYTE *blob, TCS_LOADKEY_INFO *info)
{
	Trspi_UnloadBlob_UUID(offset, blob, &info->keyUUID);
	Trspi_UnloadBlob_UUID(offset, blob, &info->parentKeyUUID);
	Trspi_UnloadBlob(offset, TCPA_DIGEST_SIZE, info->paramDigest.digest, blob);
	UnloadBlob_AUTH(offset, blob, &info->authData);
}

void
Trspi_LoadBlob_BOUND_DATA(UINT16 * offset, TCPA_BOUND_DATA bd,
		UINT32 payloadLength, BYTE * blob)
{
	Trspi_LoadBlob_TCPA_VERSION(offset, blob, bd.ver);
	Trspi_LoadBlob(offset, 1, blob, &bd.payload);
	Trspi_LoadBlob(offset, payloadLength, blob, bd.payloadData);
}

void
Trspi_LoadBlob_CHANGEAUTH_VALIDATE(UINT16 * offset, BYTE * blob,
		TCPA_CHANGEAUTH_VALIDATE * caValidate)
{
	Trspi_LoadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob, caValidate->newAuthSecret.authdata);
	Trspi_LoadBlob(offset, TCPA_SHA1_160_HASH_LEN, blob, caValidate->n1.nonce);
}


TSS_RESULT
get_tpm_flags(TCS_CONTEXT_HANDLE tcsContext, TSS_HTPM hTPM,
		UINT32 *volFlags, UINT32 *nonVolFlags)
{
	BYTE hashBlob[128];
	TCPA_DIGEST digest;
	TPM_AUTH auth;
	TCPA_VERSION version;
	TSS_RESULT result;
	UINT16 offset;
	TSS_HPOLICY hPolicy;

	if ((result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	/* do an owner authorized get capability call */
	UINT32ToArray(TPM_ORD_GetCapabilityOwner, hashBlob);
	Trspi_Hash(TSS_HASH_SHA1, sizeof(UINT32), hashBlob, digest.digest);

	if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_GetCapabilityOwner,
					      hPolicy, &digest, &auth)))
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

	return obj_policy_validate_auth_oiap(hPolicy, &digest, &auth);
}

TSS_RESULT
get_local_random(TSS_HCONTEXT tspContext, UINT32 size, BYTE **data)
{
	FILE *f = NULL;
	BYTE *buf = NULL;

	LogWarn("Falling back to %s", TSS_LOCAL_RANDOM_DEVICE);

	f = fopen(TSS_LOCAL_RANDOM_DEVICE, "r");
	if (f == NULL) {
		LogError("open of %s failed: %s",
				TSS_LOCAL_RANDOM_DEVICE, strerror(errno));
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	buf = calloc_tspi(tspContext, size);
	if (buf == NULL) {
		LogError("malloc of %u bytes failed", size);
		fclose(f);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if (fread(buf, size, 1, f) == 0) {
		LogError("fread of %s failed: %s", TSS_LOCAL_RANDOM_DEVICE,
				strerror(errno));
		fclose(f);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	fclose(f);
	*data = buf;

	return TSS_SUCCESS;
}

TSS_RESULT
internal_GetCap(TSS_HCONTEXT tspContext, TSS_FLAG capArea, UINT32 subCap,
		UINT32 * respSize, BYTE ** respData)
{
	UINT16 offset = 0;
	TSS_VERSION version = INTERNAL_CAP_TSP_VERSION;

	if (capArea == TSS_TSPCAP_VERSION) {
		*respData = calloc_tspi(tspContext, 4);
		Trspi_LoadBlob_TSS_VERSION(&offset, *respData, version);
		*respSize = offset;
	} else if (capArea == TSS_TSPCAP_ALG) {
		*respSize = 1;
		*respData = calloc_tspi(tspContext, 1);
		switch (subCap) {
			case TSS_ALG_RSA:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_RSA;
				break;
			case TSS_ALG_AES:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_AES;
				break;
			case TSS_ALG_SHA:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_SHA;
				break;
			case TSS_ALG_HMAC:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_HMAC;
				break;
			case TSS_ALG_DES:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_DES;
				break;
			case TSS_ALG_3DES:
				(*respData)[0] = INTERNAL_CAP_TSP_ALG_3DES;
				break;
			default:
				free_tspi(tspContext, *respData);
				return TSPERR(TSS_E_BAD_PARAMETER);
		}
	} else if (capArea == TSS_TSPCAP_PERSSTORAGE) {
		*respData = calloc_tspi(tspContext, 1);
		*respSize = 1;
		(*respData)[0] = INTERNAL_CAP_TSP_PERSSTORAGE;
	} else
		return TSPERR(TSS_E_BAD_PARAMETER);

	return TSS_SUCCESS;
}

TSS_RESULT
Spi_UnloadBlob_STORE_PUBKEY(UINT16 *offset, BYTE *blob, TCPA_STORE_PUBKEY *store)
{

	Trspi_UnloadBlob_UINT32(offset, &store->keyLength, blob);

	if (store->keyLength > 0) {
		store->key = calloc(1, store->keyLength);
		if (store->key == NULL) {
			LogError("malloc of %d bytes failed.", store->keyLength);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, store->keyLength, blob, store->key);
	} else {
		store->key = NULL;
	}

	return TSS_SUCCESS;
}


TSS_RESULT
Spi_UnloadBlob_KEY_PARMS(UINT16 *offset, BYTE *blob, TCPA_KEY_PARMS *keyParms)
{
	Trspi_UnloadBlob_UINT32(offset, &keyParms->algorithmID, blob);
	Trspi_UnloadBlob_UINT16(offset, &keyParms->encScheme, blob);
	Trspi_UnloadBlob_UINT16(offset, &keyParms->sigScheme, blob);
	Trspi_UnloadBlob_UINT32(offset, &keyParms->parmSize, blob);

	if (keyParms->parmSize > 0) {
		keyParms->parms = calloc(1, keyParms->parmSize);
		if (keyParms->parms == NULL) {
			LogError("malloc of %d bytes failed.", keyParms->parmSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, keyParms->parmSize, blob, keyParms->parms);
	} else {
		keyParms->parms = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Spi_UnloadBlob_KEY(UINT16 *offset, BYTE *blob, TCPA_KEY *key)
{
	TSS_RESULT result;

	Trspi_UnloadBlob_TCPA_VERSION(offset, blob, &key->ver);
	Trspi_UnloadBlob_UINT16(offset, &key->keyUsage, blob);
	Trspi_UnloadBlob_KEY_FLAGS(offset, blob, &key->keyFlags);
	key->authDataUsage = blob[(*offset)++];
	LogDebugFn("authDataUsage: 0x%hhx", key->authDataUsage);
	if ((result = Spi_UnloadBlob_KEY_PARMS(offset, (BYTE *)blob, &key->algorithmParms)))
		return result;

	Trspi_UnloadBlob_UINT32(offset, &key->PCRInfoSize, blob);
	if (key->PCRInfoSize > 0) {
		key->PCRInfo = calloc(1, key->PCRInfoSize);
		if (key->PCRInfo == NULL) {
			LogError("malloc of %d bytes failed.", key->PCRInfoSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, key->PCRInfoSize, blob, key->PCRInfo);
	} else {
		key->PCRInfo = NULL;
	}

	if ((result = Spi_UnloadBlob_STORE_PUBKEY(offset, blob, &key->pubKey)))
		return result;

	Trspi_UnloadBlob_UINT32(offset, &key->encSize, blob);
	if (key->encSize > 0) {
		key->encData = calloc(1, key->encSize);
		if (key->encData == NULL) {
			LogError("malloc of %d bytes failed.", key->encSize);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		Trspi_UnloadBlob(offset, key->encSize, blob, key->encData);
	} else {
		key->encData = NULL;
	}

	return result;
}

void
free_key_refs(TCPA_KEY *key)
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

	free(key->PCRInfo);
	key->PCRInfo = NULL;
	key->PCRInfoSize = 0;
}
