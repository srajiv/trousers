
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcsps.h"
#include "tcslog.h"


#define TSS_TPM_RSP_BLOB_AUTH_LEN	(sizeof(TPM_NONCE) + sizeof(TPM_DIGEST) + sizeof(TPM_BOOL))

TSS_RESULT
tpm_rsp_parse(TPM_COMMAND_CODE ordinal, BYTE *b, UINT32 len, ...)
{
	TSS_RESULT result = TSS_SUCCESS;
	UINT64 offset1, offset2;
	va_list ap;

	va_start(ap, len);

	switch (ordinal) {
	/* TPM_BLOB: TPM_CURRENT_TICKS
	 * return: UINT32 *, BYTE ** */
	case TPM_ORD_GetTicks:
	{
		UINT32 *len1 = va_arg(ap, UINT32 *);
		BYTE **blob1 = va_arg(ap, BYTE **);
		va_end(ap);

		if (!len1 || !blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		*blob1 = malloc(sizeof(TPM_CURRENT_TICKS));
		if (*blob1 == NULL) {
			LogError("malloc of %zd bytes failed", sizeof(TPM_CURRENT_TICKS));
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		offset1 = TSS_TPM_TXBLOB_HDR_LEN;
		UnloadBlob(&offset1, sizeof(TPM_CURRENT_TICKS), b, *blob1);
		*len1 = sizeof(TPM_CURRENT_TICKS);

		break;
	}
	/* TPM BLOB: TPM_SYMMETRIC_KEY, optional AUTH, AUTH
	 * return:   UINT32 *, BYTE **, optional AUTH, AUTH */
	case TPM_ORD_ActivateIdentity:
	{
		UINT32 *len1;
		BYTE **blob1;
		TPM_AUTH *auth1, *auth2;

		len1 = va_arg(ap, UINT32 *);
		blob1 = va_arg(ap, BYTE **);
		auth1 = va_arg(ap, TPM_AUTH *);
		auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!len1 || !blob1 || !auth2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		offset1 = offset2 = TSS_TPM_TXBLOB_HDR_LEN;
		UnloadBlob_SYMMETRIC_KEY(&offset1, b, NULL);
		offset1 -= TSS_TPM_TXBLOB_HDR_LEN;

		if ((*blob1 = malloc(offset1)) == NULL) {
			LogError("malloc of %zd bytes failed", (size_t)offset1);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		*len1 = offset1;
		UnloadBlob(&offset2, offset1, b, *blob1);

		if (auth1)
			UnloadBlob_Auth(&offset2, b, auth1);
		UnloadBlob_Auth(&offset2, b, auth2);

		break;
	}
	/* TPM BLOB: TPM_KEY, UINT32, BLOB, optional AUTH, AUTH
	 * return:   UINT32 *, BYTE **, UINT32 *, BYTE **, optional AUTH, AUTH */
	case TPM_ORD_MakeIdentity:
	{
		UINT32 *len1, *len2;
		BYTE **blob1, **blob2;
		TPM_AUTH *auth1, *auth2;

		len1 = va_arg(ap, UINT32 *);
		blob1 = va_arg(ap, BYTE **);
		len2 = va_arg(ap, UINT32 *);
		blob2 = va_arg(ap, BYTE **);
		auth1 = va_arg(ap, TPM_AUTH *);
		auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!len1 || !blob1 || !len2 || !blob2 || !auth2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		offset1 = offset2 = TSS_TPM_TXBLOB_HDR_LEN;
		UnloadBlob_KEY(&offset1, b, NULL);
		offset1 -= TSS_TPM_TXBLOB_HDR_LEN;

		if ((*blob1 = malloc(offset1)) == NULL) {
			LogError("malloc of %zd bytes failed", (size_t)offset1);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		*len1 = offset1;

		UnloadBlob(&offset2, offset1, b, *blob1);

		/* offset2 points to the stuff after the key */
		UnloadBlob_UINT32(&offset2, len2, b);

		if ((*blob2 = malloc(*len2)) == NULL) {
			LogError("malloc of %u bytes failed", *len2);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		UnloadBlob(&offset2, *len2, b, *blob2);

		if (auth1)
			UnloadBlob_Auth(&offset2, b, auth1);
		UnloadBlob_Auth(&offset2, b, auth2);

		break;
	}
	/* 1 UINT32, 1 BLOB, 1 optional AUTH */
	case TPM_ORD_FieldUpgrade:
	case TPM_ORD_CreateWrapKey:
	case TPM_ORD_GetPubKey:
	{
		UINT32 *data_len;
		BYTE **data;
		TPM_AUTH *auth;

		data_len = va_arg(ap, UINT32 *);
		data = va_arg(ap, BYTE **);
		auth = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!data || !data_len) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		if (auth) {
			offset1 = offset2 = len - TSS_TPM_RSP_BLOB_AUTH_LEN;
			UnloadBlob_Auth(&offset1, b, auth);
		} else
			offset2 = len;

		offset1 = TSS_TPM_TXBLOB_HDR_LEN;
		offset2 -= offset1;
		if ((*data = malloc((size_t)offset2)) == NULL) {
			LogError("malloc of %zd bytes failed", (size_t)offset2);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		memcpy(*data, &b[offset1], offset2);
		*data_len = offset2;
		break;
	}
	/* 1 UINT32, 1 optional AUTH */
	case TPM_ORD_LoadKey:
	case TPM_ORD_LoadKey2:
	{
		UINT32 *handle;
		TPM_AUTH *auth;

		handle = va_arg(ap, UINT32 *);
		auth = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!handle) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		if (auth) {
			offset1 = len - TSS_TPM_RSP_BLOB_AUTH_LEN;
			UnloadBlob_Auth(&offset1, b, auth);
		}

		offset1 = TSS_TPM_TXBLOB_HDR_LEN;
		UnloadBlob_UINT32(&offset1, handle, b);
		break;
	}
	/* 1 AUTH */
	case TPM_ORD_ResetLockValue:
	case TPM_ORD_SetRedirection:
	case TPM_ORD_DisableOwnerClear:
	case TPM_ORD_OwnerSetDisable:
	{
		TPM_AUTH *auth = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!auth) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		offset1 = len - TSS_TPM_RSP_BLOB_AUTH_LEN;
		UnloadBlob_Auth(&offset1, b, auth);
		break;
	}
	default:
		LogDebugFn("Unknown ordinal: 0x%x", ordinal);
		result = TCSERR(TSS_E_INTERNAL_ERROR);
		break;
	}

	return result;
}

TSS_RESULT
tpm_rqu_build(TPM_COMMAND_CODE ordinal, UINT64 *outOffset, BYTE *out_blob, ...)
{
	TSS_RESULT result = TCSERR(TSS_E_INTERNAL_ERROR);
	va_list ap;

	DBG_ASSERT(ordinal);
	DBG_ASSERT(outOffset);
	DBG_ASSERT(out_blob);

	va_start(ap, out_blob);

	switch (ordinal) {
	/* 1 UINT32, 1 UINT16, 1 BLOB, 1 UINT32, 1 BLOB, 1 options AUTH, 1 AUTH */
	case TPM_ORD_CreateMigrationBlob:
	{
		UINT32 keyslot1 = va_arg(ap, UINT32);
		UINT16 type1 = va_arg(ap, int);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		UINT32 in_len2 = va_arg(ap, UINT32);
		BYTE *in_blob2 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		TPM_AUTH *auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!in_blob1 || !in_blob2 || !auth2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keyslot1, out_blob);
		LoadBlob_UINT16(outOffset, type1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_UINT32(outOffset, in_len2, out_blob);
		LoadBlob(outOffset, in_len2, out_blob, in_blob2);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 UINT16, 1 20 byte value, 1 UINT16, 1 UINT32, 1 BLOB, 2 AUTHs */
	case TPM_ORD_ChangeAuth:
	{
		UINT32 keyslot1 = va_arg(ap, UINT32);
		UINT16 proto1 = va_arg(ap, int);
		BYTE *digest1 = va_arg(ap, BYTE *);
		UINT16 entity1 = va_arg(ap, int);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		TPM_AUTH *auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!digest1 || !in_blob1 || !auth1 || !auth2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keyslot1, out_blob);
		LoadBlob_UINT16(outOffset, proto1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob_UINT16(outOffset, entity1, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Auth(outOffset, out_blob, auth2);
		LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 2 DIGEST/ENCAUTH's, 1 UINT32, 1 BLOB, 1 optional AUTH, 1 AUTH */
	case TPM_ORD_MakeIdentity:
	{
		BYTE *dig1, *dig2, *blob1;
		UINT32 len1;
		TPM_AUTH *auth1, *auth2;

		dig1 = va_arg(ap, BYTE *);
		dig2 = va_arg(ap, BYTE *);
		len1 = va_arg(ap, UINT32);
		blob1 = va_arg(ap, BYTE *);
		auth1 = va_arg(ap, TPM_AUTH *);
		auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!dig1 || !dig2 || !blob1 || !auth2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, dig1);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, dig2);
		LoadBlob(outOffset, len1, out_blob, blob1);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 3 UINT32's, 1 BLOB, 1 optional AUTH */
	case TPM_ORD_NV_WriteValue:
	case TPM_ORD_NV_WriteValueAuth:
	{
		UINT32 i = va_arg(ap, UINT32);
		UINT32 j = va_arg(ap, UINT32);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!in_blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, i, out_blob);
		LoadBlob_UINT32(outOffset, j, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 3 UINT32's, 1 optional AUTH */
	case TPM_ORD_NV_ReadValue:
	case TPM_ORD_NV_ReadValueAuth:
	case TPM_ORD_SetRedirection:
	{
		UINT32 i = va_arg(ap, UINT32);
		UINT32 j = va_arg(ap, UINT32);
		UINT32 k = va_arg(ap, UINT32);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, i, out_blob);
		LoadBlob_UINT32(outOffset, j, out_blob);
		LoadBlob_UINT32(outOffset, k, out_blob);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 20 byte value, 1 UINT32, 1 BLOB */
	case TPM_ORD_CreateEndorsementKeyPair:
	{
		BYTE *digest1 = va_arg(ap, BYTE *);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		va_end(ap);

		if (!digest1 || !in_blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 20 byte value, 1 UINT32, 1 BLOB, 1 AUTH */
	case TPM_ORD_CreateCounter:
	{
		BYTE *digest1 = va_arg(ap, BYTE *);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!digest1 || !in_blob1 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 BYTE, 1 UINT32, 1 BLOB, 1 UINT32, 1 BLOB, 1 AUTH */
	case TPM_ORD_DAA_Sign:
	case TPM_ORD_DAA_Join:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		BYTE stage1 = va_arg(ap, int);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		UINT32 in_len2 = va_arg(ap, UINT32);
		BYTE *in_blob2 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !in_blob1 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob_BOOL(outOffset, stage1, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_UINT32(outOffset, in_len2, out_blob);
		LoadBlob(outOffset, in_len2, out_blob, in_blob2);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 2 UINT32's, 1 BLOB, 1 UINT32, 1 BLOB, 1 optional AUTH */
	case TPM_ORD_ConvertMigrationBlob:
	case TPM_ORD_SetCapability:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		UINT32 in_len2 = va_arg(ap, UINT32);
		BYTE *in_blob2 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !in_blob1 || !in_blob2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_UINT32(outOffset, in_len2, out_blob);
		LoadBlob(outOffset, in_len2, out_blob, in_blob2);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 2 UINT32's, 1 20 byte value, 2 optional AUTHs */
	case TPM_ORD_CertifyKey:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		UINT32 keySlot2 = va_arg(ap, UINT32);
		BYTE *digest1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		TPM_AUTH *auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !keySlot2 || !digest1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob_UINT32(outOffset, keySlot2, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		if (auth1 && auth2) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, *outOffset, ordinal, out_blob);
		} else if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else if (auth2) {
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 2 UINT32's, 1 BLOB, 1 optional AUTH */
	case TPM_ORD_GetCapability:
	case TPM_ORD_UnBind:
	case TPM_ORD_Sign:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (in_len1 && !in_blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		if (in_len1)
			LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 20 byte value, 1 UINT32, 1 optional BLOB, 1 UINT32, 1 BLOB, 1 AUTH */
	case TPM_ORD_Seal:
	case TPM_ORD_Sealx:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		BYTE *digest1 = va_arg(ap, BYTE *);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		UINT32 in_len2 = va_arg(ap, UINT32);
		BYTE *in_blob2 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !in_blob2 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_UINT32(outOffset, in_len2, out_blob);
		LoadBlob(outOffset, in_len2, out_blob, in_blob2);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 2 UINT32's, 1 BLOB, 1 optional AUTH, 1 AUTH */
	case TPM_ORD_ActivateIdentity:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		TPM_AUTH *auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !in_blob1 || !auth2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 20-byte blob, 1 BLOB, 1 optional AUTH */
	case TPM_ORD_Quote:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		BYTE *digest1 = va_arg(ap, BYTE *);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !digest1 || !in_blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);

		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 2 20-byte blobs, 1 BLOB, 1 AUTH */
	case TPM_ORD_CreateWrapKey:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		BYTE *digest1 = va_arg(ap, BYTE *);
		BYTE *digest2 = va_arg(ap, BYTE *);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !digest1 || !digest2 || !in_blob1 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest2);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 2 BLOBs, 1 optional AUTH */
	case TPM_ORD_NV_DefineSpace:
	case TPM_ORD_LoadManuMaintPub:
	{
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		UINT32 in_len2 = va_arg(ap, UINT32);
		BYTE *in_blob2 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!in_blob1 || !in_blob2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob(outOffset, in_len2, out_blob, in_blob2);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 2 20-byte blobs, 1 optional AUTH */
	case TPM_ORD_TickStampBlob:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		BYTE *digest1 = va_arg(ap, BYTE *);
		BYTE *digest2 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1 || !digest1 || !digest2) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest2);

		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 BLOB */
	case TPM_ORD_ReadManuMaintPub:
	case TPM_ORD_ReadPubek:
	case TPM_ORD_PCR_Reset:
	case TPM_ORD_SetOperatorAuth:
	{
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		va_end(ap);

		if (!in_blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 BLOB, 2 optional AUTHs */
	case TPM_ORD_LoadKey:
	case TPM_ORD_LoadKey2:
	case TPM_ORD_DirWriteAuth:
	case TPM_ORD_CertifySelfTest:
	case TPM_ORD_Unseal:
	case TPM_ORD_Extend:
	case TPM_ORD_StirRandom:
	case TPM_ORD_LoadMaintenanceArchive: /* XXX */
	case TPM_ORD_FieldUpgrade:
	{
		UINT32 val1 = va_arg(ap, UINT32);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		TPM_AUTH *auth2 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (in_len1 && !in_blob1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, val1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		if (auth1 && auth2) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH2_COMMAND, *outOffset, ordinal, out_blob);
		} else if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else if (auth2) {
			LoadBlob_Auth(outOffset, out_blob, auth2);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT16, 1 BLOB, 1 AUTH */
	case TPM_ORD_AuthorizeMigrationKey:
	{
		UINT16 scheme1 = va_arg(ap, int);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!in_blob1 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT16(outOffset, scheme1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT16, 1 UINT32, 1 BLOB, 1 UINT32, 2 BLOBs, 1 AUTH */
	case TPM_ORD_TakeOwnership:
	{
		UINT16 scheme1 = va_arg(ap, int);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		UINT32 in_len2 = va_arg(ap, UINT32);
		BYTE *in_blob2 = va_arg(ap, BYTE *);
		UINT32 in_len3 = va_arg(ap, UINT32);
		BYTE *in_blob3 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!in_blob1 || !in_blob2 || !in_blob3 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT16(outOffset, scheme1, out_blob);
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_UINT32(outOffset, in_len2, out_blob);
		LoadBlob(outOffset, in_len2, out_blob, in_blob2);
		LoadBlob(outOffset, in_len3, out_blob, in_blob3);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 BOOL, 1 20 byte value, 1 optional AUTH */
	case TPM_ORD_GetAuditDigestSigned:
	{
		UINT32 keyslot1 = va_arg(ap, UINT32);
		TSS_BOOL bool1 = va_arg(ap, int);
		BYTE *digest1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!digest1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keyslot1, out_blob);
		LoadBlob_BOOL(outOffset, bool1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);

		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT16, 1 UINT32, 1 20 byte value */
	case TPM_ORD_OSAP:
	{
		UINT16 type1 = va_arg(ap, int);
		UINT32 value1 = va_arg(ap, UINT32);
		BYTE *digest1 = va_arg(ap, BYTE *);
		va_end(ap);

		if (!digest1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT16(outOffset, type1, out_blob);
		LoadBlob_UINT32(outOffset, value1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT16, 1 20 byte value, 1 UINT16, 1 AUTH */
	case TPM_ORD_ChangeAuthOwner:
	{
		UINT16 type1 = va_arg(ap, int);
		BYTE *digest1 = va_arg(ap, BYTE *);
		UINT16 type2 = va_arg(ap, int);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!digest1 || !auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT16(outOffset, type1, out_blob);
		LoadBlob(outOffset, TPM_SHA1_160_HASH_LEN, out_blob, digest1);
		LoadBlob_UINT16(outOffset, type2, out_blob);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 BOOL, 1 AUTH */
	case TPM_ORD_SetOrdinalAuditStatus:
	{
		UINT32 ord1 = va_arg(ap, UINT32);
		TSS_BOOL bool1 = va_arg(ap, int);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, ord1, out_blob);
		LoadBlob_BOOL(outOffset, bool1, out_blob);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 BOOL, 1 optional AUTH */
	case TPM_ORD_OwnerSetDisable:
	case TPM_ORD_PhysicalSetDeactivated:
	case TPM_ORD_CreateMaintenanceArchive:
	case TPM_ORD_SetOwnerInstall:
	{
		TSS_BOOL bool1 = va_arg(ap, int);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_BOOL(outOffset, bool1, out_blob);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 optional AUTH */
	case TPM_ORD_OwnerClear:
	case TPM_ORD_DisablePubekRead:
	case TPM_ORD_GetCapabilityOwner:
	case TPM_ORD_ResetLockValue:
	case TPM_ORD_DisableOwnerClear:
	case TPM_ORD_SetTempDeactivated:
	case TPM_ORD_OIAP:
	case TPM_ORD_OwnerReadPubek:
	case TPM_ORD_SelfTestFull:
	case TPM_ORD_GetTicks:
	case TPM_ORD_GetTestResult:
	case TPM_ORD_KillMaintenanceFeature:
	{
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 optional AUTH */
	case TPM_ORD_OwnerReadInternalPub:
	case TPM_ORD_GetPubKey:
	case TPM_ORD_ReleaseCounterOwner:
	case TPM_ORD_ReleaseCounter:
	case TPM_ORD_IncrementCounter:
	case TPM_ORD_PcrRead:
	case TPM_ORD_DirRead:
	case TPM_ORD_ReadCounter:
	case TPM_ORD_Terminate_Handle:
	case TPM_ORD_GetAuditDigest:
	case TPM_ORD_GetRandom:
	{
		UINT32 i = va_arg(ap, UINT32);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, i, out_blob);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else {
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);
		}

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT16 only */
	case TSC_ORD_PhysicalPresence:
	{
		UINT16 i = va_arg(ap, int);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT16(outOffset, i, out_blob);
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	default:
		LogError("Unknown ordinal: 0x%x", ordinal);
		break;
	}

	return result;
}
