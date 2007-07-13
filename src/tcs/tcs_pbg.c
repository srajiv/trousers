
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
#include "spi_internal_types.h"
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
		//LoadBlob_UINT32(outOffset, len1, out_blob);
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
	/* 3 UINT32's, 1 AUTH */
	case TPM_ORD_SetRedirection:
	{
		UINT32 i, j, k;
		TPM_AUTH *auth1;

		i = va_arg(ap, UINT32);
		j = va_arg(ap, UINT32);
		k = va_arg(ap, UINT32);
		auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, i, out_blob);
		LoadBlob_UINT32(outOffset, j, out_blob);
		LoadBlob_UINT32(outOffset, k, out_blob);
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
	/* 2 UINT32's, 1 BLOB, 1 optional AUTH */
	case TPM_ORD_LoadKey:
	case TPM_ORD_LoadKey2:
	{
		UINT32 keySlot1 = va_arg(ap, UINT32);
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!keySlot1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, keySlot1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		if (auth1) {
			LoadBlob_Auth(outOffset, out_blob, auth1);
			LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);
		} else
			LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 UINT32, 1 BLOB, 1 AUTH */
	case TPM_ORD_FieldUpgrade:
	{
		UINT32 in_len1 = va_arg(ap, UINT32);
		BYTE *in_blob1 = va_arg(ap, BYTE *);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_UINT32(outOffset, in_len1, out_blob);
		LoadBlob(outOffset, in_len1, out_blob, in_blob1);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 BOOL only */
	case TPM_ORD_SetOwnerInstall:
	case TPM_ORD_PhysicalSetDeactivated:
	{
		TSS_BOOL state = va_arg(ap, int);
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_BOOL(outOffset, state, out_blob);
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 BOOL, 1 AUTH */
	case TPM_ORD_OwnerSetDisable:
	{
		TSS_BOOL state = va_arg(ap, int);
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_BOOL(outOffset, state, out_blob);
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	/* 1 AUTH only */
	case TPM_ORD_ResetLockValue:
	case TPM_ORD_DisableOwnerClear:
	{
		TPM_AUTH *auth1 = va_arg(ap, TPM_AUTH *);
		va_end(ap);

		if (!auth1) {
			LogError("Internal error for ordinal 0x%x", ordinal);
			break;
		}

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_Auth(outOffset, out_blob, auth1);
		LoadBlob_Header(TPM_TAG_RQU_AUTH1_COMMAND, *outOffset, ordinal, out_blob);

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
	/* No data, just an ordinal */
	case TPM_ORD_SetTempDeactivated:
	case TPM_ORD_DisableForceClear:
	case TPM_ORD_ForceClear:
	case TPM_ORD_PhysicalDisable:
	case TPM_ORD_PhysicalEnable:
	{
		va_end(ap);

		*outOffset += TSS_TPM_TXBLOB_HDR_LEN;
		LoadBlob_Header(TPM_TAG_RQU_COMMAND, *outOffset, ordinal, out_blob);

		result = TSS_SUCCESS;
		break;
	}
	default:
		LogDebugFn("Unknown ordinal: 0x%x", ordinal);
		break;
	}

	return result;
}
