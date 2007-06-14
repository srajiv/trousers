
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"

#define TSS_OPENSSL_ASN1_ERROR	(0xffffffff)

typedef struct tdTSS_BLOB {
	ASN1_INTEGER *		structVersion;
	ASN1_INTEGER *		blobType;
	ASN1_INTEGER *		blobLength;
	ASN1_OCTET_STRING *	blob;
} TSS_BLOB;

ASN1_SEQUENCE(TSS_BLOB) = {
	ASN1_SIMPLE(TSS_BLOB, structVersion, ASN1_INTEGER),
	ASN1_SIMPLE(TSS_BLOB, blobType, ASN1_INTEGER),
	ASN1_SIMPLE(TSS_BLOB, blobLength, ASN1_INTEGER),
	ASN1_SIMPLE(TSS_BLOB, blob, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSS_BLOB)
IMPLEMENT_ASN1_FUNCTIONS(TSS_BLOB)


TSS_RESULT
Tspi_EncodeDER_TssBlob(UINT32 rawBlobSize,		/* in */
			BYTE *rawBlob,			/* in */
			UINT32 blobType,		/* in */
			UINT32 *derBlobSize,		/* in/out */
			BYTE *derBlob)			/* out */
{
	TSS_BLOB *tssBlob = NULL;
	BYTE *encBlob = NULL;
	UINT32 encBlobLen;
	UINT32 tempVal;
	BYTE tempBuf[sizeof(UINT32)];
	int i, j;

	if ((rawBlobSize == 0) || (rawBlob == NULL))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((blobType < TSS_BLOB_TYPE_KEY) || (blobType > TSS_BLOB_TYPE_CMK_BYTE_STREAM))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((*derBlobSize != 0) && (derBlob == NULL))
		return TSPERR(TSS_E_BAD_PARAMETER);

	tssBlob = TSS_BLOB_new();
	if (!tssBlob)
		return TSPERR(TSS_E_OUTOFMEMORY);

	if (ASN1_INTEGER_set(tssBlob->structVersion, TSS_BLOB_STRUCT_VERSION) == 0) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	if (ASN1_INTEGER_set(tssBlob->blobType, blobType) == 0) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	/* The TSS working group has stated that the ASN1_INTEGER representation should
	 * be 4 bytes in length.  OpenSSL uses the shortest length possible so this hack
	 * needs to be done in place of:
	 *   ASN1_INTEGER_set(tssBlob->blobLength, rawBlobSize)
	 */
	tssBlob->blobLength->type = V_ASN1_INTEGER;
	tssBlob->blobLength->length = sizeof(tempBuf);
	tssBlob->blobLength->data = (unsigned char *)OPENSSL_malloc(sizeof(tempBuf) + 1);
	if (!tssBlob->blobLength->data) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	tempVal = rawBlobSize;
	for (i = 0; i < (int)sizeof(tempBuf); i++) {
		tempBuf[i] = tempVal & 0xff;
		tempVal >>= 8;
	}
	for (i = sizeof(tempBuf) - 1, j = 0; i >= 0; i--, j++)
		tssBlob->blobLength->data[j] = tempBuf[i];

	/* end hack */

	if (ASN1_OCTET_STRING_set(tssBlob->blob, rawBlob, rawBlobSize) == 0) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	encBlobLen = i2d_TSS_BLOB(tssBlob, &encBlob);
	if (encBlobLen <= 0) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if (*derBlobSize != 0) {
		if (encBlobLen <= *derBlobSize) {
			memcpy(derBlob, encBlob, encBlobLen);
		}
		else {
			OPENSSL_free(encBlob);
			TSS_BLOB_free(tssBlob);
			return TSPERR(TSS_E_BAD_PARAMETER);
		}
	}

	*derBlobSize = encBlobLen;

	OPENSSL_free(encBlob);
	TSS_BLOB_free(tssBlob);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_DecodeBER_TssBlob(UINT32 berBlobSize,		/* in */
			BYTE *berBlob,			/* in */
			UINT32 *blobType,		/* out */
			UINT32 *rawBlobSize,		/* in/out */
			BYTE *rawBlob)			/* out */
{
	TSS_BLOB *tssBlob = NULL;
	const BYTE *encBlob = berBlob;
	UINT32 encBlobLen = berBlobSize;
	UINT32 decStructVersion, decBlobType, decBlobSize;

	if ((berBlobSize == 0) || (berBlob == NULL))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((*rawBlobSize != 0) && (rawBlob == NULL))
		return TSPERR(TSS_E_BAD_PARAMETER);

	tssBlob = d2i_TSS_BLOB(NULL, &encBlob, encBlobLen);
	if (!tssBlob)
		return TSPERR(TSS_E_INTERNAL_ERROR);

	decStructVersion = ASN1_INTEGER_get(tssBlob->structVersion);
	if (decStructVersion == TSS_OPENSSL_ASN1_ERROR) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	if (decStructVersion > TSS_BLOB_STRUCT_VERSION) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	decBlobType = ASN1_INTEGER_get(tssBlob->blobType);
	if (decBlobType == TSS_OPENSSL_ASN1_ERROR) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}
	if ((decBlobType < TSS_BLOB_TYPE_KEY) || (decBlobType > TSS_BLOB_TYPE_CMK_BYTE_STREAM)) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	decBlobSize = ASN1_INTEGER_get(tssBlob->blobLength);
	if (decBlobSize == TSS_OPENSSL_ASN1_ERROR) {
		TSS_BLOB_free(tssBlob);
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if (*rawBlobSize != 0) {
		if (decBlobSize <= *rawBlobSize) {
			memcpy(rawBlob, tssBlob->blob->data, decBlobSize);
		}
		else {
			TSS_BLOB_free(tssBlob);
			return TSPERR(TSS_E_BAD_PARAMETER);
		}
	}

	*rawBlobSize = decBlobSize;
	*blobType = decBlobType;

	TSS_BLOB_free(tssBlob);

	return TSS_SUCCESS;
}

