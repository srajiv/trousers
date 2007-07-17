
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

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "obj.h"
#include "tsplog.h"
#include "tsp_seal.h"

TSS_RESULT
sealx_mask_cb(UINT32 sharedSecretLen,
	      BYTE *sharedSecret,
	      UINT32 ulSizeNonces,
	      BYTE *rgbNonceEvenOSAP,
	      BYTE *rgbNonceOddOSAP,
	      UINT32 ulDataLength,
	      BYTE *rgbDataToMask,
	      BYTE *rgbMaskedData)
{
	UINT32 mgf1SeedLen;
	BYTE *mgf1Seed, *mgf1Buffer;
	UINT32 i;
	TSS_RESULT result;

	mgf1SeedLen = (ulSizeNonces * 2) + strlen("XOR") + sharedSecretLen;
	if ((mgf1Seed = (BYTE *)calloc(1, mgf1SeedLen)) == NULL) {
		LogError("malloc of %u bytes failed.", mgf1SeedLen);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	mgf1Buffer = mgf1Seed;
	memcpy(mgf1Buffer, rgbNonceEvenOSAP, ulSizeNonces);
	mgf1Buffer += ulSizeNonces;
	memcpy(mgf1Buffer, rgbNonceOddOSAP, ulSizeNonces);
	mgf1Buffer += ulSizeNonces;
	memcpy(mgf1Buffer, "XOR", strlen("XOR"));
	mgf1Buffer += strlen("XOR");
	memcpy(mgf1Buffer, sharedSecret, sharedSecretLen);

	if ((result = Trspi_MGF1(TSS_HASH_SHA1, mgf1SeedLen, mgf1Seed, ulDataLength, rgbMaskedData)))
		goto done;

	for (i = 0; i < ulDataLength; i++)
		rgbMaskedData[i] ^= rgbDataToMask[i];

done:
	free(mgf1Seed);

	return result;
}

