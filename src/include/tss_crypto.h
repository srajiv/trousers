
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _TSS_CRYPTO_H_
#define _TSS_CRYPTO_H_

TCPA_RESULT
TSS_Hash(UINT32 HashType, UINT32 BufSize, BYTE * Buf, BYTE * Digest);

UINT32
TSS_HMAC(UINT32 HashType, UINT32 SecretSize, BYTE* Secret, UINT32 BufSize, BYTE* Buf, BYTE* hmacOut);

int TSS_RSA_Encrypt(unsigned char *dataToEncrypt,
		unsigned int dataToEncryptLen,
		unsigned char *encryptedData,
		unsigned int *encryptedDataLen,
		unsigned char *publicKey,
		unsigned int keysize);

int TSS_Verify( UINT32 HashType, BYTE *pHash, UINT32 iHashLength,
		unsigned char *pModulus, int iKeyLength,
		BYTE *pSignature, UINT32 sig_len);


int TSS_RSA_PKCS15_Encrypt(unsigned char *dataToEncrypt,
			unsigned int dataToEncryptLen,
			unsigned char *encryptedData,
			unsigned int *encryptedDataLen,
			unsigned char * publicKey,
			unsigned int keysize);
#endif
