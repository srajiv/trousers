
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

/*
 * crypto.c - openssl TSS crypto routines
 *
 * Kent Yoder <shpedoikal@gmail.com>
 *
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"


/*
 * Hopefully this will make the code clearer since
 * OpenSSL returns 1 on success
 */
#define EVP_SUCCESS 1

TSS_RESULT
Trspi_Hash(UINT32 HashType, UINT32 BufSize, BYTE* Buf, BYTE* Digest)
{
	EVP_MD_CTX md_ctx;
	unsigned int result_size;
	int rv;

	switch (HashType) {
		case TSS_HASH_SHA1:
			rv = EVP_DigestInit(&md_ctx, EVP_sha1());
			break;
		default:
			rv = TSS_E_BAD_PARAMETER;
			goto out;
			break;
	}

	if (rv != EVP_SUCCESS) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	rv = EVP_DigestUpdate(&md_ctx, Buf, BufSize);
	if (rv != EVP_SUCCESS) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	result_size = EVP_MD_CTX_size(&md_ctx);
	rv = EVP_DigestFinal(&md_ctx, Digest, &result_size);
	if (rv != EVP_SUCCESS) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	} else
		rv = TSS_SUCCESS;

	goto out;

err:
	ERR_load_crypto_strings();
	/* XXX Log something here instead */
	ERR_print_errors_fp(stderr);
out:
        return rv;
}

UINT32
Trspi_HMAC(UINT32 HashType, UINT32 SecretSize, BYTE* Secret, UINT32 BufSize, BYTE* Buf, BYTE* hmacOut)
{
	/*HMAC_CTX hmac_ctx;*/
	const EVP_MD *md;
	unsigned int len;
	int rv = TSS_SUCCESS;

	switch (HashType) {
		case TSS_HASH_SHA1:
			md = EVP_sha1();
			break;
		default:
			rv = TSS_E_BAD_PARAMETER;
			goto out;
			break;
	}

	len = EVP_MD_size(md);

	HMAC(md, Secret, SecretSize, Buf, BufSize, hmacOut, &len);
out:
	return rv;
}

/* XXX int set to unsigned int values */
int
Trspi_RSA_Encrypt(unsigned char *dataToEncrypt, /* in */
		unsigned int dataToEncryptLen,  /* in */
		unsigned char *encryptedData,   /* out */
		unsigned int *encryptedDataLen, /* out */
		unsigned char *publicKey,
		unsigned int keysize)
{
	int rv;
	unsigned char exp[] = { 0x01, 0x00, 0x01 }; /* 65537 hex */
	unsigned char oaepPad[] = "TCPA";
	int oaepPadLen = 4;
	RSA *rsa = RSA_new();
	BYTE encodedData[256];
	int encodedDataLen;

	if (rsa == NULL) {
		rv = TSS_E_OUTOFMEMORY;
		goto err;
	}

	/* set the public key value in the OpenSSL object */
	rsa->n = BN_bin2bn(publicKey, keysize, rsa->n);
	/* set the public exponent */
	rsa->e = BN_bin2bn(exp, sizeof(exp), rsa->e);

	if (rsa->n == NULL || rsa->e == NULL) {
		rv = TSS_E_OUTOFMEMORY;
		goto err;
	}

	/* padding constraint for PKCS#1 OAEP padding */
	if ((int)dataToEncryptLen >= (RSA_size(rsa) - ((2 * SHA_DIGEST_LENGTH) + 1))) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	encodedDataLen = MIN(RSA_size(rsa), 256);

	/* perform our OAEP padding here with custom padding parameter */
	rv = RSA_padding_add_PKCS1_OAEP(encodedData, encodedDataLen, dataToEncrypt,
			dataToEncryptLen, oaepPad, oaepPadLen);
	if (rv != EVP_SUCCESS) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	/* call OpenSSL with no additional padding */
	rv = RSA_public_encrypt(encodedDataLen, encodedData,
				encryptedData, rsa, RSA_NO_PADDING);
	if (rv == -1) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	/* RSA_public_encrypt returns the size of the encrypted data */
	*encryptedDataLen = rv;
	rv = TSS_SUCCESS;
	goto out;

err:
	ERR_load_crypto_strings();
	/* XXX Log something here instead */
	ERR_print_errors_fp(stderr);
out:
	if (rsa)
		RSA_free(rsa);
        return rv;
}

TSS_RESULT
Trspi_Verify(UINT32 HashType, BYTE *pHash, UINT32 iHashLength,
	   unsigned char *pModulus, int iKeyLength,
	   BYTE *pSignature, UINT32 sig_len)
{
	int rv, nid;
	unsigned char exp[] = { 0x01, 0x00, 0x01 }; /* 65537 hex */
	unsigned char buf[256];
	RSA *rsa = RSA_new();

	if (rsa == NULL) {
		rv = TSS_E_OUTOFMEMORY;
		goto err;
	}

	/* We assume we're verifying data from a TPM, so there are only
	 * two options, SHA1 data and PKCSv1.5 encoded signature data.
	 */
	switch (HashType) {
		case TSS_HASH_SHA1:
			nid = NID_sha1;
			break;
		case TSS_HASH_OTHER:
			nid = NID_undef;
			break;
		default:
			rv = TSS_E_BAD_PARAMETER;
			goto out;
			break;
	}

	/* set the public key value in the OpenSSL object */
	rsa->n = BN_bin2bn(pModulus, iKeyLength, rsa->n);
	/* set the public exponent */
	rsa->e = BN_bin2bn(exp, sizeof(exp), rsa->e);

	if (rsa->n == NULL || rsa->e == NULL) {
		rv = TSS_E_OUTOFMEMORY;
		goto err;
	}

	/* if we don't know the structure of the data we're verifying, do a public decrypt
	 * and compare menually. If we know we're looking for a SHA1 hash, allow OpenSSL
	 * to do the work for us.
	 */
	if (nid == NID_undef) {
		rv = RSA_public_decrypt(sig_len, pSignature, buf, rsa, RSA_PKCS1_PADDING);
		if (rv != (int)iHashLength) {
			rv = TSS_E_FAIL;
		} else if (memcmp(pHash, buf, iHashLength)) {
			rv = TSS_E_FAIL;
		}
	} else {
		if ((rv = RSA_verify(nid, pHash, iHashLength, pSignature, sig_len, rsa)) == 0) {
			rv = TSS_E_FAIL;
			goto out;
		}
	}

	rv = TSS_SUCCESS;
	goto out;

err:
	ERR_load_crypto_strings();
	/* XXX Log something here instead */
	ERR_print_errors_fp(stderr);

out:
	if (rsa)
		RSA_free(rsa);
        return rv;
}

/* No need to call the tss version of RSA_public_encrypt here, since
 * we're using PKCS 1.5 padding
 */

TSS_RESULT
Trspi_RSA_PKCS15_Encrypt(unsigned char *dataToEncrypt,
                       unsigned int dataToEncryptLen,
                       unsigned char *encryptedData,
                       unsigned int *encryptedDataLen,
                       unsigned char * publicKey,
                       unsigned int keysize) /* BYTE* seed); this seed must be 256 - 11 */
{
	int rv;
	unsigned char exp[] = { 0x01, 0x00, 0x01 }; /* 65537 hex */
	RSA *rsa = RSA_new();

	if (rsa == NULL) {
		rv = TSS_E_OUTOFMEMORY;
		goto err;
	}

	/* set the public key value in the OpenSSL object */
	rsa->n = BN_bin2bn(publicKey, keysize, rsa->n);
	/* set the public exponent */
	rsa->e = BN_bin2bn(exp, sizeof(exp), rsa->e);

	if (rsa->n == NULL || rsa->e == NULL) {
		rv = TSS_E_OUTOFMEMORY;
		goto err;
	}

	/* XXX (CAST TO UNSIGNED) XXX  padding constraint for PKCS#1 v1.5 padding */
	if ((int)dataToEncryptLen > (RSA_size(rsa) - 11)) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	rv = RSA_public_encrypt(dataToEncryptLen, dataToEncrypt,
				encryptedData, rsa, RSA_PKCS1_PADDING);
	if (rv == -1) {
		rv = TSS_E_INTERNAL_ERROR;
		goto err;
	}

	/* RSA_public_encrypt returns the size of the encrypted data */
	*encryptedDataLen = rv;
	rv = TSS_SUCCESS;
	goto out;

err:
	ERR_load_crypto_strings();
	/* XXX Log something here instead */
	ERR_print_errors_fp(stderr);
out:
	if (rsa)
		RSA_free(rsa);
        return rv;
}
