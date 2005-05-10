
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _TROUSERS_H_
#define _TROUSERS_H_

#include <tss/tcpa_types.h>

/*
 * Utility functions offered by trousers for use in your TSS app.
 *
 * All functions prefixed by Trspi_ are specific to the trousers TSS and
 * should not be used in applications that are intended to be portable.
 *
 */

/* Blob unloading functions */
void       Trspi_UnloadBlob(UINT16 *offset, UINT32 size, BYTE *container, BYTE *object);
void       Trspi_UnloadBlob_BYTE(UINT16 *offset, BYTE *dataOut, BYTE *blob);
void       Trspi_UnloadBlob_BOOL(UINT16 *offset, BOOL *dataOut, BYTE *blob);
void       Trspi_UnloadBlob_UINT32(UINT16 *offset, UINT32 *out, BYTE *blob);
void       Trspi_UnloadBlob_UINT16(UINT16 *offset, UINT16 *out, BYTE *blob);
void       Trspi_UnloadBlob_TSS_VERSION(UINT16 *offset, BYTE *blob, TSS_VERSION *out);
void       Trspi_UnloadBlob_TCPA_VERSION(UINT16 *offset, BYTE *blob, TCPA_VERSION *out);
TSS_RESULT Trspi_UnloadBlob_PCR_INFO(TCS_CONTEXT_HANDLE hContext, UINT16 *offset, BYTE *blob, TCPA_PCR_INFO *pcr);
TSS_RESULT Trspi_UnloadBlob_PCR_SELECTION(TCS_CONTEXT_HANDLE, UINT16 *offset, BYTE *blob, TCPA_PCR_SELECTION *pcr);
TSS_RESULT Trspi_UnloadBlob_STORED_DATA(TCS_CONTEXT_HANDLE, UINT16 *offset, BYTE *blob, TCPA_STORED_DATA *data);
void       Trspi_UnloadBlob_KEY_FLAGS(UINT16 *offset, BYTE *blob, TCPA_KEY_FLAGS *flags);
TSS_RESULT Trspi_UnloadBlob_KEY_PARMS(TCS_CONTEXT_HANDLE, UINT16 *offset, BYTE *blob, TCPA_KEY_PARMS *keyParms);
void       Trspi_UnloadBlob_UUID(UINT16 *offset, BYTE *blob, TSS_UUID *uuid);
TSS_RESULT Trspi_UnloadBlob_KEY(TCS_CONTEXT_HANDLE, UINT16 *offset, BYTE *blob, TCPA_KEY *key);
TSS_RESULT Trspi_UnloadBlob_STORE_PUBKEY(TSS_HCONTEXT, UINT16 *, BYTE *, TCPA_STORE_PUBKEY *);
void       Trspi_UnloadBlob_TCPA_EVENT_CERT(UINT16 *offset, BYTE *blob, TCPA_EVENT_CERT *cert);
void       Trspi_UnloadBlob_DIGEST(UINT16 *offset, BYTE *blob, TCPA_DIGEST digest);
TSS_RESULT Trspi_UnloadBlob_PUBKEY(TCS_CONTEXT_HANDLE, UINT16 *offset, BYTE *blob, TCPA_PUBKEY *pubKey);
TSS_RESULT Trspi_UnloadBlob_KEY(TSS_HCONTEXT, UINT16 * offset, BYTE * blob, TCPA_KEY * key);
void       Trspi_UnloadBlob_MigrationKeyAuth(TSS_HCONTEXT, UINT16 * offset, TCPA_MIGRATIONKEYAUTH * migAuth, BYTE * blob);
TSS_RESULT Trspi_UnloadBlob_PCR_EVENT(UINT16 *offset, BYTE *blob, TSS_PCR_EVENT *event);
void       Trspi_UnloadBlob_KM_KEYINFO(UINT16 *offset, BYTE *blob, TSS_KM_KEYINFO *info);

/* Blob loading functions */
void Trspi_LoadBlob(UINT16 *offset, UINT32 size, BYTE *container, BYTE *object);
void Trspi_LoadBlob_UINT32(UINT16 *offset, UINT32 in, BYTE *blob);
void Trspi_LoadBlob_UINT16(UINT16 *offset, UINT16 in, BYTE *blob);
void Trspi_LoadBlob_BYTE(UINT16 *offset, BYTE data, BYTE *blob);
void Trspi_LoadBlob_BOOL(UINT16 *offset, BOOL data, BYTE *blob);
void Trspi_LoadBlob_RSA_KEY_PARMS(UINT16 *offset, BYTE *blob, TCPA_RSA_KEY_PARMS *parms);
void Trspi_LoadBlob_BOUND_DATA(UINT16 *offset, TCPA_BOUND_DATA bd, UINT32 payloadLength, BYTE *blob);
void Trspi_LoadBlob_TSS_VERSION(UINT16 *offset, BYTE *blob, TSS_VERSION version);
void Trspi_LoadBlob_TCPA_VERSION(UINT16 *offset, BYTE *blob, TCPA_VERSION version);
void Trspi_LoadBlob_PCR_INFO(UINT16 *offset, BYTE *blob, TCPA_PCR_INFO *pcr);
void Trspi_LoadBlob_PCR_SELECTION(UINT16 *offset, BYTE *blob, TCPA_PCR_SELECTION pcr);
void Trspi_LoadBlob_STORED_DATA(UINT16 *offset, BYTE *blob, TCPA_STORED_DATA *data);
void Trspi_LoadBlob_KEY(UINT16 *offset, BYTE *blob, TCPA_KEY *key);
void Trspi_LoadBlob_KEY_FLAGS(UINT16 *offset, BYTE *blob, TCPA_KEY_FLAGS *flags);
void Trspi_LoadBlob_KEY_PARMS(UINT16 *offset, BYTE *blob, TCPA_KEY_PARMS *keyInfo);
void Trspi_LoadBlob_STORE_PUBKEY(UINT16 *offset, BYTE *blob, TCPA_STORE_PUBKEY *store);
void Trspi_LoadBlob_UUID(UINT16 *offset, BYTE *blob, TSS_UUID uuid);
void Trspi_LoadBlob_PUBKEY(UINT16 *offset, BYTE *blob, TCPA_PUBKEY pubKey);
void Trspi_LoadBlob_CERTIFY_INFO(UINT16 *offset, BYTE *blob, TCPA_CERTIFY_INFO *certify);
void Trspi_LoadBlob_STORE_ASYMKEY(UINT16 *offset, BYTE *blob, TCPA_STORE_ASYMKEY *store);
void Trspi_LoadBlob_CHANGEAUTH_VALIDATE(UINT16 *offset, BYTE *blob, TCPA_CHANGEAUTH_VALIDATE *caValidate);
void Trspi_LoadBlob_PCR_EVENT(UINT16 *offset, BYTE *blob, TSS_PCR_EVENT *event);
void Trspi_LoadBlob_PRIVKEY_DIGEST(UINT16 * offset, BYTE * blob, TCPA_KEY *key);


/* Cryptographic functions */

#define SHA1_HASH_SIZE		20

/* Hash @BufSize bytes at location @Buf using the algorithm @HashType.  Currently only
 * TSS_HASH_SHA1 is a suported type, so 20 bytes will be written to @Digest */
TCPA_RESULT Trspi_Hash(UINT32 HashType, UINT32 BufSize, BYTE *Buf, BYTE *Digest);

UINT32 Trspi_HMAC(UINT32 HashType, UINT32 SecretSize, BYTE*Secret, UINT32 BufSize, BYTE*Buf, BYTE*hmacOut);

/* RSA encrypt @dataToEncryptLen bytes at location @dataToEncrypt using public key
 * @publicKey of size @keysize. This data will be encrypted using OAEP padding in
 * the openssl library using the OAEP padding parameter "TCPA".  This will allow
 * data encrypted with this function to be decrypted by a TPM using non-legacy keys */
int Trspi_RSA_Encrypt(unsigned char *dataToEncrypt,
		unsigned int dataToEncryptLen,
		unsigned char *encryptedData,
		unsigned int *encryptedDataLen,
		unsigned char *publicKey,
		unsigned int keysize);

int Trspi_Verify( UINT32 HashType, BYTE *pHash, UINT32 iHashLength,
		unsigned char *pModulus, int iKeyLength,
		BYTE *pSignature, UINT32 sig_len);


/* RSA encrypt @dataToEncryptLen bytes at location @dataToEncrypt using public key
 * @publicKey of size @keysize. This data will be encrypted using PKCS#1.5 padding in
 * the openssl library.  This function is intended to be used with legacy keys. */
int Trspi_RSA_PKCS15_Encrypt(unsigned char *dataToEncrypt,
			unsigned int dataToEncryptLen,
			unsigned char *encryptedData,
			unsigned int *encryptedDataLen,
			unsigned char *publicKey,
			unsigned int keysize);
#endif
