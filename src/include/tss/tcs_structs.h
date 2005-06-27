/*++

  TSS Core Service structures

*/

#ifndef __TCS_STRUCT_H__
#define __TCS_STRUCT_H__

// Errata: This should be named TSS_AUTH to avoid confussion with TPM structures
typedef struct tdTPM_AUTH
{
	TCS_AUTHHANDLE  AuthHandle;
	TCPA_NONCE   NonceOdd;   // system
	TCPA_NONCE   NonceEven;   // TPM
	TSS_BOOL   fContinueAuthSession;
	TCPA_AUTHDATA    HMAC;
} TPM_AUTH;


typedef struct tdTCS_LOADKEY_INFO
{
	TSS_UUID   keyUUID;
	TSS_UUID   parentKeyUUID;
	TCPA_DIGEST   paramDigest; // SHA1 digest of the TPM_LoadKey
	// Command input parameters
	// As defined in TCPA Main
	// Specification
	TPM_AUTH   authData;  // Data regarding a valid auth
	// Session including the
	// HMAC digest
} TCS_LOADKEY_INFO;

#endif // __TCS_STRUCT_H__

