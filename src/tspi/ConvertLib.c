
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

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "tss_crypto.h"
#include "obj.h"

#include "atmel.h"

/*******************************************
 *	ConvertLib_xxx
 *		These funcs are TSPI exported functions to 
 *			make commonly used conversions available to app
 *			writers.
 ******************************************/

#if 0
TSS_RESULT
ConvertLib_Blob_TcpaKey(TSS_HCONTEXT context, BYTE * blob, TCPA_KEY * key)
{
	UINT16 offset;
	TCS_CONTEXT_HANDLE tcsContext;

	if (internal_GetContextForContextObject(context, &tcsContext))
		return TSS_E_INTERNAL_ERROR;

	offset = 0;
	UnloadBlob_KEY(tcsContext, &offset, blob, key);

	return TSS_SUCCESS;
}

TSS_RESULT
ConvertLib_TcpaKey_Blob(TCPA_KEY key, UINT32 * size, BYTE * blob)
{
	UINT16 offset;

	offset = 0;
	LoadBlob_KEY(&offset, blob, &key);
	*size = offset;

	return TSS_SUCCESS;
}

TSS_RESULT
IBM_Tspi_SetPopupMesssage_SBCS(TSS_HPOLICY hPolicy, char *message)
{
	TSS_RESULT result;
	BYTE tempMessage[256];
	UINT32 size;

	size = StringToUnicodeArray(message, tempMessage);
	if (size == 0)
		return TSS_E_BAD_PARAMETER;

	result =
	    Tspi_SetAttribData(hPolicy, TSS_TSPATTRIB_POLICY_POPUPSTRING, 0, size, tempMessage);

	return result;
}

TSS_RESULT
IBM_Tspi_SetPopupMesssage_WCHAR(TSS_HPOLICY hPolicy, UNICODE * message)
{
	TSS_RESULT result;
	BYTE tempMessage[256];
	UINT32 size;

	size = UnicodeToArray(tempMessage, message);
	if (size == 0)
		return TSS_E_BAD_PARAMETER;

	result =
	    Tspi_SetAttribData(hPolicy, TSS_TSPATTRIB_POLICY_POPUPSTRING, 0, size, tempMessage);

	return result;
}
#endif

/********************************************
 *	Atmel_Tspi_xxx
 *		These are functions exported outside of the
 *		TSS spec that are TPM Specific commands
 ********************************************/

TSS_RESULT
Atmel_Tspi_SetState(TSS_HTPM hTPM, BOOL fOwnerAuth, BYTE stateID, UINT32 stateData)
{				/* UINT32 sizeState, BYTE* stateValue ) */
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	TCS_AUTH ownerAuth;
	TCPA_DIGEST digest;
	TSS_HPOLICY hOwnerPolicy;
	UINT16 offset;
	BYTE hashBlob[1024];
	UINT32 sizeState;
	BYTE stateValue[128];

	if ((result = obj_isConnected_1(hTPM, &tcsContext)))
		return result;

	/* ---  Convert the stateData to something meaningful */
	switch (stateID) {
	case ATMEL_STATE_ID_TPM_IO_A:
	case ATMEL_STATE_ID_TPM_IO_B:
	case ATMEL_STATE_ID_TPM_IO_C:
	case ATMEL_STATE_ID_BATTERY:
	case ATMEL_STATE_ID_FAILMOD:
	case ATMEL_STATE_ID_FIPS:
	case ATMEL_STATE_ID_EN_SETSTATE:
	case ATMEL_STATE_ID_TPM_CONFIG:
		sizeState = 1;
		stateValue[0] = (BYTE) stateData;
		break;

	case ATMEL_STATE_ID_FAILCOUNT:
		sizeState = 2;
		UINT16ToArray((UINT16) stateData, stateValue);
		break;

/* 	case ATMEL_STATE_ID_EXTAMPER: */
/* 	case ATMEL_STATE_ID_INTAMPER: */
/* 	case ATMEL_STATE_ID_CODEREV: */
	default:
		return TSS_E_BAD_PARAMETER;

	}

	/* ---  Check if we should call OwnerSetState or just SetState */

	if (fOwnerAuth) {
		if ((result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hOwnerPolicy)))
			return result;

		/* ---  Do theAuth */
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_OwnerSetState, hashBlob);
		LoadBlob_BYTE(&offset, stateID, hashBlob);
		LoadBlob_UINT32(&offset, sizeState, hashBlob);
		LoadBlob(&offset, sizeState, hashBlob, stateValue);

		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hOwnerPolicy, digest, &ownerAuth)))
			return result;

		/* ---  Send Command */
		if ((result = Atmel_TPM_OwnerSetState(tcsContext, stateID, sizeState, stateValue, &ownerAuth)))
			return result;

		/* ---  Validate Auth */
		offset = 0;
		LoadBlob_UINT32(&offset, result, hashBlob);
		LoadBlob_UINT32(&offset, TPM_ORD_OwnerSetState, hashBlob);

		TSS_Hash(TSS_HASH_SHA1, offset, hashBlob, digest.digest);

		if ((result = secret_ValidateAuth_OIAP(hOwnerPolicy, digest, &ownerAuth)))
			return result;

	} else {
		if ((result = Atmel_TPM_SetState(tcsContext, stateID, sizeState, stateValue)))
			return result;
	}
	return TSS_SUCCESS;
}

TSS_RESULT
Atmel_Tspi_GetState(TSS_HCONTEXT hContext, BYTE stateID, UINT32 * sizeState, BYTE ** stateValue)
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if ((result = obj_isConnected_1(hContext, &tcsContext)))
		return result;

	return Atmel_TPM_GetState(tcsContext, stateID, sizeState, stateValue);
}

/* -------------------------------------------------------------------------------------- */
#define CHIP_VENDOR_UNKNOWN 0
#define CHIP_VENDOR_ATMEL 1
#define CHIP_VENDOR_NATL 2
#define CHIP_VENDOR_IFX 3

#define TCS_VENDOR_UNKNOWN 0
#define TCS_VENDOR_IBM 1

BOOL firstVendorCheck = 1;
UINT32
internal_getChipVendor(TSS_HCONTEXT hContext)
{
	static UINT16 vendor;
	UINT32 respSize;
	BYTE *resp;
	BYTE subCap[4];
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if (firstVendorCheck == 0)
		return vendor;

	if ((result = obj_isConnected_1(hContext, &tcsContext)))
		return result;

	UINT32ToArray(TCPA_CAP_PROP_MANUFACTURER, subCap);
	if ((result = TCSP_GetCapability(tcsContext, TCPA_CAP_PROPERTY, 4, subCap, &respSize, &resp)))
		return 0;

	if (!memcmp(resp, "ATML", 4))
		vendor = CHIP_VENDOR_ATMEL;
	else if (!memcmp(resp, "NSM", 3))
		vendor = CHIP_VENDOR_NATL;
	else if (!memcmp(resp, "IFX", 3))
		vendor = CHIP_VENDOR_IFX;
	else
		vendor = CHIP_VENDOR_UNKNOWN;

	TCS_FreeMemory(tcsContext, resp);

	firstVendorCheck = 0;
	return vendor;
}

BOOL firstTCSVendorCheck = 1;
UINT32
internal_getTCSVendor(TSS_HCONTEXT hContext)
{
	static UINT16 vendor;
	UINT32 respSize;
	BYTE *resp;
/* 	BYTE subCap[4]; */
	TCPA_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

/* 	return TCS_VENDOR_IBM;	//for now */
	LogDebug1("getTCSVendor");
	if (firstTCSVendorCheck == 0) {
		LogDebug1("Already got vendor");
		return vendor;
	}

	if ((result = obj_isConnected_1(hContext, &tcsContext)))
		return result;

/* 	UINT32ToArray( TSS_TCSCAP_MANUFACTURER, subCap ); */
	if ((result = TCS_GetCapability(tcsContext, TSS_TCSCAP_MANUFACTURER, 0, NULL, &respSize, &resp)))
		return 0;

	if (!memcmp(resp, "IBM", 3)) {
		LogDebug1("TCS Vendor is IBM");
		vendor = TCS_VENDOR_IBM;
	} else {
		LogDebug("TCS Vendor is Unknown( %c%c%c%c )",
			   resp[0], resp[1], resp[2], resp[3]);
		vendor = TCS_VENDOR_UNKNOWN;
	}

	TCS_FreeMemory(tcsContext, resp);

	firstTCSVendorCheck = 0;
	LogDebug1("Leaving TCS Vendor check");
	return vendor;
/* 	return TCS_VENDOR_IBM; */
}

TSS_RESULT
ConvertLib_UINT32ToArray(UINT32 in, BYTE * out)
{
	UINT32ToArray(in, out);
	return 0;
}

/* ---	Call this to see if the chip has an owner */
TSS_RESULT
IBM_Tspi_CheckOwnerInstalled(TSS_HCONTEXT hContext, BOOL * hasOwner)
{
/* 	UINT32 keySize; */
/* 	BYTE*	keyBlob; */
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
/* 	TCS_AUTH bsAuth; */
	TCS_AUTHHANDLE authHandle;
	TCPA_NONCE nonce0 = { { 0 } }, nonce1 = { { 0 } };
	UINT32 vendor;

	if (internal_getTCSVendor(hContext) != TCS_VENDOR_IBM)
		return TSS_E_NOTIMPL;

	if ((result = obj_isConnected_1(hContext, &tcsContext)))
		return result;

	/* ---  First check for an owner in the chip */

	/**********************************
	 *	Atmel's chip will respond in the following:
	 *		Any owner Auth or SRK auth command will be checked 
	 *		for presence of owner before verifying auth
	 *		of command.  So, a NO_SRK error will be thrown if
	 *		there is no owner, otherwise AUTHFAIL will be thrown.
	 ************************************/

	vendor = internal_getChipVendor(hContext);
/* 	if( internal_getChipVendor( hContext ) == CHIP_VENDOR_ATMEL ) */
	if (vendor == CHIP_VENDOR_ATMEL) {
		result =
		    TCSP_OSAP(tcsContext, TCPA_ET_KEYHANDLE, 0x40000000, nonce0,
			      &authHandle, &nonce1, &nonce1);

		/* ---  need this to keep tcs from bouncing the auth/context match */
/* 		if( result = TCSP_OIAP( tcsContext, &bsAuth.AuthHandle, &bsAuth.NonceEven )) */
/* 			return result; */

/* 		result = TCSP_GetPubKey( tcsContext, 0x40000000, &bsAuth, &keySize, &keyBlob ); */
		if (result == 0) {
			TCSP_TerminateHandle(tcsContext, authHandle);
			*hasOwner = TRUE;
		} else if (result == 0x15) {	/* no handles but passed */
			*hasOwner = TRUE;
		} else if (result == 0x0D)	/* ATML */
			*hasOwner = FALSE;
		else {
			return TSS_E_INTERNAL_ERROR;
		}
	} else if (vendor == CHIP_VENDOR_NATL) {
		result =
		    TCSP_OSAP(tcsContext, TCPA_ET_KEYHANDLE, 0x40000000, nonce0,
			      &authHandle, &nonce1, &nonce1);

		if (result == 0) {
			TCSP_TerminateHandle(tcsContext, authHandle);
			*hasOwner = TRUE;
		} else if (result == 0x15) {	/* no handles but passed */
			*hasOwner = TRUE;
		} else if (result == 0x12)
			*hasOwner = FALSE;
		else {
			return TSS_E_INTERNAL_ERROR;
		}

	} else
		return TSS_E_NOTIMPL;

	return TSS_SUCCESS;
}

/* ---	Call this at the beginning to make sure the keyfile has the SRK in it */
TSS_RESULT
IBM_Tspi_CheckSystemStorage(TSS_HKEY hSRK)
{
	UINT32 keySize;
	BYTE *keyBlob;
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
/* 	TSS_HKEY hSRK; */
	TSS_HCONTEXT hContext;
/* 	TCPA_KEY keyContainer; */
/* 	UINT16 offset; */

	if ((result = obj_isConnected_1(hSRK, &tcsContext)))
		return result;

	if ((hContext = obj_getTspContext(tcsContext)) == 0)
		return TSS_E_INTERNAL_ERROR;

	if (internal_getTCSVendor(hContext) != TCS_VENDOR_IBM)
		return TSS_E_INTERNAL_ERROR;

	/* ---  Try to get the SRK info out of the TCS keyfile */
	result = TCS_GetRegisteredKeyBlob(tcsContext, SRK_UUID, &keySize, &keyBlob);
	TCS_FreeMemory(tcsContext, keyBlob);

	/* ---  If failed NOT_REGISTERED, then read the info and register it */
	if (result) {		/* == TCS_E_KEY_NOT_REGISTERED ) */
		if ((result = Tspi_Key_GetPubKey(hSRK, &keySize, &keyBlob)))
			return result;

		TCS_FreeMemory(tcsContext, keyBlob);

		/* ---  Forget this now because IBM tcs registers it on getPubKey */
/* 		if( result = Tspi_Context_RegisterKey( hContext, hSRK, TSS_PS_TYPE_SYSTEM, SRK_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID )) */
/* 			return result; */

	}

/* 	else if( result ) */
/* 		return  TSS_E_INTERNAL_ERROR ; */

	return TSS_SUCCESS;
}

/*
#define ERROR_MASK_TDDL 0
#define ERROR_MASK_TPM	0x00
#define ERROR_MASK_TCS
#define ERROR_MASK_TSP

TSS_RESULT IBM_GetErrorString( TSS_RESULT result, char* string, int stringSize, char* detailString, int detailStringSize )
{
	
	

	if( detailString != NULL )
	{

	}

	return 0;
}

  */
