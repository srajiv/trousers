
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
#include <wchar.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "tspps.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "obj.h"


TSS_RESULT
Tspi_Context_Create(TSS_HCONTEXT * phContext)	/*  out */
{
	if (phContext == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_context_add(phContext);
}

TSS_RESULT
Tspi_Context_Close(TSS_HCONTEXT tspContext)	/*  in */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	/* Get the TCS context, if we're connected */
	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/* ---  Have the TCS do its thing */
	TCS_CloseContext(tcsContext);

	/* XXX Assume 1 TSPi context per process. Is there a reason to
	 * open more than 1? */
	destroy_ps();

	/* free all context related memory */
	free_tspi(tspContext, NULL);

	/* ---  Destroy all objects */
	obj_close_context(tspContext);

	/* We're not a connected context, so just exit */
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_Connect(TSS_HCONTEXT tspContext,	/*  in */
		     UNICODE *wszDestination	/*  in */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsHandle;
	BYTE *wMachineName = NULL;
	TSS_HPOLICY hPolicy;
	TSS_HOBJECT hTpm;
	UINT32 string_len = 0;

	/* see if we've already called connect with this context */
	if ((result = obj_context_is_connected(tspContext, &tcsHandle)) == TSS_SUCCESS) {
		LogError("attempted to call %s on an already connected "
			 "context!", __FUNCTION__);
		return TSPERR(TSS_E_CONNECTION_FAILED);
	} else if (result != TSPERR(TSS_E_NO_CONNECTION))
		return result;

	if (wszDestination == NULL) {
		if ((result = obj_context_get_machine_name(tspContext,
							&string_len,
							&wMachineName)))
			return result;

		if ((result = TCS_OpenContext_RPC((UNICODE *)wMachineName, &tcsHandle,
						CONNECTION_TYPE_TCP_PERSISTANT)))
			return result;
	} else {
		string_len = wcslen(wszDestination);
		if (string_len >= 256 || string_len < 1) {
			LogError1("Invalid hostname.");
			return TSPERR(TSS_E_BAD_PARAMETER);
		}

		if ((result = TCS_OpenContext_RPC(wszDestination, &tcsHandle,
						CONNECTION_TYPE_TCP_PERSISTANT)))
			return result;

		if ((result = obj_context_set_machine_name(tspContext, wszDestination,
						wcslen(wszDestination))))
			return result;
	}

        /* Assign an empty policy to this new object */
        if ((obj_policy_add(tspContext, TSS_POLICY_USAGE, &hPolicy)))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        obj_context_set_policy(tspContext, hPolicy);

        if ((obj_tpm_add(tspContext, &hTpm)))
                return TSPERR(TSS_E_INTERNAL_ERROR);

        obj_connectContext(tspContext, tcsHandle);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_FreeMemory(TSS_HCONTEXT tspContext,	/* in */
			BYTE * rgbMemory		/* in */
    )
{
	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	return free_tspi(tspContext, rgbMemory);
}

TSS_RESULT
Tspi_Context_GetDefaultPolicy(TSS_HCONTEXT tspContext,	/*  in */
			      TSS_HPOLICY * phPolicy	/*  out */
    )
{
	if (phPolicy == NULL )
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	return obj_context_get_policy(tspContext, phPolicy);
}

TSS_RESULT
Tspi_Context_CreateObject(TSS_HCONTEXT tspContext,	/*  in */
			  TSS_FLAG objectType,		/*  in */
			  TSS_FLAG initFlags,		/*  in */
			  TSS_HOBJECT * phObject	/*  out */
    )
{
	TSS_RESULT result;

	if (phObject == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	switch (objectType) {
	case TSS_OBJECT_TYPE_POLICY:
		switch (initFlags) {
			case TSS_POLICY_MIGRATION:
				/* fall through */
			case TSS_POLICY_USAGE:
				break;
			default:
				return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);
		}

		result = obj_policy_add(tspContext, initFlags, phObject);
		break;
	case TSS_OBJECT_TYPE_RSAKEY:
		/* If other flags are set that disagree with the SRK, this will
		 * help catch that conflict in the later steps */
		if (initFlags & TSS_KEY_TSP_SRK) {
			initFlags |= (TSS_KEY_TYPE_STORAGE |
				      TSS_KEY_NOT_MIGRATABLE |
				      TSS_KEY_NON_VOLATILE | TSS_KEY_SIZE_2048 |
				      TSS_KEY_NO_AUTHORIZATION);
		}

		/* Set default key flags */

		/* Default key size = 2k */
		if ((initFlags & TSS_KEY_SIZE_MASK) == 0)
			initFlags |= TSS_KEY_SIZE_2048;

		/* Default key type = storage */
		if ((initFlags & TSS_KEY_TYPE_MASK) == 0)
			initFlags |= TSS_KEY_TYPE_STORAGE;

		/* Check the key flags */
		switch (initFlags & TSS_KEY_SIZE_MASK) {
			case TSS_KEY_SIZE_512:
				/* fall through */
			case TSS_KEY_SIZE_1024:
				/* fall through */
			case TSS_KEY_SIZE_2048:
				/* fall through */
			case TSS_KEY_SIZE_4096:
				/* fall through */
			case TSS_KEY_SIZE_8192:
				/* fall through */
			case TSS_KEY_SIZE_16384:
				break;
			default:
				return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);
		}

		switch (initFlags & TSS_KEY_TYPE_MASK) {
			case TSS_KEY_TYPE_STORAGE:
				/* fall through */
			case TSS_KEY_TYPE_SIGNING:
				/* fall through */
			case TSS_KEY_TYPE_BIND:
				/* fall through */
			case TSS_KEY_TYPE_AUTHCHANGE:
				/* fall through */
			case TSS_KEY_TYPE_LEGACY:
				/* fall through */
			case TSS_KEY_TYPE_IDENTITY:
				break;
			default:
				return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);
		}

		result = obj_rsakey_add(tspContext, initFlags, phObject);
		break;
	case TSS_OBJECT_TYPE_ENCDATA:
		switch (initFlags & TSS_ENCDATA_TYPE_MASK) {
			case TSS_ENCDATA_LEGACY:
				/* fall through */
			case TSS_ENCDATA_SEAL:
				/* fall through */
			case TSS_ENCDATA_BIND:
				break;
			default:
				return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);
		}

		result = obj_encdata_add(tspContext,
				(initFlags & TSS_ENCDATA_TYPE_MASK),
				phObject);
		break;
	case TSS_OBJECT_TYPE_PCRS:
		/* There are no valid flags for a PCRs object */
		if (initFlags & ~(0UL))
			return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);

		result = obj_pcrs_add(tspContext, phObject);
		break;
	case TSS_OBJECT_TYPE_HASH:
		switch (initFlags) {
			case TSS_HASH_DEFAULT:
				/* fall through */
			case TSS_HASH_SHA1:
				/* fall through */
			case TSS_HASH_OTHER:
				break;
			default:
				return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);
		}

		result = obj_hash_add(tspContext, initFlags, phObject);
		break;
	default:
		LogDebug1("Invalid Object type");
		return TSPERR(TSS_E_INVALID_OBJECT_TYPE);
		break;
	}

	return result;
}

TSS_RESULT
Tspi_Context_CloseObject(TSS_HCONTEXT tspContext,	/*  in */
			 TSS_HOBJECT hObject		/*  in */
    )
{
	TSS_RESULT result;

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (obj_is_pcrs(hObject)) {
		result = obj_pcrs_remove(hObject, tspContext);
	} else if (obj_is_encdata(hObject)) {
		result = obj_encdata_remove(hObject, tspContext);
	} else if (obj_is_hash(hObject)) {
		result = obj_hash_remove(hObject, tspContext);
	} else if (obj_is_rsakey(hObject)) {
		result = obj_rsakey_remove(hObject, tspContext);
	} else if (obj_is_policy(hObject)) {
		result = obj_policy_remove(hObject, tspContext);
	} else {
		result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_Context_GetTpmObject(TSS_HCONTEXT tspContext,	/*  in */
			  TSS_HTPM * phTPM		/*  out */
    )
{
	if (phTPM == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	return obj_tpm_get(tspContext, phTPM);
}

TSS_RESULT
Tspi_Context_GetCapability(TSS_HCONTEXT tspContext,	/*  in */
			   TSS_FLAG capArea,		/*  in */
			   UINT32 ulSubCapLength,	/*  in */
			   BYTE * rgbSubCap,		/*  in */
			   UINT32 * pulRespDataLength,	/*  out */
			   BYTE ** prgbRespData		/*  out */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	UINT32 subCap;

	if (prgbRespData == NULL || pulRespDataLength == NULL )
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (rgbSubCap == NULL && ulSubCapLength != 0)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (ulSubCapLength > sizeof(UINT32))
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	switch (capArea) {
		case TSS_TSPCAP_ALG:
		case TSS_TSPCAP_VERSION:
		case TSS_TSPCAP_PERSSTORAGE:
			if (capArea == TSS_TSPCAP_ALG) {
				if (ulSubCapLength != sizeof(UINT32) || !rgbSubCap)
					return TSPERR(TSS_E_BAD_PARAMETER);
			}

			result = internal_GetCap(tspContext, capArea,
						 rgbSubCap ? *(UINT32 *)rgbSubCap : 0,
						 pulRespDataLength,
						 prgbRespData);
			break;
		case TSS_TCSCAP_ALG:
		case TSS_TCSCAP_VERSION:
		case TSS_TCSCAP_CACHING:
		case TSS_TCSCAP_PERSSTORAGE:
			/* make sure we're connected to a TCS first */
			if ((result = obj_context_is_connected(tspContext,
							&tcsContext)))
				return result;

			if (capArea == TSS_TCSCAP_ALG) {
				if (ulSubCapLength != sizeof(UINT32) || !rgbSubCap)
					return TSPERR(TSS_E_BAD_PARAMETER);
			}

			subCap = rgbSubCap ? endian32(*(UINT32 *)rgbSubCap) : 0;

			result = TCS_GetCapability(tcsContext,
							capArea,
							ulSubCapLength,
							(BYTE *)&subCap,
							pulRespDataLength,
							prgbRespData);
			break;
		default:
			result = TSPERR(TSS_E_BAD_PARAMETER);
			break;
	}

	return result;
}

TSS_RESULT
Tspi_Context_LoadKeyByBlob(TSS_HCONTEXT tspContext,	/*  in */
			   TSS_HKEY hUnwrappingKey,	/*  in */
			   UINT32 ulBlobLength,		/*  in */
			   BYTE * rgbBlobData,		/*  in */
			   TSS_HKEY * phKey		/*  out */
    )
{
	TPM_AUTH auth;
	BYTE blob[1024];
	UINT16 offset;
	TCPA_DIGEST digest;
	TSS_RESULT result;
	UINT32 keyslot;
	TSS_HPOLICY hPolicy;
	TCS_CONTEXT_HANDLE tcsContext;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	TCS_KEY_HANDLE myTCSKeyHandle;
	TCPA_KEY keyContainer;
	TSS_BOOL useAuth;
	TPM_AUTH *pAuth;
	TSS_FLAG initFlags;
	UINT16 realKeyBlobSize;

	if (phKey == NULL || rgbBlobData == NULL )
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext) || !obj_is_rsakey(hUnwrappingKey))
		return TSPERR(TSS_E_INVALID_HANDLE);

	/* Loading a key always requires us to be connected to a TCS */
	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/* ---  Get the Parent Handle */
	parentTCSKeyHandle = getTCSKeyHandle(hUnwrappingKey);
	if (parentTCSKeyHandle == NULL_HCONTEXT) {
		LogDebug1("parentTCSKeyHandle == 0 - Failure");
		return TSPERR(TSS_E_KEY_NOT_LOADED);
	}

	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, rgbBlobData,
			&keyContainer);
	realKeyBlobSize = offset;

	if ((result = obj_rsakey_get_policy(hUnwrappingKey, TSS_POLICY_USAGE,
					&hPolicy, &useAuth)))
		return result;

	if (useAuth) {
		/* ---  Create the Authorization */
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		Trspi_LoadBlob(&offset, ulBlobLength, blob, rgbBlobData);
		Trspi_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hPolicy, &digest, &auth)))
			return result;

		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	if ((result = TCSP_LoadKeyByBlob(tcsContext, parentTCSKeyHandle,
					ulBlobLength, rgbBlobData,
					pAuth, &myTCSKeyHandle, &keyslot)))
		return result;

	if (useAuth) {
		/* ---  Validate return auth */
		offset = 0;
		Trspi_LoadBlob_UINT32(&offset, result, blob);
		Trspi_LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		Trspi_LoadBlob_UINT32(&offset, keyslot, blob);
		Trspi_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &auth)))
			return result;
	}

	/* ---  Create a new Object */
	initFlags = 0;
	if (keyContainer.pubKey.keyLength == 0x100)
		initFlags |= TSS_KEY_SIZE_2048;
	else if (keyContainer.pubKey.keyLength == 0x80)
		initFlags |= TSS_KEY_SIZE_1024;
	else if (keyContainer.pubKey.keyLength == 0x40)
		initFlags |= TSS_KEY_SIZE_512;

	/* clear the key type field */
	initFlags &= ~TSS_KEY_TYPE_MASK;

	if (keyContainer.keyUsage == TPM_KEY_STORAGE)
		initFlags |= TSS_KEY_TYPE_STORAGE;
	else
		initFlags |= TSS_KEY_TYPE_SIGNING;	/* loading the blob
							   will fix this
							   back to what it
							   should be. */

	if ((result = obj_rsakey_add(tspContext, initFlags, phKey))) {
		LogDebug1("Failed create object");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	if ((result = obj_rsakey_set_tcpakey(*phKey,realKeyBlobSize, rgbBlobData))) {
		LogDebug1("Key loaded but failed to setup the key object"
			  "correctly");
		return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	addKeyHandle(myTCSKeyHandle, *phKey);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_LoadKeyByUUID(TSS_HCONTEXT tspContext,		/* in */
			   TSS_FLAG persistentStorageType,	/* in */
			   TSS_UUID uuidData,			/* in */
			   TSS_HKEY * phKey			/* out */
    )
{
	TSS_RESULT result;
	TSS_UUID parentUUID, srk_uuid = TSS_UUID_SRK;
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_KEY theKey;
	UINT16 offset;
	UINT32 keyBlobSize;
	BYTE *keyBlob = NULL;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_FLAG initFlags;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	TCPA_KEY_HANDLE keySlot;
	UINT32 parentPSType;
	TSS_HKEY parentTspHandle;

	if (phKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	/* Loading a key always requires us to be connected to a TCS */
	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/* ---  This key is in the System Persistant storage */
	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		if ((result = TCSP_LoadKeyByUUID(tcsContext,
						uuidData,
						NULL,
						&tcsKeyHandle))
				== TCS_E_KM_LOADFAILED)
			return result;

		if ((result = TCS_GetRegisteredKeyBlob(tcsContext,
						uuidData,
						&keyBlobSize,
						&keyBlob)))
			return result;
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		/* ---  Get my KeyBlob */
		if ((result = keyreg_GetKeyByUUID(&uuidData,
						&keyBlobSize,
						&keyBlob)))
			return result;

		/* ---  Get my Parent's UUID */
		if ((result = keyreg_GetParentUUIDByUUID(&uuidData,
						&parentUUID))) {
			free(keyBlob);
			return result;
		}

		/* ---  Get my Parent's Storage Type */
		if ((result = keyreg_GetParentPSTypeByUUID(&uuidData,
						&parentPSType))) {
			free(keyBlob);
			return result;
		}
		/******************************************
		 * If the parent is system persistant, then just call
		 *  the TCS Load.
		 * If the parent is in user storage, then we need to
		 *  call Tspi_LoadKeyByUUID and get a parentKeyObject.
		 *  This object can then be translated into a
		 *  TCS_KEY_HANDLE.
		 ******************************************/

		if (parentPSType == TSS_PS_TYPE_SYSTEM) {
			if ((result = TCSP_LoadKeyByUUID(tcsContext,
							parentUUID,
							NULL,
							&parentTCSKeyHandle))) {
				free(keyBlob);
				return result;
			}
		} else if (parentPSType == TSS_PS_TYPE_USER) {
			if ((result = Tspi_Context_LoadKeyByUUID(tspContext,
							parentPSType,
							parentUUID,
							&parentTspHandle))) {
				free(keyBlob);
				return result;
			}
			/* Get the parentTCS Key Handle
			 * from our table */
			parentTCSKeyHandle = getTCSKeyHandle(parentTspHandle);
			if (parentTCSKeyHandle == 0) {
				free(keyBlob);
				LogDebug1("XXX Can't find parent in table"
						" after loading -"
						" Unexpected XXX");
				return TSPERR(TSS_E_INTERNAL_ERROR);
			}

			/* Close the object since it's not needed
			 * anymore */
			obj_rsakey_remove(parentTspHandle, tspContext);
		} else {
			free(keyBlob);
			return TSPERR(TSS_E_BAD_PARAMETER);
		}

		/*******************************
		 * Now the parent is loaded and we have the parent key
		 * handle call the TCS to actually load the key now.
		 ******************************/

		if ((result = TCSP_LoadKeyByBlob(tcsContext,
						parentTCSKeyHandle,
						keyBlobSize, keyBlob,
						NULL, &tcsKeyHandle,
						&keySlot))) {
			free(keyBlob);
			return result;
		}
	} else {
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	/**************************
	 *	Now the key is loaded.  Need to create a Key
	 *		object and put the gus in there
	 ****************************/
	LogDebug1("Key is loaded, create a new key object for the user");

	offset = 0;
	Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob, &theKey);
	initFlags = 0;

	if (theKey.pubKey.keyLength == 0x100)
		initFlags |= TSS_KEY_SIZE_2048;
	else if (theKey.pubKey.keyLength == 0x80)
		initFlags |= TSS_KEY_SIZE_1024;
	else if (theKey.pubKey.keyLength == 0x40)
		initFlags |= TSS_KEY_SIZE_512;

	/* Make sure to setup the key properly if its the SRK */
	if (!(memcmp(&uuidData, &srk_uuid, sizeof(TSS_UUID))))
		initFlags |= TSS_KEY_TSP_SRK;

	/* ---  Create the keyObject */
	if ((result = obj_rsakey_add(tspContext, initFlags, phKey))) {
		free(keyBlob);
		return result;
	}

	/* Update our table to bind the tcsKeyHandle to this TspKeyHandle */
	addKeyHandle(tcsKeyHandle, *phKey);

	/* ---  Stuff the data into the object */
	if ((result = obj_rsakey_set_tcpakey(*phKey, keyBlobSize, keyBlob))) {
		free(keyBlob);
		return result;
	}

	free(keyBlob);
	//keyreg_SetUUIDOfKeyObject(*phKey, uuidData, persistentStorageType);
	if ((result = obj_rsakey_set_uuid(*phKey, &uuidData)))
		return result;

	if ((result = obj_rsakey_set_pstype(*phKey, persistentStorageType)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_RegisterKey(TSS_HCONTEXT tspContext,		/* in */
			 TSS_HKEY hKey,				/* in */
			 TSS_FLAG persistentStorageType,	/* in */
			 TSS_UUID uuidKey,			/* in */
			 TSS_FLAG persistentStorageTypeParent,	/* in */
			 TSS_UUID uuidParentKey			/* in */
    )
{

	BYTE *keyBlob;
	UINT32 keyBlobSize;
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if (!obj_is_context(tspContext) || !obj_is_rsakey(hKey))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		/* make sure we're connected to a TCS */
		if ((result = obj_context_is_connected(tspContext, &tcsContext)))
			return result;

		if (persistentStorageTypeParent == TSS_PS_TYPE_USER) {
			return TSPERR(TSS_E_NOTIMPL);
		} else if (persistentStorageTypeParent == TSS_PS_TYPE_SYSTEM) {
			if ((result = obj_rsakey_get_blob(hKey,
						&keyBlobSize, &keyBlob)))
				return result;

			if ((result = TCS_RegisterKey(tcsContext,
						     uuidParentKey,
						     uuidKey,
						     keyBlobSize,
						     keyBlob,
						     strlen(PACKAGE_STRING) + 1,
						     PACKAGE_STRING)))
				return result;
		} else {
			return TSPERR(TSS_E_BAD_PARAMETER);
		}
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		if ((result = obj_rsakey_get_blob(hKey,
						&keyBlobSize, &keyBlob)))
			return result;

		if (keyreg_IsKeyAlreadyRegistered(tspContext, keyBlobSize,
						  keyBlob))
			return TSPERR(TSS_E_KEY_ALREADY_REGISTERED);

		if ((result = keyreg_WriteKeyToFile(&uuidKey, &uuidParentKey,
					  persistentStorageTypeParent,
					  keyBlobSize, keyBlob)))
			return result;
	} else {
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	//keyreg_SetUUIDOfKeyObject(hKey, uuidKey, persistentStorageType);
	if ((result = obj_rsakey_set_uuid(hKey, &uuidKey)))
		return result;

	if ((result = obj_rsakey_set_pstype(hKey, persistentStorageType)))
		return result;


	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_UnregisterKey(TSS_HCONTEXT tspContext,		/* in */
			   TSS_FLAG persistentStorageType,	/* in */
			   TSS_UUID uuidKey,			/* in */
			   TSS_HKEY *phKey			/* out */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if (phKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		/* make sure we're connected to a TCS first */
		if ((result = obj_context_is_connected(tspContext, &tcsContext)))
			return result;

		/* get the key first, so it doesn't disappear when we
		 * unregister it */
		if ((result = Tspi_Context_GetKeyByUUID(tspContext,
							TSS_PS_TYPE_SYSTEM,
							uuidKey, phKey)))
			return result;

		/* now unregister it */
		if ((result = TCSP_UnregisterKey(tcsContext, uuidKey)))
			return result;
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		if (!obj_is_context(tspContext))
			return TSPERR(TSS_E_INVALID_HANDLE);

		/* get the key first, so it doesn't disappear when we
		 * unregister it */
		if ((result = Tspi_Context_GetKeyByUUID(tspContext,
							TSS_PS_TYPE_USER,
							uuidKey, phKey)))
			return result;

		/* now unregister it */
		if ((result = keyreg_RemoveKey(&uuidKey)))
			return result;
	} else {
		return TSPERR(TSS_E_BAD_PARAMETER);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetKeyByUUID(TSS_HCONTEXT tspContext,		/* in */
			  TSS_FLAG persistentStorageType,	/* in */
			  TSS_UUID uuidData,			/* in */
			  TSS_HKEY * phKey			/* out */
    )
{

	UINT16 offset;
	TCPA_RESULT result;
	UINT32 keyBlobSize = 0;
	BYTE *keyBlob = NULL;
	TCPA_KEY theKey;
	TSS_FLAG initFlag = 0;
	TCS_CONTEXT_HANDLE tcsContext;

	if (phKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		/* make sure we're connected to a TCS first */
		if ((result = obj_context_is_connected(tspContext, &tcsContext)))
			return result;

		if ((result = TCS_GetRegisteredKeyBlob(tcsContext, uuidData,
						       &keyBlobSize,
						       &keyBlob)))
			return result;

		offset = 0;
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob, &theKey);
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		if (!obj_is_context(tspContext))
			return TSPERR(TSS_E_INVALID_HANDLE);

		if ((result = keyreg_GetKeyByUUID(&uuidData, &keyBlobSize,
						&keyBlob)))
			return result;

		offset = 0;
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob, &theKey);
	} else
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (theKey.pubKey.keyLength == 0x100)
		initFlag |= TSS_KEY_SIZE_2048;
	else if (theKey.pubKey.keyLength == 0x80)
		initFlag |= TSS_KEY_SIZE_1024;
	else if (theKey.pubKey.keyLength == 0x40)
		initFlag |= TSS_KEY_SIZE_512;

	if ((result = obj_rsakey_add(tspContext, initFlag, phKey))) {
		free(keyBlob);
		return result;
	}

	if ((result = obj_rsakey_set_tcpakey(*phKey, keyBlobSize, keyBlob))) {
		free(keyBlob);
		return result;
	}

	free(keyBlob);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetKeyByPublicInfo(TSS_HCONTEXT tspContext,	/* in */
				TSS_FLAG persistentStorageType,	/* in */
				TSS_ALGORITHM_ID algID,		/* in */
				UINT32 ulPublicInfoLength,	/* in */
				BYTE * rgbPublicInfo,		/* in */
				TSS_HKEY * phKey		/* out */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_ALGORITHM_ID tcsAlgID;
	UINT32 keyBlobSize;
	BYTE *keyBlob;
	TSS_RESULT result;
	TSS_HKEY keyOutHandle;
	UINT32 flag = 0;
	TCPA_KEY keyContainer;
	UINT16 offset;

	if (phKey == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		/* make sure we're connected to a TCS */
		if ((result = obj_context_is_connected(tspContext, &tcsContext)))
			return result;

		if (algID == TSS_ALG_RSA)
			tcsAlgID = TCPA_ALG_RSA;
		else {
			LogError1("Algorithm ID was not type RSA.");
			return TSPERR(TSS_E_BAD_PARAMETER);
		}

		if ((result = TCSP_GetRegisteredKeyByPublicInfo(tcsContext,
							       tcsAlgID,
							       ulPublicInfoLength,
							       rgbPublicInfo,
							       &keyBlobSize,
							       &keyBlob)))
			return result;

		/* need to setup the init flags of the create object based on
		 * the size of the blob's pubkey */
		offset = 0;
		Trspi_UnloadBlob_KEY(tspContext, &offset, keyBlob,
				&keyContainer);
		switch (keyContainer.pubKey.keyLength) {
			case 2048:
				flag |= TSS_KEY_SIZE_16384;
				break;
			case 1024:
				flag |= TSS_KEY_SIZE_8192;
				break;
			case 512:
				flag |= TSS_KEY_SIZE_4096;
				break;
			case 256:
				flag |= TSS_KEY_SIZE_2048;
				break;
			case 128:
				flag |= TSS_KEY_SIZE_1024;
				break;
			case 64:
				flag |= TSS_KEY_SIZE_512;
				break;
			default:
				LogError1("Key was not a known keylength.");
				free(keyBlob);
				return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		if (keyContainer.keyUsage == TPM_KEY_SIGNING)
			flag |= TSS_KEY_TYPE_SIGNING;
		else if (keyContainer.keyUsage == TPM_KEY_STORAGE)
			flag |= TSS_KEY_TYPE_STORAGE;
		else if (keyContainer.keyUsage == TPM_KEY_IDENTITY)
			flag |= TSS_KEY_TYPE_IDENTITY;
		else if (keyContainer.keyUsage == TPM_KEY_AUTHCHANGE)
			flag |= TSS_KEY_TYPE_AUTHCHANGE;
		else if (keyContainer.keyUsage == TPM_KEY_BIND)
			flag |= TSS_KEY_TYPE_BIND;
		else if (keyContainer.keyUsage == TPM_KEY_LEGACY)
			flag |= TSS_KEY_TYPE_LEGACY;

		if (keyContainer.authDataUsage == TPM_AUTH_NEVER)
			flag |= TSS_KEY_NO_AUTHORIZATION;
		else if (keyContainer.authDataUsage == TPM_AUTH_ALWAYS)
			flag |= TSS_KEY_AUTHORIZATION;
		else {
			LogError1("keyContainer.authDataUsage was not "
					"always or never");
			free_tspi(tspContext, keyBlob);
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		if (keyContainer.keyFlags & migratable)
			flag |= TSS_KEY_MIGRATABLE;
		else
			flag |= TSS_KEY_NOT_MIGRATABLE;

		if (keyContainer.keyFlags & volatileKey)
			flag |= TSS_KEY_VOLATILE;
		else
			flag |= TSS_KEY_NON_VOLATILE;

		/* ---  Create a new Key Object */
		if ((result = obj_rsakey_add(tspContext, flag, &keyOutHandle))) {
			free(keyBlob);
			return result;
		}
		/* ---  Stick the info into this net KeyObject */
		if ((result = obj_rsakey_set_tcpakey(keyOutHandle,
						 keyBlobSize, keyBlob))) {
			free(keyBlob);
			return result;
		}

		free(keyBlob);
		*phKey = keyOutHandle;
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		return TSPERR(TSS_E_NOTIMPL);	/* TODO */
	} else
		return TSPERR(TSS_E_BAD_PARAMETER);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetRegisteredKeysByUUID(TSS_HCONTEXT tspContext,		/*  in */
				     TSS_FLAG persistentStorageType,	/*  in */
				     TSS_UUID * pUuidData,		/*  in */
				     UINT32 * pulKeyHierarchySize,	/*  out */
				     TSS_KM_KEYINFO ** ppKeyHierarchy	/*  out */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if (pulKeyHierarchySize == NULL || ppKeyHierarchy == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		/* make sure we're connected to a TCS */
		if ((result = obj_context_is_connected(tspContext, &tcsContext)))
			return result;

		return TCS_EnumRegisteredKeys(tcsContext, pUuidData,
						pulKeyHierarchySize,
						ppKeyHierarchy);
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		return TSPERR(TSS_E_NOTIMPL);	/* TODO */
	} else
		return TSPERR(TSS_E_BAD_PARAMETER);

	return TSS_SUCCESS;
}
