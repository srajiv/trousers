
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
#include "tcs_int_literals.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "tspps.h"
#include "tss_crypto.h"
#include "hosttable.h"

char *tss_layers[] = { "tpm", "tddl", "tcs", "tsp" };

TSS_RESULT
internal_GetMachineName(UNICODE *name, int nameSize)
{
	mbstate_t ps;
	const char *s = "localhost";
	size_t ret;

	memset(&ps, 0, sizeof(mbstate_t));

	ret = mbsrtowcs(name, &s, nameSize, &ps);
	if (ret == (size_t)(-1)) {
		LogError("Error converting string %s to UNICODE", s);
		return TSS_E_INTERNAL_ERROR;
	}

	return TSS_SUCCESS;

}

TSS_RESULT
Tspi_Context_Create(TSS_HCONTEXT * phContext)	/*  out */
{
	TSS_HOBJECT hObject;
	UINT32 objectSize = sizeof(TCPA_CONTEXT_OBJECT);
	TCPA_CONTEXT_OBJECT *object;
	AnObject *anObject;
	TSS_RESULT result;

	LogDebug1("Tspi_Context_Create");

	if (phContext == NULL)
		return TSS_E_BAD_PARAMETER;

	/* ---  First get the handle from the TCS */
#if 0
//      if( result = TCS_OpenContext( &tcsHandle ))
//              return result;
#endif
	/* ---  Now create a new context object with default settings */
	hObject = addObject(0, TSS_OBJECT_TYPE_CONTEXT);
	if (hObject == 0)
		return TSS_E_INTERNAL_ERROR;

	object = calloc(1, objectSize);
	if (object == NULL) {
		LogError("malloc of %d bytes failed.", objectSize);
		return TSS_E_INTERNAL_ERROR;
	}
	object->tcsHandle = 0;
	object->policy = 0;
	object->silentMode = TSS_TSPATTRIB_CONTEXT_NOT_SILENT;

	if ((result = setObject(hObject, object, objectSize)))
		return TSS_E_INTERNAL_ERROR;

	/* sanity checking */
	anObject = getAnObjectByHandle(hObject);
	if (anObject == NULL) {
		LogError("No object found with handle matching 0x%x", hObject);
		return TSS_E_INTERNAL_ERROR;
	}

	free(object);

	/* ---  Return the new objectHandle to the context */
	*phContext = hObject;

	LogDebug1("Leaving Context Create");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_Close(TSS_HCONTEXT hContext)	/*  in */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	LogDebug1("Tspi_Context_Close");
	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	/* Get the TCS context, if we're connected */
	result = internal_CheckContext_1(hContext, &tcsContext);
	if (result == TSS_SUCCESS) {
		/* ---  Destroy all objects */
		destroyObjectsByContext(tcsContext);

		/* free all context related memory */
		free_tspi(tcsContext, NULL);

		/* Assume 1 TSPi context per process. Is there a reason to open more than 1? */
		destroy_ps();

		LogDebug1("Leaving Context Close");
		/* ---  Have the TCS do its thing */
		return TCS_CloseContext(tcsContext);
	}

	/* We're not a connected context, so just exit */
	return TSS_SUCCESS;
}

TSS_RESULT
ConnectGuts(TSS_HCONTEXT hContext, UNICODE *wszDestination, TCS_CONTEXT_HANDLE tcsHandle)
{
	TSS_HOBJECT hObject;
	UINT32 objectSize;
	TCPA_CONTEXT_OBJECT *object;
	AnObject *anObject;
	TCPA_TPM_OBJECT *tpmObject;

	anObject = getAnObjectByHandle(hContext);
	if (anObject == NULL) {
		LogError("No object found with handle matching 0x%x", hContext);
		return TSS_E_INTERNAL_ERROR;
	}

	object = anObject->memPointer;

	object->tcsHandle = tcsHandle;
	anObject->tcsContext = tcsHandle;

	/* this length was checked to be in bounds in Tspi_Context_Connect() */
	object->machineNameLength = wcslen(wszDestination);
	wcscpy(object->machineName, wszDestination);

	/* ---  Assign an empty policy to this new object        */
	if (Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				      TSS_POLICY_USAGE, &object->policy))
		return TSS_E_INTERNAL_ERROR;

	/* ---  Now add a TPM object to this context */
	objectSize = sizeof (TCPA_TPM_OBJECT);

	hObject = addObject(hContext, TSS_OBJECT_TYPE_TPM);
	if (hObject == 0)
		return TSS_E_INTERNAL_ERROR;

	tpmObject = calloc(1, objectSize);
	if (tpmObject == NULL) {
		LogError("calloc of %d bytes failed.", objectSize);
		return TSS_E_OUTOFMEMORY;
	}

	if (Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				      TSS_POLICY_USAGE, &tpmObject->policy)) {
		free(tpmObject);
		return TSS_E_INTERNAL_ERROR;
	}

	internal_CopySecrets(object->policy, tpmObject->policy);
	if (setObject(hObject, tpmObject, objectSize)) {
		free(tpmObject);
		return TSS_E_INTERNAL_ERROR;
	}

	/* setObject creates a copy of this for us, so we can free it here */
	free(tpmObject);

	return TSS_SUCCESS;
}

#if 0
TSS_RESULT
Tspi_Context_Connect_Special(TSS_HCONTEXT hContext, UNICODE * wszDestination)
{
	TSS_RESULT result;

	TCS_CONTEXT_HANDLE tcsHandle;
#if 0
	UINT32 objectSize;
	TCPA_CONTEXT_OBJECT *object;
	AnObject *anObject;
	TCPA_TPM_OBJECT *tpmObject;
#endif
	char machineName[256] = "";
	UNICODE wMachineName[256];
	unsigned int i, j;

	LogDebug1("Tspi_Context_Connect_Special");
	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if (wszDestination == NULL) {
		internal_GetMachineName(machineName, 256);
	} else {
		wcscpy(wMachineName, wszDestination);
	}
	/* ---  Get a TCS_CONTEXT_HANDLE */
	if ((result = TCS_OpenContext_RPC(wMachineName, &tcsHandle, 2)))
		return result;

	if ((result = ConnectGuts(hContext, wszDestination, tcsHandle)))
		return result;

	LogDebug1("Leaving Context Connect Special");
	return TSS_SUCCESS;
}
#endif

TSS_RESULT
Tspi_Context_Connect(TSS_HCONTEXT hContext,	/*  in */
		     UNICODE *wszDestination	/*  in */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsHandle;
	UNICODE wMachineName[256];
	AnObject *anObject;
	TCPA_CONTEXT_OBJECT *object;
	int string_len = 0;

	LogDebug1("Tspi_Context_Connect");
	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if (wszDestination == NULL) {
		internal_GetMachineName(wMachineName, 256);
	} else {
		/* XXX According to the man page, wcsnlen is a GNU extension */
		string_len = wcsnlen(wszDestination, 256);
		if (string_len >= 256 || string_len < 1) {
			LogError1("Invalid hostname.");
			return TSS_E_BAD_PARAMETER;
		}
		wcsncpy(wMachineName, wszDestination, string_len + 1);
	}

	/* see if we've already called connect with this context */
	anObject = getAnObjectByHandle(hContext);
	if (anObject == NULL) {
		LogError("No object found with handle matching 0x%x", hContext);
		return TSS_E_INTERNAL_ERROR;
	}

	object = anObject->memPointer;
	if (wcslen(object->machineName) != 0) {
		LogError("attempted to call %s on an already connected context!", __FUNCTION__);
		return TSS_E_CONNECTION_FAILED;
	}

	/* ---  Get a TCS_CONTEXT_HANDLE */
	if ((result = TCS_OpenContext_RPC(wMachineName, &tcsHandle, CONNECTION_TYPE_TCP_PERSISTANT)))
		return result;

	if ((result = ConnectGuts(hContext, wMachineName, tcsHandle)))
		return result;

	LogDebug1("Leaving Context Connect");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_FreeMemory(TSS_HCONTEXT hContext,	/*  in */
			BYTE * rgbMemory	/*  in */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

#if 0
	/* we don't need this, you should be able to free memory on an unconnected context */
	if ((result = internal_CheckContext_1(hContext, &tcsContext)))
		return result;
#endif

	free_tspi(tcsContext, rgbMemory);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetDefaultPolicy(TSS_HCONTEXT hContext,	/*  in */
			      TSS_HPOLICY * phPolicy	/*  out */
    )
{
	AnObject *object = NULL;
	TCPA_CONTEXT_OBJECT *cObject;
	TSS_RESULT result;

	if (phPolicy == NULL )
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	object = getAnObjectByHandle(hContext);
	if (object == NULL) {
		LogError("No object found with handle matching 0x%x", hContext);
		return TSS_E_INVALID_HANDLE;
	}
	cObject = object->memPointer;
	if (cObject == NULL) {
		LogError1("internal mem pointer is not set!");
		return TSS_E_INTERNAL_ERROR;
	}

	*phPolicy = cObject->policy;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_CreateObject(TSS_HCONTEXT hContext,	/*  in */
			  TSS_FLAG objectType,	/*  in */
			  TSS_FLAG initFlags,	/*  in */
			  TSS_HOBJECT * phObject	/*  out */
    )
{
	UINT32 objectSize = 0;
	void *object;
	UINT16 numPCRs;
	UINT16 sizeOfSelect;
	UINT16 i;
	TCPA_VERSION *version;
	TCPA_RSA_KEY_PARMS rsaKeyParms;
	UINT16 zero;
	TSP_INTERNAL_POLICY_OBJECT *pObj;
	TCPA_RSAKEY_OBJECT *rsaObj;
	TCPA_HASH_OBJECT *hashObj;
	TCPA_PCR_OBJECT *pcrObj;
	TCPA_ENCDATA_OBJECT *encDataObj;
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	LogDebug("Tspi_Context_CreateObject of type %.8X", objectType);

	if (phObject == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_1(hContext, &tcsContext)))
		return result;

	switch (objectType) {
	case TSS_OBJECT_TYPE_POLICY:
		LogDebug1("Policy Object");

		if ((check_flagset_collision(initFlags, (TSS_POLICY_MIGRATION | TSS_POLICY_USAGE))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		/* if any flags other than policy type are on, its invalid */
		if (initFlags & ~(TSS_POLICY_MIGRATION | TSS_POLICY_USAGE))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((initFlags & (TSS_POLICY_USAGE | TSS_POLICY_MIGRATION)) == 0)
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		*phObject = addObject(hContext, objectType);
		if (*phObject == 0)
			return TSS_E_INTERNAL_ERROR;

		objectSize = sizeof(TSP_INTERNAL_POLICY_OBJECT);
		object = calloc(1, objectSize);
		if (object == NULL) {
			LogError("calloc of %d bytes failed.", objectSize);
			return TSS_E_OUTOFMEMORY;
		}
		pObj = (TSP_INTERNAL_POLICY_OBJECT *)object;
		pObj->p.SecretMode = TSS_SECRET_MODE_NONE;
		pObj->p.SecretLifetime = TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS;

		if (initFlags & TSS_POLICY_USAGE)
			pObj->p.PolicyType = TSS_POLICY_USAGE;
		else if (initFlags & TSS_POLICY_MIGRATION)
			pObj->p.PolicyType = TSS_POLICY_MIGRATION;

		break;
	case TSS_OBJECT_TYPE_RSAKEY:
		LogDebug1("RSAKey Object");

		/* ---  Check the default flag */
		if (initFlags & TSS_KEY_DEFAULT) {
			/* ---  If any other flags are set...error */
			if (initFlags & (~TSS_KEY_DEFAULT))
				return TSS_E_INVALID_OBJECT_INIT_FLAG;
		}

		if (initFlags & TSS_KEY_EMPTY_KEY) {
			if (initFlags & (~TSS_KEY_EMPTY_KEY))
				return TSS_E_INVALID_OBJECT_INIT_FLAG;
		}

		/* If other flags are set that disagree with the SRK, this will help
		 * catch that conflict in the later steps */
		if (initFlags & TSS_KEY_SRK_HANDLE) {
			initFlags |= (TSS_KEY_TYPE_STORAGE | TSS_KEY_NOT_MIGRATABLE |
			     TSS_KEY_NON_VOLATILE | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION);
		}


		/* Check for conflicting key flags */
		if ((check_flagset_collision(initFlags, (TSS_KEY_SIZE_512  | TSS_KEY_SIZE_1024 |
					     TSS_KEY_SIZE_2048 | TSS_KEY_SIZE_4096 | TSS_KEY_SIZE_8192 |
					     TSS_KEY_SIZE_16384))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((check_flagset_collision(initFlags, (TSS_KEY_TYPE_STORAGE | TSS_KEY_TYPE_SIGNING |
							 TSS_KEY_TYPE_BIND | TSS_KEY_TYPE_AUTHCHANGE |
							 TSS_KEY_TYPE_LEGACY | TSS_KEY_TYPE_IDENTITY))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((check_flagset_collision(initFlags, (TSS_KEY_MIGRATABLE | TSS_KEY_NOT_MIGRATABLE))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((check_flagset_collision(initFlags, (TSS_KEY_VOLATILE  | TSS_KEY_NON_VOLATILE))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((check_flagset_collision(initFlags, (TSS_KEY_AUTHORIZATION  | TSS_KEY_NO_AUTHORIZATION))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		/* Set default key flags */

		/* Default key size = 2k */
		if ((initFlags & (TSS_KEY_SIZE_512  | TSS_KEY_SIZE_1024 | TSS_KEY_SIZE_2048 |
				  TSS_KEY_SIZE_4096 | TSS_KEY_SIZE_8192 | TSS_KEY_SIZE_16384)) == 0)
			initFlags |= TSS_KEY_SIZE_2048;

		/* Default key type = storage */
		if ((initFlags & (TSS_KEY_TYPE_IDENTITY | TSS_KEY_TYPE_SIGNING | TSS_KEY_TYPE_BIND |
				  TSS_KEY_TYPE_STORAGE | TSS_KEY_TYPE_LEGACY | TSS_KEY_TYPE_AUTHCHANGE)) == 0)
			initFlags |= TSS_KEY_TYPE_STORAGE;

		/* Default key migration flag = not migratable */
		if ((initFlags & (TSS_KEY_MIGRATABLE | TSS_KEY_NOT_MIGRATABLE)) == 0)
			initFlags |= TSS_KEY_NOT_MIGRATABLE;

		/* Default key volatile flag = volatile */
		if ((initFlags & (TSS_KEY_VOLATILE | TSS_KEY_NON_VOLATILE)) == 0)
			initFlags |= TSS_KEY_VOLATILE;

		/* ---  Check Authorization flag */
		if ((initFlags & (TSS_KEY_NO_AUTHORIZATION | TSS_KEY_AUTHORIZATION)) == 0) {
			if (initFlags & TSS_KEY_TYPE_STORAGE)
				initFlags |= TSS_KEY_NO_AUTHORIZATION;
			else
				initFlags |= TSS_KEY_AUTHORIZATION;
		}

		/* --   If we got this far, life is good with the flags */
		/* ---  Start to setup the key object */

		objectSize = sizeof (TCPA_RSAKEY_OBJECT);
		*phObject = addObject(hContext, objectType);
		if (*phObject == 0)
			return TSS_E_INTERNAL_ERROR;

		object = calloc(1, objectSize);
		if (object == NULL) {
			LogError("calloc of %d bytes failed.", objectSize);
			return TSS_E_OUTOFMEMORY;
		}

		rsaObj = (TCPA_RSAKEY_OBJECT *)object;

		/* create the key's policy objects */
		if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					  TSS_POLICY_MIGRATION, &rsaObj->migPolicy))) {
			free(object);
			LogError1("Error creating migration policy for key object.");
			return TSS_E_INTERNAL_ERROR;
		}

		if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					  TSS_POLICY_USAGE, &rsaObj->usagePolicy))) {
			free(object);
			LogError1("Error creating usage policy for key object.");
			return TSS_E_INTERNAL_ERROR;
		}

		/* if we're an emtpy key, exit now; we assume the app will set our properties */
		if (initFlags & TSS_KEY_EMPTY_KEY)
			break;

		version = getCurrentVersion(hContext);
		if (version == NULL) {
			free(object);
			return TSS_E_INTERNAL_ERROR;
		}
		memcpy(&rsaObj->tcpaKey.ver, version, sizeof (TCPA_VERSION));
		rsaObj->tcpaKey.algorithmParms.algorithmID = TCPA_ALG_RSA;
		rsaObj->tcpaKey.algorithmParms.parmSize = 12;
		rsaObj->tcpaKey.algorithmParms.parms = calloc(1, rsaObj->tcpaKey.algorithmParms.parmSize);
		if (rsaObj->tcpaKey.algorithmParms.parms == NULL) {
			LogError("calloc of %d bytes failed.", rsaObj->tcpaKey.algorithmParms.parmSize);
			free(object);
			return TSS_E_OUTOFMEMORY;
		}
		rsaKeyParms.exponentSize = 0;
		rsaKeyParms.numPrimes = 2;
		memset(&rsaObj->tcpaKey.keyFlags, 0, sizeof(TCPA_KEY_FLAGS));

		rsaObj->tcpaKey.pubKey.keyLength = 0;
		rsaObj->tcpaKey.encSize = 0;
		rsaObj->privateKey.Privlen = 0;
		rsaObj->tcpaKey.PCRInfoSize = 0;
		rsaObj->persStorageType = TSS_PS_TYPE_NO;

		/* End of all the default stuff */

		if (initFlags & TSS_KEY_VOLATILE)
			rsaObj->tcpaKey.keyFlags |= volatileKey;
		if (initFlags & TSS_KEY_MIGRATABLE)
			rsaObj->tcpaKey.keyFlags |= migratable;
		if (initFlags & TSS_KEY_AUTHORIZATION) {
			rsaObj->usesAuth = TRUE;
			rsaObj->tcpaKey.authDataUsage = TPM_AUTH_ALWAYS;
		} else {
			rsaObj->usesAuth = FALSE;
		}

		/* set the key length */
		if (initFlags & TSS_KEY_SIZE_512) {
			rsaKeyParms.keyLength = 512;
		} else if (initFlags & TSS_KEY_SIZE_1024) {
			rsaKeyParms.keyLength = 1024;
		} else if (initFlags & TSS_KEY_SIZE_2048) {
			rsaKeyParms.keyLength = 2048;
		} else if (initFlags & TSS_KEY_SIZE_4096) {
			rsaKeyParms.keyLength = 4096;
		} else if (initFlags & TSS_KEY_SIZE_8192) {
			rsaKeyParms.keyLength = 8192;
		} else if (initFlags & TSS_KEY_SIZE_16384) {
			rsaKeyParms.keyLength = 16384;
		}

		if (initFlags & TSS_KEY_TSP_SRK) {
			addKeyHandle(FIXED_SRK_KEY_HANDLE, *phObject);
			rsaObj->privateKey.Privlen = 0;
			rsaObj->tcpaKey.PCRInfoSize = 0;
			rsaKeyParms.keyLength = 2048;
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_STORAGE;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_NONE;
			rsaObj->tcpaKey.keyFlags |= volatileKey;
		}

		/* assign encryption and signature schemes */
		if (initFlags & TSS_KEY_TYPE_SIGNING) {
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_SIGN;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_NONE;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_RSASSAPKCS1V15_SHA1;
		} else if (initFlags & TSS_KEY_TYPE_BIND) {
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_BIND;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_NONE;

		} else if (initFlags & TSS_KEY_TYPE_LEGACY) {
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_LEGACY;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_RSASSAPKCS1V15_SHA1;
		} else if (initFlags & TSS_KEY_TYPE_STORAGE) {
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_STORAGE;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_NONE;
		} else if (initFlags & TSS_KEY_TYPE_IDENTITY) {
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_IDENTITY;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_NONE;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_RSASSAPKCS1V15_SHA1;
		} else if (initFlags & TSS_KEY_TYPE_AUTHCHANGE) {
			rsaObj->tcpaKey.keyUsage = TSS_KEYUSAGE_AUTHCHANGE;
			rsaObj->tcpaKey.algorithmParms.encScheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
			rsaObj->tcpaKey.algorithmParms.sigScheme = TSS_SS_NONE;
		}
#if 0
		if (initFlags & TSS_KEY_MIGRATABLE) {
			rsaObj->tcpaKey.keyFlags.migratable = 1;	/*  |= FLAG_MIGRATABLE; */
		}
#endif
		if (initFlags & TSS_KEY_SRK_HANDLE) {
			addKeyHandle(FIXED_SRK_KEY_HANDLE, *phObject);
		}
		zero = 0;
		LoadBlob_RSA_KEY_PARMS(&zero, rsaObj->tcpaKey.algorithmParms.parms, &rsaKeyParms);

		break;
	case TSS_OBJECT_TYPE_ENCDATA:
		LogDebug1("EncData Object");

		if ((check_flagset_collision(initFlags,
					     (TSS_ENCDATA_LEGACY | TSS_ENCDATA_SEAL | TSS_ENCDATA_BIND))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if (initFlags & ~(TSS_ENCDATA_LEGACY | TSS_ENCDATA_SEAL | TSS_ENCDATA_BIND))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((initFlags & (TSS_ENCDATA_LEGACY | TSS_ENCDATA_SEAL | TSS_ENCDATA_BIND)) == 0)
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		objectSize = sizeof (TCPA_ENCDATA_OBJECT);
		*phObject = addObject(hContext, objectType);
		if (*phObject == 0)
			return TSS_E_INTERNAL_ERROR;
		object = calloc(1, objectSize);
		if (object == NULL) {
			LogError("calloc of %d bytes failed.", objectSize);
			return TSS_E_OUTOFMEMORY;
		}

		encDataObj = (TCPA_ENCDATA_OBJECT *)object;

		if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					  TSS_POLICY_MIGRATION, &encDataObj->migPolicy))) {
			free(object);
			return TSS_E_INTERNAL_ERROR;
		}
		if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					  TSS_POLICY_USAGE, &encDataObj->usagePolicy))) {
			free(object);
			LogError1("Error creating usage policy for encrypted data object.");
			return TSS_E_INTERNAL_ERROR;
		}
		break;
	case TSS_OBJECT_TYPE_PCRS:
		LogDebug1("PCR Object");

		/* There are no valid flags for a PCRs object */
		if (initFlags & ~(0UL))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		objectSize = sizeof (TCPA_PCR_OBJECT);
		*phObject = addObject(hContext, objectType);
		if (*phObject == 0)
			return TSS_E_INTERNAL_ERROR;
		object = calloc(1, objectSize);
		if (object == NULL) {
			LogError("calloc of %d bytes failed.", objectSize);
			return TSS_E_OUTOFMEMORY;
		}

		numPCRs = getMaxPCRs(tcsContext);
		sizeOfSelect = (((numPCRs - 1) >> 3) + 1);

		pcrObj = (TCPA_PCR_OBJECT *)object;

		pcrObj->select.sizeOfSelect = sizeOfSelect;
		pcrObj->select.pcrSelect = malloc(sizeOfSelect);
		if (pcrObj->select.pcrSelect == NULL) {
			LogError("malloc of %d bytes failed.", sizeOfSelect);
			free(object);
			return TSS_E_OUTOFMEMORY;
		}
/* 		pcrObj->pcrComposite.select.sizeOfSelect = sizeOfSelect; */
/* 		pcrObj->pcrComposite.select.pcrSelect = malloc( sizeOfSelect ); */
		for (i = 0; i < sizeOfSelect; i++)
/* 			pcrObj->pcrComposite.select.pcrSelect[i] = 0x00; */
			pcrObj->select.pcrSelect[i] = 0;
		break;
	case TSS_OBJECT_TYPE_HASH:
		LogDebug1("Hash Object");

		if ((check_flagset_collision(initFlags,
		     (TSS_HASH_DEFAULT | TSS_HASH_SHA1 | TSS_HASH_OTHER))))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if (initFlags & ~(TSS_HASH_DEFAULT | TSS_HASH_SHA1 | TSS_HASH_OTHER))
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		if ((initFlags & (TSS_HASH_DEFAULT | TSS_HASH_SHA1 | TSS_HASH_OTHER)) == 0)
			return TSS_E_INVALID_OBJECT_INIT_FLAG;

		objectSize = sizeof (TCPA_HASH_OBJECT);
		*phObject = addObject(hContext, objectType);
		if (*phObject == 0)
			return TSS_E_INTERNAL_ERROR;

		/* hashData is implicitly set to NULL by calling calloc here as is
		 * hashUpdateSize and hashUpdateBuffer.
		 */
		object = calloc(1, objectSize);
		if (object == NULL) {
			LogError("calloc of %d bytes failed.", objectSize);
			return TSS_E_OUTOFMEMORY;
		}

		hashObj = (TCPA_HASH_OBJECT *)object;

		if ((initFlags & TSS_HASH_SHA1) || (initFlags & TSS_HASH_DEFAULT)) {
			hashObj->hashType = TSS_HASH_SHA1;
			hashObj->hashSize = 20;
		} else if (initFlags & TSS_HASH_OTHER) {
			hashObj->hashType = TSS_HASH_OTHER;
			hashObj->hashSize = 0;
		} else {
			free(object);
			return TSS_E_INVALID_OBJECT_INIT_FLAG;
		}
		break;
	default:
		LogDebug1("Invalid Object type");
		return TSS_E_INVALID_OBJECT_TYPE;
		break;
	}

	LogDebug1("Setting Object into tables");
	if ((result = setObject(*phObject, object, objectSize))) {
		free(object);
		return TSS_E_INTERNAL_ERROR;
	}

	free(object);

	LogDebug1("Done creating Object");

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_CloseObject(TSS_HCONTEXT hContext,	/*  in */
			 TSS_HOBJECT hObject	/*  in */
    )
{
	TSS_RESULT result = 0;
	AnObject *anObject;
	TCPA_RSAKEY_OBJECT *rsaObj;
	TCS_CONTEXT_HANDLE tcsContext;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_2(hContext, hObject, &tcsContext)))
		return result;

	switch (getObjectTypeByHandle(hObject)) {	/* using policy object to derefference first element */
	case 0:
		result = TSS_E_INTERNAL_ERROR;
		break;
	case TSS_OBJECT_TYPE_RSAKEY:

		anObject = getAnObjectByHandle(hObject);
		if (anObject == NULL || anObject->memPointer == NULL) {
			LogError("No object found with handle matching 0x%x", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		rsaObj = anObject->memPointer;

		if (rsaObj->privateKey.Privlen != 0)
			free_tspi(tcsContext, rsaObj->privateKey.Privkey);
		if (rsaObj->tcpaKey.algorithmParms.parmSize != 0)
			free_tspi(tcsContext, rsaObj->tcpaKey.algorithmParms.parms);
		if (rsaObj->tcpaKey.encSize != 0)
			free_tspi(tcsContext, rsaObj->tcpaKey.encData);
		if (rsaObj->tcpaKey.PCRInfoSize != 0)
			free_tspi(tcsContext, rsaObj->tcpaKey.PCRInfo);
		if (rsaObj->tcpaKey.pubKey.keyLength != 0)
			free_tspi(tcsContext, rsaObj->tcpaKey.pubKey.key);
		break;
	case TSS_OBJECT_TYPE_PCRS:
		/* need to free components of this object */
		break;
	default:		/* ---  Everything else...just continue */
		break;
	}
	/* ---  All objects do this */
	removeObject(hObject);

/* 	if( objectBuffer != NULL ) */
/* 		free( objectBuffer ); */
	return result;
}

TSS_RESULT
Tspi_Context_GetTpmObject(TSS_HCONTEXT hContext,	/*  in */
			  TSS_HTPM * phTPM	/*  out */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	LogDebug1("Tspi_GetTpmObject");

	if (phTPM == NULL)
		return TSS_E_BAD_PARAMETER;

	for (;;) {
		if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
			break;	/* return result; */

		if ((result = internal_CheckContext_1(hContext, &tcsContext)))
			break;	/* return result; */

		result = obj_getTpmObject(tcsContext, phTPM);

		break;
	}
	LogDebug("Leaving GetTpmObject with result %.8X", result);
	return result;
}

TSS_RESULT
internal_GetCap(TCS_CONTEXT_HANDLE hContext, TSS_FLAG capArea, UINT32 subCap,
		UINT32 * respSize, BYTE ** respData)
{
	UINT16 offset = 0;
	TSS_VERSION version = INTERNAL_CAP_TSP_VERSION;

	LogDebug1("internal_GetCap");
	if (capArea == TSS_TSPCAP_VERSION) {
		*respData = calloc_tspi(hContext, 4);
		LoadBlob_TSS_VERSION(&offset, *respData, version);
		*respSize = offset;
	} else if (capArea == TSS_TSPCAP_ALG) {
		*respSize = 1;
		*respData = calloc_tspi(hContext, 1);
		switch (subCap) {
		case TSS_ALG_RSA:
			(*respData)[0] = INTERNAL_CAP_TSP_ALG_RSA;
			break;
		case TSS_ALG_AES:
			(*respData)[0] = INTERNAL_CAP_TSP_ALG_AES;
			break;
		case TSS_ALG_SHA:
			(*respData)[0] = INTERNAL_CAP_TSP_ALG_SHA;
			break;
		case TSS_ALG_HMAC:
			(*respData)[0] = INTERNAL_CAP_TSP_ALG_HMAC;
			break;
		case TSS_ALG_DES:
			(*respData)[0] = INTERNAL_CAP_TSP_ALG_DES;
			break;
		case TSS_ALG_3DES:
			(*respData)[0] = INTERNAL_CAP_TSP_ALG_3DES;
			break;
		default:
			try_FreeMemory(*respData);
			return TSS_E_BAD_PARAMETER;
		}
/*		if( subCap == TSS_ALG_RSA ||
			subCap == TSS_ALG_SHA )
		{
			*respData = calloc_tspi( hContext, 1 );
			*respSize = 1;
			(*respData)[0] = TRUE;
		}
		else
		{
			*respData = calloc_tspi( hContext, 1 );
			*respSize = 1;
			(*respData)[0] = FALSE;
		}
		*/
	} else if (capArea == TSS_TSPCAP_PERSSTORAGE) {
		*respData = calloc_tspi(hContext, 1);
		*respSize = 1;
		(*respData)[0] = INTERNAL_CAP_TSP_PERSSTORAGE;
	} else
		return TSS_E_BAD_PARAMETER;

	LogDebug1("leaving internal_GetCap");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetCapability(TSS_HCONTEXT hContext,	/*  in */
			   TSS_FLAG capArea,	/*  in */
			   UINT32 ulSubCapLength,	/*  in */
			   BYTE * rgbSubCap,	/*  in */
			   UINT32 * pulRespDataLength,	/*  out */
			   BYTE ** prgbRespData	/*  out */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;
	UINT32 subCap;

	if (prgbRespData == NULL || pulRespDataLength == NULL )
		return TSS_E_BAD_PARAMETER;

	if (rgbSubCap == NULL && ulSubCapLength != 0)
		return TSS_E_BAD_PARAMETER;

	if (ulSubCapLength > sizeof(UINT32))
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_Context_GetCap");
	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_1(hContext, &tcsContext)))
		return result;

	switch (capArea) {
		case TSS_TSPCAP_ALG:
		case TSS_TSPCAP_VERSION:
		case TSS_TSPCAP_PERSSTORAGE:
			LogDebug1("Dectected to be TSP query");
			if (capArea == TSS_TSPCAP_ALG) {
				if (ulSubCapLength != sizeof(UINT32) && rgbSubCap)
					return TSS_E_BAD_PARAMETER;
			}

			result = internal_GetCap(hContext, capArea, *(UINT32 *)rgbSubCap,
							pulRespDataLength, prgbRespData);
			break;
		case TSS_TCSCAP_ALG:
		case TSS_TCSCAP_VERSION:
		case TSS_TCSCAP_CACHING:
		case TSS_TCSCAP_PERSSTORAGE:
			LogDebug1("Dectected to be TCS query");
			if (capArea == TSS_TCSCAP_ALG) {
				if (ulSubCapLength != sizeof(UINT32) && rgbSubCap)
					return TSS_E_BAD_PARAMETER;
			}

			subCap = endian32(*(UINT32 *)rgbSubCap);

			result = TCS_GetCapability(tcsContext,
							capArea,
							ulSubCapLength,
							(BYTE *)&subCap,
							pulRespDataLength,
							prgbRespData);
			break;
		default:
			result = TSS_E_BAD_PARAMETER;
			break;
	}

	LogDebug1("Leaving Tspi_Context_GetCap");
	return result;
}

TSS_RESULT
Tspi_Context_LoadKeyByBlob(TSS_HCONTEXT hContext,	/*  in */
			   TSS_HKEY hUnwrappingKey,	/*  in */
			   UINT32 ulBlobLength,	/*  in */
			   BYTE * rgbBlobData,	/*  in */
			   TSS_HKEY * phKey	/*  out */
    )
{

	TCS_AUTH auth;
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
	BOOL useAuth;
	TCS_AUTH *pAuth;
	TSS_FLAG initFlags;
	UINT16 realKeyBlobSize;

	if (phKey == NULL || rgbBlobData == NULL )
		return TSS_E_BAD_PARAMETER;

	LogDebug1("Tspi_Context_LoadKeyByBlob");

	/* ------------------------------------- */
	for (;;) {
		if ((result = internal_CheckObjectType_2(hContext,
					       TSS_OBJECT_TYPE_CONTEXT,
					       hUnwrappingKey, TSS_OBJECT_TYPE_RSAKEY)))
			break;	/* return result; */

		if ((result = internal_CheckContext_2(hContext, hUnwrappingKey, &tcsContext)))
			break;	/* return result; */

		/* ---  Get the Parent Handle */
		parentTCSKeyHandle = getTCSKeyHandle(hUnwrappingKey);
		if (parentTCSKeyHandle == 0) {
			LogDebug1("parentTCSKeyHandle == 0 - Failure");
			result = TSS_E_KEY_NOT_LOADED;
			break;
		}

		offset = 0;
		UnloadBlob_KEY(tcsContext, &offset, rgbBlobData, &keyContainer);
		realKeyBlobSize = offset;

		if ((result = Tspi_GetPolicyObject(hUnwrappingKey, TSS_POLICY_USAGE, &hPolicy)))
			break;	/* return result; */

		if ((result = policy_UsesAuth(hPolicy, &useAuth)))
			break;

		break;
	}
	if (result) {
		LogDebug("Failed with result %.8X", result);
		return result;
	}
	/* ------------------------------------- */
	if (useAuth) {

		/* ---  Create the Authorization */
		offset = 0;
		LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		LoadBlob(&offset, ulBlobLength, blob, rgbBlobData);
		TSS_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);

		if ((result = secret_PerformAuth_OIAP(hPolicy, digest, &auth)))
			return result;

		pAuth = &auth;
	} else {
		pAuth = NULL;
	}

	/* ---  Do the command */
	if ((result = TCSP_LoadKeyByBlob(tcsContext,	/* hContext,                // in */
					parentTCSKeyHandle,	/* hUnwrappingKey,          // in */
					ulBlobLength,	/*  in */
					rgbBlobData,	/*  in */
					pAuth,	/* &auth,                // in, out */
					&myTCSKeyHandle,	/*  out */
					&keyslot)))
		return result;

	if (useAuth) {
		/* ---  Validate return auth */
		offset = 0;
		LoadBlob_UINT32(&offset, result, blob);
		LoadBlob_UINT32(&offset, TPM_ORD_LoadKey, blob);
		LoadBlob_UINT32(&offset, keyslot, blob);
		TSS_Hash(TSS_HASH_SHA1, offset, blob, digest.digest);

		if ((result = secret_ValidateAuth_OIAP(hPolicy, digest, &auth)))
			return result;
	}
#if 0
	else {
		//---   Do the command
		if (result = TCSP_LoadKeyByBlob(tcsContext,	//hContext,         // in
						parentTCSKeyHandle,	//hUnwrappingKey,           // in
						ulBlobLength,	// in
						rgbBlobData,	// in
						NULL,	// in, out
						&myTCSKeyHandle,	// out
						&keyslot))
			return result;
	}
#endif

	/* ---  Create a new Object */
	initFlags = 0;
	if (keyContainer.pubKey.keyLength == 0x100)
		initFlags |= TSS_KEY_SIZE_2048;
	else if (keyContainer.pubKey.keyLength == 0x80)
		initFlags |= TSS_KEY_SIZE_1024;
	else if (keyContainer.pubKey.keyLength == 0x40)
		initFlags |= TSS_KEY_SIZE_512;

	if (keyContainer.keyUsage == TSS_KEYUSAGE_STORAGE)
		initFlags |= TSS_KEY_TYPE_STORAGE;
	else
		initFlags |= TSS_KEY_TYPE_SIGNING;	/* loading the blob will fix this back to what it should be. */
/*
	if( keyContainer.pubKey.keyLength == 0x100 )
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_SIZE_2048, phKey );
	else if( keyContainer.pubKey.keyLength == 0x80 )
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_SIZE_1024, phKey );
	else if( keyContainer.pubKey.keyLength == 0x40 )
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_SIZE_512, phKey );
*/
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, phKey);

	if (result) {
		LogDebug1("Failed create object");
		return TSS_E_INTERNAL_ERROR;
	}

/* 	Tspi_SetAttribData( *phKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, ulBlobLength, rgbBlobData ); */
	if ((result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
			       TSS_TSPATTRIB_KEYBLOB_BLOB, realKeyBlobSize, rgbBlobData))) {
		LogDebug1("Key loaded but failed to setup the key object correctly");
		return TSS_E_INTERNAL_ERROR;
	}

	addKeyHandle(myTCSKeyHandle, *phKey);

	LogDebug1("Leaving Loadkeybyblob");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_LoadKeyByUUID(TSS_HCONTEXT hContext,	/*  in */
			   TSS_FLAG persistentStorageType,	/*  in */
			   TSS_UUID uuidData,	/*  in */
			   TSS_HKEY * phKey	/*  out */
    )
{
	TSS_RESULT result;
	TSS_UUID parentUUID;
	TCS_CONTEXT_HANDLE tcsContext;
	TCPA_KEY theKey;
	UINT16 offset;
	UINT32 keyBlobSize;
	BYTE *keyBlob;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_FLAG initFlag;
	TCS_KEY_HANDLE parentTCSKeyHandle;
	TCPA_KEY_HANDLE keySlot;
	UINT32 parentPSType;
	TSS_HKEY parentTspHandle;

	if (phKey == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_1(hContext, &tcsContext)))
		return result;

	*phKey = 0;

	for (;;) {
		/* ---  This key is in the System Persistant storage */
		if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
			LogDebug1("PS type SYSTEM");
			if ((result = TCSP_LoadKeyByUUID(tcsContext,
							uuidData,
							NULL,
							&tcsKeyHandle)) == TCS_E_KM_LOADFAILED) {
				break;
			}

			if ((result = TCS_GetRegisteredKeyBlob(tcsContext, uuidData, &keyBlobSize, &keyBlob)))
				break;
		}
		/* ---  This key is in the User Persistent Storage */
		else if (persistentStorageType == TSS_PS_TYPE_USER) {
			LogDebug1("USER PS TYPE");
			/* ---  Get my KeyBlob */
			if ((result = keyreg_GetKeyByUUID(tcsContext, &uuidData, &keyBlobSize, &keyBlob)))
				break;	/* return TSS_E_INTERNAL_ERROR; */

			/* ---  Get my Parent's UUID */
			if ((result = keyreg_GetParentUUIDByUUID(&uuidData, &parentUUID)))
				break;	/* return TSS_E_INTERNAL_ERROR; */

			/* ---  Get my Parent's Storage Type */
			if ((result = keyreg_GetParentPSTypeByUUID(&uuidData, &parentPSType)))
				break;	/* return TSS_E_INTERNAL_ERROR; */

			/******************************************
			 *	If the parent is system persistant, then just call the TCS Load.
			 *		If the parent is in user storage, then we need to call 
			 *		Tspi_LoadKeyByUUID and get a parentKeyObject.  This object 
			 *		can then be translated into a TCS_KEY_HANDLE.
			 ******************************************/

			LogDebug1("Checking Parent PS TYPE");
			if (parentPSType == TSS_PS_TYPE_SYSTEM) {
				LogDebug1("Parent is PS SYSTEM");
				if ((result = TCSP_LoadKeyByUUID(tcsContext, parentUUID,
							       NULL, &parentTCSKeyHandle)))
					break;
/* 					return TSS_E_INTERNAL_ERROR; */
			} else if (parentPSType == TSS_PS_TYPE_USER) {
				LogDebug1("Parent is PS USER, load parent first");
				/* ---  Get the UUID to call the TSPI function */
				/*                      ConvertGUIDToUUID( parentGuidParam, &parentUUID ); */
				if ((result = Tspi_Context_LoadKeyByUUID(hContext,
								       parentPSType,
								       parentUUID, &parentTspHandle)))
					break;	/* return result; */

				/* ---  Get the parentTCS Key Handle from our table */
				parentTCSKeyHandle = getTCSKeyHandle(parentTspHandle);
				if (parentTCSKeyHandle == 0) {
					LogDebug1("Can't find parent in table after loading - Unexpected");
					result = TSS_E_INTERNAL_ERROR;	/* return TSS_E_INTERNAL_ERROR; */
				}

				/* ---  Close the object since it's not needed anymore */
				Tspi_Context_CloseObject(hContext, parentTspHandle);
			} else {
				LogDebug1("Invliad PS type parent");
				result = TSS_E_BAD_PARAMETER;
				break;
			}	/* return TSS_E_INTERNAL_ERROR; */

			/*******************************
			 *	Now the parent is loaded and we have the parent key handle
			 *		call the TCS to actually load the key now.
			 ******************************/

			if ((result = TCSP_LoadKeyByBlob(tcsContext, parentTCSKeyHandle,
					       keyBlobSize, keyBlob, NULL, &tcsKeyHandle, &keySlot)))
				return result;

			/* ---  Dont' care about keySlot */

		} else {
			LogDebug1("Invalid PS TYPE");
			result = TSS_E_BAD_PARAMETER;
			break;
		}
		break;
	}
	if (result) {
		/* convert the TCS layer return code to a TSP */
		if (result == TCS_E_KEY_NOT_REGISTERED)
			result = TSS_E_PS_KEY_NOTFOUND;
		LogDebug("Failed with result %.8X", result);
		return result;
	}
	/**************************
	 *	Now the key is loaded.  Need to create a Key
	 *		object and put the gus in there
	 ****************************/
	LogDebug1("Key is loaded, create a new key object for the user");

	offset = 0;
	UnloadBlob_KEY(tcsContext, &offset, keyBlob, &theKey);
	initFlag = 0;

	if (theKey.pubKey.keyLength == 0x100)
		initFlag |= TSS_KEY_SIZE_2048;
	else if (theKey.pubKey.keyLength == 0x80)
		initFlag |= TSS_KEY_SIZE_1024;
	else if (theKey.pubKey.keyLength == 0x40)
		initFlag |= TSS_KEY_SIZE_512;

	/* ---  Create the keyObject */
	if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlag, phKey)))
		return result;

	/* ---  Update our table to bind the tcsKeyHandle to this TspKeyHandle */
	addKeyHandle(tcsKeyHandle, *phKey);

	/* ---  Stuff the data into the object */
	if ((result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
				keyBlobSize, keyBlob)))
		return result;

	keyreg_SetUUIDOfKeyObject(*phKey, uuidData, persistentStorageType);

	LogDebug1("Done with LoadByUUID");
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_RegisterKey(TSS_HCONTEXT hContext,	/*  in  */
			 TSS_HKEY hKey,	/*  in */
			 TSS_FLAG persistentStorageType,	/*  in */
			 TSS_UUID uuidKey,	/*  in */
			 TSS_FLAG persistentStorageTypeParent,	/*  in */
			 TSS_UUID uuidParentKey	/*  in */
    )
{

	BYTE *keyBlob;
	UINT32 keyBlobSize;
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsContext;

	if ((result = internal_CheckObjectType_2(hContext, TSS_OBJECT_TYPE_CONTEXT, hKey,
				       TSS_OBJECT_TYPE_RSAKEY)))
		return result;

	if ((result = internal_CheckContext_2(hContext, hKey, &tcsContext)))
		return result;

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		if (persistentStorageTypeParent == TSS_PS_TYPE_USER)
			return TSS_E_NOTIMPL;
		else if (persistentStorageTypeParent == TSS_PS_TYPE_SYSTEM) {
			if ((result = Tspi_GetAttribData(hKey,
							TSS_TSPATTRIB_KEY_BLOB,
							TSS_TSPATTRIB_KEYBLOB_BLOB,
							&keyBlobSize, &keyBlob)))
				return result;


			if ((result = TCS_RegisterKey(tcsContext,
						     uuidParentKey,
						     uuidKey,
						     keyBlobSize,
						     keyBlob,
						     0,
						     NULL))) {
				/* convert a TCS return to a TSP return */
				if (result == TCS_E_KEY_NOT_REGISTERED)
					result = TSS_E_PS_KEY_NOTFOUND;

				return result;
			}
		} else
			return TSS_E_BAD_PARAMETER;

	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		if ((result = Tspi_GetAttribData(hKey,
						TSS_TSPATTRIB_KEY_BLOB,
						TSS_TSPATTRIB_KEYBLOB_BLOB, &keyBlobSize, &keyBlob)))
			return result;

		if (keyreg_IsKeyAlreadyRegistered(keyBlobSize, keyBlob))
			return TSS_E_KEY_ALREADY_REGISTERED;

		if ((result = keyreg_WriteKeyToFile(&uuidKey, &uuidParentKey,
					  persistentStorageTypeParent, keyBlobSize, keyBlob)))
			return result;
	} else
		return TSS_E_BAD_PARAMETER;

	keyreg_SetUUIDOfKeyObject(hKey, uuidKey, persistentStorageType);
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_UnregisterKey(TSS_HCONTEXT hContext,		/* in */
			   TSS_FLAG persistentStorageType,	/* in */
			   TSS_UUID uuidKey,			/* in */
			   TSS_HKEY *phKey			/* out */
    )
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
#if 0
	TCS_KEY_HANDLE tcsKeyHandle;
	TCS_AUTH auth;
	BYTE hashBlob[512];
	UINT16 offset;
	TCPA_DIGEST digest;
	TSS_HPOLICY hPolicy;
	UINT32 pubKeySize;
	BYTE *pubKeyBlob;
	TCPA_PUBKEY pubKeyContainer;
	BOOL usesAuth;
	TSS_HKEY hTempKey;
#endif

	if (phKey == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		if ((result = internal_CheckContext_1(hContext, &tcsContext)))
			return result;

		/* get the key first, so it doesn't disappear when we unregister it */
		if ((result = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, uuidKey, phKey)))
			return result;

		/* now unregister it */
		if ((result = TCSP_UnregisterKey(tcsContext, uuidKey))) {
			/* convert the TCS return code to a TSP return */
			if (result == TCS_E_KEY_NOT_REGISTERED)
				result = TSS_E_PS_KEY_NOTFOUND;
			return result;
		}
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		/* get the key first, so it doesn't disappear when we unregister it */
		if ((result = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_USER, uuidKey, phKey)))
			return result;

		/* now unregister it */
		if ((result = keyreg_RemoveKey(NULL_TCS_HANDLE, &uuidKey))) {
			return result;
		}
	} else {
		return TSS_E_BAD_PARAMETER;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetKeyByUUID(TSS_HCONTEXT hContext,	/*  in */
			  TSS_FLAG persistentStorageType,	/*  in */
			  TSS_UUID uuidData,	/*  in */
			  TSS_HKEY * phKey	/*  out */
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
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_1(hContext, &tcsContext)))
		return result;

	*phKey = 0;
	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		if ((result = TCS_GetRegisteredKeyBlob(tcsContext, uuidData, &keyBlobSize, &keyBlob))) {
			/* convert TCS return to a TSS return */
			if (result == TCS_E_KEY_NOT_REGISTERED)
				result = TSS_E_PS_KEY_NOTFOUND;
			return result;
		}
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		if ((result = keyreg_GetKeyByUUID(tcsContext, &uuidData, &keyBlobSize, &keyBlob))) {
			/* convert TCS return to a TSS return */
			if (result == TCS_E_KEY_NOT_REGISTERED)
				result = TSS_E_PS_KEY_NOTFOUND;
			return result;
		}
	} else
		return TSS_E_BAD_PARAMETER;

	offset = 0;
	UnloadBlob_KEY(tcsContext, &offset, keyBlob, &theKey);

	if (theKey.pubKey.keyLength == 0x100)
		initFlag |= TSS_KEY_SIZE_2048;
	else if (theKey.pubKey.keyLength == 0x80)
		initFlag |= TSS_KEY_SIZE_1024;
	else if (theKey.pubKey.keyLength == 0x40)
		initFlag |= TSS_KEY_SIZE_512;

	if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlag, phKey)))
		return result;

	if ((result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
				keyBlobSize, keyBlob)))
		return result;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetKeyByPublicInfo(TSS_HCONTEXT hContext,	/*  in */
				TSS_FLAG persistentStorageType,	/*  in */
				TSS_ALGORITHM_ID algID,	/*  in */
				UINT32 ulPublicInfoLength,	/*  in */
				BYTE * rgbPublicInfo,	/*  in */
				TSS_HKEY * phKey	/*  out */
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
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_1(hContext, &tcsContext)))
		return result;

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		if (algID == TSS_ALG_RSA)
			tcsAlgID = TCPA_ALG_RSA;
		else {
			LogError1("Algorithm ID was not type RSA.");
			return TSS_E_BAD_PARAMETER;/* not sure about other alg's */
		}

		if ((result = TCSP_GetRegisteredKeyByPublicInfo(tcsContext,
							       tcsAlgID,
							       ulPublicInfoLength,
							       rgbPublicInfo,
							       &keyBlobSize, &keyBlob)))
			return result;

		// need to setup the init flags of the create object based on the size of the blob's pubkey
		offset = 0;
		UnloadBlob_KEY(tcsContext, &offset, keyBlob, &keyContainer);
		if (keyContainer.pubKey.keyLength == 0x100)
			flag |= TSS_KEY_SIZE_2048;
		else if (keyContainer.pubKey.keyLength == 0x80)
			flag |= TSS_KEY_SIZE_1024;
		else if (keyContainer.pubKey.keyLength == 0x40)
			flag |= TSS_KEY_SIZE_512;
		else {
			LogError1("pubkey.keylength was not a known keylength.");
			Tspi_Context_FreeMemory(hContext, keyBlob);
			destroy_key_refs(&keyContainer);
			return TSS_E_INTERNAL_ERROR;
		}

		if (keyContainer.keyUsage == TSS_KEYUSAGE_SIGN)
			flag |= TSS_KEY_TYPE_SIGNING;
		else if (keyContainer.keyUsage == TSS_KEYUSAGE_STORAGE)
			flag |= TSS_KEY_TYPE_STORAGE;
		else if (keyContainer.keyUsage == TSS_KEYUSAGE_IDENTITY)
			flag |= TSS_KEY_TYPE_IDENTITY;
		else if (keyContainer.keyUsage == TSS_KEYUSAGE_AUTHCHANGE)
			flag |= TSS_KEY_TYPE_AUTHCHANGE;
		else if (keyContainer.keyUsage == TSS_KEYUSAGE_BIND)
			flag |= TSS_KEY_TYPE_BIND;
		else if (keyContainer.keyUsage == TSS_KEYUSAGE_LEGACY)
			flag |= TSS_KEY_TYPE_LEGACY;

		if (keyContainer.authDataUsage == 0x00)
			flag |= TSS_KEY_NO_AUTHORIZATION;
		else if (keyContainer.authDataUsage == 0x01)
			flag |= TSS_KEY_AUTHORIZATION;
		else {
			LogError1("keyContainer.authDataUsage was not 0 or 1");
			Tspi_Context_FreeMemory(hContext, keyBlob);
			return TSS_E_INTERNAL_ERROR;
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
		if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					      flag, &keyOutHandle))) {
			Tspi_Context_FreeMemory(hContext, keyBlob);
			destroy_key_refs(&keyContainer);
			return result;
		}
		/* ---  Stick the info into this net KeyObject */
		if ((result = Tspi_SetAttribData(keyOutHandle, TSS_TSPATTRIB_KEY_BLOB,
				       TSS_TSPATTRIB_KEYBLOB_BLOB, keyBlobSize, keyBlob))) {
			Tspi_Context_FreeMemory(hContext, keyBlob);
			destroy_key_refs(&keyContainer);
			return result;
		}

		*phKey = keyOutHandle;
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		return TSS_E_NOTIMPL;	/* TODO */
	} else
		return TSS_E_BAD_PARAMETER;

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_GetRegisteredKeysByUUID(TSS_HCONTEXT hContext,	/*  in */
				     TSS_FLAG persistentStorageType,	/*  in */
				     TSS_UUID * pUuidData,	/*  in */
				     UINT32 * pulKeyHierarchySize,	/*  out */
				     TSS_KM_KEYINFO ** ppKeyHierarchy	/*  out */
    )
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcs_context;

	if (pulKeyHierarchySize == NULL || ppKeyHierarchy == NULL)
		return TSS_E_BAD_PARAMETER;

	if ((result = internal_CheckObjectType_1(hContext, TSS_OBJECT_TYPE_CONTEXT)))
		return result;

	if ((result = internal_CheckContext_1(hContext, &tcs_context)))
		return result;

	if (persistentStorageType == TSS_PS_TYPE_SYSTEM) {
		return TCS_EnumRegisteredKeys(tcs_context,
							pUuidData,
							pulKeyHierarchySize,
							ppKeyHierarchy);
	} else if (persistentStorageType == TSS_PS_TYPE_USER) {
		return TSS_E_NOTIMPL;	/* to do */
	} else
		return TSS_E_BAD_PARAMETER;

	return TSS_SUCCESS;
}
