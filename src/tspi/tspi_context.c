
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "tcs_tsp.h"
#include "tspps.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "obj.h"


TSS_RESULT
Tspi_Context_Create(TSS_HCONTEXT * phContext)	/* out */
{
	if (phContext == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	return obj_context_add(phContext);
}

TSS_RESULT
Tspi_Context_Close(TSS_HCONTEXT tspContext)	/* in */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	/* Get the TCS context, if we're connected */
	if ((result = obj_context_is_connected(tspContext, &tcsContext)))
		return result;

	/* Have the TCS do its thing */
	TCS_CloseContext(tcsContext);

	/* Note: Memory that was returned to the app that was alloc'd by this
	 * context isn't free'd here.  Any memory that the app doesn't explicitly
	 * free is left for it to free itself. */

	/* Destroy all objects */
	obj_close_context(tspContext);

	/* close the ps file */
	PS_close();

	/* We're not a connected context, so just exit */
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Context_Connect(TSS_HCONTEXT tspContext,	/* in */
		     UNICODE *wszDestination)	/* in */
{
	TSS_RESULT result;
	TCS_CONTEXT_HANDLE tcsHandle;
	BYTE *machine_name = NULL;
	TSS_HPOLICY hPolicy;
	TSS_HOBJECT hTpm;
	UINT32 string_len = 0;

	/* see if we've already called connect with this context */
	if ((result = obj_context_is_connected(tspContext, &tcsHandle)) == TSS_SUCCESS) {
		LogError("attempted to call %s on an already connected "
			 "context!", __FUNCTION__);
		return TSPERR(TSS_E_CONNECTION_FAILED);
	} else if (result != TSPERR(TSS_E_NO_CONNECTION)) {
		return result;
	}

	if (wszDestination == NULL) {
		if ((result = obj_context_get_machine_name(tspContext,
							   &string_len,
							   &machine_name)))
			return result;

		if ((result = TCS_OpenContext_RPC(machine_name, &tcsHandle,
						  CONNECTION_TYPE_TCP_PERSISTANT)))
			return result;
	} else {
		if ((machine_name =
		    Trspi_UNICODE_To_Native((BYTE *)wszDestination, NULL)) == NULL) {
			LogError("Error converting hostname to UTF-8");
			return TSPERR(TSS_E_INTERNAL_ERROR);
		}

		if ((result = TCS_OpenContext_RPC(machine_name, &tcsHandle,
						CONNECTION_TYPE_TCP_PERSISTANT)))
			return result;

		if ((result = obj_context_set_machine_name(tspContext, machine_name,
						strlen((char *)machine_name)+1)))
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
			BYTE * rgbMemory)		/* in */
{
	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	return free_tspi(tspContext, rgbMemory);
}

TSS_RESULT
Tspi_Context_GetDefaultPolicy(TSS_HCONTEXT tspContext,	/* in */
			      TSS_HPOLICY * phPolicy)	/* out */
{
	if (phPolicy == NULL )
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	return obj_context_get_policy(tspContext, phPolicy);
}

TSS_RESULT
Tspi_Context_CreateObject(TSS_HCONTEXT tspContext,	/* in */
			  TSS_FLAG objectType,		/* in */
			  TSS_FLAG initFlags,		/* in */
			  TSS_HOBJECT * phObject)	/* out */
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
#ifdef TSS_BUILD_RSAKEY_LIST
	case TSS_OBJECT_TYPE_RSAKEY:
		/* If other flags are set that disagree with the SRK, this will
		 * help catch that conflict in the later steps */
		if (initFlags & TSS_KEY_TSP_SRK) {
			initFlags |= (TSS_KEY_TYPE_STORAGE |
				      TSS_KEY_NOT_MIGRATABLE |
				      TSS_KEY_NON_VOLATILE | TSS_KEY_SIZE_2048 |
				      TSS_KEY_AUTHORIZATION);
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
#endif
#ifdef TSS_BUILD_ENCDATA_LIST
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

		result = obj_encdata_add(tspContext, (initFlags & TSS_ENCDATA_TYPE_MASK), phObject);
		break;
#endif
#ifdef TSS_BUILD_PCRS_LIST
	case TSS_OBJECT_TYPE_PCRS:
		/* There are no valid flags for a PCRs object */
		if (initFlags & ~(0UL))
			return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);

		result = obj_pcrs_add(tspContext, phObject);
		break;
#endif
#ifdef TSS_BUILD_HASH_LIST
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
#endif
#ifdef TSS_BUILD_DAA
	case TSS_OBJECT_TYPE_DAA:
		/* There are no valid flags for a DAA object */
		if (initFlags & ~(0UL))
			return TSPERR(TSS_E_INVALID_OBJECT_INITFLAG);

		result = obj_daa_add(tspContext, phObject);
		break;
#endif
	default:
		LogDebug("Invalid Object type");
		return TSPERR(TSS_E_INVALID_OBJECT_TYPE);
		break;
	}

	return result;
}

TSS_RESULT
Tspi_Context_CloseObject(TSS_HCONTEXT tspContext,	/* in */
			 TSS_HOBJECT hObject)		/* in */
{
	TSS_RESULT result;

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if (obj_is_pcrs(hObject)) {
#ifdef TSS_BUILD_PCRS_LIST
		result = obj_pcrs_remove(hObject, tspContext);
#endif
	} else if (obj_is_encdata(hObject)) {
#ifdef TSS_BUILD_ENCDATA_LIST
		result = obj_encdata_remove(hObject, tspContext);
#endif
	} else if (obj_is_hash(hObject)) {
#ifdef TSS_BUILD_HASH_LIST
		result = obj_hash_remove(hObject, tspContext);
#endif
	} else if (obj_is_rsakey(hObject)) {
#ifdef TSS_BUILD_RSAKEY_LIST
		result = obj_rsakey_remove(hObject, tspContext);
#endif
	} else if (obj_is_policy(hObject)) {
		result = obj_policy_remove(hObject, tspContext);
	} else {
		result = TSPERR(TSS_E_INVALID_HANDLE);
	}

	return result;
}

TSS_RESULT
Tspi_Context_GetTpmObject(TSS_HCONTEXT tspContext,	/*  in */
			  TSS_HTPM * phTPM)		/*  out */
{
	if (phTPM == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_context(tspContext))
		return TSPERR(TSS_E_INVALID_HANDLE);

	return obj_tpm_get(tspContext, phTPM);
}

