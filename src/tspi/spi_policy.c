
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

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "obj.h"

TSS_RESULT
Tspi_Policy_SetSecret(TSS_HPOLICY hPolicy,	/*  in */
		      TSS_FLAG secretMode,	/*  in */
		      UINT32 ulSecretLength,	/*  in */
		      BYTE * rgbSecret	/*  in */
    )
{
	TSS_RESULT result;
	TSS_HCONTEXT tspContext;
	AnObject *anObject;

	if ((result = obj_checkType_1(hPolicy, TSS_OBJECT_TYPE_POLICY)))
		return result;

	if ((tspContext = obj_getTspContext(hPolicy)) == NULL_HCONTEXT)
		return TSS_E_INTERNAL_ERROR;

	anObject = getAnObjectByHandle(tspContext);
	if (anObject == NULL || anObject->memPointer == NULL)
		return TSS_E_INTERNAL_ERROR;

	if (((TCPA_CONTEXT_OBJECT *) anObject->memPointer)->silentMode ==
	    TSS_TSPATTRIB_CONTEXT_SILENT && secretMode == TSS_SECRET_MODE_POPUP)
		return TSS_E_SILENT_CONTEXT;

	if (secretMode == TSS_SECRET_MODE_SHA1 || secretMode == TSS_SECRET_MODE_NONE) {
		if ((result = internal_SetSecret(hPolicy, secretMode, ulSecretLength, rgbSecret, FALSE)))
			return result;
	} else {
		if ((result = internal_SetSecret(hPolicy, secretMode, ulSecretLength, rgbSecret, TRUE)))
			return result;
	}
	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_Policy_FlushSecret(TSS_HPOLICY hPolicy	/*  in */
    )
{
	TSS_RESULT result;
	if ((result = obj_checkType_1(hPolicy, TSS_OBJECT_TYPE_POLICY)))
		return result;

	return internal_FlushSecret(hPolicy);
}

TSS_RESULT
Tspi_Policy_AssignToObject(TSS_HPOLICY hPolicy,	/*  in */
			   TSS_HOBJECT hObject	/*  in */
    )
{
/* 	void* object = NULL; */
/* 	UINT32 objectSize; */
	AnObject *object;
	TSS_RESULT result;
	TCPA_POLICY_OBJECT *policyObject;

	if ((result = obj_checkType_1(hPolicy, TSS_OBJECT_TYPE_POLICY)))
		return result;

	object = getAnObjectByHandle(hPolicy);
	if (object == NULL || object->memPointer == NULL)
		return TSS_E_INVALID_HANDLE;

	policyObject = &((TSP_INTERNAL_POLICY_OBJECT *)object->memPointer)->p;

	switch (getObjectTypeByHandle(hObject)) {
	case 0:
		return TSS_E_INVALID_HANDLE;
		break;
	case TSS_OBJECT_TYPE_POLICY:
	case TSS_OBJECT_TYPE_PCRS:
	case TSS_OBJECT_TYPE_HASH:
		return TSS_E_BAD_PARAMETER;
		break;

	case TSS_OBJECT_TYPE_RSAKEY:

		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		if (policyObject->PolicyType == TSS_POLICY_MIGRATION)
			((TCPA_RSAKEY_OBJECT *) object->memPointer)->migPolicy = hPolicy;
		else if (policyObject->PolicyType == TSS_POLICY_USAGE)
			((TCPA_RSAKEY_OBJECT *) object->memPointer)->usagePolicy = hPolicy;
		else {
			LogError1("Policy type is neither migration nor usage!");
			return TSS_E_INTERNAL_ERROR;
		}

		break;
	case TSS_OBJECT_TYPE_TPM:
		object = getAnObjectByHandle(hObject);
		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}
		((TCPA_TPM_OBJECT *) object->memPointer)->policy = hPolicy;

		break;
	case TSS_OBJECT_TYPE_ENCDATA:

		object = getAnObjectByHandle(hObject);

		if (object == NULL)
			return TSS_E_INVALID_HANDLE;
		if (object->memPointer == NULL) {
			LogError("internal object pointer for handle 0x%x not found!", hObject);
			return TSS_E_INTERNAL_ERROR;
		}

		if (policyObject->PolicyType == TSS_POLICY_MIGRATION) {
			((TCPA_ENCDATA_OBJECT *) object->memPointer)->migPolicy = hPolicy;
		} else if (policyObject->PolicyType == TSS_POLICY_USAGE)
			((TCPA_ENCDATA_OBJECT *) object->memPointer)->usagePolicy = hPolicy;
		else {
			LogError1("Policy type is neither migration nor usage!");
			return TSS_E_INTERNAL_ERROR;
		}

		break;
	}

	return TSS_SUCCESS;
}
