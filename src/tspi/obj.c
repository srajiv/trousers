
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
#include <errno.h>
#include <string.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "log.h"
#include "obj.h"

TSS_HOBJECT
getNextObjectHandle()
{
	pthread_mutex_lock(&handle_lock);

	/* return any object handle except NULL_HOBJECT */
	do {
		nextObjectHandle++;
	} while (nextObjectHandle == NULL_HOBJECT);

	pthread_mutex_unlock(&handle_lock);

	return nextObjectHandle;
}

AnObject *
createNewObject()
{
	AnObject *ret;
	ret = calloc(1, sizeof(AnObject));
	if (!ret)
		LogError("calloc of %d bytes failed: %s", sizeof(AnObject), strerror(errno));
	return ret;
}

AnObject *
concatObjects(AnObject **first, AnObject *second)
{
	AnObject *index;

	pthread_mutex_lock(&objectlist_lock);

	if (*first == NULL)
		*first = second;
	else {
		for (index = *first; index->next; next(index)) ;
		index->next = second;
	}

	pthread_mutex_unlock(&objectlist_lock);

	return *first;
}

AnObject *
getAnObjectByHandle(UINT32 oHandle)
{
	AnObject *index;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; next(index)) {
		if (index->objectHandle == oHandle)
			break;
	}

	pthread_mutex_unlock(&objectlist_lock);

	return index;
}

TSS_HOBJECT
addNewObject(UINT32 contextHandle, UINT32 objectType)
{
	AnObject *object;

	object = createNewObject();
	if (object == NULL) {
		return 0;
	}
	object->objectHandle = getNextObjectHandle();
	if (objectType == TSS_OBJECT_TYPE_CONTEXT) {
		object->tcsContext = contextHandle;
		object->tspContext = object->objectHandle;
	} else {
		object->tspContext = contextHandle;
		internal_GetContextForContextObject(contextHandle, &object->tcsContext);
	}
	object->objectType = objectType;

	concatObjects(&objectList, object);

	return object->objectHandle;
}

TSS_RESULT
setObject(TSS_HOBJECT objectHandle, void *buffer, UINT32 sizeOfBuffer)
{
	AnObject *object;

	object = getAnObjectByHandle(objectHandle);
	if (object == NULL) {
		LogError("object handle 0x%x not found", objectHandle);
		return TSS_E_INVALID_HANDLE;
	}

	pthread_mutex_lock(&objectlist_lock);

	if (object->memPointer != NULL)
		try_FreeMemory(object->memPointer);
	object->memPointer = malloc(sizeOfBuffer);
	if (object->memPointer == NULL) {
		LogError("malloc of %d bytes failed.", sizeOfBuffer);
		pthread_mutex_unlock(&objectlist_lock);
		return TSS_E_OUTOFMEMORY;
	}
	memcpy(object->memPointer, buffer, sizeOfBuffer);
	object->objectSize = sizeOfBuffer;

	pthread_mutex_unlock(&objectlist_lock);

	return TSS_SUCCESS;
}

#if 0
TSS_RESULT
getObject(TSS_HOBJECT objectHandle, void **outBuffer, UINT32 * outSize)
{
	AnObject *object;

	object = getAnObjectByHandle(objectHandle);
	if (object == NULL)
		return TSS_E_INVALID_HANDLE;

	*outBuffer = malloc(object->objectSize);
	if (*outBuffer == NULL) {
		LogError1("Malloc Failure.");
		return TSS_E_OUTOFMEMORY;
	}
	memcpy(*outBuffer, object->memPointer, object->objectSize);
	*outSize = object->objectSize;
	return TSS_SUCCESS;
}
#endif

void
destroyObject(AnObject * object)
{
	if (object == NULL)
		return;

	if (object->memPointer != NULL)
		try_FreeMemory(object->memPointer);

	try_FreeMemory(object);

	return;
}

void
removeObject(TSS_HOBJECT objectHandle)
{
	AnObject *toKill;
	AnObject *prev = NULL;
	AnObject *index;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; prev = index, next(index)) {
		if (index->objectHandle == objectHandle) {
			toKill = index;
			if (prev == NULL)
				objectList = toKill->next;
			else
				prev->next = toKill->next;
			destroyObject(toKill);
			break;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);
}

void
destroyObjectsByContext(TCS_CONTEXT_HANDLE tcsContext)
{
	AnObject *index;
	AnObject *next = NULL;
	AnObject *toKill;
	AnObject *prev = NULL;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; ) {
		next = index->next;
		if (index->tcsContext == tcsContext) {
			toKill = index;
			if (prev == NULL) {
				objectList = toKill->next;
			} else {
				prev->next = toKill->next;
			}
			destroyObject(toKill);
			index = next;
		} else {
			prev = index;
			index = next;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);
}

UINT32
getObjectTypeByHandle(TSS_HOBJECT objectHandle)
{
	AnObject *object;

	object = getAnObjectByHandle(objectHandle);
	if (object == NULL)
		return 0;
	return object->objectType;
}

TSS_RESULT
obj_getTpmObject(TCS_CONTEXT_HANDLE tcsContext, TSS_HOBJECT * out)
{
	AnObject *index;
	TSS_RESULT result = TSS_E_INVALID_HANDLE;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; next(index)) {
		if (index->tcsContext == tcsContext && index->objectType == TSS_OBJECT_TYPE_TPM) {
			*out = index->objectHandle;
			result = TSS_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);

	return result;
}

TCS_CONTEXT_HANDLE
obj_getContextForObject(TSS_HOBJECT objectHandle)
{
	AnObject *object = NULL;
	object = getAnObjectByHandle(objectHandle);
	if (object == NULL)
		return 0;
	return object->tcsContext;
}

#if 0
TSS_HOBJECT
obj_GetPolicyOfObject(TSS_HOBJECT objectHandle, UINT32 policyType)
{
	AnObject *object;
	TSS_HOBJECT ret = 0;

	object = getAnObjectByHandle(objectHandle);
	if (object->objectType == TSS_OBJECT_TYPE_TPM) {
		ret = ((TCPA_TPM_OBJECT *) object)->policy;
	} else if (object->objectType == TSS_OBJECT_TYPE_RSAKEY) {
		if (policyType == TSS_POLICY_MIGRATION)
			ret = ((TCPA_RSAKEY_OBJECT *) object)->migPolicy;
		else if (policyType == TSS_POLICY_USAGE)
			ret = ((TCPA_RSAKEY_OBJECT *) object)->usagePolicy;
		else
			ret = 0;
	} else if ((object->objectHandle = TSS_OBJECT_TYPE_ENCDATA)) {
		if (policyType == TSS_POLICY_MIGRATION) {
			if (((TCPA_ENCDATA_OBJECT *) object)->encType != TSS_ENCDATA_SEAL)
				ret = 0;
			else
				ret = ((TCPA_ENCDATA_OBJECT *) object)->migPolicy;
		} else if (policyType == TSS_POLICY_USAGE)
			ret = ((TCPA_ENCDATA_OBJECT *) object)->usagePolicy;
		else
			ret = 0;
	} else
		ret = 0;

	return ret;
}
#endif

TSS_RESULT
internal_GetContextForContextObject(TSS_HCONTEXT hContext, TCS_CONTEXT_HANDLE * handleOut)
{
	AnObject *object = NULL;

	pthread_mutex_lock(&objectlist_lock);

	for (object = objectList; object; object = object->next) {
		if (object->objectHandle == hContext)
			break;
	}

	if (object == NULL) {
		pthread_mutex_unlock(&objectlist_lock);
		return TSS_E_INVALID_HANDLE;
	}

	*handleOut = ((TCPA_CONTEXT_OBJECT *) object->memPointer)->tcsHandle;

	pthread_mutex_unlock(&objectlist_lock);

	return TSS_SUCCESS;
}

TSS_RESULT
internal_GetContextObjectForContext(TCS_CONTEXT_HANDLE tcsContext, TSS_HCONTEXT * tspContext)
{
	AnObject *object = NULL;
	TSS_RESULT result = TSS_E_INVALID_HANDLE;

	pthread_mutex_lock(&objectlist_lock);

	for (object = objectList; object; next(object)) {
		if (object->objectType == TSS_OBJECT_TYPE_CONTEXT
		    && object->tcsContext == tcsContext) {
			*tspContext = object->tspContext;
			result = TSS_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);

	return result;
}

BOOL
anyPopupPolicies(TSS_HCONTEXT context)
{
	AnObject *index;
	BOOL ret = FALSE;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; next(index)) {
		if (index->objectType == TSS_OBJECT_TYPE_POLICY &&
		    index->tspContext == context &&
		    ((TSP_INTERNAL_POLICY_OBJECT *)index->memPointer)->p.SecretMode == TSS_SECRET_MODE_POPUP) {
			ret = TRUE;
			break;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);

	return ret;
}

/* ====================================================================================================== */

TSPKeyHandleContainer *
createNewTSPKeyHandleContainer()
{
	return calloc(1, sizeof(TSPKeyHandleContainer));
}

TCSKeyHandleContainer *
createNewTCSKeyHandleContainer()
{
	return calloc(1, sizeof(TCSKeyHandleContainer));
}

TCSKeyHandleContainer *
concatTCSKeyHandleContainer(TCSKeyHandleContainer ** first, TCSKeyHandleContainer * second)
{
	TCSKeyHandleContainer *index;
	if (*first == NULL)
		*first = second;
	else {
		for (index = *first; index && index->next; next(index)) ;
		index->next = second;
	}

	return *first;
}

TSPKeyHandleContainer *
concatTSPKeyHandleContainer(TSPKeyHandleContainer ** first, TSPKeyHandleContainer * second)
{
	TSPKeyHandleContainer *index;
	if (*first == NULL)
		*first = second;
	else {
		for (index = *first; index && index->next; next(index)) ;
		index->next = second;
	}

	return *first;
}

TCSKeyHandleContainer *
getTCSKeyHandleContainerByTCSHandle(TCS_KEY_HANDLE tcsHandle)
{
	TCSKeyHandleContainer *index;

	pthread_mutex_lock(&keylist_lock);

	for (index = glKeyHandleManager; index; next(index)) {
		if (index->tcsKeyHandle == tcsHandle)
			break;
	}

	pthread_mutex_unlock(&keylist_lock);

	return index;
}

/* ----------------------------------------------------------------------------- */

/*	These can be called by other funcs */

void
addNewKeyHandle(TCS_KEY_HANDLE tcsHandle, TSS_HKEY tspHandle)
{
	TCSKeyHandleContainer *newTCS = NULL;
	TSPKeyHandleContainer *newTSP = NULL;

	newTSP = createNewTSPKeyHandleContainer();
	newTSP->tspKeyHandle = tspHandle;

	newTCS = getTCSKeyHandleContainerByTCSHandle(tcsHandle);

	pthread_mutex_lock(&keylist_lock);

	if (newTCS == NULL) {
		newTCS = createNewTCSKeyHandleContainer();
		newTCS->tcsKeyHandle = tcsHandle;
		concatTCSKeyHandleContainer(&glKeyHandleManager, newTCS);
	}
	concatTSPKeyHandleContainer(&newTCS->tspHandles, newTSP);

	pthread_mutex_unlock(&keylist_lock);
}

#if 0
void
removeTSPKeyHandle(TSS_HKEY tspHandle)
{
	TCSKeyHandleContainer *tcsIndex = NULL;
	TSPKeyHandleContainer *tspIndex = NULL;
	TSPKeyHandleContainer *toKill = NULL;
	TSPKeyHandleContainer *prev = NULL;

	for (tcsIndex = glKeyHandleManager; tcsIndex; next(tcsIndex)) {
		for (prev = NULL, tspIndex = tcsIndex->tspHandles; tspIndex;
		     prev = tspIndex, next(tspIndex)) {
			if (tspIndex->tspKeyHandle == tspHandle) {
				toKill = tspIndex;
				if (prev == NULL)
					tcsIndex->tspHandles = toKill->next;
				else
					prev->next = toKill->next;
/* 				free( toKill ); */
				try_FreeMemory(toKill->next);
				return;
			}
		}
	}
}

void
removeTCSKeyHandle(TCS_KEY_HANDLE tcsHandle)
{
	TCSKeyHandleContainer *index = NULL;
	TCSKeyHandleContainer *toKill = NULL;
	TCSKeyHandleContainer *prev = NULL;
	TSPKeyHandleContainer *tspIndex = NULL;

	index = getTCSKeyHandleContainerByTCSHandle(tcsHandle);
	if (index == NULL)
		return;

	for (tspIndex = index->tspHandles; tspIndex; next(tspIndex)) {
		removeTSPKeyHandle(tspIndex->tspKeyHandle);
	}

	for (index = glKeyHandleManager; index; prev = index, next(index)) {
		toKill = index;
		if (toKill->tcsKeyHandle == tcsHandle) {
			if (prev == NULL)
				glKeyHandleManager = toKill->next;
			else
				prev->next = toKill->next;
			try_FreeMemory(toKill);
			break;
		}
	}
	return;
}
#endif

TCS_KEY_HANDLE
getTCSKeyHandle(TSS_HKEY tspHandle)
{
	TCSKeyHandleContainer *ret = NULL;
	TSPKeyHandleContainer *tspIndex;
	TCS_KEY_HANDLE ret_handle = 0;

	pthread_mutex_lock(&keylist_lock);

	for (ret = glKeyHandleManager; ret; next(ret)) {
		for (tspIndex = ret->tspHandles; tspIndex; next(tspIndex)) {
			if (tspIndex->tspKeyHandle == tspHandle) {
				ret_handle = ret->tcsKeyHandle;
				break;
			}
		}
	}

	pthread_mutex_unlock(&keylist_lock);

	return ret_handle;
}
