
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

AnObject *objectList = NULL;
UINT32 nextObjectHandle = 0xC0000000;

TCSKeyHandleContainer *glKeyHandleManager = NULL;

pthread_mutex_t objectlist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t keylist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t handle_lock = PTHREAD_MUTEX_INITIALIZER;

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
addObject(UINT32 contextHandle, UINT32 objectType)
{
	AnObject *object;

	object = createNewObject();
	if (object == NULL) {
		return 0;
	}
	object->objectHandle = getNextObjectHandle();
	if (objectType == TSS_OBJECT_TYPE_CONTEXT) {
		/* tcsContext will be set by obj_connectContext() */
		object->tcsContext = 0;
		object->tspContext = object->objectHandle;
	} else {
		object->tspContext = contextHandle;
		object->tcsContext = obj_getTcsContext(contextHandle);
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
		free(object->memPointer);
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

void
destroyObject(AnObject * object)
{
	if (object == NULL)
		return;

	if (object->memPointer != NULL)
		free(object->memPointer);

	free(object);

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
obj_closeContext(TSS_HCONTEXT tspContext)
{
	AnObject *index;
	AnObject *next = NULL;
	AnObject *toKill;
	AnObject *prev = NULL;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; ) {
		next = index->next;
		if (index->tspContext == tspContext) {
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
obj_getTpmObject(TSS_HCONTEXT tspContext, TSS_HOBJECT *out)
{
	AnObject *index;
	TSS_RESULT result = TSS_E_INVALID_HANDLE;

	pthread_mutex_lock(&objectlist_lock);

	for (index = objectList; index; next(index)) {
		if (index->tspContext == tspContext && index->objectType == TSS_OBJECT_TYPE_TPM) {
			*out = index->objectHandle;
			result = TSS_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);

	return result;
}

TCS_CONTEXT_HANDLE
obj_getTcsContext(TSS_HOBJECT objectHandle)
{
	AnObject *object = NULL;
	object = getAnObjectByHandle(objectHandle);
	if (object == NULL)
		return 0;
	return object->tcsContext;
}

TSS_HCONTEXT
obj_getTspContext(TSS_HOBJECT objectHandle)
{
	AnObject *object = NULL;
	object = getAnObjectByHandle(objectHandle);
	if (object == NULL)
		return 0;
	return object->tspContext;
}

/* go through the object list and mark all objects with TSP handle tspContext
 * as being connected to the TCS with handle tcsContext
 */
TSS_RESULT
obj_connectContext(TSS_HCONTEXT tspContext, TCS_CONTEXT_HANDLE tcsContext)
{
	AnObject *tmp;

	pthread_mutex_lock(&objectlist_lock);

	for (tmp = objectList; tmp; tmp = tmp->next) {
		if (tmp->tspContext == tspContext) {
			if (tmp->tcsContext != 0) {
				LogDebug("%s: tagging an already connected tcsContext! OBJECT TYPE: %x",
						__FUNCTION__, getObjectTypeByHandle(tmp->objectType));
			}
			tmp->tcsContext = tcsContext;
		}
	}

	pthread_mutex_unlock(&objectlist_lock);

	return TSS_SUCCESS;
}

/* make sure object handle is has a session */
TSS_RESULT
obj_checkSession_1(TSS_HOBJECT objHandle1)
{
	TSS_HCONTEXT tspContext1;

	tspContext1 = obj_getTspContext(objHandle1);

	if (tspContext1 == NULL_HCONTEXT) {
		return TSS_E_INVALID_HANDLE;
	}

	return TSS_SUCCESS;
}

/* make sure 2 object handles are from the same session */
TSS_RESULT
obj_checkSession_2(TSS_HOBJECT objHandle1, TSS_HOBJECT objHandle2)
{
	TSS_HCONTEXT tspContext1, tspContext2;

	tspContext1 = obj_getTspContext(objHandle1);
	tspContext2 = obj_getTspContext(objHandle2);

	if (tspContext1 != tspContext2 || tspContext1 == NULL_HCONTEXT ||
	    tspContext2 == NULL_HCONTEXT) {
		return TSS_E_INVALID_HANDLE;
	}

	return TSS_SUCCESS;
}

/* make sure 3 object handles are from the same session */
TSS_RESULT
obj_checkSession_3(TSS_HOBJECT objHandle1, TSS_HOBJECT objHandle2, TSS_HOBJECT objHandle3)
{
	TSS_HCONTEXT tspContext1, tspContext2, tspContext3;

	tspContext1 = obj_getTspContext(objHandle1);
	tspContext2 = obj_getTspContext(objHandle2);
	tspContext3 = obj_getTspContext(objHandle3);

	if (tspContext1 != tspContext2 ||
	    tspContext1 != tspContext3) {
		return TSS_E_INVALID_HANDLE;
	}

	return TSS_SUCCESS;
}

/* Check the object list for objHandle, if it exists and is connected to a TCS,
 * return the handle of the TCS.
 */
TSS_RESULT
obj_isConnected_1(TSS_HOBJECT objHandle, TCS_CONTEXT_HANDLE *tcsContext)
{
	TCS_CONTEXT_HANDLE tcsContext1;

	tcsContext1 = obj_getTcsContext(objHandle);
	if (tcsContext1 == NULL_HCONTEXT) {
		return TSS_E_NO_CONNECTION;
	}

	*tcsContext = tcsContext1;

	return TSS_SUCCESS;
}

/* Check the object list for objHandles, if they exist and are connected to the
 * same TCS, return the handle of the TCS.
 */
TSS_RESULT
obj_isConnected_2(TSS_HOBJECT objHandle1, TSS_HOBJECT objHandle2,
		  TCS_CONTEXT_HANDLE *tcsContext)
{
	TCS_CONTEXT_HANDLE tcsContext1, tcsContext2;

	tcsContext1 = obj_getTcsContext(objHandle1);
	tcsContext2 = obj_getTcsContext(objHandle2);

	/* return invalid handle before the connection check */
	if (tcsContext2 != tcsContext1) {
		return TSS_E_INVALID_HANDLE;
	}

	if (tcsContext1 == NULL_HCONTEXT || tcsContext2 == NULL_HCONTEXT) {
		return TSS_E_NO_CONNECTION;
	}

	*tcsContext = tcsContext1;

	return TSS_SUCCESS;
}

/* Check the object list for objHandles, if they exist and are connected to the
 * same TCS, return the handle of the TCS.
 */
TSS_RESULT
obj_isConnected_3(TSS_HOBJECT objHandle1, TSS_HOBJECT objHandle2,
		  TSS_HOBJECT objHandle3, TCS_CONTEXT_HANDLE *tcsContext)
{
	TCS_CONTEXT_HANDLE tcsContext1, tcsContext2, tcsContext3;

	tcsContext1 = obj_getTcsContext(objHandle1);
	tcsContext2 = obj_getTcsContext(objHandle2);
	tcsContext3 = obj_getTcsContext(objHandle3);

	/* return invalid handle before the connection check */
	if (tcsContext2 != tcsContext1 || tcsContext2 != tcsContext3) {
		return TSS_E_INVALID_HANDLE;
	}

	if (tcsContext1 == NULL_HCONTEXT || tcsContext2 == NULL_HCONTEXT ||
	    tcsContext3 == NULL_HCONTEXT) {
		return TSS_E_NO_CONNECTION;
	}

	*tcsContext = tcsContext1;

	return TSS_SUCCESS;
}

TSS_RESULT
obj_checkType_1(TSS_HOBJECT object, UINT32 objectType)
{
        AnObject *anObject;

        anObject = getAnObjectByHandle(object);
        if (anObject == NULL) {
                return TSS_E_INVALID_HANDLE;
        }

        if (anObject->objectType != objectType) {
		return TSS_E_INVALID_HANDLE;
        }

        return TSS_SUCCESS;
}

TSS_RESULT
obj_checkType_2(TSS_HOBJECT object1, UINT32 objectType1,
		TSS_HOBJECT object2, UINT32 objectType2)
{
        AnObject *anObject1, *anObject2;

        anObject1 = getAnObjectByHandle(object1);
        anObject2 = getAnObjectByHandle(object2);

        if (anObject1 == NULL || anObject2 == NULL) {
                return TSS_E_INVALID_HANDLE;
        }

        if (anObject1->objectType != objectType1 ||
	    anObject2->objectType != objectType2) {
		return TSS_E_INVALID_HANDLE;
        }

        return TSS_SUCCESS;
}

TSS_RESULT
obj_checkType_3(TSS_HOBJECT object1, UINT32 objectType1,
		TSS_HOBJECT object2, UINT32 objectType2,
		TSS_HOBJECT object3, UINT32 objectType3)
{
        AnObject *anObject1, *anObject2, *anObject3;

        anObject1 = getAnObjectByHandle(object1);
        anObject2 = getAnObjectByHandle(object2);
        anObject3 = getAnObjectByHandle(object3);

        if (anObject1 == NULL || anObject2 == NULL || anObject3 == NULL) {
                return TSS_E_INVALID_HANDLE;
        }

        if (anObject1->objectType != objectType1 ||
	    anObject2->objectType != objectType2 ||
	    anObject3->objectType != objectType3) {
		return TSS_E_INVALID_HANDLE;
        }

        return TSS_SUCCESS;
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
createTSPKeyHandleContainer()
{
	return calloc(1, sizeof(TSPKeyHandleContainer));
}

TCSKeyHandleContainer *
createTCSKeyHandleContainer()
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
addKeyHandle(TCS_KEY_HANDLE tcsHandle, TSS_HKEY tspHandle)
{
	TCSKeyHandleContainer *newTCS = NULL;
	TSPKeyHandleContainer *newTSP = NULL;

	newTSP = createTSPKeyHandleContainer();
	newTSP->tspKeyHandle = tspHandle;

	newTCS = getTCSKeyHandleContainerByTCSHandle(tcsHandle);

	pthread_mutex_lock(&keylist_lock);

	if (newTCS == NULL) {
		newTCS = createTCSKeyHandleContainer();
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
