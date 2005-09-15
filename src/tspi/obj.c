
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"

UINT32 nextObjectHandle = 0xC0000000;

TCSKeyHandleContainer *glKeyHandleManager = NULL;

pthread_mutex_t keylist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t handle_lock = PTHREAD_MUTEX_INITIALIZER;

struct obj_list tpm_list;
struct obj_list context_list;
struct obj_list hash_list;
struct obj_list pcrs_list;
struct obj_list policy_list;
struct obj_list rsakey_list;
struct obj_list encdata_list;

void
list_init(struct obj_list *list)
{
	list->head = NULL;
	pthread_mutex_init(&list->lock, NULL);
}

void
obj_list_init()
{
	list_init(&tpm_list);
	list_init(&context_list);
	list_init(&hash_list);
	list_init(&pcrs_list);
	list_init(&policy_list);
	list_init(&rsakey_list);
	list_init(&encdata_list);
}

TSS_HOBJECT
obj_get_next_handle()
{
	pthread_mutex_lock(&handle_lock);

	/* return any object handle except NULL_HOBJECT */
	do {
		nextObjectHandle++;
	} while (nextObjectHandle == NULL_HOBJECT);

	pthread_mutex_unlock(&handle_lock);

	return nextObjectHandle;
}

/* search through the provided list for an object with handle matching
 * @handle. If found, return a pointer to the object with the list
 * locked, else return NULL.  To release the lock, caller should
 * call obj_list_put() after manipulating the object.
 */
struct tsp_object *
obj_list_get_obj(struct obj_list *list, UINT32 handle)
{
	struct tsp_object *obj;

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; obj = obj->next) {
		if (obj->handle == handle)
			break;
	}

	if (obj == NULL)
		pthread_mutex_unlock(&list->lock);

	return obj;
}

/* search through the provided list for an object with TSP context
 * matching @tspContext. If found, return a pointer to the object
 * with the list locked, else return NULL.  To release the lock,
 * caller should call obj_list_put() after manipulating the object.
 */
struct tsp_object *
obj_list_get_tspcontext(struct obj_list *list, UINT32 tspContext)
{
	struct tsp_object *obj;

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; obj = obj->next) {
		if (obj->tspContext == tspContext)
			break;
	}

	return obj;
}

/* search through the provided list for an object with TCS context
 * matching @tcsContext. If found, return a pointer to the object
 * with the list locked, else return NULL.  To release the lock,
 * caller should call obj_list_put() after manipulating the object.
 */
struct tsp_object *
obj_list_get_tcscontext(struct obj_list *list, UINT32 tcsContext)
{
	struct tsp_object *obj;

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; obj = obj->next) {
		if (obj->tcsContext == tcsContext)
			break;
	}

	return obj;
}

/* release a list whose handle was returned by obj_list_get_obj() */
void
obj_list_put(struct obj_list *list)
{
	pthread_mutex_unlock(&list->lock);
}

TSS_RESULT
obj_list_add(struct obj_list *list,
	     UINT32	      tsp_context,
	     void	     *data,
	     TSS_HOBJECT     *phObject)
{
        struct tsp_object *new_obj, *tmp;
	TSS_RESULT result;

        new_obj = calloc(1, sizeof(struct tsp_object));
        if (new_obj == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(struct tsp_object));
                return TSPERR(TSS_E_OUTOFMEMORY);
        }

        new_obj->handle = obj_get_next_handle();
        new_obj->data = data;

	if (list == &context_list) {
		new_obj->tspContext = new_obj->handle;
		new_obj->tcsContext = 0;
	} else {
		new_obj->tspContext = tsp_context;
		if ((result = obj_context_get_tcs_context(tsp_context,
						&new_obj->tcsContext))) {
			free(new_obj);
			return TSPERR(TSS_E_INVALID_HANDLE);
		}
	}

        pthread_mutex_lock(&list->lock);

        if (list->head == NULL) {
                list->head = new_obj;
        } else {
                tmp = list->head;
                list->head = new_obj;
                new_obj->next = tmp;
        }

        pthread_mutex_unlock(&list->lock);

        *phObject = new_obj->handle;

        return TSS_SUCCESS;
}

TSS_RESULT
obj_list_remove(struct obj_list *list, TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
	struct tsp_object *obj, *prev = NULL;
	TSS_RESULT result = TSPERR(TSS_E_INVALID_HANDLE);

	pthread_mutex_lock(&list->lock);

	for (obj = list->head; obj; prev = obj, obj = obj->next) {
		if (obj->handle == hObject) {
			/* validate tspContext */
			if (obj->tspContext != tspContext)
				break;

			free(obj->data);
			if (prev)
				prev->next = obj->next;
			else
				list->head = obj->next;
			free(obj);
			result = TSS_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&list->lock);

	return result;
}

/* a generic routine for removing all members of a list who's tsp context
 * matches @tspContext */
void
obj_list_close(struct obj_list *list, TSS_HCONTEXT tspContext)
{
	struct tsp_object *index;
	struct tsp_object *next = NULL;
	struct tsp_object *toKill;
	struct tsp_object *prev = NULL;

	pthread_mutex_lock(&list->lock);

	for (index = list->head; index; ) {
		next = index->next;
		if (index->tspContext == tspContext) {
			toKill = index;
			if (prev == NULL) {
				list->head = toKill->next;
			} else {
				prev->next = toKill->next;
			}

			free(toKill->data);
			free(toKill);

			index = next;
		} else {
			prev = index;
			index = next;
		}
	}

	pthread_mutex_unlock(&list->lock);
}

void
obj_close_context(TSS_HCONTEXT tspContext)
{
	obj_list_close(&tpm_list, tspContext);
	obj_list_close(&context_list, tspContext);
	obj_list_close(&pcrs_list, tspContext);
	obj_list_close(&policy_list, tspContext);

	/* these three must be custom due to the need to free members of their
	 * private data areas. */
	obj_list_hash_close(&hash_list, tspContext);
	obj_list_rsakey_close(&rsakey_list, tspContext);
	obj_list_encdata_close(&encdata_list, tspContext);
}

/* Some TSP context object will have a reference to this TCS context handle
 * if it is valid, so there's no need to search every list */
TSS_HCONTEXT
obj_lookupTspContext(TCS_CONTEXT_HANDLE tcsContext)
{
	struct tsp_object *obj;
	TSS_HCONTEXT hContext;

	if ((obj = obj_list_get_tcscontext(&context_list, tcsContext)) == NULL)
		return TSPERR(TSS_E_INVALID_HANDLE);

	hContext = obj->tspContext;

	obj_list_put(&context_list);

	return hContext;
}

/* go through the object list and mark all objects with TSP handle tspContext
 * as being connected to the TCS with handle tcsContext
 */
void
obj_connectContext_list(struct obj_list *list, TSS_HCONTEXT tspContext,
			TCS_CONTEXT_HANDLE tcsContext)
{
	struct tsp_object *tmp;

	pthread_mutex_lock(&list->lock);

	for (tmp = list->head; tmp; tmp = tmp->next) {
		if (tmp->tspContext == tspContext) {
			tmp->tcsContext = tcsContext;
		}
	}

	pthread_mutex_unlock(&list->lock);
}

void
obj_connectContext(TSS_HCONTEXT tspContext, TCS_CONTEXT_HANDLE tcsContext)
{
	obj_connectContext_list(&tpm_list, tspContext, tcsContext);
	obj_connectContext_list(&context_list, tspContext, tcsContext);
	obj_connectContext_list(&hash_list, tspContext, tcsContext);
	obj_connectContext_list(&pcrs_list, tspContext, tcsContext);
	obj_connectContext_list(&policy_list, tspContext, tcsContext);
	obj_connectContext_list(&rsakey_list, tspContext, tcsContext);
	obj_connectContext_list(&encdata_list, tspContext, tcsContext);
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

TSS_RESULT
addKeyHandle(TCS_KEY_HANDLE tcsHandle, TSS_HKEY tspHandle)
{
	TCSKeyHandleContainer *newTCS = NULL;
	TSPKeyHandleContainer *newTSP = NULL;

	if ((newTSP = calloc(1, sizeof(TSPKeyHandleContainer))) == NULL) {
		LogError("malloc of %d bytes failed.",
				sizeof(TSPKeyHandleContainer));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
	newTSP->tspKeyHandle = tspHandle;

	newTCS = getTCSKeyHandleContainerByTCSHandle(tcsHandle);

	pthread_mutex_lock(&keylist_lock);

	if (newTCS == NULL) {
		if ((newTCS = calloc(1, sizeof(TCSKeyHandleContainer))) == NULL) {
			LogError("malloc of %d bytes failed.",
					sizeof(TCSKeyHandleContainer));
			free(newTSP);
			return TSPERR(TSS_E_OUTOFMEMORY);
		}
		newTCS->tcsKeyHandle = tcsHandle;
		concatTCSKeyHandleContainer(&glKeyHandleManager, newTCS);
	}
	concatTSPKeyHandleContainer(&newTCS->tspHandles, newTSP);

	LogDebugFn("TSP handle 0x%x maps to TCS 0x%x", tspHandle, tcsHandle);
	pthread_mutex_unlock(&keylist_lock);

	return TSS_SUCCESS;
}

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
