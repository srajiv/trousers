
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
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "tsplog.h"
#include "obj.h"

UINT32 nextObjectHandle = 0xC0000000;

pthread_mutex_t handle_lock = PTHREAD_MUTEX_INITIALIZER;

TPM_LIST_DECLARE;
CONTEXT_LIST_DECLARE;
HASH_LIST_DECLARE;
PCRS_LIST_DECLARE;
POLICY_LIST_DECLARE;
RSAKEY_LIST_DECLARE;
ENCDATA_LIST_DECLARE;
DAA_LIST_DECLARE;

void
list_init(struct obj_list *list)
{
	list->head = NULL;
	pthread_mutex_init(&list->lock, NULL);
}

void
obj_list_init()
{
	TPM_LIST_INIT();
	CONTEXT_LIST_INIT();
	HASH_LIST_INIT();
	PCRS_LIST_INIT();
	POLICY_LIST_INIT();
	RSAKEY_LIST_INIT();
	ENCDATA_LIST_INIT();
	DAA_LIST_INIT();
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
obj_list_add(struct obj_list *list, UINT32 tsp_context, TSS_FLAG flags, void *data,
	     TSS_HOBJECT *phObject)
{
        struct tsp_object *new_obj, *tmp;

        new_obj = calloc(1, sizeof(struct tsp_object));
        if (new_obj == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct tsp_object));
                return TSPERR(TSS_E_OUTOFMEMORY);
        }

        new_obj->handle = obj_get_next_handle();
	new_obj->flags = flags;
        new_obj->data = data;

	if (list == &context_list) {
		new_obj->tspContext = new_obj->handle;
		new_obj->tcsContext = 0;
	} else {
		new_obj->tspContext = tsp_context;
		obj_context_get_tcs_context(tsp_context, &new_obj->tcsContext);
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
	TPM_LIST_CLOSE(tspContext);
	CONTEXT_LIST_CLOSE(tspContext);
	HASH_LIST_CLOSE(tspContext);
	PCRS_LIST_CLOSE(tspContext);
	POLICY_LIST_CLOSE(tspContext);
	RSAKEY_LIST_CLOSE(tspContext);
	ENCDATA_LIST_CLOSE(tspContext);
	DAA_LIST_CLOSE(tspContext);
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
        TPM_LIST_CONNECT(tspContext, tcsContext);
        CONTEXT_LIST_CONNECT(tspContext, tcsContext);
        HASH_LIST_CONNECT(tspContext, tcsContext);
        PCRS_LIST_CONNECT(tspContext, tcsContext);
        POLICY_LIST_CONNECT(tspContext, tcsContext);
        RSAKEY_LIST_CONNECT(tspContext, tcsContext);
        ENCDATA_LIST_CONNECT(tspContext, tcsContext);
        DAA_LIST_CONNECT(tspContext, tcsContext);
}

