
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "trousers/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"


unsigned long nextContextHandle = 0xA0000000;
struct tcs_context *tcs_context_table = NULL;

pthread_mutex_t tcs_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

/*================================================================= */
/*================================================================= */
/*		Proto's for just this file */
TCS_CONTEXT_HANDLE getNextHandle();
struct tcs_context *create_tcs_context();
struct tcs_context *get_context(TCS_CONTEXT_HANDLE);
struct tcs_context *get_previous_context(TCS_CONTEXT_HANDLE);

/*=========================================================================== */
TSS_BOOL initContextHandle = 1;

TCS_CONTEXT_HANDLE
getNextHandle()
{
	UINT32 tempRand;
	time_t currentTime;

	if (initContextHandle) {
		currentTime = time(NULL);
		srand(currentTime);
		tempRand = rand();
		tempRand = tempRand << 16;
		tempRand &= 0x00FF0000;
		nextContextHandle |= tempRand;
		initContextHandle = 0;
	}
	currentTime = time(NULL);
	srand(currentTime + 1);
	tempRand = rand();
/*	srandom( currentTime + 1 ); */
/*	tempRand = random(); */
	tempRand = tempRand << 8;
	tempRand &= 0x0000FF00;
	if (nextContextHandle == 0)
		return getNextHandle();
/*		nextContextHandle++; */
	else
		return ((nextContextHandle++) | tempRand);
}

struct tcs_context *
create_tcs_context()
{
	struct tcs_context *ret = (struct tcs_context *)calloc(1, sizeof(struct tcs_context));

	if (ret != NULL) {
		ret->handle = getNextHandle();
		if (tpm_metrics.authctx_swap) {
			ret->u_auth.blob = NULL;
		} else {
			pthread_cond_init(&(ret->u_auth.cond), NULL);
		}
	}
	return ret;
}

struct tcs_context *
get_context(TCS_CONTEXT_HANDLE handle)
{
	struct tcs_context *index;
	index = tcs_context_table;
	while (index) {
		if (index->handle == handle)
			break;
		index = index->next;
	}

	return index;
}

struct tcs_context *
get_previous_context(TCS_CONTEXT_HANDLE handle)
{
	struct tcs_context *index;
	index = tcs_context_table;
	while (index) {
		if (index->next) {
			if (index->next->handle == handle)
				return index;
		}
		index = index->next;
	}

	return 0;
}

/* runs through the list of all keys loaded by context c and decrements
 * their ref count by 1, then free's their structures.
 */
void
ctx_ref_count_keys(struct tcs_context *c)
{
	struct keys_loaded *cur, *prev;

	if (c == NULL)
		return;

	cur = prev = c->keys;

	while (cur != NULL) {
		key_mgr_dec_ref_count(cur->key_handle);
		cur = cur->next;
		free(prev);
		prev = cur;
	}
}

void
destroy_context(TCS_CONTEXT_HANDLE handle)
{
	struct tcs_context *toKill;
	struct tcs_context *previous;

	pthread_mutex_lock(&tcs_ctx_lock);

	toKill = get_context(handle);
	previous = get_previous_context(handle);

	if (!previous && tcs_context_table->handle == handle) {	/*this means that toKill is the first one */
		tcs_context_table = tcs_context_table->next;
	} else if (previous && toKill) {	/*both are found */
		previous->next = toKill->next;
	} else {
		pthread_mutex_unlock(&tcs_ctx_lock);
		return;
	}

	pthread_mutex_unlock(&tcs_ctx_lock);

	ctx_ref_count_keys(toKill);
	free(toKill);
}

TCS_CONTEXT_HANDLE
make_context()
{
	struct tcs_context *index;

	pthread_mutex_lock(&tcs_ctx_lock);

	index = tcs_context_table;

	if (!index) {
		tcs_context_table = create_tcs_context();
		if (tcs_context_table == NULL) {
			LogError("Malloc Failure.");
			pthread_mutex_unlock(&tcs_ctx_lock);
			return 0;
		}
		index = tcs_context_table;
	} else {
		while (index->next) {
			index = index->next;
		}
		index->next = create_tcs_context();
		if (index->next == NULL) {
			LogError("Malloc Failure.");
			pthread_mutex_unlock(&tcs_ctx_lock);
			return 0;
		}
		index = index->next;
	}

	pthread_mutex_unlock(&tcs_ctx_lock);

	return index->handle;
}


TCPA_RESULT
ctx_verify_context(TCS_CONTEXT_HANDLE tcsContext)
{
	struct tcs_context *c;

	if (tcsContext == InternalContext) {
		LogDebug("Success: %.8X is an Internal Context", tcsContext);
		return TSS_SUCCESS;
	}

	pthread_mutex_lock(&tcs_ctx_lock);

	c = get_context(tcsContext);

	pthread_mutex_unlock(&tcs_ctx_lock);

	if (c == NULL) {
		LogDebug("Fail: Context %.8X not found", tcsContext);
		return TCSERR(TCS_E_INVALID_CONTEXTHANDLE);
	}

	return TSS_SUCCESS;
}


pthread_cond_t *
ctx_get_cond_var(TCS_CONTEXT_HANDLE tcs_handle)
{
	struct tcs_context *c;
	pthread_cond_t *ret = NULL;

	pthread_mutex_lock(&tcs_ctx_lock);

	c = get_context(tcs_handle);

	if (c != NULL)
		ret = &(c->u_auth.cond);

	pthread_mutex_unlock(&tcs_ctx_lock);

	return ret;
}

/* make a new entry in the per-context list of loaded keys. If the list already
 * contains a pointer to the key in memory, just return success.
 */
TSS_RESULT
ctx_mark_key_loaded(TCS_CONTEXT_HANDLE ctx_handle,
		   TCS_KEY_HANDLE key_handle)
{
	struct tcs_context *c;
	struct keys_loaded *k = NULL, *new;
	TSS_RESULT result = TCSERR(TSS_E_FAIL);

	pthread_mutex_lock(&tcs_ctx_lock);

	c = get_context(ctx_handle);

	if (c != NULL) {
		k = c->keys;
		while (k != NULL) {
			if (k->key_handle == key_handle) {
				/* we've previously created a pointer to key_handle in the global
				 * list of loaded keys and incremented that key's reference count,
				 * so there's no need to do anything.
				 */
				result = TSS_SUCCESS;
				break;
			}

			k = k->next;
		}
	} else {
		pthread_mutex_unlock(&tcs_ctx_lock);
		return result;
	}

	/* if we have no record of this key being loaded by this context, create a new
	 * entry and increment the key's reference count in the global list.
	 */
	if (k == NULL) {
		new = calloc(1, sizeof(struct keys_loaded));
		if (new == NULL) {
			LogError("malloc of %zd bytes failed.", sizeof(struct keys_loaded));
			pthread_mutex_unlock(&tcs_ctx_lock);
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		new->key_handle = key_handle;
		new->next = c->keys;
		c->keys = new;
		result = key_mgr_inc_ref_count(new->key_handle);
	}

	pthread_mutex_unlock(&tcs_ctx_lock);

	return result;
}

