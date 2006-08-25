
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

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
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "auth_mgr.h"


/* Note: The after taking the auth_mgr_lock in any of the functions below, the
 * mem_cache_lock cannot be taken without risking a deadlock. So, the auth_mgr
 * functions must be "self-contained" wrt locking */

/* no locking done in init since its called by only a single thread */
TSS_RESULT
auth_mgr_init()
{
	memset(&auth_mgr, 0, sizeof(struct _auth_mgr));

	auth_mgr.max_auth_sessions = tpm_metrics.num_auths;

	auth_mgr.overflow = calloc(TSS_DEFAULT_OVERFLOW_AUTHS, sizeof(pthread_cond_t *));
	if (auth_mgr.overflow == NULL) {
		LogError("malloc of %zd bytes failed",
			 (TSS_DEFAULT_OVERFLOW_AUTHS * sizeof(pthread_cond_t *)));
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	pthread_mutex_init(&auth_mgr_lock, NULL);

	return TSS_SUCCESS;
}

TSS_RESULT
auth_mgr_final()
{
	int i;

	pthread_mutex_lock(&auth_mgr_lock);

	/* wake up any sleeping threads, so they can be joined */
	for (i = 0; i < TSS_DEFAULT_OVERFLOW_AUTHS; i++) {
		if (auth_mgr.overflow[i] != NULL)
			pthread_cond_signal(auth_mgr.overflow[i]);
	}

	free(auth_mgr.overflow);

	pthread_mutex_unlock(&auth_mgr_lock);

	return TSS_SUCCESS;
}

/* if there's a TCS context waiting to get auth, wake it up or swap it in */
void
auth_mgr_swap_in()
{
#if 0
	if (tpm_metrics.authctx_swap) {
		// XXX
		LogError("IN AUTHCTX SWAP PATH.");
	} else {
#endif
		if (auth_mgr.overflow[auth_mgr.of_tail] != NULL) {
			LogDebug("waking up thread %x, auth slot has opened",
				 (UINT32)pthread_self());
			/* wake up the next sleeping thread in order and increment tail */
			pthread_cond_signal(auth_mgr.overflow[auth_mgr.of_tail]);
			auth_mgr.overflow[auth_mgr.of_tail] = NULL;
			auth_mgr.of_tail = (auth_mgr.of_tail + 1) % TSS_DEFAULT_OVERFLOW_AUTHS;
		}
		/* else nobody needs to be swapped in, so continue */
		LogDebug("no threads need to be signaled.");
#if 0
	}
#endif
}

/* we need to swap out an auth context or add a waiting context to the overflow queue */
TSS_RESULT
auth_mgr_swap_out(TCS_CONTEXT_HANDLE hContext)
{
#if 0
	if (tpm_metrics.authctx_swap) {
		LogError("IN AUTHCTX SWAP PATH.");
		return TCSERR(TSS_E_INTERNAL_ERROR);
	} else {
#endif
		pthread_cond_t *cond = ctx_get_cond_var(hContext);

		if (cond == NULL) {
			LogError("condition variable not found for TCS context 0x%x", hContext);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}

		/* Test whether we are the last awake thread.  If we are, we can't go to sleep
		 * since then there'd be no worker thread to wake the others up. This situation
		 * can arise when we're on a busy system who's TPM doesn't support auth ctx
		 * swapping.
		 */
		if (auth_mgr.sleeping_threads == (tcsd_options.num_threads - 1)) {
			LogError("auth mgr failing: too many threads already waiting");
			return TCPA_E_RESOURCES;
		}

		if (auth_mgr.overflow[auth_mgr.of_head] == NULL) {
			auth_mgr.overflow[auth_mgr.of_head] = cond;
			auth_mgr.of_head = (auth_mgr.of_head + 1) % TSS_DEFAULT_OVERFLOW_AUTHS;
			/* go to sleep */
			LogDebug("thread %x going to sleep until auth slot opens",
				 (UINT32)pthread_self());
			auth_mgr.sleeping_threads++;
			pthread_cond_wait(cond, &auth_mgr_lock);
			auth_mgr.sleeping_threads--;
		} else {
			LogError("auth mgr queue is full! There are currently %d "
				 "TCS sessions waiting on an auth session!",
				 TSS_DEFAULT_OVERFLOW_AUTHS);
			return TCSERR(TSS_E_INTERNAL_ERROR);
		}
#if 0
	}
#endif

	return TSS_SUCCESS;
}

/* close all auth contexts associated with this TCS_CONTEXT_HANDLE */
TSS_RESULT
auth_mgr_close_context(TCS_CONTEXT_HANDLE tcs_handle)
{
	int i;
	TSS_RESULT result;

	pthread_mutex_lock(&auth_mgr_lock);

	for (i = 0; i < AUTH_TABLE_SIZE; i++) {
		if (auth_mgr.auth_mapper[i].full == TRUE &&
		    auth_mgr.auth_mapper[i].ctx == tcs_handle) {
			result = internal_TerminateHandle(auth_mgr.auth_mapper[i].auth);
			if (result == TCPA_E_INVALID_AUTHHANDLE) {
				LogDebug("Tried to close an invalid auth handle: %x",
					 auth_mgr.auth_mapper[i].auth);
			} else if (result != TCPA_SUCCESS) {
				LogDebug("TPM_TerminateHandle returned %d", result);
			}
			auth_mgr.open_auth_sessions--;
			auth_mgr.auth_mapper[i].full = FALSE;
			LogDebug("released auth for TCS %x TPM %x", tcs_handle,
				 auth_mgr.auth_mapper[i].auth);
			auth_mgr_swap_in();
		}
	}

	pthread_mutex_unlock(&auth_mgr_lock);

	return TSS_SUCCESS;
}

void
auth_mgr_release_auth(TPM_AUTH *auth0, TPM_AUTH *auth1)
{
	if (auth0)
		auth_mgr_release_auth_handle(auth0->AuthHandle);

	if (auth1)
		auth_mgr_release_auth_handle(auth1->AuthHandle);
}

/* unload the auth ctx associated with this auth handle */
TSS_RESULT
auth_mgr_release_auth_handle(TCS_AUTHHANDLE tpm_auth_handle)
{
	int i;
	TSS_RESULT result = TSS_SUCCESS;

	pthread_mutex_lock(&auth_mgr_lock);

	for (i = 0; i < AUTH_TABLE_SIZE; i++) {
		if (auth_mgr.auth_mapper[i].full == TRUE &&
		    auth_mgr.auth_mapper[i].auth == tpm_auth_handle) {
			result = internal_TerminateHandle(auth_mgr.auth_mapper[i].auth);
			if (result == TCPA_E_INVALID_AUTHHANDLE) {
				LogDebug("Tried to close an invalid auth handle: %x",
					 auth_mgr.auth_mapper[i].auth);
			} else if (result != TCPA_SUCCESS) {
				LogDebug("TPM_TerminateHandle returned %d", result);
			}
			auth_mgr.open_auth_sessions--;
			auth_mgr.auth_mapper[i].full = FALSE;
			LogDebug("released auth for TCS %x TPM %x",
				 auth_mgr.auth_mapper[i].ctx, tpm_auth_handle);
			auth_mgr_swap_in();
		}
	}

	pthread_mutex_unlock(&auth_mgr_lock);

	return result;
}

TSS_RESULT
auth_mgr_check(TCS_CONTEXT_HANDLE tcsContext, TCS_AUTHHANDLE tpm_auth_handle)
{
	int i;
	TSS_RESULT result = TCSERR(TSS_E_INTERNAL_ERROR);

	pthread_mutex_lock(&auth_mgr_lock);

	for (i = 0; i < AUTH_TABLE_SIZE; i++) {
		if (auth_mgr.auth_mapper[i].full == TRUE &&
		    auth_mgr.auth_mapper[i].auth  == tpm_auth_handle &&
		    auth_mgr.auth_mapper[i].ctx   == tcsContext) {
			result = TSS_SUCCESS;
			break;
		}
	}

	pthread_mutex_unlock(&auth_mgr_lock);
	if (result == TCSERR(TSS_E_INTERNAL_ERROR))
		LogError("no auth in table for TCS handle 0x%x", tcsContext);
	return result;
}

TSS_RESULT
auth_mgr_add(TCS_CONTEXT_HANDLE tcsContext, TCS_AUTHHANDLE tpm_auth_handle)
{
	TSS_RESULT result = TCSERR(TSS_E_INTERNAL_ERROR);
	int i;

	for (i = 0; i < AUTH_TABLE_SIZE; i++) {
		if (auth_mgr.auth_mapper[i].full == FALSE) {
			auth_mgr.auth_mapper[i].auth = tpm_auth_handle;
			auth_mgr.auth_mapper[i].ctx = tcsContext;
			auth_mgr.auth_mapper[i].full = TRUE;
			result = TSS_SUCCESS;
			auth_mgr.open_auth_sessions++;
			LogDebug("added auth for TCS %x TPM %x", tcsContext, tpm_auth_handle);
			break;
		} else {
			/* sanity check */
			if (auth_mgr.auth_mapper[i].auth == tpm_auth_handle) {
				LogDebug("***************************** "
					  "UNCLEAN AUTH MAPPER TABLE");
				auth_mgr.auth_mapper[i].full = FALSE;
				auth_mgr.open_auth_sessions--;
				i--;
				LogDebug("CLEANED TABLE");
			}
		}
	}

	if (result == TCSERR(TSS_E_INTERNAL_ERROR))
		LogError("auth_mapper table is full!!");

	return result;
}

TSS_BOOL
auth_mgr_req_new(TCS_CONTEXT_HANDLE hContext)
{
	int i, opened = 0;

	for (i = 0; i < AUTH_TABLE_SIZE; i++) {
		if (auth_mgr.auth_mapper[i].full == TRUE &&
		    auth_mgr.auth_mapper[i].ctx  == hContext) {
			opened++;
		}
	}

	/* If this TSP has already opened its max open auth handles, deny
	 *  another open */
	if (opened >= MAX(2, auth_mgr.max_auth_sessions/2)) {
		LogDebug("Max opened auth handles already opened.");
		return FALSE;
	}

	/* if we have one opened already and there's a slot available, ok */
	if (opened && ((auth_mgr.max_auth_sessions - auth_mgr.open_auth_sessions) >= 1))
		return TRUE;

	/* we don't already have one open and there are at least 2 slots left */
	if ((auth_mgr.max_auth_sessions - auth_mgr.open_auth_sessions) >= 2)
		return TRUE;

	LogDebug("Request for new auth handle denied by TCS. (%d opened "
			"sessions)", opened);

	return FALSE;
}

TSS_RESULT
auth_mgr_oiap(TCS_CONTEXT_HANDLE hContext,	/* in */
	      TCS_AUTHHANDLE *authHandle,	/* out */
	      TCPA_NONCE *nonce0)		/* out */
{
	TSS_RESULT result;

	pthread_mutex_lock(&auth_mgr_lock);

	/* are the maximum number of auth sessions open? */
	if (auth_mgr_req_new(hContext) == FALSE) {
		if ((result = auth_mgr_swap_out(hContext)))
			goto done;
	}

	if ((result = TCSP_OIAP_Internal(hContext, authHandle, nonce0)))
		goto done;

	/* success, add an entry to the table */
	result = auth_mgr_add(hContext, *authHandle);
done:
	pthread_mutex_unlock(&auth_mgr_lock);

	return result;
}

TSS_RESULT
auth_mgr_osap(TCS_CONTEXT_HANDLE hContext,	/* in */
	      TCPA_ENTITY_TYPE entityType,	/* in */
	      UINT32 entityValue,		/* in */
	      TCPA_NONCE nonceOddOSAP,		/* in */
	      TCS_AUTHHANDLE *authHandle,	/* out */
	      TCPA_NONCE *nonceEven,		/* out */
	      TCPA_NONCE *nonceEvenOSAP)	/* out */
{
	TSS_RESULT result;
	UINT32 newEntValue = 0;

	/* if ET is not KEYHANDLE or KEY, newEntValue is a don't care */
	if (entityType == TCPA_ET_KEYHANDLE || entityType == TCPA_ET_KEY) {
		if (ensureKeyIsLoaded(hContext, entityValue, &newEntValue))
			return TCSERR(TSS_E_FAIL);
	} else {
		newEntValue = entityValue;
	}

	pthread_mutex_lock(&auth_mgr_lock);

	/* are the maximum number of auth sessions open? */
	if (auth_mgr_req_new(hContext) == FALSE) {
		if ((result = auth_mgr_swap_out(hContext)))
			goto done;
	}

	if ((result = TCSP_OSAP_Internal(hContext, entityType, newEntValue, nonceOddOSAP,
					 authHandle, nonceEven, nonceEvenOSAP)))
		goto done;

	/* success, add an entry to the table */
	result = auth_mgr_add(hContext, *authHandle);
done:
	pthread_mutex_unlock(&auth_mgr_lock);

	return result;
}

