
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
#include <pthread.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcslog.h"
#include "tcsem.h"

#ifdef EVLOG_SOURCE_IMA
#include "imaem.h"
#endif


TCS_CONTEXT_HANDLE InternalContext = 0x30000000;

struct event_log *tcs_event_log = NULL;

TSS_RESULT
event_log_init()
{
	if (tcs_event_log != NULL)
		return TCS_SUCCESS;

	tcs_event_log = calloc(1, sizeof(struct event_log));
	if (tcs_event_log == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(struct event_log));
		return TSS_E_OUTOFMEMORY;
	}

	pthread_mutex_init(&(tcs_event_log->lock), NULL);

	/* allocate as many event lists as there are PCR's */
	tcs_event_log->lists = calloc(tpm_metrics.num_pcrs, sizeof(struct event_wrapper *));
	if (tcs_event_log->lists == NULL) {
		LogError("malloc of %d bytes failed.",
				tpm_metrics.num_pcrs * sizeof(struct event_wrapper *));
		free(tcs_event_log);
		return TSS_E_OUTOFMEMORY;
	}

	/* assign external event log sources here */
	tcs_event_log->firmware_source = NULL;
#ifdef EVLOG_SOURCE_IMA
	tcs_event_log->kernel_source = &ima_source;
#else
	tcs_event_log->kernel_source = NULL;
#endif

	return TCS_SUCCESS;
}

TSS_RESULT
event_log_final()
{
	struct event_wrapper *cur, *next;
	UINT32 i;

	pthread_mutex_lock(&(tcs_event_log->lock));

	for (i = 0; i < tpm_metrics.num_pcrs; i++) {
		cur = tcs_event_log->lists[i];
		while (cur != NULL) {
			next = cur->next;
			free(cur->event.rgbPcrValue);
			free(cur->event.rgbEvent);
			free(cur);
			cur = next;
		}
	}

	pthread_mutex_unlock(&(tcs_event_log->lock));

	free(tcs_event_log->lists);
	free(tcs_event_log);

	return TCS_SUCCESS;
}

TSS_RESULT
copy_pcr_event(TSS_PCR_EVENT *dest, TSS_PCR_EVENT *source)
{
	memcpy(dest, source, sizeof(TSS_PCR_EVENT));
	return TCS_SUCCESS;
}

TSS_RESULT
event_log_add(TSS_PCR_EVENT *event, UINT32 *pNumber)
{
	struct event_wrapper *new, *tmp;
	TSS_RESULT result;
	UINT32 i;

	pthread_mutex_lock(&(tcs_event_log->lock));

	new = calloc(1, sizeof(struct event_wrapper));
	if (new == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(struct event_wrapper));
		pthread_mutex_unlock(&(tcs_event_log->lock));
		return TSS_E_OUTOFMEMORY;
	}

	if ((result = copy_pcr_event(&(new->event), event))) {
		free(new);
		pthread_mutex_unlock(&(tcs_event_log->lock));
		return result;
	}

	/* go to the end of the list to add the element, so that they're in order */
	i = 0;
	if (tcs_event_log->lists[event->ulPcrIndex] == NULL) {
		tcs_event_log->lists[event->ulPcrIndex] = new;
	} else {
		i++;
		tmp = tcs_event_log->lists[event->ulPcrIndex];
		while (tmp->next != NULL) {
			i++;
			tmp = tmp->next;
		}
		tmp->next = new;
	}

	*pNumber = ++i;

	pthread_mutex_unlock(&(tcs_event_log->lock));

	return TCS_SUCCESS;
}

TSS_PCR_EVENT *
get_pcr_event(UINT32 pcrIndex, UINT32 eventNumber)
{
	struct event_wrapper *tmp;
	UINT32 counter = 0;

	pthread_mutex_lock(&(tcs_event_log->lock));

	tmp = tcs_event_log->lists[pcrIndex];
	for (; tmp; tmp = tmp->next) {
		if (counter == eventNumber) {
			break;
		}
		counter++;
	}

	pthread_mutex_unlock(&(tcs_event_log->lock));

	return (tmp ? &(tmp->event) : NULL);
}

/* the lock should be held before calling this function */
UINT32
get_num_events(UINT32 pcrIndex)
{
	struct event_wrapper *tmp;
	UINT32 counter = 0;

	tmp = tcs_event_log->lists[pcrIndex];
	for (; tmp; tmp = tmp->next) {
		counter++;
	}

	return counter;
}

TSS_RESULT
TCS_LogPcrEvent_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 TSS_PCR_EVENT Event,		/* in */
			 UINT32 *pNumber)		/* out */
{
	TSS_RESULT result;

	if((result = ctx_verify_context(hContext)))
		return result;

	if(Event.ulPcrIndex >= tpm_metrics.num_pcrs)
		return TSS_E_BAD_PARAMETER;

	if (tcsd_options.kernel_pcrs & (1 << Event.ulPcrIndex)) {
		LogInfo("PCR %d is configured to be kernel controlled. Event logging denied.",
				Event.ulPcrIndex);
		return TCS_E_FAIL;
	}

	if (tcsd_options.firmware_pcrs & (1 << Event.ulPcrIndex)) {
		LogInfo("PCR %d is configured to be firmware controlled. Event logging denied.",
				Event.ulPcrIndex);
		return TCS_E_FAIL;
	}

	return event_log_add(&Event, pNumber);
}

/* This routine will handle creating the TSS_PCR_EVENT structures from log
 * data produced by an external source. The external source in mind here
 * is the log of PCR extends done by the kernel from beneath the TSS
 * (via direct calls to the device driver).
 */
TSS_RESULT
TCS_GetExternalPcrEvent(UINT32 PcrIndex,		/* in */
			UINT32 *pNumber,		/* in, out */
			TSS_PCR_EVENT **ppEvent)	/* out */
{
	int log_handle;
	char *source;

	if (tcsd_options.kernel_pcrs & (1 << PcrIndex)) {
		source = tcsd_options.kernel_log_file;

		if (tcs_event_log->kernel_source != NULL) {
			if (tcs_event_log->kernel_source->open((void *)source, &log_handle))
				return TSS_E_INTERNAL_ERROR;

			if (tcs_event_log->kernel_source->get_entry(log_handle, PcrIndex,
						pNumber, ppEvent)) {
				tcs_event_log->kernel_source->close(log_handle);
				return TSS_E_INTERNAL_ERROR;
			}

			tcs_event_log->kernel_source->close(log_handle);
		} else {
			LogError("No source for externel kernel events was compiled in, but "
					"the tcsd is configured to use one! (see %s)",
					TCSD_CONFIG_FILE);
			return TSS_E_INTERNAL_ERROR;
		}
	} else if (tcsd_options.firmware_pcrs & (1 << PcrIndex)) {
		source = tcsd_options.firmware_log_file;

		if (tcs_event_log->firmware_source != NULL) {
			if (tcs_event_log->firmware_source->open((void *)source, &log_handle))
				return TSS_E_INTERNAL_ERROR;

			if (tcs_event_log->firmware_source->get_entry(log_handle, PcrIndex,
						pNumber, ppEvent)) {
				tcs_event_log->firmware_source->close(log_handle);
				return TSS_E_INTERNAL_ERROR;
			}

			tcs_event_log->firmware_source->close(log_handle);
		} else {
			LogError("No source for externel firmware events was compiled in, but "
					"the tcsd is configured to use one! (see %s)",
					TCSD_CONFIG_FILE);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		LogError("PCR index %d not flagged as kernel or firmware controlled.", PcrIndex);
		return TSS_E_INTERNAL_ERROR;
	}

	return TCS_SUCCESS;
}

TSS_RESULT
TCS_GetPcrEvent_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
			 UINT32 PcrIndex,		/* in */
			 UINT32 *pNumber,		/* in, out */
			 TSS_PCR_EVENT **ppEvent)	/* out */
{
	TSS_RESULT result;
	TSS_PCR_EVENT *event;

	if ((result = ctx_verify_context(hContext)))
		return result;

	if(PcrIndex >= tpm_metrics.num_pcrs)
		return TSS_E_BAD_PARAMETER;

	/* if this is a kernel or firmware controlled PCR, call an external routine */
        if ((tcsd_options.kernel_pcrs & (1 << PcrIndex)) ||
	    (tcsd_options.firmware_pcrs & (1 << PcrIndex))) {
		pthread_mutex_lock(&(tcs_event_log->lock));
		result =  TCS_GetExternalPcrEvent(PcrIndex, pNumber, ppEvent);
		pthread_mutex_unlock(&(tcs_event_log->lock));

		return result;
	}

	if (ppEvent == NULL) {
		pthread_mutex_lock(&(tcs_event_log->lock));

		*pNumber = get_num_events(PcrIndex);

		pthread_mutex_unlock(&(tcs_event_log->lock));
	} else {
		*ppEvent = calloc(1, sizeof(TSS_PCR_EVENT));
		if (*ppEvent == NULL) {
			LogError("malloc of %d bytes failed.", sizeof(TSS_PCR_EVENT));
			return TSS_E_OUTOFMEMORY;
		}

		event = get_pcr_event(PcrIndex, *pNumber);
		if (event == NULL) {
			free(*ppEvent);
			return TSS_E_BAD_PARAMETER;
		}

		if ((result = copy_pcr_event(*ppEvent, event))) {
			free(*ppEvent);
			return result;
		}
	}

	return TCS_SUCCESS;
}

/* This routine will handle creating the TSS_PCR_EVENT structures from log
 * data produced by an external source. The external source in mind here
 * is the log of PCR extends done by the kernel from beneath the TSS
 * (via direct calls to the device driver).
 */
TSS_RESULT
TCS_GetExternalPcrEventsByPcr(UINT32 PcrIndex,		/* in */
				UINT32 FirstEvent,		/* in */
				UINT32 *pEventCount,		/* in, out */
				TSS_PCR_EVENT **ppEvents)	/* out */
{
	int log_handle;
	char *source;

	if (tcsd_options.kernel_pcrs & (1 << PcrIndex)) {
		source = tcsd_options.kernel_log_file;

		if (tcs_event_log->kernel_source != NULL) {
			if (tcs_event_log->kernel_source->open((void *)source, &log_handle))
				return TSS_E_INTERNAL_ERROR;

			if (tcs_event_log->kernel_source->get_entries_by_pcr(log_handle, PcrIndex,
						FirstEvent, pEventCount, ppEvents)) {
				tcs_event_log->kernel_source->close(log_handle);
				return TSS_E_INTERNAL_ERROR;
			}

			tcs_event_log->kernel_source->close(log_handle);
		} else {
			LogError("No source for externel kernel events was compiled in, but "
					"the tcsd is configured to use one! (see %s)",
					TCSD_CONFIG_FILE);
			return TSS_E_INTERNAL_ERROR;
		}
	} else if (tcsd_options.firmware_pcrs & (1 << PcrIndex)) {
		source = tcsd_options.firmware_log_file;

		if (tcs_event_log->firmware_source != NULL) {
			if (tcs_event_log->firmware_source->open((void *)source, &log_handle))
				return TSS_E_INTERNAL_ERROR;

			if (tcs_event_log->firmware_source->get_entries_by_pcr(log_handle, PcrIndex,
						FirstEvent, pEventCount, ppEvents)) {
				tcs_event_log->firmware_source->close(log_handle);
				return TSS_E_INTERNAL_ERROR;
			}

			tcs_event_log->firmware_source->close(log_handle);
		} else {
			LogError("No source for externel firmware events was compiled in, but "
					"the tcsd is configured to use one! (see %s)",
					TCSD_CONFIG_FILE);
			return TSS_E_INTERNAL_ERROR;
		}
	} else {
		LogError("PCR index %d not flagged as kernel or firmware controlled.", PcrIndex);
		return TSS_E_INTERNAL_ERROR;
	}

	return TCS_SUCCESS;
}

TSS_RESULT
TCS_GetPcrEventsByPcr_Internal(TCS_CONTEXT_HANDLE hContext,	/* in */
				UINT32 PcrIndex,		/* in */
				UINT32 FirstEvent,		/* in */
				UINT32 *pEventCount,		/* in, out */
				TSS_PCR_EVENT **ppEvents)	/* out */
{
	UINT32 lastEventNumber, i, eventIndex;
	TSS_RESULT result;
	struct event_wrapper *tmp;

	if ((result = ctx_verify_context(hContext)))
		return result;

	if (PcrIndex >= tpm_metrics.num_pcrs)
		return TSS_E_BAD_PARAMETER;

	/* if this is a kernel or firmware controlled PCR, call an external routine */
        if ((tcsd_options.kernel_pcrs & (1 << PcrIndex)) ||
	    (tcsd_options.firmware_pcrs & (1 << PcrIndex))) {
		pthread_mutex_lock(&(tcs_event_log->lock));
		result = TCS_GetExternalPcrEventsByPcr(PcrIndex, FirstEvent,
							pEventCount, ppEvents);
		pthread_mutex_unlock(&(tcs_event_log->lock));

		return result;
	}

	pthread_mutex_lock(&(tcs_event_log->lock));

	lastEventNumber = get_num_events(PcrIndex);

	pthread_mutex_unlock(&(tcs_event_log->lock));

	/* if pEventCount is larger than the number of events to return, just return less.
	 * *pEventCount will be set to the number returned below.
	 */
	lastEventNumber = MIN(lastEventNumber, *pEventCount);

	if (FirstEvent > lastEventNumber)
		return TSS_E_BAD_PARAMETER;

	if (lastEventNumber == 0) {
		*pEventCount = 0;
		*ppEvents = NULL;
		return TCS_SUCCESS;
	}

	/* FirstEvent is 0 indexed see TSS 1.1b spec section 4.7.2.2.3. That means that
	 * the following calculation is not off by one. :-)
	 */
	*ppEvents = calloc((lastEventNumber - FirstEvent), sizeof(TSS_PCR_EVENT));
	if (*ppEvents == NULL) {
		LogError("malloc of %d bytes failed.",
				sizeof(TSS_PCR_EVENT) * (lastEventNumber - FirstEvent));
		return TSS_E_OUTOFMEMORY;
	}

	pthread_mutex_lock(&(tcs_event_log->lock));

	tmp = tcs_event_log->lists[PcrIndex];

	/* move through the list until we get to the first event requested */
	for (i = 0; i < FirstEvent; i++)
		tmp = tmp->next;

	/* copy events from the first requested to the last requested */
	for (eventIndex = 0; i < lastEventNumber; eventIndex++, i++) {
		copy_pcr_event(&((*ppEvents)[eventIndex]), &(tmp->event));
		tmp = tmp->next;
	}

	pthread_mutex_unlock(&(tcs_event_log->lock));

	*pEventCount = eventIndex;

	return TCS_SUCCESS;
}

/* XXX needs modification for external event sources */
TSS_RESULT
TCS_GetPcrEventLog_Internal(TCS_CONTEXT_HANDLE hContext,/* in  */
			    UINT32 *pEventCount,	/* out */
			    TSS_PCR_EVENT **ppEvents)	/* out */
{
	TSS_RESULT result;
	UINT32 numEvents, pcrEvents, i, j;
	struct event_wrapper *tmp;

	if ((result = ctx_verify_context(hContext)))
		return result;

	pthread_mutex_lock(&(tcs_event_log->lock));

	/* add up the total number of events in the log */
	for (numEvents = 0, i = 0; i < tpm_metrics.num_pcrs; i++)
		numEvents += get_num_events(i);

	if (numEvents == 0) {
		*pEventCount = 0;
		*ppEvents = NULL;
		pthread_mutex_unlock(&(tcs_event_log->lock));
		return TSS_SUCCESS;
	}

	*ppEvents = calloc(numEvents, sizeof(TSS_PCR_EVENT));
	if (*ppEvents == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(TSS_PCR_EVENT) * numEvents);
		pthread_mutex_unlock(&(tcs_event_log->lock));
		return TSS_E_OUTOFMEMORY;
	}

	for (i = 0; i < tpm_metrics.num_pcrs; i++) {
		pcrEvents = get_num_events(i);

		tmp = tcs_event_log->lists[i];
		for (j = 0; j < pcrEvents; j++) {
			copy_pcr_event(&((*ppEvents)[i + j]), &(tmp->event));
			tmp = tmp->next;
		}
	}

	pthread_mutex_unlock(&(tcs_event_log->lock));

	*pEventCount = numEvents;

	return TSS_SUCCESS;
}

