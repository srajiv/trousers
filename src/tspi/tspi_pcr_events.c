
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_TPM_GetEvent(TSS_HTPM hTPM,		/* in */
		  UINT32 ulPcrIndex,		/* in */
		  UINT32 ulEventNumber,		/* in */
		  TSS_PCR_EVENT * pPcrEvent)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	TSS_PCR_EVENT *event = NULL;

	if (pPcrEvent == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if ((result = TCS_GetPcrEvent(tcsContext, ulPcrIndex, &ulEventNumber, &event)))
		return result;

	memcpy(pPcrEvent, event, sizeof(TSS_PCR_EVENT));
	free(event);

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetEvents(TSS_HTPM hTPM,			/* in */
		   UINT32 ulPcrIndex,			/* in */
		   UINT32 ulStartNumber,		/* in */
		   UINT32 * pulEventNumber,		/* in, out */
		   TSS_PCR_EVENT ** prgbPcrEvents)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	TSS_PCR_EVENT *events = NULL;

	if (pulEventNumber == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	if (prgbPcrEvents) {
		if ((result = TCS_GetPcrEventsByPcr(tcsContext, ulPcrIndex,
						    ulStartNumber,
						    pulEventNumber,
						    &events)))
			return result;

		*prgbPcrEvents = events;
	} else {
		/* if the pointer to receive events is NULL, the app only
		 * wants a total number of events for this PCR. */
		if ((result = TCS_GetPcrEvent(tcsContext, ulPcrIndex,
					      pulEventNumber, NULL)))
			return result;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
Tspi_TPM_GetEventLog(TSS_HTPM hTPM,			/* in */
		     UINT32 * pulEventNumber,		/* out */
		     TSS_PCR_EVENT ** prgbPcrEvents)	/* out */
{
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;

	if (pulEventNumber == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_tpm_is_connected(hTPM, &tcsContext)))
		return result;

	/* if the pointer to receive events is NULL, the app only wants a
	 * total number of events for all PCRs. */
	if (prgbPcrEvents == NULL) {
		UINT16 numPcrs = get_num_pcrs(tcsContext);
		UINT32 i, numEvents = 0;

		*pulEventNumber = 0;
		for (i = 0; i < numPcrs; i++) {
			if ((result = TCS_GetPcrEvent(tcsContext, i,
						      &numEvents, NULL)))
				return result;

			*pulEventNumber += numEvents;
		}
	} else {
		return TCS_GetPcrEventLog(tcsContext, pulEventNumber,
					  prgbPcrEvents);
	}

	return TSS_SUCCESS;
}

