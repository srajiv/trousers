
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
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "trousers/tss.h"
#include "tcs_utils.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tddl.h"
#include "req_mgr.h"
#include "tcslog.h"

static struct tpm_req_mgr *trm;

TSS_RESULT
req_mgr_submit_req(BYTE *blob)
{
	TSS_RESULT result;
	BYTE loc_buf[TSS_TPM_TXBLOB_SIZE];
	UINT32 size = TSS_TPM_TXBLOB_SIZE;
	UINT32 retry = TSS_REQ_MGR_MAX_RETRIES;

	pthread_mutex_lock(&(trm->queue_lock));

	/* XXX Put a retry limit in here... */
	do {
		result = Tddli_TransmitData(blob, Decode_UINT32(&blob[2]), loc_buf, &size);
	} while (!result && (Decode_UINT32(&loc_buf[6]) == TCPA_E_RETRY) && --retry);

	if (!result)
		memcpy(blob, loc_buf, Decode_UINT32(&loc_buf[2]));

	pthread_mutex_unlock(&(trm->queue_lock));

	return result;
}

TSS_RESULT
req_mgr_init()
{
	if ((trm = calloc(1, sizeof(struct tpm_req_mgr))) == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(struct tpm_req_mgr));
		return TSS_E_OUTOFMEMORY;
	}

	pthread_mutex_init(&(trm->queue_lock), NULL);

	return Tddli_Open();
}

TSS_RESULT
req_mgr_final()
{
	free(trm);

	return Tddli_Close();
}

