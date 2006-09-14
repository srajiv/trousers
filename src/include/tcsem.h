
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#ifndef _TCSEM_H_
#define _TCSEM_H_

struct ext_log_source {
        int (*open)(void *, int *);
        TSS_RESULT (*get_entries_by_pcr)(int, UINT32, UINT32, UINT32 *, TSS_PCR_EVENT **);
        TSS_RESULT (*get_entry)(int, UINT32, UINT32 *, TSS_PCR_EVENT **);
        int (*close)(int);
};

struct event_wrapper {
	TSS_PCR_EVENT event;
	struct event_wrapper *next;
};

struct event_log {
	pthread_mutex_t lock;
	struct ext_log_source *firmware_source;
	struct ext_log_source *kernel_source;
	struct event_wrapper **lists;
};

/* include the compiled-in log sources and struct references here */
#include "imaem.h"
#include "biosem.h"

#ifdef EVLOG_SOURCE_IMA
#define EVLOG_IMA_SOURCE	&ima_source
#else
#define EVLOG_IMA_SOURCE	NULL
#endif

#ifdef EVLOG_SOURCE_BIOS
#define EVLOG_BIOS_SOURCE	&bios_source
#else
#define EVLOG_BIOS_SOURCE	NULL
#endif

#endif
