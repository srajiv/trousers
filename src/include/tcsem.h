
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
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

/* define the compiled-in log sources here */
#define EVLOG_SOURCE_IMA	1

#endif
