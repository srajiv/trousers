
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _HOSTTABLE_H_
#define _HOSTTABLE_H_

#include <pthread.h>

#define CONNECTION_TYPE_TCP_PERSISTANT	1

struct host_table_entry {
	struct host_table_entry *next;
	TCS_CONTEXT_HANDLE tcsContext;
	BYTE *hostname;
	int type;
	int socket;
};

struct host_table {
	struct host_table_entry *entries;
	pthread_mutex_t lock;
};

extern struct host_table *ht;
struct host_table_entry *get_table_entry(TCS_CONTEXT_HANDLE);
TSS_RESULT add_table_entry(struct host_table_entry *, TCS_CONTEXT_HANDLE);
void remove_table_entry(TCS_CONTEXT_HANDLE);


#endif
