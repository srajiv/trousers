
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifndef _MEMMGR_H_
#define _MEMMGR_H_

typedef struct tdMemSlot {
	void *memPointer;
	struct tdMemSlot *next;
} MemSlot;

typedef struct tdContextMemSlot {
	TCS_CONTEXT_HANDLE tcsContext;
	MemSlot *memSlots;
	struct tdContextMemSlot *next;
} ContextMemSlot;

pthread_mutex_t memtable_lock = PTHREAD_MUTEX_INITIALIZER;

ContextMemSlot *SpiMemoryTable = NULL;

#endif
