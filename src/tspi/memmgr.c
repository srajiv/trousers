
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

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "memmgr.h"
#include "log.h"

MemSlot *
createNewMemSlot()
{
	return calloc(1, sizeof(MemSlot));
}

ContextMemSlot *
createNewContextMemSlot()
{
	return calloc(1, sizeof(ContextMemSlot));
}

MemSlot *
concatMemSlot(MemSlot **first, MemSlot *second)
{
	MemSlot *index;
	if (*first == NULL)
		*first = second;
	else {
		for (index = *first; index->next; next(index)) ;
		index->next = second;
	}
	return *first;
}

#if 0
ContextMemSlot *
concatContextMemSlot(ContextMemSlot ** first, ContextMemSlot * second)
{
	ContextMemSlot *index;
	if (*first == NULL)
		*first = second;
	else {
		for (index = *first; index->next; next(index)) ;
		index->next = second;
	}
	return *first;
}
#endif

ContextMemSlot *
getContextMemSlotByContext(TCS_CONTEXT_HANDLE tcsContext)
{
	ContextMemSlot *index;
	for (index = SpiMemoryTable; index; next(index))
		if (index->tcsContext == tcsContext)
			return index;

	return NULL;
}

TSS_RESULT
freeContextMemSlot(TCS_CONTEXT_HANDLE tcsContext)
{
	ContextMemSlot *prev = NULL, *index, *next;
	MemSlot *ms_index, *ms_next;

	for(index = SpiMemoryTable; index; index = index->next) {
		next = index->next;
		if (index->tcsContext == tcsContext) {
			for (ms_index = index->memSlots; ms_index; ms_index = ms_next) {
				ms_next = ms_index->next;
				free(ms_index->memPointer);
				free(ms_index);
			}

			if (prev != NULL)
				prev->next = next;

			free(index);
		}
	}

	return TSS_SUCCESS;
}

TSS_RESULT
removeMemSlotByPointer(ContextMemSlot *cms, void *pointer)
{
	MemSlot *index;
	MemSlot *prev = NULL;
	MemSlot *toKill;

	for (index = cms->memSlots; index; prev = index, next(index)) {
		if (index->memPointer == pointer) {
			toKill = index;
			if (prev == NULL)
				cms->memSlots = toKill->next;
			else
				prev->next = toKill->next;
			try_FreeMemory(pointer);
			try_FreeMemory(toKill);
			return TSS_SUCCESS;

		}

	}
	LogError1("Internal error: pointer to allocated memory not found.");
	return TSS_E_INTERNAL_ERROR;
}

/*
 * calloc_tspi will be called by functions outside of this file. All locking
 * is done here.
 */
void *
calloc_tspi(TCS_CONTEXT_HANDLE tcsContext, UINT32 howMuch)
{

	ContextMemSlot *index;
	MemSlot *newSlot;

	pthread_mutex_lock(&memtable_lock);

	index = getContextMemSlotByContext(tcsContext);
	if (index == NULL) {
		index = createNewContextMemSlot();
		if (index == NULL) {
			pthread_mutex_unlock(&memtable_lock);
			return index;
		}
		index->tcsContext = tcsContext;
	}
	newSlot = createNewMemSlot();
	newSlot->memPointer = calloc(1, howMuch);
	if (newSlot->memPointer == NULL) {
		free(index);
		LogError("malloc of %d bytes failed.", howMuch);
		pthread_mutex_unlock(&memtable_lock);
		return NULL;
	}

	concatMemSlot(&index->memSlots, newSlot);

	pthread_mutex_unlock(&memtable_lock);

	return newSlot->memPointer;
}

/*
 * free_tspi will be called by functions outside of this file. All locking
 * is done here.
 */
TSS_RESULT
free_tspi(TCS_CONTEXT_HANDLE tcsContext, void *memPointer)
{
	ContextMemSlot *index;
	TSS_RESULT result;

	pthread_mutex_lock(&memtable_lock);

	if (memPointer == NULL) {
		result = freeContextMemSlot(tcsContext);
		pthread_mutex_unlock(&memtable_lock);
		return result;
	}

	index = getContextMemSlotByContext(tcsContext);
	if (index == NULL) {
		pthread_mutex_unlock(&memtable_lock);
		return TSS_E_INVALID_HANDLE;
	}

	if ((result = removeMemSlotByPointer(index, memPointer))) {
		pthread_mutex_unlock(&memtable_lock);
		return result;
	}

	pthread_mutex_unlock(&memtable_lock);

	return TSS_SUCCESS;
}

#if 0
BOOL
isThisPointerSPI(TCS_CONTEXT_HANDLE tcsContext, void *memPointer)
{
	ContextMemSlot *index;
	MemSlot *memSlot;

	index = getContextMemSlotByContext(tcsContext);
	if (index == NULL)
		return FALSE;

	for (memSlot = index->memSlots; memSlot; next(memSlot))
		if (memSlot->memPointer == memPointer)
			return TRUE;

	return FALSE;
}
#endif
