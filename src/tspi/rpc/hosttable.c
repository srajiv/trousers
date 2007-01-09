
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

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tsplog.h"
#include "hosttable.h"
#include "obj.h"

struct host_table *ht = NULL;

TSS_RESULT
host_table_init()
{
	ht = calloc(1, sizeof(struct host_table));
	if (ht == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct host_table));
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	MUTEX_INIT(ht->lock);

	return TSS_SUCCESS;
}

void __attribute__ ((constructor)) my_init(void)
{
	host_table_init();
	obj_list_init();
}

#if 0
void
host_table_final()
{
	struct host_table_entry *hte, *next = NULL;

	MUTEX_LOCK(ht->lock);

	for (hte = ht->entries; hte; hte = next) {
		if (hte)
			next = hte->next;
		free(hte);
	}

	MUTEX_UNLOCK(ht->lock);

	free(ht);
	ht = NULL;
}

void __attribute__ ((destructor)) my_fini(void)
{
	host_table_final();
}
#endif

TSS_RESULT
add_table_entry(struct host_table_entry *entry, TCS_CONTEXT_HANDLE tcsContext)
{
	struct host_table_entry *hte;

	for (hte = ht->entries; hte; hte = hte->next) {
		if (hte->tcsContext == tcsContext) {
			LogError("Tspi_Context_Connect() attempted on an "
					"already connected context!");
			return TSPERR(TSS_E_CONNECTION_FAILED);
		}
	}

	/* fill in the entry */
	entry->tcsContext = tcsContext;

	if( ht->entries == NULL ) {
		ht->entries = entry;
	} else {
		for (hte = ht->entries; hte->next; hte = hte->next)
			;
		hte->next = entry;
	}

	return TSS_SUCCESS;
}

void
remove_table_entry(TCS_CONTEXT_HANDLE tcsContext)
{
	struct host_table_entry *hte, *prev = NULL;

	MUTEX_LOCK(ht->lock);

	for (hte = ht->entries; hte; prev = hte, hte = hte->next) {
		if (hte->tcsContext == tcsContext) {
			if (prev != NULL)
				prev->next = hte->next;
			else
				ht->entries = hte->next;
			free(hte);
			break;
		}
	}

	MUTEX_UNLOCK(ht->lock);
}

struct host_table_entry *
get_table_entry(TCS_CONTEXT_HANDLE hContext)
{
	struct host_table_entry *index = NULL;

	MUTEX_LOCK(ht->lock);

	for (index = ht->entries; index; index = index->next) {
		if (index->tcsContext == hContext)
			break;
	}

	if (index)
		MUTEX_LOCK(index->lock);

	MUTEX_UNLOCK(ht->lock);

	return index;
}

void
put_table_entry(struct host_table_entry *entry)
{
	if (entry)
		MUTEX_UNLOCK(entry->lock);
}

