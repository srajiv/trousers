
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

/*
 * imaem.c
 *
 * Routines for handling PCR events from the Integrity Measurement
 * Architecture.
 *
 * The external event source format used by IMA:
 *
 * int[1] PCR Index (bin) | char[20] SHA1 (bin) | char[40MAX] eventname + '\0'
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcsps.h"
#include "log.h"
#include "tcsem.h"

#ifdef EVLOG_SOURCE_IMA

#include "imaem.h"

struct ext_log_source ima_source = {
	ima_open,
	ima_get_entries_by_pcr,
	ima_get_entry,
	ima_close
};

int
ima_open(void *source, int *handle)
{
	int fd;

	if ((fd = open((char *)source, O_RDONLY)) < 0) {
		LogError("Error opening PCR log file %s: %s", (char *)source, strerror(errno));
		return -1;
	}

	*handle = fd;

	return 0;
}

TSS_RESULT
ima_get_entries_by_pcr(int handle, UINT32 pcr_index, UINT32 first,
			UINT32 *count, TSS_PCR_EVENT **events)
{
	int pcr_value;
	char page[IMA_READ_SIZE];
	int i, error_path = 1, bytes_read, bytes_left, ptr = 0, tmp_ptr;
	UINT32 seen_indices = 0, copied_events = 0;
	struct event_wrapper *list = calloc(1, sizeof(struct event_wrapper));
	struct event_wrapper *cur = list;
	TSS_RESULT result = TSS_E_INTERNAL_ERROR;

	if (list == NULL) {
		LogError("malloc of %d bytes failed.", sizeof(struct event_wrapper));
		return TSS_E_OUTOFMEMORY;
	}

	if (*count == 0) {
		result = TCS_SUCCESS;
		goto free_list;
	}

	/* make the initial read from the file */
	if ((bytes_read = read(handle, page, IMA_READ_SIZE)) <= 0) {
		LogError("read from event source failed: %s", strerror(errno));
		free(list);
		return result;
	}

	while (1) {
		bytes_left = bytes_read - ptr;
		if (bytes_left < IMA_MIN_EVENT_SIZE) {
			/* We need to do another read from the file to get the next complete
			 * log entry
			 */
			memcpy(page, &page[ptr], bytes_left);

			if ((bytes_read = read(handle, &page[bytes_left],
							IMA_READ_SIZE - bytes_left)) <= 0) {
				if (bytes_left == 0) {
					goto copy_events;
				} else {
					LogError("read from event source failed: %s",
						 strerror(errno));
					goto free_list;
				}
			}

			/* if we *still* haven't read out one more entry from the file,
			 * just exit
			 */
			if (bytes_read + bytes_left < IMA_MIN_EVENT_SIZE) {
				LogError("Only %d bytes left to parse, which is less than the"
					 " size of an event!", bytes_left + bytes_read);
				result = TSS_E_INTERNAL_ERROR;
				goto free_list;
			}

			/* page has new data in it now, so reset ptr to read the fresh data */
			ptr = 0;
		} else if (bytes_left < IMA_MAX_EVENT_SIZE) {
			/* if the last byte of the read data is not a zero, we're not looking
			 * at a complete log entry. Read more data to get the next complete
			 * entry.
			 */
			if (page[bytes_read - 1] != '\0') {
				memcpy(page, &page[ptr], bytes_left);

				if ((bytes_read = read(handle, &page[bytes_left],
							IMA_READ_SIZE - bytes_left)) < 0) {
					LogError("read from event source failed: %s", strerror(errno));
					goto free_list;
				}

				/* page has new data in it now, so reset ptr to read the
				 * fresh data.
				 */
				ptr = 0;
			}
		}

		/* copy the initial 4 bytes (PCR index) XXX endianess ignored */
		memcpy(&pcr_value, &page[ptr], sizeof(int));
		ptr += sizeof(int);

		/* if the index is the one we're looking for, grab the entry */
		if (pcr_index == pcr_value) {
			if (seen_indices >= first) {
				/* grab this entry */
				cur->event.rgbPcrValue = malloc(20);
				if (cur->event.rgbPcrValue == NULL) {
					LogError("malloc of %d bytes failed.", 20);
					result = TSS_E_OUTOFMEMORY;
					goto free_list;
				}

				cur->event.ulPcrIndex = pcr_index;
				cur->event.ulPcrValueLength = 20;

				/* copy the SHA1 XXX endianess ignored */
				memcpy(cur->event.rgbPcrValue, &page[ptr], 20);
				ptr += 20;

				/* copy the event name XXX endianess ignored */
				tmp_ptr = ptr;
				while (page[ptr] != '\0')
					ptr++;
				cur->event.ulEventLength = ptr - tmp_ptr + 1; //add the terminator

				cur->event.rgbEvent = malloc(cur->event.ulEventLength);
				if (cur->event.rgbEvent == NULL) {
					LogError("malloc of %d bytes failed.", cur->event.ulEventLength);
					result = TSS_E_OUTOFMEMORY;
					goto free_list;
				}

				memcpy(cur->event.rgbEvent, &page[tmp_ptr], cur->event.ulEventLength);
				/* add 1 to skip over the '\0' */
				ptr++;

				copied_events++;
				if (copied_events == *count)
					goto copy_events;

				cur->next = calloc(1, sizeof(struct event_wrapper));
				if (cur->next == NULL) {
					LogError("malloc of %d bytes failed.",
							sizeof(struct event_wrapper));
					result = TSS_E_OUTOFMEMORY;
					goto free_list;
				}
				cur = cur->next;
			} else {
				/* move the data pointer through the 20 bytes of SHA1 +
				 * event name + '\0' */
				ptr += 20;
				while (page[ptr] != '\0')
					ptr++;
				ptr++;
			}
			seen_indices++;
		}
	}

copy_events:
	/* we've copied all the events we need to from this PCR, now
	 * copy them all into one contiguous memory block
	 */
	*events = calloc(copied_events, sizeof(TSS_PCR_EVENT));
	if (*events == NULL) {
		LogError("malloc of %d bytes failed.", copied_events * sizeof(TSS_PCR_EVENT));
		result = TSS_E_OUTOFMEMORY;
		goto free_list;
	}

	cur = list;
	for (i = 0; i < copied_events; i++) {
		memcpy(&((*events)[i]), &(cur->event), sizeof(TSS_PCR_EVENT));
		cur = cur->next;
	}

	*count = copied_events;
	/* assume we're in an error path until we get here */
	error_path = 0;
	result = TCS_SUCCESS;

free_list:
	cur = list->next;
	while (cur != NULL) {
		if (error_path) {
			free(cur->event.rgbEvent);
			free(cur->event.rgbPcrValue);
		}
		free(list);
		list = cur;
		cur = list->next;
	}
	free(list);
	return result;
}

TSS_RESULT
ima_get_entry(int handle, UINT32 pcr_index, UINT32 *num, TSS_PCR_EVENT **ppEvent)
{
	int pcr_value, bytes_read, bytes_left, tmp_ptr, ptr = 0;
	char page[IMA_READ_SIZE];
	UINT32 seen_indices = 0;
	TSS_RESULT result = TSS_E_INTERNAL_ERROR;
	TSS_PCR_EVENT *e = NULL;

	/* make the initial read from the file */
	if ((bytes_read = read(handle, page, IMA_READ_SIZE)) <= 0) {
		LogError("read from event source failed: %s", strerror(errno));
		return result;
	}

	while (1) {
		bytes_left = bytes_read - ptr;
		if (bytes_left < IMA_MIN_EVENT_SIZE) {
			memcpy(page, &page[ptr], bytes_left);

			if ((bytes_read = read(handle, &page[bytes_left],
							IMA_READ_SIZE - bytes_left)) <= 0) {
				LogError("read from event source failed: %s", strerror(errno));
				goto done;
			}

			/* if we *still* haven't read out one more entry from the file,
			 * just exit. Hopefully we've processed the entire file.
			 */
			if (bytes_read + bytes_left < IMA_MIN_EVENT_SIZE) {
				goto done;
			}

			/* page has new data in it now, so reset ptr to read the fresh data */
			ptr = 0;
		} else if (bytes_left < IMA_MAX_EVENT_SIZE) {
			/* if the last byte of the read data is not a zero, we're not looking
			 * at a complete log entry. Read more data to get the next complete
			 * entry.
			 */
			if (page[bytes_read - 1] != '\0') {
				memcpy(page, &page[ptr], bytes_left);

				if ((bytes_read = read(handle, &page[bytes_left],
							IMA_READ_SIZE - bytes_left)) < 0) {
					LogError("read from event source failed: %s", strerror(errno));
					goto done;
				}

				/* page has new data in it now, so reset ptr to read the
				 * fresh data.
				 */
				ptr = 0;
			}
		}

		/* copy the initial 4 bytes (PCR index) XXX endianess ignored */
		memcpy(&pcr_value, &page[ptr], sizeof(int));
		ptr += sizeof(int);

		if (pcr_index == pcr_value) {
			if (seen_indices == *num) {
				*ppEvent = calloc(1, sizeof(TSS_PCR_EVENT));
				if (*ppEvent == NULL) {
					LogError("malloc of %d bytes failed.", sizeof(TSS_PCR_EVENT));
					return TSS_E_INTERNAL_ERROR;
				}

				e = *ppEvent;

				e->rgbPcrValue = malloc(20);
				if (e->rgbPcrValue == NULL) {
					LogError("malloc of %d bytes failed.", 20);
					free(e);
					e = NULL;
					break;
				}

				e->ulPcrIndex = pcr_index;
				e->ulPcrValueLength = 20;

				/* copy the SHA1 XXX endianess ignored */
				memcpy(e->rgbPcrValue, &page[ptr], 20);
				ptr += 20;

				/* copy the event name XXX endianess ignored */
				tmp_ptr = ptr;
				while (page[ptr] != '\0')
					ptr++;
				e->ulEventLength = ptr - tmp_ptr + 1; // add the terminator

				if (e->ulEventLength > 41) {
					LogError("Error parsing IMA PCR Log event structure, event "
						 "length is %u", e->ulEventLength);
					free(e->rgbPcrValue);
					free(e);
					e = NULL;
					break;
				}

				e->rgbEvent = malloc(e->ulEventLength);
				if (e->rgbEvent == NULL) {
					free(e->rgbPcrValue);
					free(e);
					e = NULL;
					LogError("malloc of %d bytes failed.", e->ulEventLength);
					break;
				}

				memcpy(e->rgbEvent, &page[tmp_ptr], e->ulEventLength);
				result = TCS_SUCCESS;

				break;
			}
			seen_indices++;
			/* move the data pointer through the 20 bytes of SHA1 +
			 * event name + '\0' */
			ptr += 20;
			while (page[ptr] != '\0')
				ptr++;
			ptr++;
		}
	}

done:
	if (e == NULL)
		*ppEvent = NULL;

	return result;
}

int
ima_close(int handle)
{
	close(handle);

	return 0;
}

#endif
