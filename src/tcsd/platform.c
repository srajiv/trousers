
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004, 2005
 *
 */


#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <utmp.h>
#include <pthread.h>

#include "tss/tss.h"
#include "spi_internal_types.h"
#include "tcs_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcsps.h"
#include "tcslog.h"

pthread_mutex_t utmp_lock = PTHREAD_MUTEX_INITIALIZER;

char
platform_get_runlevel()
{
	char runlevel;
	struct utmp ut, save, *next = NULL;
	struct timeval tv;
	int flag = 0, counter = 0;

	pthread_mutex_lock(&utmp_lock);

	memset(&ut, 0, sizeof(struct utmp));
	memset(&save, 0, sizeof(struct utmp));
	memset(&tv, 0, sizeof(struct timeval));

	ut.ut_type = RUN_LVL;

	next = getutid(&ut);

	while (next != NULL) {
		if (next->ut_tv.tv_sec > tv.tv_sec) {
			memcpy(&save, next, sizeof(*next));
			flag = 1;
		} else if (next->ut_tv.tv_sec == tv.tv_sec) {
			if (next->ut_tv.tv_usec > tv.tv_usec) {
				memcpy(&save, next, sizeof(*next));
				flag = 1;
			}
		}

		counter++;
		next = getutid(&ut);
	}

	if (flag) {
		//printf("prev_runlevel=%c, runlevel=%c\n", save.ut_pid / 256, save.ut_pid % 256);
		runlevel = save.ut_pid % 256;
	} else {
		//printf("unknown\n");
		runlevel = 'u';
	}

	pthread_mutex_unlock(&utmp_lock);

	return runlevel;
}

