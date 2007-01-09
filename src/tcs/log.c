
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "tcslog.h"

int foreground = 0;

/*
 * LogBlobData()
 *
 *   Log a blob's data to the debugging stream
 *
 * szDescriptor - The APPID tag found in the caller's environment at build time
 * sizeOfBlob - The size of the data to log
 * blob - the data to log
 *
 */

void
LogBlobData(char *szDescriptor, unsigned long sizeOfBlob, unsigned char *blob)
{
	char temp[64];
	unsigned int i;

	if (!foreground)
		openlog(szDescriptor, LOG_NDELAY|LOG_PID, TSS_SYSLOG_LVL);
	memset(temp, 0, sizeof(temp));

	for (i = 0; (unsigned long)i < sizeOfBlob; i++) {
		if ((i > 0) && ((i % 16) == 0)) {
			if (foreground)
				fprintf(stdout, "%s %s\n", szDescriptor, temp);
			else
				syslog(LOG_DEBUG, temp);
			memset(temp, 0, sizeof(temp));
		}
		snprintf(&temp[(i%16)*3], 4, "%.2X ", blob[i]);
	}

	if (i == sizeOfBlob) {
		if (foreground)
			fprintf(stdout, "%s %s\n", szDescriptor, temp);
		else
			syslog(LOG_DEBUG, temp);
	}
}


