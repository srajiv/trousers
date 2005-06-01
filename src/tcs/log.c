
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdio.h>
#include <string.h>
#include <syslog.h>

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

void LogBlobData( char* szDescriptor, unsigned long sizeOfBlob, unsigned char* blob )
{
	char temp[1024];
	char oneByte[8];
	unsigned long i;

	openlog(szDescriptor, LOG_NDELAY|LOG_PID, LOG_LOCAL5);
	memset( temp, 0, sizeof( temp ));

	for( i = 0 ; i < sizeOfBlob ; i++ )
	{
		if( i && (( i & 0x0F ) == 0 ))
		{
			syslog(LOG_DEBUG, temp );
			memset( temp, 0, sizeof( temp ));
		}
		sprintf( oneByte, "%.2X ", blob[i] );
		strcat( temp, oneByte );
	}
	if( temp[2] != 0 )
		syslog(LOG_DEBUG, temp );
}


