
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _TSPLOG_H_
#define _TSPLOG_H_

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>

/* log to stdout */
#define LogMessage(dest, priority, layer, fmt, ...) \
	do { \
		if (getenv("TSS_DEBUG_OFF") == NULL) { \
			fprintf(dest, "%s %s %s:%d " fmt "\n", priority, layer, __FILE__, __LINE__, ## __VA_ARGS__); \
		} \
	} while (0)

#define LogMessage1(dest, priority, layer, data) \
	do { \
		if (getenv("TSS_DEBUG_OFF") == NULL) { \
			fprintf(dest, "%s %s %s:%d %s\n", priority, layer, __FILE__, __LINE__, data); \
		} \
	} while (0)

/* Debug logging */
#ifdef TSS_DEBUG
#define LogDebug(fmt, ...)	LogMessage(stdout, "LOG_DEBUG", APPID, fmt, ##__VA_ARGS__)
#define LogDebug1(data)		LogMessage1(stdout, "LOG_DEBUG", APPID, data)
#define LogBlob(sz,blb)		LogBlobData(APPID, sz, blb)

/* Error logging */
#define LogError(fmt, ...)	LogMessage(stderr, "LOG_ERR", APPID, "ERROR: " fmt, ##__VA_ARGS__)
#define LogError1(data)		LogMessage1(stderr, "LOG_ERR", APPID, "ERROR: " data)

/* Warn logging */
#define LogWarn(fmt, ...)	LogMessage(stdout, "LOG_WARNING", APPID, "WARNING: " fmt, ##__VA_ARGS__)
#define LogWarn1(data)		LogMessage1(stdout, "LOG_WARNING", APPID, "WARNING: " data)

/* Info Logging */
#define LogInfo(fmt, ...)	LogMessage(stdout, "LOG_INFO", APPID, fmt, ##__VA_ARGS__)
#define LogInfo1(data)		LogMessage1(stdout, "LOG_INFO", APPID, data)
#else
#define LogDebug(fmt, ...)
#define LogDebug1(data)
#define LogBlob(sz,blb)
#define LogError(fmt, ...)
#define LogError1(data)
#define LogWarn(fmt, ...)
#define LogWarn1(data)
#define LogInfo(fmt, ...)
#define LogInfo1(data)
#endif

void LogBlobData(char *appid, unsigned long sizeOfBlob, unsigned char *blob);

#endif
