
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>

/* change your syslog destination here */
#define TSS_SYSLOG_LVL	LOG_LOCAL5

#define LogMessage(priority, layer, fmt, ...) \
        do { \
                openlog(layer, LOG_NDELAY|LOG_PID, TSS_SYSLOG_LVL); \
                syslog(priority, "%s:%d " fmt, __FILE__, __LINE__, ## __VA_ARGS__); \
        } while (0)

#define LogMessage1(priority, layer, data) \
        do { \
                openlog(layer, LOG_NDELAY|LOG_PID, TSS_SYSLOG_LVL); \
                syslog(priority, "%s:%d %s", __FILE__, __LINE__, data); \
        } while (0)

/* Debug logging */
#ifdef TSS_DEBUG
#define LogDebug(fmt, ...)	LogMessage(LOG_DEBUG, APPID, fmt, ##__VA_ARGS__)
#define LogDebug1(data)		LogMessage1(LOG_DEBUG, APPID, data)
#define LogBlob(sz,blb)		LogBlobData(APPID, sz, blb)
#else
#define LogDebug(fmt, ...)
#define LogDebug1(data)
#define LogBlob(sz,blb)
#endif

/* Error logging */
#define LogError(fmt, ...)	LogMessage(LOG_ERR, APPID, "ERROR: " fmt, ##__VA_ARGS__)
#define LogError1(data)		LogMessage1(LOG_ERR, APPID, "ERROR: " data)

/* Warn logging */
#define LogWarn(fmt, ...)	LogMessage(LOG_WARNING, APPID, "WARNING: " fmt, ##__VA_ARGS__)
#define LogWarn1(data)		LogMessage1(LOG_WARNING, APPID, "WARNING: " data)

/* Info Logging */
#define LogInfo(fmt, ...)	LogMessage(LOG_INFO, APPID, fmt, ##__VA_ARGS__)
#define LogInfo1(data)		LogMessage1(LOG_INFO, APPID, data)

void LogBlobData(char *appid, unsigned long sizeOfBlob, unsigned char *blob);

#endif
