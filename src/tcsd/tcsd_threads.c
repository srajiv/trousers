
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
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_int_literals.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcslog.h"

struct tcsd_thread_mgr *tm = NULL;

TSS_RESULT
tcsd_threads_final()
{
	int rc;
	UINT32 i;

	pthread_mutex_lock(&(tm->lock));

	tm->shutdown = 1;

	pthread_mutex_unlock(&(tm->lock));

	/* wait for all currently running threads to exit */
	for (i = 0; i < tm->max_threads; i++) {
		if (tm->thread_data[i].thread_id != (pthread_t)0) {
			if ((rc = pthread_join(tm->thread_data[i].thread_id, NULL))) {
				LogError("pthread_join() failed: error: %d", rc);
			}
		}
	}

	free(tm->thread_data);
	free(tm);

	return TSS_SUCCESS;
}

TSS_RESULT
tcsd_threads_init(void)
{
	/* allocate the thread mgmt structure */
	tm = calloc(1, sizeof(struct tcsd_thread_mgr));
	if (tm == NULL) {
		LogError("malloc of %zd bytes failed.", sizeof(struct tcsd_thread_mgr));
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	/* set the max threads variable from config */
	tm->max_threads = tcsd_options.num_threads;

	/* allocate each thread's data structure */
	tm->thread_data = calloc(tcsd_options.num_threads, sizeof(struct tcsd_thread_data));
	if (tm->thread_data == NULL) {
		LogError("malloc of %zu bytes failed.",
			 tcsd_options.num_threads * sizeof(struct tcsd_thread_data));
		free(tm);
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	return TSS_SUCCESS;
}


TSS_RESULT
tcsd_thread_create(int socket, char *hostname)
{
	UINT32 thread_num;
#ifndef TCSD_SINGLE_THREAD_DEBUG
	int rc;
	pthread_attr_t tcsd_thread_attr;

	/* init the thread attribute */
	if ((rc = pthread_attr_init(&tcsd_thread_attr))) {
		LogError("pthread_attr_init failed: error=%d: %s", rc, strerror(rc));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	/* make all threads joinable */
	if ((rc = pthread_attr_setdetachstate(&tcsd_thread_attr, PTHREAD_CREATE_JOINABLE))) {
		LogError("pthread_attr_init failed: error=%d: %s", rc, strerror(rc));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	pthread_mutex_lock(&(tm->lock));
#endif
	if (tm->num_active_threads == tm->max_threads) {
		close(socket);
		if (hostname != NULL) {
			LogError("max number of connections reached (%d), new connection"
				 " from %s refused.", tm->max_threads, hostname);
		} else {
			LogError("max number of connections reached (%d), new connection"
				 " refused.", tm->max_threads);
		}
		pthread_mutex_unlock(&(tm->lock));
		return TCSERR(TSS_E_CONNECTION_FAILED);
	}

	/* search for an open slot to store the thread data in */
	for (thread_num = 0; thread_num < tm->max_threads; thread_num++) {
		if (tm->thread_data[thread_num].thread_id == (pthread_t)0)
			break;
	}

	DBG_ASSERT(thread_num != tm->max_threads);

	tm->thread_data[thread_num].sock = socket;
	tm->thread_data[thread_num].context = NULL_TCS_HANDLE;
	if (hostname != NULL)
		memcpy(tm->thread_data[thread_num].hostname, hostname, strlen(hostname));

#ifdef TCSD_SINGLE_THREAD_DEBUG
	(void)tcsd_thread_run((void *)(&(tm->thread_data[thread_num])));
#else
	if ((rc = pthread_create(&(tm->thread_data[thread_num].thread_id),
				 &tcsd_thread_attr,
				 tcsd_thread_run,
				 (void *)(&(tm->thread_data[thread_num]))))) {
		LogError("pthread_create() failed: %d", rc);
		pthread_mutex_unlock(&(tm->lock));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	tm->num_active_threads++;

	pthread_mutex_unlock(&(tm->lock));
#endif
	return TSS_SUCCESS;
}

/* since we don't want any of the worker threads to catch any signals,
 * we must mask off any potential signals here after creating the threads.  If any of
 * the created threads catch a signal, they'd eventually call pthread_join() on
 * themselves, causing a deadlock.
 */
void
thread_signal_init()
{
	sigset_t thread_sigmask;
	int rc;

	if ((rc = sigfillset(&thread_sigmask))) {
		LogError("sigfillset failed: error=%d: %s", rc, strerror(rc));
		LogError("worker thread %u is exiting prematurely", (unsigned int)pthread_self());
		pthread_exit(NULL);
	}

	if ((rc = pthread_sigmask(SIG_BLOCK, &thread_sigmask, NULL))) {
		LogError("pthread_sigmask failed: error=%d: %s", rc, strerror(rc));
		LogError("worker thread %u is exiting prematurely", (unsigned int)pthread_self());
		pthread_exit(NULL);
	}
}

void *
tcsd_thread_run(void *v)
{
	struct tcsd_thread_data *data = (struct tcsd_thread_data *)v;
	BYTE buffer[TCSD_TXBUF_SIZE];
	struct tcsd_packet_hdr *ret_buf = NULL;
	TSS_RESULT result;
	int sizeToSend, sent_total, sent;
	UINT16 offset;
#ifndef TCSD_SINGLE_THREAD_DEBUG
	int rc;

	thread_signal_init();
#endif

	if ((data->buf_size = recv(data->sock, buffer, TCSD_TXBUF_SIZE, 0)) < 0) {
		LogError("Failed Receive: %s", strerror(errno));
		goto done;
	}
	LogDebug("Rx'd packet");

	data->buf = buffer;

	while (1) {
		sent_total = 0;
		if (data->buf_size > TCSD_TXBUF_SIZE) {
			LogError("Packet received from socket %d was too large (%u bytes)",
				 data->sock, data->buf_size);
			goto done;
		} else if (data->buf_size < (int)((2 * sizeof(UINT32)) + sizeof(UINT16))) {
			LogError("Packet received from socket %d was too small (%u bytes)",
				 data->sock, data->buf_size);
			goto done;
		}

		if ((result = getTCSDPacket(data, &ret_buf)) != TSS_SUCCESS) {
			/* something internal to the TCSD went wrong in preparing the packet
			 * to return to the TSP.  Use our already allocated buffer to return a
			 * TSS_E_INTERNAL_ERROR return code to the TSP. In the non-error path,
			 * these LoadBlob's are done in getTCSDPacket().
			 */
			offset = 0;
			/* load result */
			LoadBlob_UINT32(&offset, result, buffer, NULL);
			/* load packet size */
			LoadBlob_UINT32(&offset, sizeof(struct tcsd_packet_hdr), buffer, NULL);
			/* load num parms */
			LoadBlob_UINT16(&offset, 0, buffer, NULL);

			sizeToSend = sizeof(struct tcsd_packet_hdr);
			LogDebug("Sending 0x%X bytes back", sizeToSend);

			while (sent_total < sizeToSend) {
				if ((sent = send(data->sock,
						 &data->buf[sent_total],
						 sizeToSend - sent_total, 0)) < 0) {
					LogError("Packet send to TSP failed: send: %s. Thread exiting.",
							strerror(errno));
					goto done;
				}
				sent_total += sent;
			}
		} else {
			sizeToSend = Decode_UINT32((BYTE *)&(ret_buf->packet_size));

			LogDebug("Sending 0x%X bytes back", sizeToSend);

			while (sent_total < sizeToSend) {
				if ((sent = send(data->sock,
						 &(((BYTE *)ret_buf)[sent_total]),
						 sizeToSend - sent_total, 0)) < 0) {
					LogError("response to TSP failed: send: %s. Thread exiting.",
							strerror(errno));
					free(ret_buf);
					ret_buf = NULL;
					goto done;
				}
				sent_total += sent;
			}
			free(ret_buf);
			ret_buf = NULL;
		}

		if (tm->shutdown) {
			LogDebug("Thread %u exiting via shutdown signal!", (unsigned int)pthread_self());
			break;
		}

		/* receive the next packet */
		if ((data->buf_size = recv(data->sock, buffer, TCSD_TXBUF_SIZE, 0)) < 0) {
			LogError("TSP has closed its connection: %s. Thread exiting.", strerror(errno));
			break;
		} else if (data->buf_size == 0) {
			LogDebug("The TSP has closed the socket's connection. Thread exiting.");
			break;
		}
	}

done:
	/* Closing connection to TSP */
	close(data->sock);
	data->sock = -1;
	data->buf = NULL;
	data->buf_size = -1;
	/* If the connection was not shut down cleanly, free TCS resources here */
	if (data->context != NULL_TCS_HANDLE) {
		TCS_CloseContext_Internal(data->context);
		data->context = NULL_TCS_HANDLE;
	}

#ifndef TCSD_SINGLE_THREAD_DEBUG
	pthread_mutex_lock(&(tm->lock));
	tm->num_active_threads--;
	/* if we're not in shutdown mode, then nobody is waiting to join this thread, so
	 * detach it so that its resources are free at pthread_exit() time. */
	if (!tm->shutdown) {
		if ((rc = pthread_detach(data->thread_id))) {
			LogError("pthread_detach failed (errno %d)."
				 " Resources may not be properly released.", rc);
		}
	}
	data->hostname[0] = '\0';
	data->thread_id = (pthread_t)0;
	pthread_mutex_unlock(&(tm->lock));
	pthread_exit(NULL);
#else
	return NULL;
#endif
}
