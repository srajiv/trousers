
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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#include "tss/tss.h"
#include "tcs_internal_types.h"
#include "spi_internal_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsps.h"
#include "tspps.h"
#include "tcsd.h"
#include "req_mgr.h"

struct tcsd_config tcsd_options;
struct tpm_properties tpm_metrics;

int sd, newsd;

void
tcsd_shutdown()
{
	/* order is important here:
	 * allow all threads to complete their current request */
	tcsd_threads_final();
	closeDiskCache();
	auth_mgr_final();
	(void)req_mgr_final();
	conf_file_final(&tcsd_options);
	event_log_final();
}

void
tcsd_signal_int(int signal)
{
	switch (signal) {
		case SIGINT:
			LogInfo1("Caught SIGINT. Cleaning up and exiting.");
			break;
		case SIGHUP:
			LogInfo1("Caught SIGHUP. Cleaning up and exiting.");
			break;
		default:
			LogError("Caught signal %d (which I didn't register for!)."
					" Ignoring.", signal);
			break;
	}
	tcsd_shutdown();
	exit(signal);
}

void
tcsd_signal_chld(int signal)
{
	/* kill zombies */
	wait3(NULL, WNOHANG, NULL);
}

TSS_RESULT
signals_init()
{
	int rc;
	sigset_t sigmask;

	sigemptyset(&sigmask);
	if ((rc = sigaddset(&sigmask, SIGCHLD))) {
		LogError("sigaddset: %s", strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}
	if ((rc = sigaddset(&sigmask, SIGINT))) {
		LogError("sigaddset: %s", strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}
	if ((rc = sigaddset(&sigmask, SIGHUP))) {
		LogError("sigaddset: %s", strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	if ((rc = pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL))) {
		LogError("pthread_sigmask: %s", strerror(rc));
		return TSS_E_INTERNAL_ERROR;
	}

	tcsd_sa_int.sa_handler = tcsd_signal_int;
	tcsd_sa_chld.sa_handler = tcsd_signal_chld;
	tcsd_sa_chld.sa_flags = SA_RESTART;

	if ((rc = sigaction(SIGINT, &tcsd_sa_int, NULL))) {
		LogError("signal SIGINT not registered: %s", strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	if ((rc = sigaction(SIGHUP, &tcsd_sa_int, NULL))) {
		LogError("signal SIGHUP not registered: %s", strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	if ((rc = sigaction(SIGCHLD, &tcsd_sa_chld, NULL))) {
		LogError("signal SIGCHLD not registered: %s", strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
tcsd_startup()
{
	TSS_RESULT result;

	if ((result = signals_init()))
		return result;

	if ((result = conf_file_init(&tcsd_options)))
		return result;

	if ((result = tcsd_threads_init())) {
		conf_file_final(&tcsd_options);
		return result;
	}

	if ((result = req_mgr_init())) {
		conf_file_final(&tcsd_options);
		return result;
	}

	if ((result = ps_dirs_init())) {
		conf_file_final(&tcsd_options);
		(void)req_mgr_final();
		return result;
	}

	if ((result = initDiskCache())) {
		conf_file_final(&tcsd_options);
		(void)req_mgr_final();
		return result;
	}

	if ((result = get_tpm_metrics(&tpm_metrics))) {
		conf_file_final(&tcsd_options);
		closeDiskCache();
		(void)req_mgr_final();
		return result;
	}

	/* must happen after get_tpm_metrics() */
	if ((result = auth_mgr_init())) {
		conf_file_final(&tcsd_options);
		closeDiskCache();
		(void)req_mgr_final();
		return result;
	}

	if ((result = event_log_init())) {
		auth_mgr_final();
		conf_file_final(&tcsd_options);
		closeDiskCache();
		(void)req_mgr_final();
		return result;
	}

	return TSS_SUCCESS;
}

int
main(int argc, char **argv)
{
	struct sockaddr_in addr;
	TSS_RESULT result;
	socklen_t size;
	int sd, c;
	char hostname[80];

	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
			case 'f':
				foreground = 1;
				break;
			default:
				LogError("invalid option: %s", optarg);
				return -1;
				break;
		}
	}

	if ((result = tcsd_startup()))
		return (int)result;

	if (!foreground) {
		if (daemon(0, 0) == -1) {
			perror("daemon");
			tcsd_shutdown();
			return -1;
		}
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		LogError("Failed socket: %s", strerror(errno));
		return -1;
	}
	memset(&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(tcsd_options.port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		LogError("Failed bind: %s", strerror(errno));
		return -1;
	}
	if (listen(sd, TCSD_MAX_SOCKETS_QUEUED) < 0) {
		LogError("Failed listen: %s", strerror(errno));
		return -1;
	}
	size = sizeof (addr);
	LogInfo("%s: TCSD up and running.", PACKAGE_STRING);
	do {
		newsd = accept(sd, (struct sockaddr *) &addr, &size);
		LogDebug("accepted socket %i", newsd);
		if (newsd < 0) {
			LogError("Failed accept: %s", strerror(errno));
			break;
		}

		/* Resolve the TSP's hostname and spawn a thread to service it */
		if ((getnameinfo(&addr, size, hostname, 80, NULL, 0, 0))) {
			LogError1("Connecting hostname could not be resolved.");
			tcsd_thread_create(newsd, NULL);
		} else {
			LogInfo("Connection accepted from %s", hostname);

			tcsd_thread_create(newsd, hostname);
		}
	} while (1);

	return 0;
}
