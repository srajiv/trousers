
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
#if (defined (__OpenBSD__) || defined (__FreeBSD__))
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsps.h"
#include "tcsd.h"
#include "req_mgr.h"

struct tcsd_config tcsd_options;
struct tpm_properties tpm_metrics;

void
tcsd_shutdown()
{
	/* order is important here:
	 * allow all threads to complete their current request */
	tcsd_threads_final();
	PS_close_disk_cache();
	auth_mgr_final();
	(void)req_mgr_final();
	conf_file_final(&tcsd_options);
	EVENT_LOG_final();
}

void
tcsd_signal_int(int signal)
{
	switch (signal) {
		case SIGINT:
			LogInfo("Caught SIGINT. Cleaning up and exiting.");
			break;
		case SIGHUP:
			LogInfo("Caught SIGHUP. Cleaning up and exiting.");
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
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if ((rc = sigaddset(&sigmask, SIGINT))) {
		LogError("sigaddset: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}
	if ((rc = sigaddset(&sigmask, SIGHUP))) {
		LogError("sigaddset: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if ((rc = THREAD_SET_SIGNAL_MASK(SIG_UNBLOCK, &sigmask, NULL))) {
		LogError("Setting thread signal mask: %s", strerror(rc));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	tcsd_sa_int.sa_handler = tcsd_signal_int;
	tcsd_sa_chld.sa_handler = tcsd_signal_chld;
	tcsd_sa_chld.sa_flags = SA_RESTART;

	if ((rc = sigaction(SIGINT, &tcsd_sa_int, NULL))) {
		LogError("signal SIGINT not registered: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if ((rc = sigaction(SIGHUP, &tcsd_sa_int, NULL))) {
		LogError("signal SIGHUP not registered: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	if ((rc = sigaction(SIGCHLD, &tcsd_sa_chld, NULL))) {
		LogError("signal SIGCHLD not registered: %s", strerror(errno));
		return TCSERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

TSS_RESULT
tcsd_startup()
{
	TSS_RESULT result;

#ifdef TSS_DEBUG
	/* Set stdout to be unbuffered to match stderr and interleave output correctly */
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
#endif

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

	result = PS_init_disk_cache();
	if (result != TSS_SUCCESS) {
		conf_file_final(&tcsd_options);
		(void)req_mgr_final();
		return result;
	}

	if ((result = get_tpm_metrics(&tpm_metrics))) {
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	/* must happen after get_tpm_metrics() */
	if ((result = auth_mgr_init())) {
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	result = EVENT_LOG_init();
	if (result != TSS_SUCCESS) {
		auth_mgr_final();
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	result = owner_evict_init();
	if (result != TSS_SUCCESS) {
		auth_mgr_final();
		conf_file_final(&tcsd_options);
		PS_close_disk_cache();
		(void)req_mgr_final();
		return result;
	}

	return TSS_SUCCESS;
}

void
usage(void)
{
	fprintf(stderr, "\tusage: tcsd [-f] [-h]\n\n");
	fprintf(stderr, "\t-f|--foreground\trun in the foreground. Logging goes to stderr "
			"instead of syslog.\n");
	fprintf(stderr, "\t-h|--help\tdisplay this help message\n");
	fprintf(stderr, "\n");
}

int
main(int argc, char **argv)
{
	struct sockaddr_in serv_addr, client_addr;
	TSS_RESULT result;
	int sd, newsd, c, option_index = 0;
	unsigned client_len;
	char *hostname = NULL;
	struct hostent *client_hostent = NULL;
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"foreground", 0, NULL, 'f'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "fh", long_options, &option_index)) != -1) {
		switch (c) {
			case 'f':
				setenv("TCSD_FOREGROUND", "1", 1);
				break;
			case 'h':
				/* fall through */
			default:
				usage();
				return -1;
				break;
		}
	}

	if ((result = tcsd_startup()))
		return (int)result;

	if (getenv("TCSD_FOREGROUND") == NULL) {
		if (daemon(0, 0) == -1) {
			perror("daemon");
			tcsd_shutdown();
			return -1;
		}
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		LogError("Failed socket: %s", strerror(errno));
		return -1;
	}

	memset(&serv_addr, 0, sizeof (serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(tcsd_options.port);

	/* If no remote_ops are defined, restrict connections to localhost
	 * only at the socket. */
	if (tcsd_options.remote_ops[0] == 0)
		serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	c = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c));
	if (bind(sd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) {
		LogError("Failed bind: %s", strerror(errno));
		return -1;
	}
	if (listen(sd, TCSD_MAX_SOCKETS_QUEUED) < 0) {
		LogError("Failed listen: %s", strerror(errno));
		return -1;
	}
	client_len = (unsigned)sizeof(client_addr);
	LogInfo("%s: TCSD up and running.", PACKAGE_STRING);
	do {
		newsd = accept(sd, (struct sockaddr *) &client_addr, &client_len);
		LogDebug("accepted socket %i", newsd);
		if (newsd < 0) {
			LogError("Failed accept: %s", strerror(errno));
			break;
		}

		if ((client_hostent = gethostbyaddr((char *) &client_addr.sin_addr,
						    sizeof(client_addr.sin_addr),
						    AF_INET)) == NULL) {
			char buf[16];
                        uint32_t addr = htonl(client_addr.sin_addr.s_addr);

                        snprintf(buf, 16, "%d.%d.%d.%d", (addr & 0xff000000) >> 24,
                                 (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8,
                                 addr & 0x000000ff);

			LogWarn("Host name for connecting IP %s could not be resolved", buf);
			hostname = strdup(buf);
		} else {
			hostname = strdup(client_hostent->h_name);
		}

		tcsd_thread_create(newsd, hostname);
		hostname = NULL;
	} while (1);

	/* To close correctly, we must recieve a SIGHUP */
	return -1;
}
