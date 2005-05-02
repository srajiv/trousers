
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2005
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "tss/tss.h"
#include "tsplog.h"

/* SSH_ASKPASS_EXE is defined at configure time */
const char *askpass = SSH_ASKPASS_EXE;

static char *
ssh_askpass(const char *msg)
{
	pid_t pid;
	int pipe_fds[2], rc, bytes_read;
	char *strip, *password;
	char buf[256];

	if ((pipe(pipe_fds)) == -1) {
		LogError("Pipe to get password from GUI failed: %s", strerror(errno));
		return NULL;
	}

	if ((pid = fork()) == -1) {
		LogError("ssh_askpass: fork: %s", strerror(errno));
		return NULL;
	} else if (pid == 0) {
		/* child writing to parent, so close the read fd in the child */
		close(pipe_fds[0]);

		/* set stdout to the pipe to send password to the parent */
		if (dup2(pipe_fds[1], fileno(stdout)) == -1) {
			LogError("ssh_askpass: dup2: %s", strerror(errno));
			exit(-1);
		}

		/* launch the askpass programand then exit */
		execl(askpass, askpass, "-xrm", "*dialog.title: TPM Authentication Dialog",
				msg, NULL);
		LogError("ssh_askpass: exec'(%s): %s", askpass, strerror(errno));
		exit(-1);
	}
	/* parent is reading from child, so close the parent's writing fd */
	close(pipe_fds[1]);

	LogDebug("dialog popup args: %s %s %s %s\n", askpass, "-xrm",
			"*dialog.title: TPM Authentication Dialog", msg);

	bytes_read = rc = 0;
	while (rc >= 0 && (bytes_read < 256)) {
		bytes_read = read(pipe_fds[0], &buf[bytes_read], 256 - bytes_read);
		if (rc == 0) {
			break;
		} else if (rc == -1) {
			if (errno == EINTR) {
				rc = 0;
			} else {
				LogError("Error on read of password: %s", strerror(errno));
				break;
			}
		}
		/* rc is greater than 0, add it to bytes_read */
		bytes_read += rc;
	}
	buf[bytes_read] = '\0';

	/* remove whitespace */
	while ((strip = rindex(buf, '\r')) != NULL) {
		*strip = '\0';
	}
	while ((strip = rindex(buf, '\n')) != NULL) {
		*strip = '\0';
	}

	password = strdup(&buf[0]);

	return password;
}

/*
 * DisplayPINWindow()
 *
 * Popup the dialog to collect an existing password.
 *
 * string - buffer that the password will be passed back to caller in
 * w_popup - UNICODE string to be displayed in the title bar of the dialog box
 *
 */
TSS_RESULT
DisplayPINWindow(char *string, UNICODE *w_popup)
{
	char c_title[256], *pass;
	mbstate_t ps;
	int rc;

	memset(&ps, 0, sizeof(mbstate_t));

	if ((rc = wcsrtombs(c_title, (const UNICODE **)&w_popup, 256, &ps)) == -1) {
		LogDebug("Error converting wide char string to bytes");
		return TSS_E_INTERNAL_ERROR;
	}
	//sprintf(c_title, "\"%s\"", c_title);

	LogDebug("dialog title: %s", c_title);

	pass = ssh_askpass(c_title);
	if (pass == NULL)
		return TSS_E_INTERNAL_ERROR;

	memcpy(string, pass, strlen(pass));
	free(pass);

	return TSS_SUCCESS;
}

/*
 * DisplayNewPINWindow()
 *
 * Popup the dialog to collect a new password.
 *
 * string - buffer that the password will be passed back to caller in
 * w_popup - UNICODE string to be displayed in the title bar of the dialog box
 *
 */
TSS_RESULT
DisplayNewPINWindow(char *string, UNICODE *w_popup)
{
	char c_title[256], *pass, *pass_verify, *label, loop = 0;
	mbstate_t ps;
	TSS_RESULT result = TSS_E_INTERNAL_ERROR;
	char *retry_prefix = "Passwords do not match.\n";
	char retry_string[512];

	memset(&ps, 0, sizeof(mbstate_t));

	wcsrtombs(c_title, (const UNICODE **)&w_popup, 256, &ps);

	while (result != TSS_SUCCESS) {
		if (loop) {
			sprintf(retry_string, "%s%s", retry_prefix, c_title);
			label = retry_string;
		} else {
			loop = 1;
			label = c_title;
		}

		pass = ssh_askpass(label);
		if (pass == NULL)
			return TSS_E_INTERNAL_ERROR;

		pass_verify = ssh_askpass("Please verify your password:");
		if (pass_verify == NULL) {
			free(pass);
			return TSS_E_INTERNAL_ERROR;
		}


		if (strlen(pass) == strlen(pass_verify) &&
				!strcmp(pass, pass_verify)) {
			memcpy(string, pass, strlen(pass));
			result = TSS_SUCCESS;
		} else {
			result = TSS_E_INTERNAL_ERROR;
		}
	}

	free(pass);
	free(pass_verify);

	return result;
}

