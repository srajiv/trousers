/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (C) International Business Machines Corp. 2005
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
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
	size_t len;
	char *pass;
	int p[2], status, ret;
	char buf[1024];
	char *title_arg = "*dialog.title: TPM Authentication Dialog";

	if (fflush(stdout) != 0) {
		LogDebug("ssh_askpass: fflush: %s", strerror(errno));
		return NULL;
	}
	if (askpass == NULL) {
		LogDebug("internal error: askpass undefined");
		return NULL;
	}
	if (pipe(p) < 0) {
		LogDebug("ssh_askpass: pipe: %s", strerror(errno));
		return NULL;
	}
	if ((pid = fork()) < 0) {
		LogDebug("ssh_askpass: fork: %s", strerror(errno));
		return NULL;
	}
	if (pid == 0) {
		seteuid(getuid());
		setuid(getuid());
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) < 0) {
			LogError("ssh_askpass: dup2: %s", strerror(errno));
			exit(-1);
		}
		execlp(askpass, askpass, "-xrm", title_arg, msg, (char *) 0);
		LogError("ssh_askpass: exec(%s): %s", askpass, strerror(errno));
		exit(-1);
	}
	close(p[1]);

	LogDebug("dialog popup args: %s %s %s %s", askpass, "-xrm", title_arg, msg);

	len = ret = 0;
	do {
		ret = read(p[0], buf + len, sizeof(buf) - 1 - len);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret <= 0)
			break;
		len += ret;
	} while (sizeof(buf) - 1 - len > 0);
	buf[len] = '\0';

	close(p[0]);
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			break;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		memset(buf, 0, sizeof(buf));
		return NULL;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = strdup(buf);
	memset(buf, 0, sizeof(buf));
	return pass;
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

	memset(&ps, 0, sizeof(mbstate_t));

	wcsrtombs(c_title, (const UNICODE **)&w_popup, 256, &ps);
	sprintf(c_title, "\"%s\"", c_title);

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

