
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <grp.h>
#include <stdlib.h>

#include "tss/tss.h"
#include "tcs_utils.h"
#include "tcsps.h"
#include "tcslog.h"
#include "tcsd_wrap.h"
#include "tcsd.h"
#include "tcsd_ops.h"

struct tcsd_config_options options_list[] = {
	{"port", opt_port},
	{"num_threads", opt_max_threads},
	{"system_ps_file", opt_system_ps_file},
	{"firmware_log_file", opt_firmware_log},
	{"firmware_pcrs", opt_firmware_pcrs},
	{"kernel_log_file", opt_kernel_log},
	{"kernel_pcrs", opt_kernel_pcrs},
	{"remote_ops", opt_remote_ops},
	{NULL, 0}
};


void
init_tcsd_config(struct tcsd_config *conf)
{
	conf->port = -1;
	conf->num_threads = -1;
	conf->system_ps_file = NULL;
	conf->system_ps_dir = NULL;
	conf->firmware_log_file = NULL;
	conf->firmware_pcrs = 0;
	conf->kernel_log_file = NULL;
	conf->kernel_pcrs = 0;
	memset(conf->remote_ops, 0, sizeof(conf->remote_ops));
	conf->unset = 0xffffffff;
}

void
config_set_defaults(struct tcsd_config *conf)
{
	/* give all unset options their default values */
	if (conf->unset & TCSD_OPTION_PORT)
		conf->port = TCSD_DEFAULT_PORT;

	if (conf->unset & TCSD_OPTION_MAX_THREADS)
		conf->num_threads = TCSD_DEFAULT_MAX_THREADS;

	if (conf->unset & TCSD_OPTION_FIRMWARE_PCRS)
		conf->firmware_pcrs = TCSD_DEFAULT_FIRMWARE_PCRS;

	if (conf->unset & TCSD_OPTION_KERNEL_PCRS)
		conf->kernel_pcrs = TCSD_DEFAULT_KERNEL_PCRS;

	/* these are strdup'd so we know we can free them at shutdown time */
	if (conf->unset & TCSD_OPTION_SYSTEM_PSFILE) {
		conf->system_ps_file = strdup(TCSD_DEFAULT_SYSTEM_PS_FILE);
		conf->system_ps_dir = strdup(TCSD_DEFAULT_SYSTEM_PS_DIR);
	}

	if (conf->unset & TCSD_OPTION_FIRMWARE_LOGFILE)
		conf->firmware_log_file = strdup(TCSD_DEFAULT_FIRMWARE_LOG_FILE);

	if (conf->unset & TCSD_OPTION_KERNEL_LOGFILE)
		conf->kernel_log_file = strdup(TCSD_DEFAULT_KERNEL_LOG_FILE);
}

int
get_config_option(char *ptr, char **arg)
{
	int i;

	for (i = 0; options_list[i].name; i++) {
		if (!strncasecmp(ptr, options_list[i].name, strlen(options_list[i].name))) {
			/* move ptr past our recognized token */
			ptr += strlen(options_list[i].name);

			/* try to move ptr to the start of the option's argument */
			while (*ptr == '=' || *ptr == ' ' || *ptr == '\t')
				ptr++;

			*arg = ptr;
			return options_list[i].option;
		}
	}
	/* on error we'll print the whole line to the log */
	*arg = ptr;
	return 0;
}

/* copy a file path from a string into a newly malloc'd string */
int
get_file_path(char *ptr, char **dest)
{
	char tmp_buf[1024];
	int i = 0;

	while (isalpha(*ptr) || isdigit(*ptr) ||
		*ptr == '/' || *ptr == '.' || *ptr == '#' || *ptr == '_')
	{
		tmp_buf[i] = *ptr;
		ptr++;
		i++;
	}

	/* move through whitespace after the path */
	while (*ptr == ' ' || *ptr == '\t')
		ptr++;

	/* if we're not at a comment or EOL, there's junk */
	if (*ptr != '#' && *ptr != '\n') {
		*dest = ptr;
		return 1;
	}

	/* too short a path */
	if (i == 0)
		return -1;

	tmp_buf[i] = '\0';
	*dest = strdup(tmp_buf);
	if (*dest == NULL) {
		LogError("malloc of %d bytes failed", strlen(tmp_buf));
	}

	return 0;
}

/* add an op ordinal, checking for duplicates along the way */
void
tcsd_add_op(int *remote_ops, int *op)
{
	int i = 0, j;

	while (op[i] != 0) {
		j = 0;
		while (remote_ops[j] != 0) {
			if (remote_ops[j] == op[i]) {
				break;
			}
			j++;
		}
		remote_ops[j] = op[i];
		i++;
	}
}

int
tcsd_set_remote_op(struct tcsd_config *conf, char *op_name)
{
	int i = 0;

	while(tcsd_ops[i]) {
		if (!strcmp(tcsd_ops[i]->name, op_name)) {
			/* match found */
			tcsd_add_op(conf->remote_ops, tcsd_ops[i]->op);
			return 0;
		}
		i++;
	}

	/* fail, op not found */
	return 1;
}

TSS_RESULT
read_conf_line(char *buf, int line_num, struct tcsd_config *conf)
{
	char *ptr = buf, *tmp_ptr = NULL, *arg, *comma;
	int option, tmp_int;

	if (ptr == NULL || *ptr == '\0' || *ptr == '#' || *ptr == '\n')
		return TSS_SUCCESS;

	/* read through whitespace */
	while (*ptr == ' ' || *ptr == '\t')
		ptr++;

	/* ignore comments */
	if (*ptr == '#')
		return TSS_SUCCESS;

	option = get_config_option(ptr, &arg);

	switch (option) {
        case opt_port:
		tmp_int = atoi(arg);
		if (tmp_int < 0 || tmp_int > 65535) {
			LogError("Config option \"port\" out of range. %s:%d: \"%d\"",
					TCSD_CONFIG_FILE, line_num, tmp_int);
			return TSS_E_INTERNAL_ERROR;
		} else {
			conf->port = tmp_int;
			conf->unset &= ~TCSD_OPTION_PORT;
		}
		break;
	case opt_max_threads:
		tmp_int = atoi(arg);
		if (tmp_int <= 0) {
			LogError("Config option \"num_threads\" out of range. %s:%d: \"%d\"",
					TCSD_CONFIG_FILE, line_num, tmp_int);
			return TSS_E_INTERNAL_ERROR;
		} else {
			conf->num_threads = tmp_int;
			conf->unset &= ~TCSD_OPTION_MAX_THREADS;
		}
		break;
	case opt_firmware_pcrs:
		conf->unset &= ~TCSD_OPTION_FIRMWARE_PCRS;
		while (1) {
			comma = rindex(arg, ',');

			if (comma == NULL) {
				if (!isdigit(*arg))
					break;

				comma = arg;
				tmp_int = atoi(comma);
				if (tmp_int >= 0 && tmp_int < TCSD_MAX_PCRS)
					conf->firmware_pcrs |= (1 << tmp_int);
				else
					LogError("Config option \"firmware_pcrs\" is out of range."
						 "%s:%d: \"%d\"", TCSD_CONFIG_FILE, line_num, tmp_int);
				break;
			}

			*comma++ = '\0';
			tmp_int = atoi(comma);
			if (tmp_int >= 0 && tmp_int < TCSD_MAX_PCRS)
				conf->firmware_pcrs |= (1 << tmp_int);
			else
				LogError("Config option \"firmware_pcrs\" is out of range. %s:%d: \"%d\"",
						TCSD_CONFIG_FILE, line_num, tmp_int);
		}
		break;
	case opt_kernel_pcrs:
		conf->unset &= ~TCSD_OPTION_KERNEL_PCRS;
		while (1) {
			comma = rindex(arg, ',');

			if (comma == NULL) {
				if (!isdigit(*arg))
					break;

				comma = arg;
				tmp_int = atoi(comma);
				if (tmp_int >= 0 && tmp_int < TCSD_MAX_PCRS)
					conf->kernel_pcrs |= (1 << tmp_int);
				else
					LogError("Config option \"kernel_pcrs\" is out of range. "
						 "%s:%d: \"%d\"", TCSD_CONFIG_FILE, line_num, tmp_int);
				break;
			}

			*comma++ = '\0';
			tmp_int = atoi(comma);
			if (tmp_int >= 0 && tmp_int < TCSD_MAX_PCRS)
				conf->kernel_pcrs |= (1 << tmp_int);
			else
				LogError("Config option \"kernel_pcrs\" is out of range. %s:%d: \"%d\"",
						TCSD_CONFIG_FILE, line_num, tmp_int);
		}
		break;
	case opt_system_ps_file:
		if (*arg != '/') {
			LogError("Config option \"system_ps_dir\" must be an absolute path name. %s:%d: \"%s\"",
					TCSD_CONFIG_FILE, line_num, arg);
		} else {
			char *dir_ptr;
			int rc;

			if ((rc = get_file_path(arg, &tmp_ptr)) < 0) {
				LogError("Config option \"system_ps_file\" is invalid. %s:%d: \"%s\"",
						TCSD_CONFIG_FILE, line_num, arg);
				return TSS_E_INTERNAL_ERROR;
			} else if (rc > 0) {
				LogError("Config option \"system_ps_file\" is invalid. %s:%d: \"%s\"",
						TCSD_CONFIG_FILE, line_num, tmp_ptr);
				return TSS_E_INTERNAL_ERROR;
			}
			if (tmp_ptr == NULL)
				return TSS_E_OUTOFMEMORY;

			if (conf->system_ps_file)
				free(conf->system_ps_file);
			if (conf->system_ps_dir)
				free(conf->system_ps_dir);

			/* break out the system ps directory from the file path */
			dir_ptr = rindex(tmp_ptr, '/');
			*dir_ptr = '\0';
			if (strlen(tmp_ptr) == 0)
				conf->system_ps_dir = strdup("/");
			else
				conf->system_ps_dir = strdup(tmp_ptr);

			if (conf->system_ps_dir == NULL) {
				LogError1("malloc failed.");
				free(tmp_ptr);
				return TSS_E_OUTOFMEMORY;
			}
			*dir_ptr = '/';
			conf->system_ps_file = tmp_ptr;
			conf->unset &= ~TCSD_OPTION_SYSTEM_PSFILE;
		}
		break;
	case opt_kernel_log:
		if (*arg != '/') {
			LogError("Config option \"kernel_log\" must be an absolute path name. %s:%d: \"%s\"",
					TCSD_CONFIG_FILE, line_num, arg);
		} else {
			int rc;

			if ((rc = get_file_path(arg, &tmp_ptr)) < 0) {
				LogError("Config option \"kernel_log\" is invalid. %s:%d: \"%s\"",
						TCSD_CONFIG_FILE, line_num, arg);
				return TSS_E_INTERNAL_ERROR;
			} else if (rc > 0) {
				LogError("Config option \"kernel_log\" is invalid. %s:%d: \"%s\"",
						TCSD_CONFIG_FILE, line_num, tmp_ptr);
				return TSS_E_INTERNAL_ERROR;
			}
			if (tmp_ptr == NULL)
				return TSS_E_OUTOFMEMORY;

			if (conf->kernel_log_file)
				free(conf->kernel_log_file);

			conf->kernel_log_file = tmp_ptr;
			conf->unset &= ~TCSD_OPTION_KERNEL_LOGFILE;
		}
		break;
	case opt_firmware_log:
		if (*arg != '/') {
			LogError("Config option \"firmware_log\" must be an absolute path name. %s:%d: \"%s\"",
					TCSD_CONFIG_FILE, line_num, arg);
		} else {
			int rc;

			if ((rc = get_file_path(arg, &tmp_ptr)) < 0) {
				LogError("Config option \"firmware_log\" is invalid. %s:%d: \"%s\"",
						TCSD_CONFIG_FILE, line_num, arg);
				return TSS_E_INTERNAL_ERROR;
			} else if (rc > 0) {
				LogError("Config option \"firmware_log\" is invalid. %s:%d: \"%s\"",
						TCSD_CONFIG_FILE, line_num, tmp_ptr);
				return TSS_E_INTERNAL_ERROR;
			}
			if (tmp_ptr == NULL)
				return TSS_E_OUTOFMEMORY;

			if (conf->firmware_log_file)
				free(conf->firmware_log_file);

			conf->firmware_log_file = tmp_ptr;
			conf->unset &= ~TCSD_OPTION_FIRMWARE_LOGFILE;
		}
		break;
	case opt_remote_ops:
		conf->unset &= ~TCSD_OPTION_REMOTE_OPS;
		comma = rindex(arg, '\n');
		*comma = '\0';
		while (1) {
			comma = rindex(arg, ',');

			if (comma == NULL) {
				comma = arg;

				if (comma != NULL) {
					if (tcsd_set_remote_op(conf, comma)) {
						LogError("Config option \"remote_ops\" is invalid. "
								"%s:%d: \"%s\"", TCSD_CONFIG_FILE, line_num, comma);
					}
				}
				break;
			}

			*comma++ = '\0';
			if (tcsd_set_remote_op(conf, comma)) {
				LogError("Config option \"remote_ops\" is invalid. "
						"%s:%d: \"%s\"", TCSD_CONFIG_FILE, line_num, comma);
			}
		}
		break;
	default:
		/* bail out on any unknown option */
		LogError("Unknown config option %s:%d \"%s\"!",
				TCSD_CONFIG_FILE, line_num, arg);
		return TSS_E_INTERNAL_ERROR;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
read_conf_file(FILE *f, struct tcsd_config *conf)
{
	int line_num = 0;
	char buf[1024];

	while (fgets(buf, 1024, f)) {
		line_num++;
		if (read_conf_line(buf, line_num, conf))
			return TSS_E_INTERNAL_ERROR;
	}

	return TSS_SUCCESS;
}

void
conf_file_final(struct tcsd_config *conf)
{
	free(conf->system_ps_file);
	free(conf->system_ps_dir);
	free(conf->kernel_log_file);
	free(conf->firmware_log_file);
}

TSS_RESULT
conf_file_init(struct tcsd_config *conf)
{
	FILE *f = NULL;
	struct stat stat_buf;
	struct group *grp;
	struct passwd *pw;
	mode_t mode = (S_IRUSR|S_IWUSR);
	TSS_RESULT result;

	init_tcsd_config(conf);

	/* look for a config file, create if it doesn't exist */
	if (stat(TCSD_CONFIG_FILE, &stat_buf) == -1) {
		if (errno == ENOENT) {
			/* no config file? use defaults */
			config_set_defaults(conf);
			LogInfo("Config file %s not found, using defaults.", TCSD_CONFIG_FILE);
			return TCS_SUCCESS;
		} else {
			LogError("stat(%s): %s", TCSD_CONFIG_FILE, strerror(errno));
			return TSS_E_INTERNAL_ERROR;
		}
	}

	/* find the gid that owns the conf file */
	grp = getgrnam(TSS_GROUP_NAME);
	if (grp == NULL) {
		LogError("getgrnam(%s): %s", TSS_GROUP_NAME, strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	pw = getpwnam(TSS_USER_NAME);
	if (pw == NULL) {
		LogError("getpwnam(%s): %s", TSS_USER_NAME, strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	/* make sure user/group TSS owns the conf file */
	if (pw->pw_uid != stat_buf.st_uid || grp->gr_gid != stat_buf.st_gid) {
		LogError("TCSD config file (%s) must be user/group %s/%s", TCSD_CONFIG_FILE,
				TSS_USER_NAME, TSS_GROUP_NAME);
		return TSS_E_INTERNAL_ERROR;
	}

	/* make sure only the tss user can manipulate the config file */
	if (((stat_buf.st_mode & 0777) ^ mode) != 0) {
		LogError("TCSD config file (%s) must be mode 0600", TCSD_CONFIG_FILE);
		return TSS_E_INTERNAL_ERROR;
	}

	if ((f = fopen(TCSD_CONFIG_FILE, "r")) == NULL) {
		LogError("fopen(%s): %s", TCSD_CONFIG_FILE, strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	result = read_conf_file(f, conf);
	fclose(f);

	/* fill out any uninitialized options */
	config_set_defaults(conf);

	return result;
}


TSS_RESULT
ps_dirs_init()
{
	struct stat stat_buf;
	mode_t mode = (S_IRWXU|S_IRWXG|S_IRWXO|S_ISVTX); /* 0777 plus sticky bit */

	/* query the key storage directory to make sure it exists and is of the right mode */
	if (stat(tcsd_options.system_ps_dir, &stat_buf) == -1) {
		if (errno == ENOENT) {
			/* The dir DNE, create it with mode drwxrwxrwt */
			if (mkdir(tcsd_options.system_ps_dir, mode) == -1) {
				LogError("mkdir(%s) failed: %s. If you'd like to use %s to"
						"store your system persistent data, please"
						" create it. Otherwise, change the location"
						" in your tcsd.conf file.",
						tcsd_options.system_ps_dir, strerror(errno),
						tcsd_options.system_ps_dir);
				return TSS_E_INTERNAL_ERROR;
			}
		} else {
			LogError("stat failed: %s", strerror(errno));
			return TSS_E_INTERNAL_ERROR;
		}
	}

	/* stat should not fail now */
	if (stat(tcsd_options.system_ps_dir, &stat_buf) == -1) {
		LogError("stat %s failed: %s", tcsd_options.system_ps_dir, strerror(errno));
		return TSS_E_INTERNAL_ERROR;
	}

	/* tcsd_options.system_ps_dir should be a directory with mode equal to mode */
	if (!S_ISDIR(stat_buf.st_mode)) {
		LogError("PS dir %s is not a directory! Exiting.", tcsd_options.system_ps_dir);
		return TSS_E_INTERNAL_ERROR;
	} else if ((stat_buf.st_mode ^ mode) != 0) {
		/* This path is likely to be hit since open &'s mode with ~umask */
		LogInfo("resetting mode of %s to: 01777", tcsd_options.system_ps_dir);
		if (chmod(tcsd_options.system_ps_dir, mode) == -1) {
			LogError("chmod(%s) failed: %s", tcsd_options.system_ps_dir, strerror(errno));
			return TSS_E_INTERNAL_ERROR;
		}
	}
	return TSS_SUCCESS;
}

