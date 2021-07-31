#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>

#include "openvpn-plugin.h"

#ifndef USE_PERL
#define DUO_SCRIPT_PATH PREFIX "/duo_openvpn.py"
#else
#define DUO_SCRIPT_PATH PREFIX "/duo_openvpn.pl"
#endif

static const char *PLUGIN_NAME = "DUO-OPENVPN";

struct context {
	char *ikey;
	char *skey;
	char *host;
	char *proxy_host;
	char *proxy_port;
	plugin_log_t plugin_log;
};

static const char *
get_variable(const char *name, const char *value, const char divider)
{
	int namelen = strlen(name);
	if (!strncmp(value, name, namelen)) {
		const char *prefix = value + namelen;
		if (*prefix == divider) {
			return prefix + 1;
		}
	}
	return NULL;
}

static const char *
get_env(const char *name, const char *envp[])
{
	if (envp) {
		for (int i = 0; envp[i]; ++i) {
			const char *result = get_variable(name, envp[i], '=');
			if (NULL != result) {
				return result;
			}
		}
	}
	return NULL;
}

static int
auth_user_pass_verify(struct context *ctx, const char *args[], const char *envp[])
{
	int pid;
	const char *control, *username, *password, *ipaddr;
	char *argv[] = { DUO_SCRIPT_PATH, NULL };

	control = get_env("auth_control_file", envp);
	username = get_env("common_name", envp);
	password = get_env("password", envp);
	ipaddr = get_env("untrusted_ip", envp);

	if (!control || !username || !password || !ipaddr) {
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	pid = fork();
	if (pid < 0) {
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	if (pid > 0) {
		int status;

		/* openvpn process forked ok, wait for first child to exit and return its status */
		pid = waitpid(pid, &status, 0);
		if (pid < 0) {
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}

		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}

		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	pid = fork();
	if (pid < 0) {
		exit(OPENVPN_PLUGIN_FUNC_ERROR);
	}

	if (pid > 0) {
		/* first child forked ok, pass deferred return up to parent openvpn process */
		exit(OPENVPN_PLUGIN_FUNC_DEFERRED);
	}

	/* second child daemonizes so PID 1 can reap */
	umask(0);
	setsid();
	chdir("/");
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	if (ctx->ikey && ctx->skey && ctx->host) {
		setenv("ikey", ctx->ikey, 1);
		setenv("skey", ctx->skey, 1);
		setenv("host", ctx->host, 1);
		if (ctx->proxy_host) {
			setenv("proxy_host", ctx->proxy_host, 1);
		}
		else {
			unsetenv("proxy_host");
		}
		if (ctx->proxy_port) {
			setenv("proxy_port", ctx->proxy_port, 1);
		}
		else {
			unsetenv("proxy_port");
		}
	}

	setenv("control", control, 1);
	setenv("username", username, 1);
	setenv("password", password, 1);
	setenv("ipaddr", ipaddr, 1);

	execvp(argv[0], argv);
	exit(1);
}

static int
load_configuration_file(const char *file_path, struct context *ctx)
{
	FILE *fp = fopen(file_path, "r");

	if (!fp) {
		ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Could not open configuration file %s", file_path);
		return 0;
	}

	char line[255];
	while (fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\r\n")] = 0;
		if (line[0] == '\0' || line[0] == '#') {
			continue;
		}

		if (strlen(line) > 250) {
			ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Configuration line longer than maximum 250 characters. Line starts with %s", line);
			return 0;
		}

		const char *potential_ikey = get_variable("integration-key", line, ' ');
		if (potential_ikey) {
			ctx->ikey = strdup(potential_ikey);
			continue;
		}

		const char *potential_skey = get_variable("secret-key", line, ' ');
		if (potential_skey) {
			ctx->skey = strdup(potential_skey);
			continue;
		}

		const char *potential_host = get_variable("host", line, ' ');
		if (potential_host) {
			ctx->host = strdup(potential_host);
			continue;
		}

		const char *potential_proxy_host = get_variable("proxy-host", line, ' ');
		if (potential_proxy_host) {
			ctx->host = strdup(potential_proxy_host);
			continue;
		}

		const char *potential_proxy_port = get_variable("proxy-port", line, ' ');
		if (potential_proxy_port) {
			ctx->proxy_port = strdup(potential_proxy_port);
			continue;
		}

		ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Unknown configuration entry in file '%s': %s", file_path, line);
		return 0;
	}
	fclose(fp);
	return 1;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[], void *per_client_context, struct openvpn_plugin_string_list **return_list)
{
	struct context *ctx = (struct context *) handle;

	if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
		return auth_user_pass_verify(ctx, argv, envp);
	} else {
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver, const struct openvpn_plugin_args_open_in *args, struct openvpn_plugin_args_open_return *ret)
{
	struct context *ctx;

	ctx = (struct context *) calloc(1, sizeof(struct context));
	ctx->plugin_log = args->callbacks->plugin_log;

	const char **argv = args->argv;
	if (argv[1] && strpbrk(argv[1], "=")) {
		const char *config_file_path = get_env("--config-file", argv);
		if (config_file_path) {
			if (argv[2]) {
				ctx->plugin_log(PLOG_WARN, PLUGIN_NAME, "Plugin is configured with a config-file option and additional parameters, but parameters are not supported alongside a configuration file.");
				return OPENVPN_PLUGIN_FUNC_ERROR;
			}
			if (!load_configuration_file(config_file_path, ctx)) {
				ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Failed to load plugin configuration from file");
				return OPENVPN_PLUGIN_FUNC_ERROR;
			}
		} else {
			ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "No 'config-file' parameter found");
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}
	} else {
		if (argv[1] && argv[2] && argv[3]) {
			ctx->plugin_log(PLOG_WARN, PLUGIN_NAME, "Plugin is configured with a legacy configuration format. Switch to using 'parameter=value' format to use any new features.");
			ctx->ikey = strdup(argv[1]);
			ctx->skey = strdup(argv[2]);
			ctx->host = strdup(argv[3]);
		}

		/* Passing proxy_host even if proxy_port is not present
		 * generates a more informative log message.
		 */
		if (argv[4]) {
			ctx->proxy_host = strdup(argv[4]);
			if (argv[5]) {
				ctx->proxy_port = strdup(argv[5]);
			}
			else {
				ctx->proxy_port = NULL;
			}
		}
		else {
			ctx->proxy_host = NULL;
			ctx->proxy_port = NULL;
		}
	}

	int success = 1;
	if (!ctx->host) {
		ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Host is not specified in plugin configuration");
		success = 0;
	}
	if (!ctx->ikey) {
		ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Integration Key is not specified in plugin configuration");
		success = 0;
	}
	if (!ctx->skey) {
		ctx->plugin_log(PLOG_ERR, PLUGIN_NAME, "Secret Key is not specified in plugin configuration");
		success = 0;
	}

	if (success != 1) {
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}

	ctx->plugin_log(PLOG_NOTE, PLUGIN_NAME, "Plugin initialised with host '%s' and integration key '%s'", ctx->host, ctx->ikey);

	ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
	ret->handle = (openvpn_plugin_handle_t) ctx;
	return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
	struct context *ctx = (struct context *) handle;

	free(ctx->ikey);
	free(ctx->skey);
	free(ctx->host);
	if (ctx->proxy_host) {
		free(ctx->proxy_host);
	}
	if (ctx->proxy_port) {
		free(ctx->proxy_port);
	}
	free(ctx);
}
