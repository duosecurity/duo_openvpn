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

struct context {
	char *ikey;
	char *skey;
	char *host;
	char *proxy_host;
	char *proxy_port;
};

static const char *
get_env(const char *name, const char *envp[])
{
	int i, namelen;
	const char *cp;

	if (envp) {
		namelen = strlen(name);
		for (i = 0; envp[i]; ++i) {
			if (!strncmp(envp[i], name, namelen)) {
				cp = envp[i] + namelen;
				if (*cp == '=') {
					return cp + 1;
				}
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

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v2(unsigned int *type_mask, const char *argv[], const char *envp[], struct openvpn_plugin_string_list **return_list)
{
	struct context *ctx;

	ctx = (struct context *) calloc(1, sizeof(struct context));

	if (argv[1] && argv[2] && argv[3]) {
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

	*type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

	return (openvpn_plugin_handle_t) ctx;
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
