// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpfilter/ctx.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>
#include <bpfilter/request.h>
#include <bpfilter/response.h>
#include <bpfilter/version.h>

#define BF_DEFAULT_BPFFS_PATH "/sys/fs/bpf"

enum
{
    BF_OPT_NO_IPTABLES_KEY,
    BF_OPT_NO_NFTABLES_KEY,
    BF_OPT_NO_CLI_KEY,
    BF_OPT_WITH_BPF_TOKEN,
    BF_OPT_BPFFS_PATH,
};

struct bf_options
{
    bool transient;
    bool with_bpf_token;
    const char *bpffs_path;
    uint16_t verbose;
};

static const char *_bf_verbose_strs[] = {
    [BF_VERBOSE_DEBUG] = "debug",
    [BF_VERBOSE_BPF] = "bpf",
    [BF_VERBOSE_BYTECODE] = "bytecode",
};

static_assert_enum_mapping(_bf_verbose_strs, _BF_VERBOSE_MAX);

static enum bf_verbose _bf_verbose_from_str(const char *str)
{
    assert(str);

    for (enum bf_verbose verbose = 0; verbose < _BF_VERBOSE_MAX; ++verbose) {
        if (bf_streq(_bf_verbose_strs[verbose], str))
            return verbose;
    }

    return -EINVAL;
}

static struct argp_option _bf_options[] = {
    {"transient", 't', 0, 0,
     "Do not load or save runtime context and remove all BPF programs on shutdown",
     0},
    {"buffer-len", 'b', "BUF_LEN_POW", 0,
     "DEPRECATED. Size of the BPF log buffer as a power of 2 (only used when --verbose is used). Default: 16.",
     0},
    {"no-iptables", BF_OPT_NO_IPTABLES_KEY, 0, 0,
     "DEPRECATED. Disable iptables support", 0},
    {"no-nftables", BF_OPT_NO_NFTABLES_KEY, 0, 0,
     "DEPRECATED. Disable nftables support", 0},
    {"no-cli", BF_OPT_NO_CLI_KEY, 0, 0, "DEPRECATED. Disable CLI support", 0},
    {"with-bpf-token", BF_OPT_WITH_BPF_TOKEN, NULL, 0,
     "Use a BPF token with the bpf() system calls. The token is created from the bpffs instance mounted at /sys/fs/bpf.",
     0},
    {"bpffs-path", BF_OPT_BPFFS_PATH, "BPFFS_PATH", 0,
     "Path to the bpffs to pin the BPF objects into. Defaults to " BF_DEFAULT_BPFFS_PATH
     ".",
     0},
    {"verbose", 'v', "VERBOSE_FLAG", 0,
     "Verbose flags to enable. Can be used more than once.", 0},
    {0},
};

static error_t _bf_opts_parser(int key, char *arg, struct argp_state *state)
{
    struct bf_options *args = state->input;
    enum bf_verbose opt;

    (void)arg;

    switch (key) {
    case 't':
        args->transient = true;
        break;
    case 'b':
        bf_warn(
            "--buffer-len is deprecated, buffer size is defined automatically");
        break;
    case BF_OPT_NO_IPTABLES_KEY:
        bf_warn("--no-iptables is deprecated");
        break;
    case BF_OPT_NO_NFTABLES_KEY:
        bf_warn("--no-nftables is deprecated");
        break;
    case BF_OPT_NO_CLI_KEY:
        bf_warn("--no-cli is deprecated");
        break;
    case BF_OPT_WITH_BPF_TOKEN:
        args->with_bpf_token = true;
        bf_info("using a BPF token");
        break;
    case BF_OPT_BPFFS_PATH:
        args->bpffs_path = arg;
        bf_info("using bpffs at %s", args->bpffs_path);
        break;
    case 'v':
        opt = _bf_verbose_from_str(arg);
        if ((int)opt < 0) {
            return bf_err_r(
                (int)opt,
                "unknown --verbose option '%s', valid --verbose options: [debug, bpf, bytecode]",
                arg);
        }
        bf_info("enabling verbose for '%s'", arg);
        if (opt == BF_VERBOSE_DEBUG)
            bf_log_set_level(BF_LOG_DBG);
        args->verbose |= BF_FLAG(opt);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int _bf_opts_init(struct bf_options *opts, int argc, char *argv[])
{
    struct argp argp = {_bf_options, _bf_opts_parser, NULL, NULL, 0, NULL,
                        NULL};

    return argp_parse(&argp, argc, argv, 0, 0, opts);
}

/**
 * Global flag to indicate whether the daemon should stop.
 */
static volatile sig_atomic_t _bf_stop_received = 0;

/**
 * Set atomic flag to stop the daemon if specific signals are received.
 *
 * @param sig Signal number.
 */
void _bf_sig_handler(int sig)
{
    (void)sig;

    _bf_stop_received = 1;
}

/**
 * Initialize bpfilter's daemon runtime.
 *
 * Setup signal handler (for graceful shutdown), initialize a fresh context,
 * discover existing chains from bpffs, and initialise various front-ends.
 *
 * @return 0 on success, negative error code on failure.
 */
static int _bf_init(int argc, char *argv[])
{
    struct sigaction sighandler = {.sa_handler = _bf_sig_handler};
    struct bf_options opts = {
        .transient = false,
        .with_bpf_token = false,
        .bpffs_path = BF_DEFAULT_BPFFS_PATH,
        .verbose = 0,
    };
    int r;

    if (sigaction(SIGINT, &sighandler, NULL) < 0)
        return bf_err_r(errno, "can't override handler for SIGINT");

    if (sigaction(SIGTERM, &sighandler, NULL) < 0)
        return bf_err_r(errno, "can't override handler for SIGTERM");

    bf_info("starting bpfilter version %s", BF_VERSION);

    r = _bf_opts_init(&opts, argc, argv);
    if (r < 0)
        return bf_err_r(r, "failed to parse command line arguments");

    r = bf_ensure_dir(BF_RUNTIME_DIR);
    if (r)
        return bf_err_r(r, "failed to ensure runtime directory exists");

    r = bf_ctx_setup(opts.with_bpf_token, opts.bpffs_path, opts.verbose);
    if (r)
        return bf_err_r(r, "failed to setup context");

    bf_ctx_dump(EMPTY_PREFIX);

    return 0;
}

extern int bf_request_handler(const struct bf_request *request,
                              struct bf_response **response);

/**
 * Process a request.
 *
 * If the handler returns 0, @p response is expected to be filled, and ready
 * to be returned to the client.
 * If the handler returns a negative error code, @p response is filled by @ref
 * _bf_process_request with a generated error response and 0 is returned. If
 * generating the error response fails, then 0 is returned.
 *
 * In other words, if 0 is returned, @p response is ready to be sent back, if
 * a negative error code is returned, an error occured during @p request
 * processing, and no response is available.
 *
 * @param request Request to process. Can't be NULL.
 * @param response Response to fill. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_process_request(struct bf_request *request,
                               struct bf_response **response)
{
    int r;

    assert(request);
    assert(response);

    if (bf_request_cmd(request) < 0 ||
        bf_request_cmd(request) >= _BF_REQ_CMD_MAX) {
        bf_warn("received a request with command %d, unknown command, ignoring",
                bf_request_cmd(request));
        return bf_response_new_failure(response, -EINVAL);
    }

    bf_info("processing request %s",
            bf_request_cmd_to_str(bf_request_cmd(request)));

    r = bf_request_handler(request, response);
    if (r) {
        /* We failed to process the request, so we need to generate an
         * error. If the error response is successfully generated, then we
         * return 0, otherwise we return the error code. */
        r = bf_response_new_failure(response, r);
    }

    return r;
}

/**
 * Loop and process requests.
 *
 * Create a socket and perform blocking accept() calls. For each connection,
 * receive a request, process it, and send the response back.
 *
 * If a signal is received, @ref _bf_stop_received will be set to 1 by @ref
 * _bf_sig_handler and blocking call to `accept()` will be interrupted.
 *
 * @return 0 on success, negative error code on failure.
 */
static int _bf_run(void)
{
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int lock = -1;
    struct sockaddr_un addr = {};
    struct ucred peer_cred;
    socklen_t peer_cred_len = sizeof(peer_cred);
    int r;

    lock = bf_acquire_lock(BF_LOCK_PATH);
    if (lock < 0) {
        return bf_err_r(
            lock,
            "failed to acquire the daemon lock, is the daemon already running? Error");
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return bf_err_r(errno, "failed to create socket");

    // We have a lock on the lock file, so no other daemon is running, we can
    // remove the socket file (if any).
    unlink(BF_SOCKET_PATH);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        return bf_err_r(errno, "failed to bind socket to %s", BF_SOCKET_PATH);
    }

    r = listen(fd, 1);
    if (r < 0)
        return bf_err_r(errno, "listen() failed");

    bf_info("waiting for requests...");

    while (!_bf_stop_received) {
        _cleanup_close_ int client_fd = -1;
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            if (_bf_stop_received) {
                bf_info("received stop signal, exiting...");
                continue;
            }

            bf_err_r(errno, "failed to accept connection, ignoring");
            continue;
        }

        // NOLINTNEXTLINE: SOL_SOCKET and SO_PEERCRED can't be directly included
        r = getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peer_cred,
                       &peer_cred_len);
        if (r) {
            bf_err_r(errno,
                     "failed to read the client's credentials, ignoring");
            continue;
        }

        r = bf_recv_request(client_fd, &request);
        if (r) {
            bf_err_r(r, "failed to receive request, ignoring");
            continue;
        }

        bf_request_set_fd(request, client_fd);

        r = _bf_process_request(request, &response);
        if (r) {
            bf_err_r(r, "failed to process request, ignoring");
            continue;
        }

        r = bf_send_response(client_fd, response);
        if (r) {
            bf_err_r(r, "failed to send response, ignoring");
            continue;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int r;

    bf_logger_setup();

    argp_program_version = "bpfilter version " BF_VERSION;
    argp_program_bug_address = BF_CONTACT;

    r = _bf_init(argc, argv);
    if (r < 0)
        return bf_err_r(r, "failed to initialize bpfilter");

    r = _bf_run();
    if (r < 0)
        return bf_err_r(r, "run() failed");

    bf_ctx_teardown();

    return r;
}
