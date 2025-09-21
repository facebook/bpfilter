// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpfilter/btf.h>
#include <bpfilter/dump.h>
#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>
#include <bpfilter/ns.h>
#include <bpfilter/pack.h>
#include <bpfilter/request.h>
#include <bpfilter/response.h>
#include <bpfilter/version.h>

#include "ctx.h"
#include "opts.h"
#include "xlate/front.h"

/**
 * Global flag to indicate whether the daemon should stop.
 */
static volatile sig_atomic_t _bf_stop_received = 0;

/**
 * Path to bpfilter's runtime context file.
 *
 * bpfilter will periodically save its internal context back to disk, to prevent
 * spurious service interruption to lose information about the current state of
 * the daemon.
 *
 * This runtime context is read back when the daemon is restarted, so bpfilter
 * can manage the BPF programs that survived the daemon reboot.
 */
static const char *ctx_path = BF_RUNTIME_DIR "/data.bin";

/**
 * Set atomic flag to stop the daemon if specific signals are received.
 *
 * @param sig Signal number.
 */
void _bf_sig_handler(int sig)
{
    UNUSED(sig);

    _bf_stop_received = 1;
}

/**
 * Load bpfilter's runtime context from disk.
 *
 * Read the daemon's runtime context from @p path and initialize the internal
 * context with it.
 *
 * @param path Path to the context file.
 * @return This function will return:
 *         - 1 if the runtime context has been succesfully restored from the disk.
 *         - 0 if no serialized context has been found on the disk.
 *         - < 0 on error.
 */
static int _bf_load(const char *path)
{
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ void *data = NULL;
    bf_rpack_node_t child, array_node;
    size_t data_len;
    int r;

    bf_assert(path);

    if (access(ctx_path, F_OK)) {
        if (errno != ENOENT) {
            return bf_info_r(errno, "failed test access to context file: %s",
                             path);
        }

        bf_info("no serialized context found on disk, "
                "a new context will be created");

        return 0;
    }

    r = bf_read_file(path, &data, &data_len);
    if (r < 0)
        return r;

    r = bf_rpack_new(&pack, data, data_len);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "ctx", &child);
    if (r)
        return r;

    r = bf_ctx_load(child);
    if (r < 0)
        return r;

    r = bf_rpack_kv_array(bf_rpack_root(pack), "cache", &child);
    if (r)
        return r;
    bf_rpack_array_foreach (child, array_node) {
        if (bf_rpack_is_nil(array_node))
            continue;

        r = bf_front_ops_get(i)->unpack(array_node);
        if (r < 0) {
            return bf_err_r(r, "failed to restore context for %s",
                            bf_front_to_str(i));
        }
    }

    bf_dbg("loaded serialized context from %s", path);

    return 1;
}

/**
 * Save bpfilter's runtime context to disk.
 *
 * @param path Path to the context file.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_save(const char *path)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const void *data;
    size_t data_len;
    int r;

    bf_assert(path);

    if (bf_ctx_is_empty()) {
        /* If the context is empty, we don't need to save it and we can remove
         * the existing save. */
        unlink(path);
        return 0;
    }

    r = bf_wpack_new(&pack);
    if (r)
        return r;

    bf_wpack_open_object(pack, "ctx");
    r = bf_ctx_save(pack);
    if (r)
        return r;
    bf_wpack_close_object(pack);

    bf_wpack_open_array(pack, "cache");
    for (int i = 0; i < _BF_FRONT_MAX; ++i) {
        if (bf_opts_is_front_enabled(i)) {
            bf_wpack_open_object(pack, NULL);
            r = bf_front_ops_get(i)->pack(pack);
            if (r < 0)
                return r;
            bf_wpack_close_object(pack);
        } else {
            bf_wpack_nil(pack);
        }
    }
    bf_wpack_close_array(pack);

    r = bf_wpack_get_data(pack, &data, &data_len);
    if (r)
        return r;

    r = bf_write_file(path, data, data_len);
    if (r < 0)
        return r;

    bf_dbg("saved serialized context to %s", path);

    return 0;
}

/**
 * Initialize bpfilter's daemon runtime.
 *
 * Setup signal handler (for graceful shutdown), load context from disk, and
 * initialise various front-ends.
 *
 * If no context can be loaded, a new one is initialized from scratch.
 *
 * Front-ends' @p init function is called every time. They are responsible for
 * checking whether they need to perform any initialization or not, depending
 * on the loaded runtime context.
 *
 * Updated context is saved back to disk.
 *
 * @return 0 on success, negative error code on failure.
 */
static int _bf_init(int argc, char *argv[])
{
    struct sigaction sighandler = {.sa_handler = _bf_sig_handler};
    int r = 0;

    if (sigaction(SIGINT, &sighandler, NULL) < 0)
        return bf_err_r(errno, "can't override handler for SIGINT");

    if (sigaction(SIGTERM, &sighandler, NULL) < 0)
        return bf_err_r(errno, "can't override handler for SIGTERM");

    bf_info("starting bpfilter version %s", BF_VERSION);

    r = bf_opts_init(argc, argv);
    if (r < 0)
        return bf_err_r(r, "failed to parse command line arguments");

    r = bf_ensure_dir(BF_RUNTIME_DIR);
    if (r)
        return bf_err_r(r, "failed to ensure runtime directory exists");

    // Either load context, or initialize it from scratch.
    if (!bf_opts_transient()) {
        r = _bf_load(ctx_path);
        if (r < 0)
            return bf_err_r(r, "failed to restore bpfilter context");
    }

    if (bf_opts_transient() || r == 0) {
        r = bf_ctx_setup();
        if (r < 0)
            return bf_err_r(r, "failed to setup context");
    }

    bf_ctx_dump(EMPTY_PREFIX);

    for (enum bf_front front = 0; front < _BF_FRONT_MAX; ++front) {
        if (!bf_opts_is_front_enabled(front))
            continue;

        r = bf_front_ops_get(front)->setup();
        if (r < 0) {
            return bf_err_r(r, "failed to setup front-end %s",
                            bf_front_to_str(front));
        }

        bf_dbg("completed setup for %s", bf_front_to_str(front));
    }

    if (!bf_opts_transient()) {
        r = _bf_save(ctx_path);
        if (r < 0) {
            return bf_err_r(r, "failed to backup context at %s", ctx_path);
        }
    }

    return 0;
}

/**
 * Clean up bpfilter's daemon runtime.
 *
 * @return 0 on success, negative error code on failure.
 */
static int _bf_clean(void)
{
    _cleanup_close_ int pindir_fd = -1;
    int r;

    for (enum bf_front front = 0; front < _BF_FRONT_MAX; ++front) {
        if (!bf_opts_is_front_enabled(front))
            continue;

        r = bf_front_ops_get(front)->teardown();
        if (r < 0) {
            bf_warn_r(r, "failed to teardown front-end %s, continuing",
                      bf_front_to_str(front));
        }
    }

    bf_ctx_teardown(bf_opts_transient());

    r = bf_ctx_rm_pindir();
    if (r < 0 && r != -ENOENT && errno != -ENOTEMPTY)
        return bf_err_r(r, "failed to remove pin directory");

    return 0;
}

/**
 * Process a request.
 *
 * The handler corresponding to @p bf_request_front(request) will be called (if any).
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
    const struct bf_front_ops *ops;
    int r;

    bf_assert(request && response);

    if (bf_request_front(request) < 0 ||
        bf_request_front(request) >= _BF_FRONT_MAX) {
        bf_warn("received a request from front %d, unknown front, ignoring",
                bf_request_front(request));
        return bf_response_new_failure(response, -EINVAL);
    }

    if (bf_request_cmd(request) < 0 ||
        bf_request_cmd(request) >= _BF_REQ_CMD_MAX) {
        bf_warn("received a request with command %d, unknown command, ignoring",
                bf_request_cmd(request));
        return bf_response_new_failure(response, -EINVAL);
    }

    if (!bf_opts_is_front_enabled(bf_request_front(request))) {
        bf_warn("received a request from %s, but front is disabled, ignoring",
                bf_front_to_str(bf_request_front(request)));
        return bf_response_new_failure(response, -ENOTSUP);
    }

    bf_info("processing request %s from %s",
            bf_request_cmd_to_str(bf_request_cmd(request)),
            bf_front_to_str(bf_request_front(request)));

    ops = bf_front_ops_get(bf_request_front(request));
    r = ops->request_handler(request, response);
    if (r) {
        /* We failed to process the request, so we need to generate an
         * error. If the error response is successfully generated, then we
         * return 0, otherwise we return the error code. */
        r = bf_response_new_failure(response, r);
    }

    if (!bf_opts_transient() &&
        (bf_request_cmd(request) == BF_REQ_RULESET_FLUSH ||
         bf_request_cmd(request) == BF_REQ_RULESET_SET ||
         bf_request_cmd(request) == BF_REQ_CHAIN_SET ||
         bf_request_cmd(request) == BF_REQ_CHAIN_LOAD ||
         bf_request_cmd(request) == BF_REQ_CHAIN_ATTACH ||
         bf_request_cmd(request) == BF_REQ_CHAIN_UPDATE ||
         bf_request_cmd(request) == BF_REQ_CHAIN_FLUSH))
        r = _bf_save(ctx_path);

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

    /// @todo Failure to process a request should not stop the daemon!
    while (!_bf_stop_received) {
        _cleanup_close_ int client_fd = -1;
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;
        _clean_bf_ns_ struct bf_ns ns = bf_ns_default();

        client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            if (_bf_stop_received) {
                bf_info("received stop signal, exiting...");
                continue;
            }

            return bf_err_r(errno, "failed to accept connection");
        }

        // NOLINTNEXTLINE: SOL_SOCKET and SO_PEERCRED can't be directly included
        r = getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peer_cred,
                       &peer_cred_len);
        if (r) {
            bf_warn_r(
                errno,
                "failed to read the client's credentials, ignoring request");
            continue;
        }

        r = bf_ns_init(&ns, peer_cred.pid);
        if (r) {
            bf_warn_r(
                r, "failed to open the client's namespaces, ignoring request");
            continue;
        }

        r = bf_recv_request(client_fd, &request);
        if (r < 0)
            return bf_err_r(r, "failed to receive request");

        bf_request_set_ns(request, &ns);
        bf_request_set_fd(request, client_fd);

        r = _bf_process_request(request, &response);
        if (r) {
            bf_err("failed to process request");
            continue;
        }

        r = bf_send_response(client_fd, response);
        if (r < 0)
            return bf_err_r(r, "failed to send response");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int r;

    bf_logger_setup();

    argp_program_version = "bpfilter version " BF_VERSION;
    argp_program_bug_address = BF_CONTACT;

    r = bf_btf_setup();
    if (r < 0)
        return bf_err_r(r, "failed to setup BTF module");

    r = _bf_init(argc, argv);
    if (r < 0)
        return bf_err_r(r, "failed to initialize bpfilter");

    r = _bf_run();
    if (r < 0)
        return bf_err_r(r, "run() failed");

    _bf_clean();
    bf_btf_teardown();

    return r;
}
