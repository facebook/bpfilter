// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bits/types/sig_atomic_t.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/btf.h"
#include "core/context.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/opts.h"
#include "shared/front.h"
#include "shared/generic.h"
#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"

/**
 * Global flag to indicate whether the daemon should stop.
 */
static volatile sig_atomic_t _stop_received = 0;

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
static const char *context_path = BF_RUNTIME_DIR "/data.bin";

/**
 * Set atomic flag to stop the daemon if specific signals are received.
 *
 * @param sig Signal number.
 */
void _sig_handler(int sig)
{
    UNUSED(sig);

    _stop_received = 1;
}

/**
 * Ensure the daemon can use the runtime directory.
 *
 * Check if the current process can access @ref BF_RUNTIME_DIR. If it doesn't
 * exists, create it with the appropriate permissions. If it exists, check
 * that it is a directory.
 *
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_ensure_runtime_dir(void)
{
    struct stat stats;
    int r;

    r = access(BF_RUNTIME_DIR, R_OK | W_OK);
    if (r < 0 && errno == ENOENT) {
        if (mkdir(BF_RUNTIME_DIR, 0755) == 0)
            return 0;

        return bf_err_code(errno, "failed to create runtime directory '%s'",
                           BF_RUNTIME_DIR);
    } else if (r < 0 && errno == EACCES) {
        return bf_err_code(errno, "can't access runtime directory '%s'",
                           BF_RUNTIME_DIR);
    } else if (r < 0) {
        return bf_err_code(errno, "failed to access runtime directory '%s'",
                           BF_RUNTIME_DIR);
    }

    if (stat(BF_RUNTIME_DIR, &stats)) {
        return bf_err_code(errno, "failed to stat runtime directory '%s'",
                           BF_RUNTIME_DIR);
    }

    if (!S_ISDIR(stats.st_mode)) {
        return bf_err_code(ENOTDIR, "runtime directory '%s' is not a directory",
                           BF_RUNTIME_DIR);
    }

    return 0;
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
    _cleanup_free_ struct bf_marsh *marsh = NULL;
    struct bf_marsh *child = NULL;
    size_t len;
    int r;

    bf_assert(path);

    if (access(context_path, F_OK)) {
        if (errno == ENOENT) {
            bf_info("no serialized context found on disk, "
                    "a new context will be created");
            return 0;
        } else {
            return bf_info_code(errno, "failed test access to context file: %s",
                                path);
        }
    }

    r = bf_read_file(path, (void **)&marsh, &len);
    if (r < 0)
        return r;

    if (len < sizeof(struct bf_marsh))
        return bf_err_code(EIO, "marshalled data is invalid");

    if (bf_marsh_size(marsh) != len) {
        return bf_err_code(
            EINVAL, "conflicting marshalled data size: got %zu, expected %zu",
            len, bf_marsh_size(marsh));
    }

    child = bf_marsh_next_child(marsh, child);
    if (!child) {
        return bf_err_code(-EINVAL,
                           "expecting a child in main marshalled context");
    }

    r = bf_context_load(child);
    if (r < 0)
        return r;

    for (int i = 0; i < _BF_FRONT_MAX; ++i) {
        child = bf_marsh_next_child(marsh, child);
        if (!child) {
            bf_err(
                "no marshalled context for %s. Skipping restoration of remaining front-specific context.",
                bf_front_to_str(i));
            break;
        }

        r = bf_front_ops_get(i)->unmarsh(child);
        if (r < 0) {
            return bf_err_code(r, "failed to restore context for %s",
                               bf_front_to_str(i));
        }
    }

    bf_dbg("loaded marshalled context from %s", path);

    return 1;
}

/**
 * Save bpfilter's runtime context to disk.
 *
 * Marshel the daemon's runtime context and save it to @p path.
 *
 * @param path Path to the context file.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_save(const char *path)
{
    _cleanup_free_ struct bf_marsh *marsh = NULL;
    int r;

    bf_assert(path);

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r < 0)
        return r;

    {
        _cleanup_free_ struct bf_marsh *child = NULL;

        r = bf_context_save(&child);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r < 0)
            return r;
    }

    for (int i = 0; i < _BF_FRONT_MAX; ++i) {
        _cleanup_free_ struct bf_marsh *child = NULL;

        if (!bf_opts_is_front_enabled(i))
            continue;

        r = bf_marsh_new(&child, NULL, 0);
        if (r < 0)
            return r;

        r = bf_front_ops_get(i)->marsh(&child);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r < 0)
            return r;
    }

    r = bf_write_file(path, marsh, bf_marsh_size(marsh));
    if (r < 0)
        return r;

    bf_dbg("saved marshalled context to %s", path);

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
 * @todo Should the runtime context be saved unconditionally?
 *
 * @return 0 on success, negative error code on failure.
 */
static int _bf_init(int argc, char *argv[])
{
    struct sigaction sighandler = {.sa_handler = _sig_handler};
    int r = 0;

    if (sigaction(SIGINT, &sighandler, NULL) < 0)
        return bf_err_code(errno, "can't override handler for SIGINT");

    if (sigaction(SIGTERM, &sighandler, NULL) < 0)
        return bf_err_code(errno, "can't override handler for SIGTERM");

    r = _bf_ensure_runtime_dir();
    if (r < 0)
        return bf_err_code(r, "failed to ensure runtime directory exists");

    r = bf_opts_init(argc, argv);
    if (r < 0)
        return bf_err_code(r, "failed to parse command line arguments");

    // Either load context, or initialize it from scratch.
    if (!bf_opts_transient()) {
        r = _bf_load(context_path);
        if (r < 0)
            return bf_err_code(r, "failed to restore bpfilter context");
    }

    if (bf_opts_transient() || r == 0) {
        r = bf_context_setup();
        if (r < 0)
            return bf_err_code(r, "failed to setup context");
    }

    bf_context_dump(EMPTY_PREFIX);

    for (enum bf_front front = 0; front < _BF_FRONT_MAX; ++front) {
        if (!bf_opts_is_front_enabled(front))
            continue;

        r = bf_front_ops_get(front)->setup();
        if (r < 0) {
            return bf_err_code(r, "failed to setup front-end %s",
                               bf_front_to_str(front));
        }

        bf_dbg("completed setup for %s", bf_front_to_str(front));
    }

    if (!bf_opts_transient()) {
        r = _bf_save(context_path);
        if (r < 0) {
            return bf_err_code(r, "failed to backup context at %s",
                               context_path);
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
    int r;

    for (enum bf_front front = 0; front < _BF_FRONT_MAX; ++front) {
        if (!bf_opts_is_front_enabled(front))
            continue;

        r = bf_front_ops_get(front)->teardown();
        if (r < 0) {
            bf_warn_code(r, "failed to teardown front-end %s, continuing",
                         bf_front_to_str(front));
        }
    }

    bf_context_teardown(bf_opts_transient());

    return 0;
}

/**
 * Process a request.
 *
 * The handler corresponding to @p request->front will be called (if any).
 * If the handler returns 0, @p response is expected to be filled, and ready
 * to be returned to the client.
 * If the handler returns a negative error code, @p response is filled by @ref
 * _process_request with a generated error response and 0 is returned. If
 * generating the error response fails, then 0 is returned.
 *
 * In other words, if 0 is returned, @p response is ready to be sent back, if
 * a negative error code is returned, an error occured during @p request
 * processing, and no response is available.
 *
 * @param request Request to process.
 * @param response Response to fill.
 * @return 0 on success, negative error code on failure.
 */
static int _process_request(struct bf_request *request,
                            struct bf_response **response)
{
    const struct bf_front_ops *ops;
    int r;

    bf_assert(request);
    bf_assert(response);

    if (!bf_opts_is_front_enabled(request->front)) {
        bf_warn("received a request from %s, but front is disabled, ignoring",
                bf_front_to_str(request->front));
        return bf_response_new_failure(response, -ENOTSUP);
    }

    bf_info("received a request from %s", bf_front_to_str(request->front));

    ops = bf_front_ops_get(request->front);
    r = ops->request_handler(request, response);
    if (r) {
        /* We failed to process the request, so we need to generate an
         * error. If the error response is successfully generated, then we
         * return 0, otherwise we return the error code. */
        r = bf_response_new_failure(response, r);
    }

    if (!bf_opts_transient() && request->cmd == BF_REQ_SET_RULES)
        r = _bf_save(context_path);

    return r;
}

/**
 * Loop and process requests.
 *
 * Create a socket and perform blocking accept() calls. For each connection,
 * receive a request, process it, and send the response back.
 *
 * If a signal is received, @ref _stop_received will be set to 1 by @ref
 * _sig_handler and blocking call to `accept()` will be interrupted.
 *
 * @return 0 on success, negative error code on failure.
 */
static int _run(void)
{
    _cleanup_close_ int fd = -1;
    struct sockaddr_un addr = {};
    int r;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return bf_err_code(errno, "failed to create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        return bf_err_code(errno, "failed to bind socket to %s",
                           BF_SOCKET_PATH);
    }

    r = listen(fd, 1);
    if (r < 0)
        return bf_err_code(errno, "listen() failed");

    bf_info("waiting for requests...");

    while (!_stop_received) {
        _cleanup_close_ int client_fd = -1;
        _cleanup_bf_request_ struct bf_request *request = NULL;
        _cleanup_bf_response_ struct bf_response *response = NULL;

        client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            if (_stop_received) {
                bf_info("received stop signal, exiting...");
                continue;
            }

            return bf_err_code(errno, "failed to accept connection");
        }

        r = bf_recv_request(client_fd, &request);
        if (r < 0)
            return bf_err_code(r, "failed to receive request");

        r = _process_request(request, &response);
        if (r) {
            bf_err("failed to process request");
            continue;
        }

        r = bf_send_response(client_fd, response);
        if (r < 0)
            return bf_err_code(r, "failed to send response");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int r;

    bf_logger_setup();

    r = bf_btf_setup();
    if (r < 0)
        return bf_err_code(r, "failed to setup BTF module");

    r = _bf_init(argc, argv);
    if (r < 0)
        return bf_err_code(r, "failed to initialize bpfilter");

    r = _run();
    if (r < 0)
        return bf_err_code(r, "run() failed");

    _bf_clean();
    bf_btf_teardown();

    unlink(BF_SOCKET_PATH); // Remove socket file.

    return r;
}
