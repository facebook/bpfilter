/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "daemon.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "process.h"

#define _BF_DAEMON_START_TIMEOUT 5
#define _BF_DAEMON_START_SLEEP 100000

int bf_test_daemon_init(struct bf_test_daemon *daemon, const char *path,
                        uint32_t options)
{
    char *args[__builtin_ctz(_BF_TEST_DAEMON_LAST) + 1] = {};
    size_t nargs = 0;

    bf_assert(daemon);

    if (options & BF_TEST_DAEMON_TRANSIENT)
        args[nargs++] = "--transient";
    if (options & BF_TEST_DAEMON_NO_CLI)
        args[nargs++] = "--no-cli";
    if (options & BF_TEST_DAEMON_NO_IPTABLES)
        args[nargs++] = "--no-iptables";
    if (options & BF_TEST_DAEMON_NO_NFTABLES)
        args[nargs++] = "--no-nftables";

    return bf_test_process_init(&daemon->process, path, args, nargs);
}

void bf_test_daemon_clean(struct bf_test_daemon *daemon)
{
    bf_assert(daemon);

    bf_test_process_clean(&daemon->process);
}

int bf_test_daemon_start(struct bf_test_daemon *daemon)
{
    clock_t begin;
    int r;

    bf_assert(daemon);

    r = bf_test_process_start(&daemon->process);
    if (r < 0)
        return bf_err_r(r, "failed to start bpfilter daemon");

    begin = clock();
    while (true) {
        _cleanup_free_ const char *err_buf = NULL;
        int status;

        r = waitpid(daemon->process.pid, &status, WNOHANG);
        if (r < 0)
            return bf_err_r(r, "waitpid() failed on bpfilter process");
        if (r != 0) {
            err_buf = bf_test_process_stderr(&daemon->process);
            return bf_err_r(-ENOENT, "bpfilter process seems to be dead:\n%s\n",
                            err_buf);
        }

        err_buf = bf_test_process_stderr(&daemon->process);
        if (err_buf && strstr(err_buf, "waiting for requests..."))
            break;

        if ((clock() - begin) / CLOCKS_PER_SEC > _BF_DAEMON_START_TIMEOUT) {
            kill(daemon->process.pid, SIGKILL);
            return bf_err_r(
                -EIO, "daemon is not showing up after %d seconds, aborting",
                _BF_DAEMON_START_TIMEOUT);
        }

        // Wait a bit for the daemon to be ready
        usleep(_BF_DAEMON_START_SLEEP);
    }

    return 0;
}

int bf_test_daemon_stop(struct bf_test_daemon *daemon)
{
    int r;

    bf_assert(daemon);

    r = bf_test_process_stop(&daemon->process);
    if (r < 0)
        return bf_err_r(r, "failed to stop bpfilter daemon");

    return r;
}
