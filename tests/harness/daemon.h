/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "harness/process.h"

/**
 * @file daemon.h
 *
 * bf_test_daemon represents a handle to manage the `bpfilter` daemon. Based
 * on the primitives defined in `harness/process.h`.
 */

struct bf_test_daemon
{
    struct bf_test_process process;
};

/**
 * Options to configure the daemon.
 *
 * Not all the options defined for `bpfilter` need to be defined below.
 */
enum bf_test_daemon_option
{
    BF_TEST_DAEMON_TRANSIENT = 1 << 0,
    BF_TEST_DAEMON_NO_CLI = 1 << 1,
    BF_TEST_DAEMON_NO_IPTABLES = 1 << 2,
    BF_TEST_DAEMON_NO_NFTABLES = 1 << 3,
    _BF_TEST_DAEMON_LAST = BF_TEST_DAEMON_NO_NFTABLES,
};

#define _clean_bf_test_daemon_                                                 \
    __attribute__((__cleanup__(bf_test_daemon_clean)))

#define bft_daemon_default()                                                   \
    {                                                                          \
        .process = bft_process_default(),                                      \
    }

/**
 * Initialize a new daemon object.
 *
 * @note `bf_test_daemon_init()` assumes none of the options defined in
 * `bf_test_daemon_option` require an argument. If this assumption is erroneous,
 * the logic used to parse the options need to be modified!
 *
 * @param daemon The daemon object to initialize. Can't be `NULL`.
 * @param path Path to the `bpfilter` binary. If `NULL`, the first `bpfilter`
 *        binary found in `$PATH` will be used.
 * @param options Command line options to start the daemon with. See
 *        `bf_test_daemon_option` for the list of available options.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_test_daemon_init(struct bf_test_daemon *daemon, const char *path,
                        uint32_t options);

/**
 * Cleanup a daemon object.
 *
 * @param daemon Daemon object to cleanup. Can't be `NULL`.
 */
void bf_test_daemon_clean(struct bf_test_daemon *daemon);

/**
 * Start a daemon process.
 *
 * Once the process is started, this function will wait for a specific log
 * from the daemon to validate the process is up and running (and didn't exit).
 *
 * @param daemon Daemon object to start the daemon process for. Can't be `NULL`.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_test_daemon_start(struct bf_test_daemon *daemon);

/**
 * Stop a daemon process.
 *
 * @param daemon Daemon object to stop the daemon process for. Can't be `NULL`.
 * @return The return code of the daemon process as an integer >= 0 on success,
 *         or a negative errno value on error.
 */
int bf_test_daemon_stop(struct bf_test_daemon *daemon);
