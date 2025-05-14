/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <sys/types.h>

/**
 * @file process.h
 *
 * The functions defined in this file are used to manage an external process.
 * They are inspired by the Python `subprocess` module.
 *
 * `bf_test_process` represents the process to manipulate, it must
 * be initialized using `bf_test_process_init()` with the correct command and
 * arguments.
 *
 * `bf_test_process_start()` will fork the current process, and run the
 * pre-defined command in the new thread. Two file descriptors will be available
 * to read the forked process' `stdout` and `stderr` streams (use
 * `bf_test_process_stdout()` and `bf_test_process_stderr()` to do so).
 *
 * The forked process can terminate by itself, in which case you need to wait
 * for it anyway using `bf_test_process_wait()`. You can also kill the process
 * manually by calling `bf_test_process_kill()` to send a `SIGTERM` signal,
 * then calling `bf_test_process_wait()`. The last option is to call
 * `bf_test_process_stop()` which will kill it and wait.
 *
 * Lastly, cleanup the resources allocated for the process with
 * `bf_test_process_clean()`.
 */

struct bf_test_process
{
    /// Command to run in the process.
    const char *cmd;
    /// Array of arguments as `char` pointers.
    char **args;
    /// Number of arguments in `args`.
    size_t nargs;
    /// PID of the process, only valid while the process is alive.
    pid_t pid;
    /// File descriptor of the process' `stdout` stream.
    int out_fd;
    /// File descriptor of the process' `stderr` stream.
    int err_fd;
};

#define _clean_bf_test_process_                                                \
    __attribute__((__cleanup__(bf_test_process_clean)))

#define bft_process_default()                                                  \
    {                                                                          \
        .out_fd = -1,                                                          \
        .err_fd = -1,                                                          \
    }

int bf_test_process_init(struct bf_test_process *process, const char *cmd,
                         char **args, size_t nargs);
void bf_test_process_clean(struct bf_test_process *process);

/**
 * Start the process.
 *
 * Fork the current process to start the requested process. Open two file
 * descriptor to communicate with the forked process (`stdout` and `stderr`).
 * Once started, the process can be waited on, killed, or stopped. Use
 * `bf_test_process_stdout()` and `bf_test_process_stderr()` to access it
 * standard output and error buffers.
 *
 * If this function succeeds, `bf_test_process_wait()` or
 * `bf_test_process_stop()` must called before cleaning the process.
 *
 * @param process The process to start. Can't be `NULL`.
 * @return 0 on success, or a negative errno value on error.
 */

int bf_test_process_start(struct bf_test_process *process);

/**
 * Wait for the process to terminate.
 *
 * This function will hang until the process has completed.
 *
 * @param process The process to wait on. Can't be NULL.
 * @return The return code of the process as a non-negative integer, or a
 *         negative errno value on error.
 */
int bf_test_process_wait(struct bf_test_process *process);

/**
 * Kill the process by sending `SIGTERM`.
 *
 * @param process The process to kill. Can't be `NULL`.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_test_process_kill(struct bf_test_process *process);

/**
 * Force the process to stop and wait for it.
 *
 * This function is equivalent to calling `bf_test_process_kill()` then
 * `bf_test_process_wait()`.
 *
 * @param process The process to stop. Can't be `NULL`.
 * @return The return code of the process as a non-negative integer, or a
 *         negative errno value on error.
 */
int bf_test_process_stop(struct bf_test_process *process);

/**
 * Run a command in a forked process.
 *
 * This function won't kill the process but only wait on it. If you call
 * `bf_run()` with a command that doesn't return, this function will hang
 * indefinitely.
 *
 * @param cmd Command to run in the process.
 * @param args Array of arguments to provide to the process.
 * @param nargs Number of arguments in @p args.
 * @return The return code of the process as a non-negative integer, or a
 *         negative errno value on error.
 */
int bf_run(const char *cmd, char **args, size_t nargs);

/**
 * Read the process' `stdout` stream.
 *
 * The buffer returned by `bf_test_process_stdout()` is dynamically allocated
 * and is owned by the caller.
 *
 * @param process Process to read the `stdout` stream from.
 * @return Buffer containing the process' `stdout` stream, or `NULL` on error.
 */
const char *bf_test_process_stdout(struct bf_test_process *process);

/**
 * Read the process' `stderr` stream.
 *
 * The buffer returned by `bf_test_process_stderr()` is dynamically allocated
 * and is owned by the caller.
 *
 * @param process Process to read the `stderr` stream from.
 * @return Buffer containing the process' `stderr` stream, or `NULL` on error.
 */
const char *bf_test_process_stderr(struct bf_test_process *process);
