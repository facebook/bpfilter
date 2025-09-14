/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE // NOLINT: required for F_SETPIPE_SZ

#include "process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

int bf_test_process_init(struct bf_test_process *process, const char *cmd,
                         char **args, size_t nargs)
{
    size_t i = 0;
    int r;

    /* execvp() requires args (its second argument) to contain the binary to
     * run at index 0, and must end with a NULL pointer. Hence, process->args
     * contains the command to run, the arguments, and a NULL pointer. */
    process->nargs = nargs + 2;
    process->args = (char **)malloc(process->nargs * sizeof(char *));
    if (!process->args)
        return bf_err_r(errno, "failed to allocate memory for bf_process.args");

    process->args[0] = strdup(cmd);
    if (!process->args[0]) {
        r = bf_err_r(errno, "failed to copy cmd to bf_process.args[0]");
        goto err_free_args;
    }

    process->cmd = process->args[0];

    for (i = 1; i < process->nargs - 1; ++i) {
        process->args[i] = strdup(args[i - 1]);
        if (!process->args[i]) {
            r = bf_err_r(errno, "failed to copy process args[%ld]", i);
            goto err_free_args;
        }
    }

    process->args[process->nargs - 1] = NULL;

    process->pid = 0;
    process->out_fd = -1;
    process->err_fd = -1;

    return 0;

err_free_args:
    for (size_t j = 0; j < i; ++j)
        freep((void *)&process->args[j]);
    return r;
}

void bf_test_process_clean(struct bf_test_process *process)
{
    if (process->args) {
        for (size_t i = 0; i < process->nargs; ++i)
            freep((void *)&process->args[i]);
    }

    freep((void *)&process->args);

    closep(&process->out_fd);
    closep(&process->err_fd);
}

static int _bf_test_process_exec(struct bf_test_process *process)
{
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    pid_t pid;
    int r;

    r = pipe(stdout_pipe);
    if (r)
        return bf_err_r(errno, "failed to create stdout pipes pair");

    r = pipe(stderr_pipe);
    if (r)
        return bf_err_r(errno, "failed to create stderr pipes pair");

    pid = fork();
    if (pid < 0)
        return bf_err_r(errno, "failed to fork child");

    if (pid == 0) {
        // We're in the child process

        r = dup2(stdout_pipe[1], STDOUT_FILENO);
        if (r < 0)
            return bf_err_r(errno, "failed to duplicate the child's stdout");

        // Bump the pipe buffer size to 1MB
        r = fcntl(stdout_pipe[1], F_SETPIPE_SZ, 1048576);
        if (r < 0) {
            return bf_err_r(errno,
                            "failed to set the child's stdout buffer size");
        }

        r = dup2(stderr_pipe[1], STDERR_FILENO);
        if (r < 0)
            return bf_err_r(errno, "failed to duplicate the child's stderr");

        // Bump the pipe buffer size to 1MB
        r = fcntl(stderr_pipe[1], F_SETPIPE_SZ, 1048576);
        if (r < 0) {
            return bf_err_r(errno,
                            "failed to set the child's stderr buffer size");
        }

        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        (void)execvp(process->cmd, process->args);

        bf_abort("failed to execvp() %s: %s", process->cmd, strerror(errno));
    }

    process->out_fd = stdout_pipe[0];
    process->err_fd = stderr_pipe[0];
    process->pid = pid;

    return 0;
}

static int _bf_fd_set_flag(int fd, int flag)
{
    int r;

    r = fcntl(fd, F_GETFL, 0);
    if (r < 0)
        return bf_err_r(errno, "failed to get flags for FD %d", fd);

    r = fcntl(fd, F_SETFL, r | flag);
    if (r < 0)
        return bf_err_r(errno, "failed to set flags for FD %d", fd);

    return 0;
}

int bf_test_process_start(struct bf_test_process *process)
{
    int r;

    r = _bf_test_process_exec(process);
    if (r < 0)
        return r;

    r = _bf_fd_set_flag(process->out_fd, O_NONBLOCK);
    if (r < 0) {
        bf_err_r(r, "failed to set O_NONBLOCK flag to stdout FD");
        goto err_fcntl;
    }

    r = _bf_fd_set_flag(process->err_fd, O_NONBLOCK);
    if (r < 0) {
        bf_err_r(r, "failed to set O_NONBLOCK flag to stderr FD");
        goto err_fcntl;
    }

    return 0;

err_fcntl:
    kill(process->pid, SIGKILL);
    return r;
}

int bf_test_process_wait(struct bf_test_process *process)
{
    int status;
    int r;

    r = waitpid(process->pid, &status, 0);
    if (r < 0)
        return bf_err_r(errno, "waitpid() on child process failed");

    return WEXITSTATUS(status);
}

int bf_test_process_kill(struct bf_test_process *process)
{
    int r;

    r = kill(process->pid, SIGTERM);
    if (r < 0)
        return bf_err_r(errno, "failed to send SIGTERM to the process");

    return 0;
}

int bf_test_process_stop(struct bf_test_process *process)
{
    int r;

    r = bf_test_process_kill(process);
    if (r < 0)
        return 0;

    return bf_test_process_wait(process);
}

int bf_run(const char *cmd, char **args, size_t nargs)
{
    _clean_bf_test_process_ struct bf_test_process process =
        bft_process_default();
    int r;

    r = bf_test_process_init(&process, cmd, args, nargs);
    if (r < 0)
        return r;

    r = bf_test_process_start(&process);
    if (r < 0)
        return r;

    r = bf_test_process_wait(&process);
    if (r < 0)
        return r;

    bf_test_process_clean(&process);

    return r;
}

const char *_bf_fd_read(int fd)
{
    _cleanup_free_ char *data = NULL;
    char buffer[1024];
    size_t tot_len = 0;
    ssize_t read_len;

    do {
        char *new_data;

        read_len = read(fd, buffer, ARRAY_SIZE(buffer));
        if (read_len == 0 || (read_len < 0 && errno == EAGAIN)) {
            // EAGAIN is expected for non-blocking FDs. Ignore it
            break;
        }
        if (read_len < 0) {
            bf_err_r(errno, "failed to read from FD %d", fd);
            freep((void *)&data);
            return NULL;
        }

        new_data = realloc(data, tot_len + read_len + 1);
        if (!new_data) {
            bf_warn("failed to grow the FD read buffer, skipping data");
            break;
        }

        strncpy(&new_data[tot_len], buffer, read_len);
        tot_len += read_len;
        data = new_data;
        data[tot_len] = '\0';
    } while (read_len == ARRAY_SIZE(buffer));

    return TAKE_PTR(data);
}

const char *bf_test_process_stdout(struct bf_test_process *process)
{
    return _bf_fd_read(process->out_fd);
}

const char *bf_test_process_stderr(struct bf_test_process *process)
{
    return _bf_fd_read(process->err_fd);
}
