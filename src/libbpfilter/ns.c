/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include "bpfilter/ns.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

#define NS_DIR_PATH_LEN 32

/**
 * Initialize a `bf_ns_info` structure for a given namespace.
 *
 * @param info `bf_ns_info` object to initialise. On failure, this parameter is
 *             unchanged. Can't be NULL.
 * @param name Name of the namespace to open. Can't be NULL.
 * @param dir_fd File descriptor of the directory to open the namespace from.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_ns_info_init(struct bf_ns_info *info, const char *name,
                            int dir_fd)
{
    _cleanup_close_ int fd = -1;
    struct stat stats;
    int r;

    assert(info);
    assert(name);

    fd = openat(dir_fd, name, O_RDONLY, 0);
    if (fd < 0)
        return -errno;

    r = fstat(fd, &stats);
    if (r)
        return -errno;

    info->fd = TAKE_FD(fd);
    info->inode = stats.st_ino;

    return 0;
}

int bf_ns_init(struct bf_ns *ns, pid_t pid)
{
    _clean_bf_ns_ struct bf_ns _ns = bf_ns_default();
    _cleanup_close_ int dirfd = -1;
    char ns_dir_path[NS_DIR_PATH_LEN];
    int r;

    assert(ns);

    /// @todo What if ``/proc`` is not readable?
    (void)snprintf(ns_dir_path, NS_DIR_PATH_LEN, "/proc/%d/ns", pid);
    dirfd = open(ns_dir_path, O_DIRECTORY, O_RDONLY);
    if (dirfd < 0)
        return bf_err_r(errno, "failed to open ns directory '%s'", ns_dir_path);

    r = _bf_ns_info_init(&_ns.net, "net", dirfd);
    if (r) {
        return bf_err_r(r, "failed to read 'net' namespace in '%s'",
                        ns_dir_path);
    }

    r = _bf_ns_info_init(&_ns.mnt, "mnt", dirfd);
    if (r) {
        return bf_err_r(r, "failed to read 'mnt' namespace in '%s'",
                        ns_dir_path);
    }

    *ns = bf_ns_move(_ns);

    return 0;
}

void bf_ns_clean(struct bf_ns *ns)
{
    assert(ns);

    closep(&ns->net.fd);
    closep(&ns->mnt.fd);
}

int bf_ns_set(const struct bf_ns *ns, const struct bf_ns *oldns)
{
    int r;

    if (!oldns || ns->net.inode != oldns->net.inode) {
        r = setns(ns->net.fd, CLONE_NEWNET);
        if (r)
            return bf_err_r(r, "failed to switch to a network namespace");
    }

    if (!oldns || ns->mnt.inode != oldns->mnt.inode) {
        r = setns(ns->mnt.fd, CLONE_NEWNS);
        if (r)
            return bf_err_r(r, "failed to switch to a mount namespace");
    }

    return 0;
}
