/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/io.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

#define BF_PERM_755 (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

int bf_ensure_dir(const char *dir)
{
    struct stat stats;
    int r;

    assert(dir);

    r = access(dir, R_OK | W_OK);
    if (r && errno == ENOENT) {
        if (mkdir(dir, BF_PERM_755) == 0)
            return 0;

        return bf_err_r(errno, "failed to create directory '%s'", dir);
    }
    if (r)
        return bf_err_r(errno, "no R/W permissions on '%s'", dir);

    if (stat(dir, &stats) != 0 || !S_ISDIR(stats.st_mode))
        return bf_err_r(-EINVAL, "'%s' is not a valid directory", dir);

    return 0;
}

int bf_opendir(const char *path)
{
    _cleanup_close_ int fd = -1;

    assert(path);

    fd = open(path, O_DIRECTORY);
    if (fd < 0)
        return -errno;

    return TAKE_FD(fd);
}

int bf_opendir_at(int parent_fd, const char *dir_name, bool mkdir_if_missing)
{
    _cleanup_close_ int fd = -1;
    int r;

    assert(dir_name);

retry:
    fd = openat(parent_fd, dir_name, O_DIRECTORY);
    if (fd < 0) {
        if (errno != ENOENT || !mkdir_if_missing)
            return -errno;

        r = mkdirat(parent_fd, dir_name, BF_PERM_755);
        if (r)
            return -errno;

        goto retry;
    }

    return TAKE_FD(fd);
}

static void bf_free_dir(DIR **dir)
{
    if (!*dir)
        return;

    closedir(*dir);
    *dir = NULL;
}

#define _free_dir_ __attribute__((__cleanup__(bf_free_dir)))

int bf_rmdir_at(int parent_fd, const char *dir_name, bool recursive)
{
    int r;

    assert(dir_name);

    if (recursive) {
        _cleanup_close_ int child_fd = -1;
        _free_dir_ DIR *dir = NULL;
        struct dirent *entry;
        int dir_fd;

        child_fd = openat(parent_fd, dir_name, O_DIRECTORY);
        if (child_fd < 0) {
            return bf_err_r(errno,
                            "failed to open child directory for removal");
        }

        dir = fdopendir(child_fd);
        if (!dir)
            return bf_err_r(errno, "failed to open DIR from file descriptor");
        /* fdopendir takes ownership of the FD, let's prevent double-close in
         * case of multithreading and FD reuse */
        TAKE_FD(child_fd);

        dir_fd = dirfd(dir);
        if (dir_fd < 0)
            return bf_err_r(errno, "failed to retrieve FD after fdopendir");

        while ((entry = readdir(dir))) {
            struct stat stat;

            if (bf_streq(entry->d_name, ".") || bf_streq(entry->d_name, ".."))
                continue;

            if (fstatat(dir_fd, entry->d_name, &stat, 0) < 0) {
                return bf_err_r(errno,
                                "failed to fstatat() file '%s' for removal",
                                entry->d_name);
            }

            if (S_ISDIR(stat.st_mode))
                r = bf_rmdir_at(dir_fd, entry->d_name, true);
            else
                r = unlinkat(dir_fd, entry->d_name, 0) == 0 ? 0 : -errno;
            if (r)
                return bf_err_r(r, "failed to remove '%s'", entry->d_name);
        }
    }

    r = unlinkat(parent_fd, dir_name, AT_REMOVEDIR);
    if (r)
        return -errno;

    return 0;
}

int bf_acquire_lock(const char *path)
{
    _cleanup_close_ int fd = -1;

    assert(path);

    fd = open(path, O_CREAT | O_RDWR, BF_PERM_755);
    if (fd < 0)
        return -errno;

    if (flock(fd, LOCK_EX | LOCK_NB) < 0)
        return -errno;

    return TAKE_FD(fd);
}
