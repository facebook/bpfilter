/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/io.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "test.h"

static void manage_dir(void **state)
{
    _cleanup_close_ int fake_file_fd = -1;
    _cleanup_close_ int fd_tmpdir = -1;
    _cleanup_close_ int fd_tmpdir_testdir = -1;
    _cleanup_close_ int fd_tmpdir_testdir_nested = -1;
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    char dirpath[1024];

    (void)snprintf(filepath, sizeof(filepath), "%s/testfile", tmpdir->dir_path);
    (void)snprintf(dirpath, sizeof(dirpath), "%s/testdir", tmpdir->dir_path);

    // Open the base directory. Use bf_ensure_dir() twice to validate idempotency
    assert_err(bf_opendir("/directory_doesnt_exist"));
    assert_ok(bf_ensure_dir(tmpdir->dir_path));
    assert_ok(bf_ensure_dir(tmpdir->dir_path));
    assert_int_gte(fd_tmpdir = bf_opendir(tmpdir->dir_path), 0);

    // bf_ensure_dir() fails if directory ("testfile" here) can't be accessed
    fake_file_fd = open(filepath, O_CREAT | O_WRONLY, 0666);
    assert_int_gte(fake_file_fd, 0);
    assert_err(bf_ensure_dir(filepath));

    // bf_opendir_at(): directory exists
    assert_ok(bf_ensure_dir(dirpath));
    assert_int_gte(
        fd_tmpdir_testdir = bf_opendir_at(fd_tmpdir, "testdir", false), 0);

    // bf_opendir_at(): directory doesn't exist
    assert_err(bf_opendir_at(fd_tmpdir_testdir, "nested", false));
    assert_int_gte(fd_tmpdir_testdir_nested =
                       bf_opendir_at(fd_tmpdir_testdir, "nested", true),
                   0);

    // Remove the directories
    assert_err(bf_rmdir_at(INT_MAX, "dir", false));
    assert_err(bf_rmdir_at(INT_MAX, "dir", true));
    assert_err(bf_rmdir_at(fd_tmpdir, "testdir", false));
    assert_ok(bf_rmdir_at(fd_tmpdir, "testdir", true));
}

static void lock_file(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];

    // Can't lock a lockfile twice
    (void)snprintf(filepath, sizeof(filepath), "%s/file.lock",
                   tmpdir->dir_path);
    assert_int_gte(fd = bf_acquire_lock(filepath), 0);
    assert_err(bf_acquire_lock(filepath));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(manage_dir, btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(lock_file, btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
