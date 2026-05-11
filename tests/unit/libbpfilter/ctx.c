/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/limits.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpfilter/core/list.h>
#include <bpfilter/ctx.h>

#include "core/lock.h"
#include "test.h"

static void no_setup(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    /* All ctx accessors must reject calls made before bf_ctx_setup. */
    assert_int_equal(bf_lock_init(&lock, BF_LOCK_READ), -EINVAL);
    assert_int_equal(bf_ctx_token(), -1);
    assert_null(bf_ctx_get_elfstub(0));
    assert_null(bf_ctx_get_bpffs_path());
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_DEBUG));
}

static void bpffs_path_matches_setup(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    const char *path;

    /* The accessor must return the path the caller passed to bf_ctx_setup. */
    path = bf_ctx_get_bpffs_path();
    assert_non_null(path);
    assert_string_equal(path, tmpdir->dir_path);
}

static void bpffs_path_is_owned_copy(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    char path_buf[PATH_MAX];
    const char *stored;

    (void)state;

    /* This test runs without the bft_setup_ctx fixture so we control the
     * lifetime of the bpffs_path buffer passed to bf_ctx_setup. */
    assert_ok(bft_tmpdir_new(&tmpdir));

    /* Copy the bpffs path into a local mutable buffer, then hand it to
     * bf_ctx_setup. */
    (void)snprintf(path_buf, sizeof(path_buf), "%s", tmpdir->dir_path);
    assert_ok(bf_ctx_setup(false, path_buf, BF_FLAG(BF_VERBOSE_DEBUG)));

    /* Stomp on the caller's buffer. The ctx must hold its own strdup'd copy:
     * before this fix, ctx->bpffs_path aliased the caller's storage and the
     * accessor would return the corrupted contents (or worse, dangling memory
     * once the caller's buffer went out of scope). */
    memset(path_buf, 'X', sizeof(path_buf) - 1);
    path_buf[sizeof(path_buf) - 1] = '\0';

    stored = bf_ctx_get_bpffs_path();
    assert_non_null(stored);
    assert_ptr_not_equal(stored, path_buf);
    assert_string_equal(stored, tmpdir->dir_path);

    /* Tear down before the tmpdir cleanup so the ctx releases its copy while
     * the bpffs path is still on disk. ASan/leak detectors would flag a
     * missing free here, exercising the matching freep() in _bf_ctx_free. */
    bf_ctx_teardown();
}

static void get_cgens_empty(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_list_ bf_list *cgens = NULL;

    (void)state;

    assert_ok(bf_lock_init(&lock, BF_LOCK_READ));
    assert_ok(bf_ctx_get_cgens(&lock, &cgens));
    assert_non_null(cgens);
    assert_int_equal(bf_list_size(cgens), 0);
}

static void get_cgens_skips_corrupt(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_list_ bf_list *cgens = NULL;
    char pindir_path[PATH_MAX];
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    _cleanup_close_ int fd = -1;

    /* The pin directory is now created unconditionally by `bf_ctx_setup`
     * (I1); just make sure it exists, don't treat an existing one as an
     * error. */
    (void)snprintf(pindir_path, sizeof(pindir_path), "%s/bpfilter",
                   tmpdir->dir_path);
    (void)mkdir(pindir_path, 0755);

    /* Create a chain dir without a `bf_ctx` map: it should be warn-and-skipped
     * during discovery. */
    (void)snprintf(dir_path, sizeof(dir_path), "%s/bpfilter/orphan_chain",
                   tmpdir->dir_path);
    assert_ok(mkdir(dir_path, 0755));

    /* Drop a regular file alongside the chain dirs to verify the !DT_DIR
     * branch is skipped. */
    (void)snprintf(file_path, sizeof(file_path), "%s/bpfilter/stray_file",
                   tmpdir->dir_path);
    assert_fd(fd = open(file_path, O_CREAT | O_WRONLY, 0644));

    assert_ok(bf_lock_init(&lock, BF_LOCK_READ));
    assert_ok(bf_ctx_get_cgens(&lock, &cgens));
    assert_non_null(cgens);
    assert_int_equal(bf_list_size(cgens), 0);
}

static void get_cgen_corrupt_returns_error(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    struct bf_cgen *cgen = NULL;
    char pindir_path[PATH_MAX];
    char dir_path[PATH_MAX];

    (void)snprintf(pindir_path, sizeof(pindir_path), "%s/bpfilter",
                   tmpdir->dir_path);
    (void)mkdir(pindir_path, 0755);

    (void)snprintf(dir_path, sizeof(dir_path), "%s/bpfilter/broken",
                   tmpdir->dir_path);
    assert_ok(mkdir(dir_path, 0755));

    /* Chain dir exists but the `bf_ctx` map is missing: bf_cgen_new_from_dir_fd
     * fails, and the error must be propagated (not swallowed as -ENOENT). */
    assert_ok(bf_lock_init_for_chain(&lock, "broken", BF_LOCK_READ,
                                     BF_LOCK_READ, false));
    assert_err(bf_ctx_get_cgen(&lock, &cgen));
    assert_null(cgen);
}

static void verbose_flags(void **state)
{
    (void)state;

    assert_true(bf_ctx_is_verbose(BF_VERBOSE_DEBUG));
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_BPF));
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_BYTECODE));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(no_setup),
        cmocka_unit_test(bpffs_path_is_owned_copy),
        cmocka_unit_test_setup_teardown(bpffs_path_matches_setup, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(get_cgens_empty, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(get_cgens_skips_corrupt, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(get_cgen_corrupt_returns_error,
                                        bft_setup_ctx, bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(verbose_flags, bft_setup_ctx,
                                        bft_teardown_ctx),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
