/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/limits.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpfilter/core/list.h>
#include <bpfilter/ctx.h>
#include <bpfilter/logger.h>

#include "core/lock.h"
#include "test.h"

static void get_cgens_empty(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_list_ bf_list *cgens = NULL;
    const struct bf_ctx *ctx = bft_state_ctx(*state);

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    assert_ok(bf_ctx_get_cgens(ctx, &lock, &cgens));
    assert_non_null(cgens);
    assert_int_equal(bf_list_size(cgens), 0);
}

static void get_cgens_skips_corrupt(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
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

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    assert_ok(bf_ctx_get_cgens(bft_state_ctx(*state), &lock, &cgens));
    assert_non_null(cgens);
    assert_int_equal(bf_list_size(cgens), 0);
}

static void get_cgen_corrupt_returns_error(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
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
    assert_ok(bf_lock_init_for_chain(&lock, bft_state_tmpdir(*state)->dir_path,
                                     "broken", BF_LOCK_READ, BF_LOCK_READ,
                                     false));
    assert_err(bf_ctx_get_cgen(bft_state_ctx(*state), &lock, &cgen));
    assert_null(cgen);
}

static void verbose_flags(void **state)
{
    (void)state;

    /* `bft_setup_ctx_state()` configures BF_VERBOSE_DEBUG through the
     * process-wide logger; verify the other flags are off. */
    assert_true(bf_logger_is_verbose(BF_VERBOSE_DEBUG));
    assert_false(bf_logger_is_verbose(BF_VERBOSE_BPF));
    assert_false(bf_logger_is_verbose(BF_VERBOSE_BYTECODE));
}

static void new_and_free_roundtrip(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    struct bf_ctx *ctx = NULL;

    (void)state;

    assert_ok(bft_tmpdir_new(&tmpdir));
    assert_ok(bf_ctx_new(&ctx, false, tmpdir->dir_path));
    assert_non_null(ctx);

    bf_ctx_free(&ctx);
    assert_null(ctx);

    /* bf_ctx_free is a no-op on a NULL pointer. */
    bf_ctx_free(&ctx);
    assert_null(ctx);
}

static void free_cleanup_attribute(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;

    (void)state;

    assert_ok(bft_tmpdir_new(&tmpdir));

    /* _free_bf_ctx_ runs bf_ctx_free at scope exit; no leaks expected. */
    {
        _free_bf_ctx_ struct bf_ctx *ctx = NULL;
        assert_ok(bf_ctx_new(&ctx, false, tmpdir->dir_path));
        assert_non_null(ctx);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(get_cgens_empty, bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(get_cgens_skips_corrupt,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(get_cgen_corrupt_returns_error,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(verbose_flags, bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test(new_and_free_roundtrip),
        cmocka_unit_test(free_cleanup_attribute),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
