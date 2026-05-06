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

#include "test.h"

static void no_setup(void **state)
{
    _free_bf_list_ bf_list *cgens = NULL;
    struct bf_cgen *cgen = NULL;

    (void)state;

    /* All ctx accessors must reject calls made before bf_ctx_setup. */
    assert_int_equal(bf_ctx_get_cgen("foo", &cgen), -EINVAL);
    assert_int_equal(bf_ctx_get_cgens(&cgens), -EINVAL);
    assert_int_equal(bf_ctx_token(), -1);
    assert_int_equal(bf_ctx_get_pindir_fd(), -EINVAL);
    assert_null(bf_ctx_get_elfstub(0));
    assert_false(bf_ctx_is_verbose(BF_VERBOSE_DEBUG));
}

static void get_cgen_unknown(void **state)
{
    struct bf_cgen *cgen = NULL;

    (void)state;

    /* The pindir is empty: every name is "not present". */
    assert_int_equal(bf_ctx_get_cgen("nope", &cgen), -ENOENT);
    assert_null(cgen);
}

static void get_cgens_empty(void **state)
{
    _free_bf_list_ bf_list *cgens = NULL;

    (void)state;

    assert_ok(bf_ctx_get_cgens(&cgens));
    assert_non_null(cgens);
    assert_int_equal(bf_list_size(cgens), 0);
}

static void get_cgens_skips_corrupt(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    _free_bf_list_ bf_list *cgens = NULL;
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    _cleanup_close_ int fd = -1;

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

    assert_ok(bf_ctx_get_cgens(&cgens));
    assert_non_null(cgens);
    assert_int_equal(bf_list_size(cgens), 0);
}

static void get_cgen_corrupt_returns_error(void **state)
{
    struct bft_tmpdir *tmpdir = *state;
    struct bf_cgen *cgen = NULL;
    char dir_path[PATH_MAX];

    (void)snprintf(dir_path, sizeof(dir_path), "%s/bpfilter/broken",
                   tmpdir->dir_path);
    assert_ok(mkdir(dir_path, 0755));

    /* Chain dir exists but the `bf_ctx` map is missing: bf_cgen_new_from_dir_fd
     * fails, and the error must be propagated (not swallowed as -ENOENT). */
    assert_err(bf_ctx_get_cgen("broken", &cgen));
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
        cmocka_unit_test_setup_teardown(get_cgen_unknown, bft_setup_ctx,
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
