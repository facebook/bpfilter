/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/cgen.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(cgen, get_program)
{
    _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;

    assert_int_equal(bf_test_make_cgen(&cgen, BF_HOOK_NF_FORWARD, 5), 0);

    {
        // Get first program in the list
        struct bf_program *program = bf_cgen_get_program(cgen, 1);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 1);
    }

    {
        // Get program from the middle of the list
        struct bf_program *program = bf_cgen_get_program(cgen, 3);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 3);
    }

    {
        // Get last program of the list
        struct bf_program *program = bf_cgen_get_program(cgen, 5);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 5);
    }

    {
        // Get program with an invalid interface
        struct bf_program *program = bf_cgen_get_program(cgen, 10);
        assert_null(program);
    }
}
