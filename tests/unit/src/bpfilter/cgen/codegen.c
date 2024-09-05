/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/codegen.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(codegen, get_program)
{
    _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;

    assert_int_equal(bf_test_make_codegen(&codegen, BF_HOOK_NF_FORWARD, 5), 0);

    {
        // Get first program in the list
        struct bf_program *program = bf_codegen_get_program(codegen, 1);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 1);
    }

    {
        // Get program from the middle of the list
        struct bf_program *program = bf_codegen_get_program(codegen, 3);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 3);
    }

    {
        // Get last program of the list
        struct bf_program *program = bf_codegen_get_program(codegen, 5);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 5);
    }

    {
        // Get program with an invalid interface
        struct bf_program *program = bf_codegen_get_program(codegen, 10);
        assert_null(program);
    }
}
