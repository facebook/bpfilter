/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "generator/codegen.h"

#include <criterion/criterion.h>

#include "generator/program.h"
#include "test.h"

Test(src_generator_codegen, get_program)
{
    _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;

    cr_assert_eq(bf_test_make_codegen(&codegen, BF_HOOK_IPT_FORWARD, 5), 0);

    {
        // Get first program in the list
        struct bf_program *program = bf_codegen_get_program(codegen, 1);
        cr_assert_not_null(program);
        cr_assert_eq(program->ifindex, 1);
    }

    {
        // Get program from the middle of the list
        struct bf_program *program = bf_codegen_get_program(codegen, 3);
        cr_assert_not_null(program);
        cr_assert_eq(program->ifindex, 3);
    }

    {
        // Get last program of the list
        struct bf_program *program = bf_codegen_get_program(codegen, 5);
        cr_assert_not_null(program);
        cr_assert_eq(program->ifindex, 5);
    }

    {
        // Get program with an invalid interface
        struct bf_program *program = bf_codegen_get_program(codegen, 10);
        cr_assert_null(program);
    }
}
