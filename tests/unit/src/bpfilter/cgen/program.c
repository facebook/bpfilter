/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/program.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(program, emit_fixup_call)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_quick();

    expect_assert_failure(bf_program_emit_fixup_call(
        NULL, BF_FIXUP_FUNC_UPDATE_COUNTERS));

    {
        // Instructions buffer should grow
        _cleanup_bf_program_ struct bf_program *program = NULL;
        size_t start_cap;

        assert_success(bf_program_new(&program, BF_HOOK_NF_FORWARD, BF_FRONT_IPT, chain));

        start_cap = program->img_cap;

        // Instructions buffer is empty after initialisation, ensure it grows.
        assert_int_equal(0,
                         bf_program_emit_fixup_call(
                             program, BF_FIXUP_FUNC_UPDATE_COUNTERS));
        assert_int_not_equal(program->img_cap, start_cap);
    }
}
