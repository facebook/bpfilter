/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/jmp.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

/**
 * Create a context and emit a given number of instructions.
 *
 * EMIT_*() macros can't be called directly from the test, as they return an
 * error code on failure. This function is a workaround to test EMIT_*() macros
 * and return a negative value on error. This negative value can then be
 * asserted by the tests.
 *
 * @param program The program to emit the instructions in.
 * @param ctx The context to create.
 * @param n_insn The number of instructions to emit.
 * @return 0 on success, or negative errno value on failure.
 */
static int emit_in_ctx(struct bf_program *program, struct bf_jmpctx *ctx,
                       size_t n_insn)
{
    *ctx = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 0));

    for (size_t i = 0; i < n_insn; i++)
        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, 0));

    return 0;
}

Test(jmp, create_and_close)
{
    _free_bf_program_ struct bf_program *program = NULL;
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain(BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    assert_success(bf_program_new(&program, chain));

    {
        // Managing context manually
        struct bf_jmpctx ctx;
        assert_int_equal(emit_in_ctx(program, &ctx, 0), 0);
        bf_jmpctx_cleanup(&ctx);
        assert_int_equal(program->img[ctx.insn_idx].off, 0);

        assert_int_equal(emit_in_ctx(program, &ctx, 1), 0);
        bf_jmpctx_cleanup(&ctx);
        assert_int_equal(program->img[ctx.insn_idx].off, 1);

        assert_int_equal(emit_in_ctx(program, &ctx, 2), 0);
        bf_jmpctx_cleanup(&ctx);
        assert_int_equal(program->img[ctx.insn_idx].off, 2);
    }

    {
        // Check if the context is automatically cleaned up
        size_t idx;

        {
            _clean_bf_jmpctx_ struct bf_jmpctx _;
            assert_int_equal(emit_in_ctx(program, &_, 0), 0);
            idx = _.insn_idx;
        }

        assert_int_equal(program->img[idx].off, 0);

        {
            _clean_bf_jmpctx_ struct bf_jmpctx _;
            assert_int_equal(emit_in_ctx(program, &_, 1), 0);
            idx = _.insn_idx;
        }

        assert_int_equal(program->img[idx].off, 1);

        {
            _clean_bf_jmpctx_ struct bf_jmpctx _;
            assert_int_equal(emit_in_ctx(program, &_, 2), 0);
            idx = _.insn_idx;
        }

        assert_int_equal(program->img[idx].off, 2);
    }
}
