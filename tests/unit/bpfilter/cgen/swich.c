/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/swich.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(swich, new_and_free_option)
{
    struct bpf_insn insns[] = {
        BPF_EXIT_INSN(),
        BPF_EXIT_INSN(),
        BPF_EXIT_INSN(),
    };

    expect_assert_failure(_bf_swich_option_new(NULL, 0, NOT_NULL, 0));
    expect_assert_failure(_bf_swich_option_new(NOT_NULL, 0, NULL, 0));
    expect_assert_failure(_bf_swich_option_free(NULL));

    {
        // Auto cleanup
        _free_bf_swich_option_ struct bf_swich_option *option = NULL;

        assert_int_equal(
            0, _bf_swich_option_new(&option, 0, (struct bpf_insn[]) {}, 0));
        _bf_swich_option_free(&option);
        assert_ptr_equal(NULL, option);
        assert_int_equal(
            0, _bf_swich_option_new(&option, 0, (struct bpf_insn[]) {}, 0));
    }

    {
        // Instructions
        struct bf_swich_option *option = NULL;

        assert_int_equal(0, _bf_swich_option_new(&option, 0, insns, 3));
        _bf_swich_option_free(&option);
    }
}

Test(swich, init_and_cleanup)
{
    _clean_bf_swich_ struct bf_swich swich;

    expect_assert_failure(bf_swich_init(NULL, NOT_NULL, 0));
    expect_assert_failure(bf_swich_init(NOT_NULL, NULL, 0));
    expect_assert_failure(bf_swich_cleanup(NULL));

    assert_success(bf_swich_init(&swich, NOT_NULL, 0));
    bf_swich_cleanup(&swich);
    assert_true(bf_list_is_empty(&swich.options));
}

Test(swich, generate_swich)
{
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_quick();
    struct bpf_insn insns[] = {
        BPF_EXIT_INSN(),
        BPF_EXIT_INSN(),
        BPF_EXIT_INSN(),
    };

    {
        // No default option
        _free_bf_program_ struct bf_program *program = NULL;
        _clean_bf_swich_ struct bf_swich swich;

        assert_success(bf_program_new(&program, chain));
        assert_success(bf_swich_init(&swich, program, 0));

        for (int i = 0; i < 3; ++i)
            assert_success(bf_swich_add_option(&swich, i, insns, i + 1));

        assert_success(bf_swich_generate(&swich));
        assert_int_equal(12, program->img_size);
        bf_swich_cleanup(&swich);
    }

    {
        // With default option (2 times)
        _free_bf_program_ struct bf_program *program = NULL;
        _clean_bf_swich_ struct bf_swich swich;

        assert_success(bf_program_new(&program, chain));
        assert_success(bf_swich_init(&swich, program, 0));

        for (int i = 0; i < 3; ++i)
            assert_success(bf_swich_add_option(&swich, i, insns, i + 1));

        assert_success(bf_swich_set_default(&swich, insns, 3));
        assert_success(bf_swich_set_default(&swich, insns, 3));

        assert_success(bf_swich_generate(&swich));
        assert_int_equal(16, program->img_size);
        bf_swich_cleanup(&swich);
    }
}
