/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>

/**
 * @file jmp.h
 *
 * @ref bf_jmpctx is a helper structure to manage jump instructions in the
 * program. It is used to emit a jump instruction and automatically clean it up
 * when the scope is exited, thanks to GCC's @c cleanup attribute.
 *
 * Example:
 * @code{.c}
 *  // Within a function body
 *  {
 *      _cleanup_bf_jmpctx_ struct bf_jmpctx ctx =
 *          bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_2, 0, 0));
 *
 *      EMIT(program,
 *          BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
 *              BF_VERDICT_ACCEPT)));
 *      EMIT(program, BPF_EXIT_INSN());
 *  }
 * @endcode
 *
 * \c ctx is a variable local to the scope, marked with \c _cleanup_bf_jmpctx_ .
 * The second argument to \c bf_jmpctx_get is the jump instruction to emit, with
 * the correct condition. When the scope is exited, the jump instruction is
 * automatically updated to point to the current instruction, which is after the
 * scope.
 *
 * Hence, all the instructions emitted within the scope will be executed if the
 * condition is not met. If the condition is met, then the program execution
 * will continue with the first instruction after the scope.
 */

struct bf_program;

/**
 * Cleanup attribute for a @ref bf_jmpctx variable.
 */
#define _cleanup_bf_jmpctx_ __attribute__((cleanup(bf_jmpctx_cleanup)))

/**
 * Create a new @ref bf_jmpctx variable.
 *
 * @param program The program to emit the jump instruction to. It must be
 *        non-NULL.
 * @param insn The jump instruction to emit.
 * @return A new @ref bf_jmpctx variable.
 */
#define bf_jmpctx_get(program, insn)                                           \
    ({                                                                         \
        size_t __idx = program->img_size;                                      \
        int __r = bf_program_emit((program), (insn));                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
        (struct bf_jmpctx) {.program = program, .insn_idx = __idx};            \
    })

/**
 * A helper structure to manage jump instructions in the program.
 *
 * @var bf_jmpctx::program
 *  The program to emit the jump instruction to.
 * @var bf_jmpctx::insn_idx
 *  The index of the jump instruction in the program's image.
 */
struct bf_jmpctx
{
    struct bf_program *program;
    size_t insn_idx;
};

/**
 * Cleanup function for @ref bf_jmpctx.
 *
 * @param ctx The @ref bf_jmpctx variable to clean up.
 */
void bf_jmpctx_cleanup(struct bf_jmpctx *ctx);
