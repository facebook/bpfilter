// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/dump.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bpfilter/cgen/program.h"
#include "core/btf.h"
#include "core/dump.h"
#include "core/helper.h"
#include "core/logger.h"

#include "external/disasm.h"

#define SYM_MAX_NAME 256

struct bf_dump_data
{
    prefix_t *prefix;
    char scratch_buff[SYM_MAX_NAME + 8];
    unsigned long address_call_base;
    size_t idx;
};

static void _bf_print_insn(void *private_data, const char *fmt, ...)
{
    va_list args;
    struct bf_dump_data *bfdd = private_data;

    va_start(args, fmt);
    (void)fprintf(stderr, "%s%-7s%s: %s %4ld: ",
                  bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_BOLD), "debug",
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                  *(bfdd->prefix), bfdd->idx);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);
}

static const char *_bf_print_call(void *private_data,
                                  const struct bpf_insn *insn)
{
    struct bf_dump_data *bfdd = private_data;

    if (insn->src_reg == BPF_PSEUDO_CALL) {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff), "%+d",
                       insn->imm);
    } else {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff), "%s",
                       bf_btf_get_name(insn->imm));
    }

    return bfdd->scratch_buff;
}

static const char *_bf_print_imm(void *private_data,
                                 const struct bpf_insn *insn, uint64_t full_imm)
{
    struct bf_dump_data *bfdd = private_data;

    if (insn->src_reg == BPF_PSEUDO_MAP_FD) {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff),
                       "map[id:%u]", insn->imm);
    } else if (insn->src_reg == BPF_PSEUDO_MAP_VALUE) {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff),
                       "map[id:%u][0]+%u", insn->imm, (insn + 1)->imm);
    } else if (insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE) {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff),
                       "map[idx:%u]+%u", insn->imm, (insn + 1)->imm);
    } else if (insn->src_reg == BPF_PSEUDO_FUNC) {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff),
                       "subprog[%+d]", insn->imm);
    } else {
        (void)snprintf(bfdd->scratch_buff, sizeof(bfdd->scratch_buff), "0x%llx",
                       (unsigned long long)full_imm);
    }

    return bfdd->scratch_buff;
}

void bf_program_dump_bytecode(const struct bf_program *program)
{
    prefix_t prefix = {};
    struct bf_dump_data bfdd = {
        .prefix = &prefix,
    };
    struct bpf_insn_cbs callbacks = {
        .cb_print = _bf_print_insn,
        .cb_call = _bf_print_call,
        .cb_imm = _bf_print_imm,
        .private_data = &bfdd,
    };
    bool double_insn = false;

    bf_assert(program);

    bf_dump_prefix_push(&prefix);

    bf_dbg("Bytecode for program at %p, %lu insn:", program, program->img_size);

    for (size_t i = 0; i < program->img_size; ++i) {
        if (i == program->img_size - 1)
            bf_dump_prefix_last(&prefix);

        if (double_insn) {
            double_insn = false;
            ++bfdd.idx;
            continue;
        }

        print_bpf_insn(&callbacks, &program->img[i], true);
        ++bfdd.idx;

        double_insn = program->img[i].code == (BPF_LD | BPF_IMM | BPF_DW);
    }

    // Force flush, otherwise output on stderr might appear.
    (void)fflush(stdout);
}
