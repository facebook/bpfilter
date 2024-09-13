/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/meta.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <endian.h>
#include <errno.h>
#include <stdint.h>

#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "core/logger.h"
#include "core/matcher.h"

#include "external/filter.h"

static int _bf_matcher_generate_meta_l3_proto(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BF_REG_1,
                             htobe16(*(uint16_t *)&matcher->payload), 0));

    return 0;
}

static int _bf_matcher_generate_meta_l4_proto(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(BPF_JNE, BF_REG_1, *(uint8_t *)&matcher->payload, 0));

    return 0;
}

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    int r;

    switch (matcher->type) {
    case BF_MATCHER_META_L3_PROTO:
        r = _bf_matcher_generate_meta_l3_proto(program, matcher);
        break;
    case BF_MATCHER_META_L4_PROTO:
        r = _bf_matcher_generate_meta_l4_proto(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    if (r)
        return r;

    return 0;
}
