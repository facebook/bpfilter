/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/ip4.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/program.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/matcher.h"
#include "core/set.h"

#include "external/filter.h"

static int
_bf_matcher_generate_ip4_addr_unique(struct bf_program *program,
                                     const struct bf_matcher *matcher)
{
    uint32_t *addr = (uint32_t *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_IP4_SADDR ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_2, *addr));

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_REG(matcher->op == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                             BPF_REG_1, BPF_REG_2, 0));

    return 0;
}

static int _bf_matcher_generate_ip4_addr_set(struct bf_program *program,
                                             const struct bf_matcher *matcher)
{
    uint32_t set_id;
    struct bf_set *set;
    int16_t offset;

    bf_assert(program);
    bf_assert(matcher);

    set_id = *(uint32_t *)matcher->payload;
    set = bf_list_get_at(&program->runtime.chain->sets, set_id);

    switch (set->type) {
    case BF_SET_IP4:
        offset = matcher->type == BF_MATCHER_IP4_SADDR ?
                     offsetof(struct iphdr, saddr) :
                     offsetof(struct iphdr, daddr);
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offset));
        EMIT(program,
             BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(0)));
        break;
    default:
        return bf_err_r(-EINVAL, "unsupported set type: %s",
                        bf_set_type_to_str(set->type));
    }

    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1, set_id);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // Jump to the next rule if map_lookup_elem returned 0
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

    return 0;
}

static int _bf_matcher_generate_ip4_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    switch (matcher->op) {
    case BF_MATCHER_EQ:
    case BF_MATCHER_NE:
        return _bf_matcher_generate_ip4_addr_unique(program, matcher);
    case BF_MATCHER_IN:
        return _bf_matcher_generate_ip4_addr_set(program, matcher);
    default:
        return -EINVAL;
    }

    return 0;
}

static int _bf_matcher_generate_ip4_proto(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    uint8_t proto = *(uint8_t *)&matcher->payload;

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6,
                              offsetof(struct iphdr, protocol)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(matcher->op == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                             BPF_REG_1, proto, 0));

    return 0;
}

static int _bf_matcher_generate_ip4_net(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    uint32_t set_id;
    struct bf_set *set;
    int16_t offset;

    bf_assert(program && matcher);

    set_id = *(uint32_t *)matcher->payload;
    set = bf_list_get_at(&program->runtime.chain->sets, set_id);
    if (!set)
        return bf_err_r(-ENOENT, "set #%d not found", set_id);

    switch (set->type) {
    case BF_SET_IP4_SUBNET:
        offset = matcher->type == BF_MATCHER_IP4_SNET ?
                     offsetof(struct iphdr, saddr) :
                     offsetof(struct iphdr, daddr);
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, 32));
        EMIT(program,
             BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, BF_PROG_SCR_OFF(0)));
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offset));
        EMIT(program,
             BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(4)));
        break;
    default:
        return bf_err_r(-EINVAL, "unsupported set type: %s",
                        bf_set_type_to_str(set->type));
    }

    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1, set_id);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // Jump to the next rule if map_lookup_elem returned 0
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

    return 0;
}

int bf_matcher_generate_ip4(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));

    switch (matcher->type) {
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_DADDR:
        r = _bf_matcher_generate_ip4_addr(program, matcher);
        break;
    case BF_MATCHER_IP4_PROTO:
        r = _bf_matcher_generate_ip4_proto(program, matcher);
        break;
    case BF_MATCHER_IP4_SNET:
    case BF_MATCHER_IP4_DNET:
        r = _bf_matcher_generate_ip4_net(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    if (r)
        return r;

    return 0;
}
