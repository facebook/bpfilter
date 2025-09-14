/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgroup.h"

#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <bpfilter/btf.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/verdict.h>

#include "cgen/cgen.h"
#include "cgen/program.h"
#include "cgen/stub.h"
#include "cgen/swich.h"
#include "filter.h"
#include "linux/bpf.h"

// Forward definition to avoid headers clusterfuck.
uint16_t htons(uint16_t hostshort);

static int _bf_cgroup_gen_inline_prologue(struct bf_program *program)
{
    int offset;
    int r;

    bf_assert(program);

    // Copy the packet size (+ETH_HLEN) into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct __sk_buff, len)));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, ETH_HLEN));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    /** The @c __sk_buff structure contains two fields related to the interface
     * index: @c ingress_ifindex and @c ifindex . @c ingress_ifindex is the
     * interface index the packet has been received on. However, we use
     * @c ifindex which is the interface index the packet is processed by: if
     * a packet is redirected locally from interface #1 to interface #2, then
     * @c ingress_ifindex will contain @c 1 but @c ifindex will contains @c 2 .
     * For egress, only @c ifindex is used.
     */
    if ((r = bf_btf_get_field_off("__sk_buff", "ifindex")) < 0)
        return r;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, r));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    /* BPF_PROG_TYPE_CGROUP_SKB doesn't provide access the the Ethernet header,
     * so we can't parse it and discover the L3 protocol ID.
     * Instead, we use the __sk_buff.family value and convert it to the
     * corresponding ethertype. */
    if ((offset = bf_btf_get_field_off("__sk_buff", "family")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset));

    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_2);

        EMIT_SWICH_OPTION(&swich, AF_INET,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IP)));
        EMIT_SWICH_OPTION(&swich, AF_INET6,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IPV6)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset), 0));

    r = bf_stub_make_ctx_skb_dynptr(program, BPF_REG_1);
    if (r)
        return r;

    r = bf_stub_parse_l3_hdr(program);
    if (r)
        return r;

    r = bf_stub_parse_l4_hdr(program);
    if (r)
        return r;

    return 0;
}

static int _bf_cgroup_gen_inline_epilogue(struct bf_program *program)
{
    UNUSED(program);

    return 0;
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @return TC return code corresponding to the verdict, as an integer.
 */
static int _bf_cgroup_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_TERMINAL_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = 1,
        [BF_VERDICT_DROP] = 0,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_TERMINAL_VERDICT_MAX);

    return verdicts[verdict];
}

const struct bf_flavor_ops bf_flavor_ops_cgroup = {
    .gen_inline_prologue = _bf_cgroup_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_gen_inline_epilogue,
    .get_verdict = _bf_cgroup_get_verdict,
};
