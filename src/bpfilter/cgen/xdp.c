/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/verdict.h>

#include "cgen/program.h"
#include "cgen/stub.h"
#include "filter.h"

/**
 * Generate XDP program prologue.
 *
 * @warning @ref bf_stub_parse_l2_ethhdr will check for L3 protocol. If L3 is
 * not IPv4, the program will be terminated.
 *
 * @param program Program to generate the prologue for. Must not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_xdp_gen_inline_prologue(struct bf_program *program)
{
    int r;

    assert(program);

    // Calculate the packet size and store it into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct xdp_md, data_end)));
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_2));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    // Store the ingress ifindex into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, ingress_ifindex)));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    r = bf_stub_make_ctx_xdp_dynptr(program, BPF_REG_1);
    if (r)
        return r;

    r = bf_stub_parse_l2_ethhdr(program);
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

static int _bf_xdp_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

static int _bf_xdp_get_verdict(enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        return XDP_PASS;
    case BF_VERDICT_DROP:
        return XDP_DROP;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_xdp = {
    .gen_inline_prologue = _bf_xdp_gen_inline_prologue,
    .gen_inline_epilogue = _bf_xdp_gen_inline_epilogue,
    .get_verdict = _bf_xdp_get_verdict,
};
