/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgroup_sock_addr.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

#include <bpfilter/flavor.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/verdict.h>

#include "cgen/program.h"
#include "cgen/swich.h"
#include "filter.h"

// Forward definition to avoid header conflicts.
uint16_t htons(uint16_t hostshort);

static int _bf_cgroup_sock_addr_gen_inline_prologue(struct bf_program *program)
{
    int r;

    assert(program);

    // The counters stub reads `pkt_size` unconditionally; zero it out.
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(pkt_size), 0));

    /* Convert `bpf_sock_addr.family` to L3 protocol ID in R7, using the same
     * `bf_swich` pattern as cgroup_skb. */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct bpf_sock_addr, family)));

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

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1,
                              offsetof(struct bpf_sock_addr, protocol)));

    return 0;
}

static int _bf_cgroup_sock_addr_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

static int
_bf_cgroup_sock_addr_gen_inline_matcher(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    (void)program;

    return bf_err_r(-ENOTSUP,
                    "matcher '%s' not yet supported for cgroup_sock_addr",
                    bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
}

/**
 * @brief Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @return Cgroup return code corresponding to the verdict, as an integer.
 */
static int _bf_cgroup_sock_addr_get_verdict(enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        return 1;
    case BF_VERDICT_DROP:
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_cgroup_sock_addr = {
    .gen_inline_prologue = _bf_cgroup_sock_addr_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_sock_addr_gen_inline_epilogue,
    .get_verdict = _bf_cgroup_sock_addr_get_verdict,
    .gen_inline_matcher = _bf_cgroup_sock_addr_gen_inline_matcher,
};
