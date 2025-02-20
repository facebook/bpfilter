/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/nf.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "bpfilter/cgen/jmp.h"
#include "bpfilter/cgen/prog/link.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/stub.h"
#include "bpfilter/cgen/swich.h"
#include "core/btf.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/verdict.h"

#include "external/filter.h"

#define BF_NF_PRIO_EVEN 2
#define BF_NF_PRIO_ODD 1

static int _bf_nf_gen_inline_prologue(struct bf_program *program);
static int _bf_nf_gen_inline_epilogue(struct bf_program *program);
static int _bf_nf_get_verdict(enum bf_verdict verdict);
static int _bf_nf_attach_prog(
    struct bf_program *new_prog, struct bf_program *old_prog,
    int (*get_new_link_cb)(struct bf_program *prog, struct bf_link *old_link,
                           struct bf_link **new_link));
static int _bf_nf_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_nf = {
    .gen_inline_prologue = _bf_nf_gen_inline_prologue,
    .gen_inline_epilogue = _bf_nf_gen_inline_epilogue,
    .get_verdict = _bf_nf_get_verdict,
    .attach_prog = _bf_nf_attach_prog,
    .detach_prog = _bf_nf_detach_prog,
};

// Forward definition to avoid headers clusterfuck.
uint16_t htons(uint16_t hostshort);

static inline bool _bf_nf_hook_is_ingress(enum bf_hook hook)
{
    return hook == BF_HOOK_NF_PRE_ROUTING || hook == BF_HOOK_NF_LOCAL_IN ||
           hook == BF_HOOK_NF_FORWARD;
}

static int _bf_nf_gen_inline_prologue(struct bf_program *program)
{
    int r;
    int offset;

    bf_assert(program);

    // Copy the ifindex from to bpf_nf_ctx.state.{in,out}.ifindex the runtime context
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "state")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, offset));
    if (_bf_nf_hook_is_ingress(program->hook)) {
        if ((offset = bf_btf_get_field_off("nf_hook_state", "in")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, offset));
    } else {
        if ((offset = bf_btf_get_field_off("nf_hook_state", "out")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, offset));
    }

    if ((offset = bf_btf_get_field_off("net_device", "ifindex")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_3, offset));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, BF_PROG_CTX_OFF(ifindex)));

    /* BPF_PROG_TYPE_CGROUP_SKB doesn't provide access the the Ethernet header,
     * so we can't parse it and discover the L3 protocol ID.
     * Instead, we use the __sk_buff.family value and convert it to the
     * corresponding ethertype. */
    if ((offset = bf_btf_get_field_off("nf_hook_state", "pf")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_2, offset));

    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_3);

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

    // Calculate the packet size (+ETH_HLEN) and store it into the runtime context
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "skb")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, offset));
    if ((offset = bf_btf_get_field_off("sk_buff", "len")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, ETH_HLEN));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(pkt_size)));

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

static int _bf_nf_gen_inline_epilogue(struct bf_program *program)
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
static int _bf_nf_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_TERMINAL_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_TERMINAL_VERDICT_MAX);

    return verdicts[verdict];
}

static int _bf_nf_attach_prog(struct bf_program *new_prog,
                              struct bf_program *old_prog,
                              int (*get_new_link_cb)(struct bf_program *prog,
                                                     struct bf_link *old_link,
                                                     struct bf_link **new_link))
{
    int r;

    bf_assert(new_prog && get_new_link_cb);

    if (old_prog && !bf_list_is_empty(&old_prog->links)) {
        /* BPF Netfilter programs can't be attached to NFPROTO_INET to filter
         * on both IPv4 and IPv6 at the same time. As a workaround, we attach
         * them to **both** NFPROTO_IPV4 and NFPROTO_IPV6. */
        bf_list_foreach (&old_prog->links, old_link_node) {
            struct bf_link *link;
            struct bpf_link_info info = {};
            struct bf_link *old_link = bf_list_node_get_data(old_link_node);

            r = bf_link_get_info(old_link, &info);
            if (r)
                return bf_err_r(r, "failed to get old Netfilter link info");

            r = get_new_link_cb(new_prog, NULL, &link);
            if (r)
                return r;

            /* BPF Netfilter programs can't be updated, so we need to create a
             * new link every time we want to attach a new program at the same
             * location. However, we can't create a new link with the same
             * priority. Hence, we use 100 and 101 successively. */
            r = bf_link_attach_nf(
                link, new_prog->runtime.prog_fd, info.netfilter.pf,
                info.netfilter.priority == BF_NF_PRIO_EVEN ? BF_NF_PRIO_ODD :
                                                             BF_NF_PRIO_EVEN);
            if (r)
                return bf_err_r(r, "failed to attach Netfilter program");
        }
    } else {
        struct bf_link *link;

        r = get_new_link_cb(new_prog, NULL, &link);
        if (r)
            return r;

        r = bf_link_attach_nf(link, new_prog->runtime.prog_fd, NFPROTO_IPV4,
                              BF_NF_PRIO_EVEN);
        if (r)
            return bf_err_r(r, "failed to attach Netfilter IPv4 program");

        r = get_new_link_cb(new_prog, NULL, &link);
        if (r)
            return r;

        r = bf_link_attach_nf(link, new_prog->runtime.prog_fd, NFPROTO_IPV6,
                              BF_NF_PRIO_EVEN);
        if (r)
            return bf_err_r(r, "failed to attach Netfilter IPv6 program");
    }

    return 0;
}

/**
 * Unload the Netfilter BPF bytecode image.
 *
 * @param program Codegen containing the image to unload. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_nf_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_link_detach(
        bf_list_node_get_data(bf_list_get_head(&program->links)));
}
