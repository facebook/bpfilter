/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/tc.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/pkt_cls.h>

#include <stddef.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/prog/link.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/stub.h"
#include "core/btf.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/verdict.h"

#include "external/filter.h"

static int _bf_tc_gen_inline_prologue(struct bf_program *program);
static int _bf_tc_gen_inline_epilogue(struct bf_program *program);
static int _bf_tc_get_verdict(enum bf_verdict verdict);
static int _bf_tc_attach_prog(
    struct bf_program *new_prog, struct bf_program *old_prog,
    int (*get_new_link_cb)(struct bf_program *prog, struct bf_link *old_link,
                           struct bf_link **new_link));
static int _bf_tc_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_tc = {
    .gen_inline_prologue = _bf_tc_gen_inline_prologue,
    .gen_inline_epilogue = _bf_tc_gen_inline_epilogue,
    .get_verdict = _bf_tc_get_verdict,
    .attach_prog = _bf_tc_attach_prog,
    .detach_prog = _bf_tc_detach_prog,
};

static int _bf_tc_gen_inline_prologue(struct bf_program *program)
{
    int r;

    bf_assert(program);

    // Calculate the packet size and store it into the runtime context
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct __sk_buff, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct __sk_buff, data_end)));
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_2));
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

    r = bf_stub_make_ctx_skb_dynptr(program, BPF_REG_1);
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

static int _bf_tc_gen_inline_epilogue(struct bf_program *program)
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
static int _bf_tc_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_TERMINAL_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = TC_ACT_OK,
        [BF_VERDICT_DROP] = TC_ACT_SHOT,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_TERMINAL_VERDICT_MAX);

    return verdicts[verdict];
}

static int _bf_tc_attach_prog(struct bf_program *new_prog,
                              struct bf_program *old_prog,
                              int (*get_new_link_cb)(struct bf_program *prog,
                                                     struct bf_link *old_link,
                                                     struct bf_link **new_link))
{
    struct bf_link *new_link;
    struct bf_link *old_link;
    int new_fd;
    unsigned int ifindex;
    int r;

    bf_assert(new_prog && get_new_link_cb);

    old_link = old_prog ? bf_list_get_at(&old_prog->links, 0) : NULL;
    new_fd = new_prog->runtime.prog_fd;
    ifindex = new_prog->runtime.chain->hook_opts.ifindex;

    r = get_new_link_cb(new_prog, old_link, &new_link);
    if (r)
        return bf_err_r(r, "failed to create new TC link");

    if (old_link) {
        r = bf_link_update(new_link, new_fd);
        if (r) {
            return bf_err_r(r,
                            "failed to update existing link for TC bf_program");
        }
    } else {
        r = bf_link_attach_tc(new_link, new_fd, ifindex);
        if (r)
            return bf_err_r(r, "failed to attach TC program");
    }

    return 0;
}

/**
 * Detach the TC BPF program.
 *
 * @param program Attached TC BPF program. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_tc_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_link_detach(bf_list_get_at(&program->links, 0));
}
