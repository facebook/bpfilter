/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stddef.h>

#include "bpfilter/cgen/prog/link.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/stub.h"
#include "core/bpf.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/verdict.h"

#include "external/filter.h"

static int _bf_xdp_gen_inline_prologue(struct bf_program *program);
static int _bf_xdp_gen_inline_epilogue(struct bf_program *program);
static int _bf_xdp_get_verdict(enum bf_verdict verdict);
static int _bf_xdp_attach_prog(
    struct bf_program *new_prog, struct bf_program *old_prog,
    int (*get_new_link_cb)(struct bf_program *prog, struct bf_link *old_link,
                           struct bf_link **new_link));
static int _bf_xdp_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_xdp = {
    .gen_inline_prologue = _bf_xdp_gen_inline_prologue,
    .gen_inline_epilogue = _bf_xdp_gen_inline_epilogue,
    .get_verdict = _bf_xdp_get_verdict,
    .attach_prog = _bf_xdp_attach_prog,
    .detach_prog = _bf_xdp_detach_prog,
};

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

    bf_assert(program);

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
    UNUSED(program);

    return 0;
}

static int _bf_xdp_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_TERMINAL_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = XDP_PASS,
        [BF_VERDICT_DROP] = XDP_DROP,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_TERMINAL_VERDICT_MAX);

    return verdicts[verdict];
}

static int _bf_xdp_attach_prog(
    struct bf_program *new_prog, struct bf_program *old_prog,
    int (*get_new_link_cb)(struct bf_program *prog, struct bf_link *old_link,
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
        return bf_err_r(r, "failed to create new XDP link");

    if (old_link) {
        r = bf_link_update(new_link, new_fd);
        if (r) {
            return bf_err_r(
                r, "failed to update existing link for XDP bf_program");
        }
    } else {
        r = bf_link_attach_xdp(new_link, new_fd, ifindex, BF_XDP_MODE_SKB);
        if (r)
            return bf_err_r(r, "failed to attach XDP program");
    }

    return 0;
}

static int _bf_xdp_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_link_detach(bf_list_get_at(&program->links, 0));
}
