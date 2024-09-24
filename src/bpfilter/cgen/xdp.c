/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stddef.h>

#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "bpfilter/cgen/stub.h"
#include "core/bpf.h"
#include "core/btf.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/verdict.h"

#include "external/filter.h"

static int _bf_xdp_gen_inline_prologue(struct bf_program *program);
static int _bf_xdp_gen_inline_epilogue(struct bf_program *program);
static int _bf_xdp_get_verdict(enum bf_verdict verdict);
static int _bf_xdp_attach_prog(struct bf_program *new_prog,
                               struct bf_program *old_prog);
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

    // Copy xdp_md pointer into BF_REG_1
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(arg)));

    // Copy xdp_md.data into BF_REG_2
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1, offsetof(struct xdp_md, data)));

    // Copy xdp_md.data_end into BF_REG_3
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_3, BF_REG_1,
                              offsetof(struct xdp_md, data_end)));

    // Calculate packet size
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BF_REG_3, BF_REG_2));

    // Copy packet size into context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    // Copy the ingress ifindex into the runtime context
    if ((r = bf_btf_get_field_off("xdp_md", "ingress_ifindex")) < 0)
        return r;
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1, r));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    r = bf_stub_make_ctx_xdp_dynptr(program, BF_REG_1);
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
    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = XDP_PASS,
        [BF_VERDICT_DROP] = XDP_DROP,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_VERDICT_MAX);

    return verdicts[verdict];
}

static int _bf_xdp_attach_prog(struct bf_program *new_prog,
                               struct bf_program *old_prog)
{
    _cleanup_close_ int prog_fd = -1;
    _cleanup_close_ int link_fd = -1;
    int r;

    bf_assert(new_prog);

    r = bf_bpf_prog_load(new_prog->prog_name,
                         bf_hook_to_bpf_prog_type(new_prog->hook),
                         new_prog->img, new_prog->img_size,
                         bf_hook_to_attach_type(new_prog->hook), &prog_fd);
    if (r)
        return bf_err_r(r, "failed to load new bf_program");

    if (old_prog) {
        r = bf_bpf_xdp_link_update(old_prog->runtime.prog_fd, prog_fd);
        if (r) {
            return bf_err_r(
                r, "failed to update existing link for XDP bf_program");
        }

        new_prog->runtime.prog_fd = TAKE_FD(old_prog->runtime.prog_fd);
    } else {
        r = bf_bpf_xdp_link_create(prog_fd,
                                   new_prog->runtime.chain->hook_opts.ifindex,
                                   &link_fd, BF_XDP_MODE_SKB);
        if (r) {
            return bf_err_r(r, "failed to create new link for XDP bf_program");
        }

        new_prog->runtime.prog_fd = TAKE_FD(link_fd);
    }

    return 0;
}

static int _bf_xdp_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_bpf_link_detach(program->runtime.prog_fd);
}
