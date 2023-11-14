/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stddef.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/flavor.h"
#include "core/logger.h"
#include "core/verdict.h"
#include "generator/program.h"
#include "generator/reg.h"
#include "generator/stub.h"
#include "shared/helper.h"

#include "external/filter.h"

static int _xdp_gen_inline_prologue(struct bf_program *program);
static int _xdp_gen_inline_epilogue(struct bf_program *program);
static int _xdp_get_verdict(enum bf_verdict verdict);
static int _xdp_attach_prog_pre_unload(struct bf_program *program, int *prog_fd,
                                       union bf_flavor_attach_attr *attr);
static int _xdp_attach_prog_post_unload(struct bf_program *program,
                                        int *prog_fd,
                                        union bf_flavor_attach_attr *attr);
static int _xdp_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_xdp = {
    .gen_inline_prologue = _xdp_gen_inline_prologue,
    .gen_inline_epilogue = _xdp_gen_inline_epilogue,
    .get_verdict = _xdp_get_verdict,
    .attach_prog_pre_unload = _xdp_attach_prog_pre_unload,
    .attach_prog_post_unload = _xdp_attach_prog_post_unload,
    .detach_prog = _xdp_detach_prog,
};

/**
 * @brief Generate XDP program prologue.
 *
 * @warning @ref bf_stub_get_l2_eth_hdr will check for L3 protocol. If L3 is
 *  not IPv4, the program will be terminated.
 *
 * @param program Program to generate the prologue for. Must not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _xdp_gen_inline_prologue(struct bf_program *program)
{
    int r;

    bf_assert(program);

    r = bf_stub_make_ctx_xdp_dynptr(program, BF_REG_1);
    if (r)
        return r;

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

    r = bf_stub_get_l2_eth_hdr(program);
    if (r)
        return r;

    r = bf_stub_get_l3_ipv4_hdr(program);
    if (r)
        return r;

    r = bf_stub_get_l4_hdr(program);
    if (r)
        return r;

    return 0;
}

static int _xdp_gen_inline_epilogue(struct bf_program *program)
{
    UNUSED(program);

    return 0;
}

static int _xdp_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = XDP_PASS,
        [BF_VERDICT_DROP] = XDP_DROP,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_VERDICT_MAX);

    return verdicts[verdict];
}

static int _xdp_attach_prog_pre_unload(struct bf_program *program, int *prog_fd,
                                       union bf_flavor_attach_attr *attr)
{
    UNUSED(program);
    UNUSED(prog_fd);
    UNUSED(attr);

    return 0;
}

/**
 * @brief Post unload attach callback.
 *
 * See @ref bf_flavor_ops::attach_prog_post_unload for more details.
 *
 * @warning At this point, the previous XDP program has been detached already.
 *  Meaning that no packet will be filtering until the function completes.
 *
 * @param program Program to unload. Must not be NULL.
 * @param prog_fd File descriptor of the program to unload.
 * @param attr Flavor-specific attributes. Unused for XDP.
 * @return 0 on success, or negative errno value on failure.
 */
static int _xdp_attach_prog_post_unload(struct bf_program *program,
                                        int *prog_fd,
                                        union bf_flavor_attach_attr *attr)
{
    UNUSED(attr);

    int fd;
    int r;

    bf_assert(program);
    bf_assert(prog_fd);

    r = bf_bpf_xdp_link_create(*prog_fd, program->ifindex, &fd,
                               BF_XDP_MODE_SKB);
    if (r)
        return bf_err_code(r, "Failed to attach XDP program to interface");

    close(*prog_fd);
    *prog_fd = fd;

    return 0;
}

static int _xdp_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_bpf_link_detach(program->runtime.prog_fd);
}
