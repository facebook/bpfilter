/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/nf.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <errno.h>
#include <stddef.h>

#include "core/bpf.h"
#include "core/logger.h"
#include "core/target.h"
#include "generator/program.h"
#include "generator/reg.h"
#include "generator/stub.h"
#include "shared/helper.h"

#include "external/filter.h"
#include "external/nf_bpf_link.h"

static int _nf_gen_inline_prologue(struct bf_program *program);
static int _nf_gen_inline_epilogue(struct bf_program *program);
static int _nf_convert_return_code(enum bf_target_standard_verdict verdict);
static int _nf_attach_prog_pre_unload(struct bf_program *program, int *prog_fd,
                                      union bf_flavor_attach_attr *attr);
static int _nf_attach_prog_post_unload(struct bf_program *program, int *prog_fd,
                                       union bf_flavor_attach_attr *attr);
static int _nf_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_nf = {
    .gen_inline_prologue = _nf_gen_inline_prologue,
    .gen_inline_epilogue = _nf_gen_inline_epilogue,
    .convert_return_code = _nf_convert_return_code,
    .attach_prog_pre_unload = _nf_attach_prog_pre_unload,
    .attach_prog_post_unload = _nf_attach_prog_post_unload,
    .detach_prog = _nf_detach_prog,
};

static int _nf_gen_inline_prologue(struct bf_program *program)
{
    int r;

    bf_assert(program);

    // Copy address of sk_buff into BF_REG_1.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_1,
                              offsetof(struct bpf_nf_ctx, state)));

    // Copy address of sk_buff into BF_REG_1.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_1,
                              offsetof(struct nf_hook_state, in)));

    // Copy address of sk_buff into BF_REG_1.
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_1, BF_REG_1,
                              offsetof(struct net_device, ifindex)));

    // If the packet is coming from the wrong interface, then quit.
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_1, program->ifindex, 2));
    EMIT(program,
         BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->convert_return_code(
                                       BF_TARGET_STANDARD_ACCEPT)));
    EMIT(program, BPF_EXIT_INSN());

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(arg)));

    // Copy address of sk_buff into BF_REG_1.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_1,
                              offsetof(struct bpf_nf_ctx, skb)));

    // Copy packet length into BF_REG_2.
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1, 112));

    // Add size of Ethernet header to BF_REG_2.
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_REG_2, ETH_HLEN));

    // Store packet length in context.
    EMIT(program, BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_REG_2,
                              offsetof(struct bf_program_context, pkt_size)));

    r = bf_stub_make_ctx_skb_dynptr(program, BF_REG_1);
    if (r)
        return r;

    // BPF_PROG_TYPE_NETFILTER's skb is stripped from the Ethernet header, so
    // we don't get it.

    r = bf_stub_get_l3_ipv4_hdr(program);
    if (r)
        return r;

    r = bf_stub_get_l4_hdr(program);
    if (r)
        return r;

    return 0;
}

static int _nf_gen_inline_epilogue(struct bf_program *program)
{
    UNUSED(program);

    return 0;
}

/**
 * @brief Convert a standard verdict into a return value.
 * @param verdict Verdict to convert. Must be valid.
 * @return TC return code corresponding to the verdict, as an integer.
 */
static int _nf_convert_return_code(enum bf_target_standard_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_TARGET_STANDARD_MAX);

    static const int verdicts[] = {
        [BF_TARGET_STANDARD_ACCEPT] = NF_ACCEPT,
        [BF_TARGET_STANDARD_DROP] = NF_DROP,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_TARGET_STANDARD_MAX);

    return verdicts[verdict];
}

static int _nf_attach_prog_pre_unload(struct bf_program *program, int *prog_fd,
                                      union bf_flavor_attach_attr *attr)
{
    int r;

    bf_assert(program);
    bf_assert(*prog_fd >= 0);
    bf_assert(attr);

    r = bf_bpf_nf_link_create(*prog_fd, program->hook, 1,
                              &attr->pre_unload_link_fd);
    if (r) {
        return bf_err_code(r,
                           "failed to create Netfilter link before unload: %s",
                           bf_strerror(errno));
    }

    return 0;
}

static int _nf_attach_prog_post_unload(struct bf_program *program, int *prog_fd,
                                       union bf_flavor_attach_attr *attr)
{
    _cleanup_close_ int post_unload_fd = -1;
    _cleanup_close_ int pre_unload_fd = attr->pre_unload_link_fd;
    int r;

    bf_assert(program);
    bf_assert(*prog_fd >= 0);

    r = bf_bpf_nf_link_create(*prog_fd, program->hook, program->ifindex,
                              &post_unload_fd);
    if (r) {
        return bf_err_code(r,
                           "failed to create Netfilter link before unload: %s",
                           bf_strerror(errno));
    }

    closep(prog_fd);
    *prog_fd = post_unload_fd;
    post_unload_fd = -1;

    return 0;
}

/**
 * @brief Unload the Netfilter BPF bytecode image.
 *
 * @param codegen Codegen containing the image to unload. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
static int _nf_detach_prog(struct bf_program *program)
{
    assert(program);

    return bf_bpf_link_detach(program->runtime.prog_fd);
}

enum nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook)
{
    bf_assert(hook >= BF_HOOK_IPT_PRE_ROUTING ||
              hook <= BF_HOOK_IPT_POST_ROUTING);

    enum nf_inet_hooks hooks[] = {
        [BF_HOOK_IPT_PRE_ROUTING] = NF_INET_PRE_ROUTING,
        [BF_HOOK_IPT_LOCAL_IN] = NF_INET_LOCAL_IN,
        [BF_HOOK_IPT_FORWARD] = NF_INET_FORWARD,
        [BF_HOOK_IPT_LOCAL_OUT] = NF_INET_LOCAL_OUT,
        [BF_HOOK_IPT_POST_ROUTING] = NF_INET_POST_ROUTING,
    };

    return hooks[hook];
}
