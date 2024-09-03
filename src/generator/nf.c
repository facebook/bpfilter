/* SPDX-License-Identifier: GPL-2.0-only */
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
#include "core/btf.h"
#include "core/logger.h"
#include "core/verdict.h"
#include "generator/jmp.h"
#include "generator/program.h"
#include "generator/reg.h"
#include "generator/stub.h"
#include "generator/swich.h"
#include "shared/helper.h"

static int _nf_gen_inline_prologue(struct bf_program *program);
static int _nf_gen_inline_epilogue(struct bf_program *program);
static int _nf_get_verdict(enum bf_verdict verdict);
static int _nf_attach_prog(struct bf_program *new_prog,
                           struct bf_program *old_prog);
static int _nf_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_nf = {
    .gen_inline_prologue = _nf_gen_inline_prologue,
    .gen_inline_epilogue = _nf_gen_inline_epilogue,
    .get_verdict = _nf_get_verdict,
    .attach_prog = _nf_attach_prog,
    .detach_prog = _nf_detach_prog,
};

// Forward definition to avoid headers clusterfuck.
uint16_t htons(uint16_t hostshort);

static int _nf_gen_inline_prologue(struct bf_program *program)
{
    int r;
    int offset;

    bf_assert(program);

    // Copy bpf_nf_ctx.state in BF_REG_1.
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "state")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_1, offset));

    // Copy bpf_nf_ctx.state.pf to the runtime context
    if ((offset = bf_btf_get_field_off("nf_hook_state", "pf")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_2, BF_REG_1, offset));
    EMIT(program,
         BPF_STX_MEM(BPF_H, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(l3_proto)));

    // Copy nf_hook_state.in in BF_REG_1.
    if ((offset = bf_btf_get_field_off("nf_hook_state", "in")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_1, offset));

    // Copy net_device.ifindex in BF_REG_1.
    if ((offset = bf_btf_get_field_off("net_device", "ifindex")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_1, BF_REG_1, offset));

    // If the packet is coming from the wrong interface, then quit.
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BF_REG_1, program->ifindex, 2));

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(arg)));

    // Copy address of sk_buff into BF_REG_1.
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "skb")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_1, offset));

    // Copy packet length into BF_REG_2.
    if ((offset = bf_btf_get_field_off("sk_buff", "len")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1, offset));

    // Add size of Ethernet header to BF_REG_2.
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_REG_2, ETH_HLEN));

    // Store packet length in context.
    EMIT(program, BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_REG_2,
                              offsetof(struct bf_program_context, pkt_size)));

    r = bf_stub_make_ctx_skb_dynptr(program, BF_REG_1);
    if (r)
        return r;

    /* BPF_PROG_TYPE_NETFILTER doesn't provide access the the Ethernet header,
     * so we can't parse it. Fill the runtime context's l3_proto and l3_offset
     * manually instead. */
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BF_REG_1);

        EMIT_SWICH_OPTION(
            &swich, AF_INET, BPF_MOV64_IMM(BF_REG_1, htons(ETH_P_IP)),
            BPF_STX_MEM(BPF_H, BF_REG_CTX, BF_REG_1, BF_PROG_CTX_OFF(l3_proto)),
            BPF_MOV64_IMM(BF_REG_1, 0),
            BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_1,
                        BF_PROG_CTX_OFF(l3_offset)));
        EMIT_SWICH_DEFAULT(
            &swich,
            BPF_MOV64_IMM(BF_REG_RET,
                          program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT)),
            BPF_EXIT_INSN());

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    r = bf_stub_parse_l3_hdr(program);
    if (r)
        return r;

    r = bf_stub_parse_l4_hdr(program);
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
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @return TC return code corresponding to the verdict, as an integer.
 */
static int _nf_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_VERDICT_MAX);

    return verdicts[verdict];
}

static int _nf_attach_prog(struct bf_program *new_prog,
                           struct bf_program *old_prog)
{
    _cleanup_close_ int prog_fd = -1;
    _cleanup_close_ int link_fd = -1;
    _cleanup_close_ int tmp_fd = -1;
    int r;

    r = bf_bpf_prog_load(new_prog->prog_name,
                         bf_hook_to_bpf_prog_type(new_prog->hook),
                         new_prog->img, new_prog->img_size,
                         bf_hook_to_attach_type(new_prog->hook), &prog_fd);
    if (r)
        return bf_err_code(r, "failed to load new bf_program");

    if (old_prog) {
        r = bf_bpf_nf_link_create(prog_fd, new_prog->hook, 1, &tmp_fd);
        if (r)
            return bf_err_code(r, "failed to create temporary link");

        closep(&old_prog->runtime.prog_fd);

        r = bf_bpf_nf_link_create(prog_fd, new_prog->hook, new_prog->ifindex,
                                  &link_fd);
        if (r)
            return bf_err_code(r, "failed to create final link");

        new_prog->runtime.prog_fd = TAKE_FD(link_fd);
    } else {
        r = bf_bpf_nf_link_create(prog_fd, new_prog->hook, new_prog->ifindex,
                                  &link_fd);
        if (r)
            return bf_err_code(
                r, "failed to create a new link for BPF_NETFILTER bf_program");

        new_prog->runtime.prog_fd = TAKE_FD(link_fd);
    }

    return 0;
}

/**
 * Unload the Netfilter BPF bytecode image.
 *
 * @param program Codegen containing the image to unload. Can't be NULL.
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
