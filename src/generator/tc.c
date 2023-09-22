/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "tc.h"

#include <linux/pkt_cls.h>

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>

#include "core/context.h"
#include "core/logger.h"
#include "generator/codegen.h"
#include "generator/program.h"
#include "generator/reg.h"
#include "generator/stub.h"
#include "shared/front.h"
#include "shared/helper.h"

#include "external/filter.h"

static int _tc_gen_inline_prologue(struct bf_program *program);
static int _tc_gen_inline_epilogue(struct bf_program *program);
static int _tc_convert_return_code(enum bf_target_standard_verdict verdict);
static int _tc_attach_prog_pre_unload(struct bf_program *program, int *prog_fd,
                                      union bf_flavor_attach_attr *attr);
static int _tc_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_tc = {
    .gen_inline_prologue = _tc_gen_inline_prologue,
    .gen_inline_epilogue = _tc_gen_inline_epilogue,
    .convert_return_code = _tc_convert_return_code,
    .attach_prog_pre_unload = _tc_attach_prog_pre_unload,
    .detach_prog = _tc_detach_prog,
};

static int _tc_gen_inline_prologue(struct bf_program *program)
{
    int r;

    bf_assert(program);

    r = bf_stub_make_ctx_skb_dynptr(program, BF_REG_1);
    if (r)
        return r;

    // Copy __sk_buff pointer into BF_REG_1
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(arg)));

    // Copy __sk_buff.data into BF_REG_2
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1,
                              offsetof(struct __sk_buff, data)));

    // Copy __sk_buff.data_end into BF_REG_3
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_3, BF_REG_1,
                              offsetof(struct __sk_buff, data_end)));

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

static int _tc_gen_inline_epilogue(struct bf_program *program)
{
    UNUSED(program);

    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

/**
 * @brief Convert a standard verdict into a return value.
 * @param verdict Verdict to convert. Must be valid.
 * @return TC return code corresponding to the verdict, as an integer.
 */
static int _tc_convert_return_code(enum bf_target_standard_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_TARGET_STANDARD_MAX);

    static const int verdicts[] = {
        [BF_TARGET_STANDARD_ACCEPT] = TC_ACT_OK,
        [BF_TARGET_STANDARD_DROP] = TC_ACT_SHOT,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_TARGET_STANDARD_MAX);

    return verdicts[verdict];
}

/**
 * @brief Attach the loaded TC program to the proper hook.
 *
 * @todo How should priority be handled?
 * @todo This function, as well as many others, is using libbpf. Not all
 *  functions uses libbpf to communicate with the kernel. This should be
 *  unified.
 *
 * @param program Program to attach to the TC hook. Can't be NULL, image
 *  must have been previously generated.
 * @param fd File descriptor of the loaded BPF program. Can't be negative.
 * @param attr Attribute used for 2-step attach workflow.
 * @return 0 on success, negative error code on failure.
 */
static int _tc_attach_prog_pre_unload(struct bf_program *program, int *prog_fd,
                                      union bf_flavor_attach_attr *attr)
{
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    int r;

    UNUSED(attr);

    bf_assert(program);
    bf_assert(*prog_fd >= 0);

    hook.sz = sizeof(hook);
    hook.ifindex = (int)program->ifindex;
    hook.attach_point = bf_hook_to_tc_hook(program->hook);

    r = bpf_tc_hook_create(&hook);
    if (r && r != -EEXIST)
        return bf_err_code(r, "failed to create TC hook");

    opts.sz = sizeof(opts);
    opts.handle = bf_tc_program_handle(program) + 1;
    opts.priority = 1;
    opts.prog_fd = *prog_fd;

    r = bpf_tc_attach(&hook, &opts);
    if (r)
        return bf_err_code(r, "failed to attach BPF program to TC hook");

    return 0;
}

/**
 * @brief Detach the TC BPF program.
 *
 * @param program Attached TC BPF program. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _tc_detach_prog(struct bf_program *program)
{
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    int r;

    bf_assert(program);

    hook.sz = sizeof(hook);
    hook.ifindex = (int)program->ifindex;
    hook.attach_point = bf_hook_to_tc_hook(program->hook);

    opts.sz = sizeof(opts);
    opts.handle = bf_tc_program_handle(program) + 1;
    opts.priority = 1;

    r = bpf_tc_detach(&hook, &opts);
    if (r) {
        return bf_err_code(r, "failed to detach %s program from %s",
                           bf_front_to_str(program->front),
                           bf_hook_to_str(program->hook));
    }

    return 0;
}

enum bpf_tc_attach_point bf_hook_to_tc_hook(enum bf_hook hook)
{
    bf_assert(hook == BF_HOOK_TC_INGRESS || hook == BF_HOOK_TC_EGRESS);

    enum bpf_tc_attach_point hooks[] = {
        [BF_HOOK_TC_INGRESS] = BPF_TC_INGRESS,
        [BF_HOOK_TC_EGRESS] = BPF_TC_EGRESS,
    };

    return hooks[hook];
}
