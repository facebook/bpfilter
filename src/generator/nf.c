/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/nf.h"

#include <assert.h>
#include <errno.h>

#include "generator/program.h"
#include "shared/helper.h"

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
    assert(program);

    return -ENOTSUP;
}

static int _nf_gen_inline_epilogue(struct bf_program *program)
{
    UNUSED(program);

    EMIT(program, BPF_EXIT_INSN());

    return -ENOTSUP;
}

/**
 * @brief Convert a standard verdict into a return value.
 * @param verdict Verdict to convert. Must be valid.
 * @return TC return code corresponding to the verdict, as an integer.
 */
static int _nf_convert_return_code(enum bf_target_standard_verdict verdict)
{
    assert(0 <= verdict && verdict < _BF_TARGET_STANDARD_MAX);

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
    assert(program);
    assert(*prog_fd >= 0);
    assert(attr);

    return 0;
}

static int _nf_attach_prog_post_unload(struct bf_program *program, int *prog_fd,
                                       union bf_flavor_attach_attr *attr)
{
    assert(program);
    assert(*prog_fd >= 0);

    UNUSED(attr);

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

    return 0;
}

enum nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook)
{
    assert(hook >= BF_HOOK_IPT_PRE_ROUTING || hook <= BF_HOOK_IPT_POST_ROUTING);

    enum nf_inet_hooks hooks[] = {
        [BF_HOOK_IPT_PRE_ROUTING] = NF_INET_PRE_ROUTING,
        [BF_HOOK_IPT_LOCAL_IN] = NF_INET_LOCAL_IN,
        [BF_HOOK_IPT_FORWARD] = NF_INET_FORWARD,
        [BF_HOOK_IPT_LOCAL_OUT] = NF_INET_LOCAL_OUT,
        [BF_HOOK_IPT_POST_ROUTING] = NF_INET_POST_ROUTING,
    };

    return hooks[hook];
}
