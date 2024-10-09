/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/cgroup.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "bpfilter/cgen/stub.h"
#include "bpfilter/cgen/swich.h"
#include "core/bpf.h"
#include "core/btf.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/verdict.h"

#include "external/filter.h"

static int _bf_cgroup_gen_inline_prologue(struct bf_program *program);
static int _bf_cgroup_gen_inline_epilogue(struct bf_program *program);
static int _bf_cgroup_get_verdict(enum bf_verdict verdict);
static int _bf_cgroup_attach_prog(struct bf_program *new_prog,
                                  struct bf_program *old_prog);
static int _bf_cgroup_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_cgroup = {
    .gen_inline_prologue = _bf_cgroup_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_gen_inline_epilogue,
    .get_verdict = _bf_cgroup_get_verdict,
    .attach_prog = _bf_cgroup_attach_prog,
    .detach_prog = _bf_cgroup_detach_prog,
};

// Forward definition to avoid headers clusterfuck.
uint16_t htons(uint16_t hostshort);

static int _bf_cgroup_gen_inline_prologue(struct bf_program *program)
{
    int offset;
    int r;

    bf_assert(program);

    // Copy __sk_buff.family to l3_proto
    if ((offset = bf_btf_get_field_off("__sk_buff", "family")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1, offset));
    EMIT(program,
         BPF_STX_MEM(BPF_H, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(l3_proto)));

    // Copy __sk_buff.data into BF_REG_2
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1,
                              offsetof(struct __sk_buff, data)));

    // Copy __sk_buff.data_end into BF_REG_3
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_3, BF_REG_1,
                              offsetof(struct __sk_buff, data_end)));

    // Calculate packet size
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BF_REG_3, BF_REG_2));

    // Add size of Ethernet header to BF_REG_3.
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_REG_3, ETH_HLEN));

    // Copy packet size into context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

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
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1, r));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    r = bf_stub_make_ctx_skb_dynptr(program, BF_REG_1);
    if (r)
        return r;

    /* BPF_PROG_TYPE_CGROUP_SKB doesn't provide access the the Ethernet header,
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
        EMIT_SWICH_OPTION(
            &swich, AF_INET6, BPF_MOV64_IMM(BF_REG_1, htons(ETH_P_IPV6)),
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

static int _bf_cgroup_gen_inline_epilogue(struct bf_program *program)
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
static int _bf_cgroup_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = 1,
        [BF_VERDICT_DROP] = 0,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_VERDICT_MAX);

    return verdicts[verdict];
}

static int _bf_cgroup_attach_prog(struct bf_program *new_prog,
                                  struct bf_program *old_prog)
{
    _cleanup_close_ int prog_fd = -1;
    _cleanup_close_ int link_fd = -1;
    _cleanup_close_ int cgroup_fd = -1;
    const char *name =
        new_prog->runtime.chain->hook_opts.name ?: new_prog->prog_name;
    const char *cgroup_path;
    int r;

    bf_assert(new_prog);

    r = bf_bpf_prog_load(name, bf_hook_to_bpf_prog_type(new_prog->hook),
                         new_prog->img, new_prog->img_size,
                         bf_hook_to_attach_type(new_prog->hook), &prog_fd);
    if (r)
        return bf_err_r(r, "failed to load new bf_program");

    if (old_prog) {
        r = bf_bpf_link_update(old_prog->runtime.prog_fd, prog_fd);
        if (r) {
            return bf_err_r(
                r, "failed to updated existing link for cgroup bf_program");
        }

        new_prog->runtime.prog_fd = TAKE_FD(old_prog->runtime.prog_fd);
    } else {
        cgroup_path = new_prog->runtime.chain->hook_opts.cgroup;
        cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
        if (cgroup_fd < 0)
            return bf_err_r(errno, "failed to open cgroup '%s'", cgroup_path);

        r = bf_bpf_cgroup_link_create(prog_fd, cgroup_fd,
                                      bf_hook_to_attach_type(new_prog->hook),
                                      &link_fd);
        if (r) {
            return bf_err_r(r,
                            "failed to create new link for cgroup bf_program");
        }

        new_prog->runtime.prog_fd = TAKE_FD(link_fd);
    }

    return 0;
}

/**
 * Detach the TC BPF program.
 *
 * @param program Attached TC BPF program. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_cgroup_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_bpf_link_detach(program->runtime.prog_fd);
}
