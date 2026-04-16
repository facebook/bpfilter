/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgroup_sock_addr.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>

#include "cgen/matcher/cmp.h"
#include "cgen/matcher/meta.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "cgen/swich.h"
#include "filter.h"

// Forward definition to avoid header conflicts.
uint16_t htons(uint16_t hostshort);

static int _bf_cgroup_sock_addr_gen_inline_prologue(struct bf_program *program)
{
    int r;

    assert(program);

    /* `R6` = `bpf_sock_addr` context pointer. Unlike packet-based flavors where
     * `R6` changes per header, the socket context is fixed so we set it once. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));

    // The counters stub reads `pkt_size` unconditionally; zero it out.
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(pkt_size), 0));

    /* Convert `bpf_sock_addr.family` to L3 protocol ID in `R7`, using the same
     * `bf_swich` pattern as cgroup_skb. */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6,
                              offsetof(struct bpf_sock_addr, family)));

    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_2);

        EMIT_SWICH_OPTION(&swich, AF_INET,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IP)));
        EMIT_SWICH_OPTION(&swich, AF_INET6,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IPV6)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6,
                              offsetof(struct bpf_sock_addr, protocol)));

    return 0;
}

static int _bf_cgroup_sock_addr_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

/**
 * @brief Load a field from the `bpf_sock_addr` context into a register.
 *
 * `R6` must already point to the context. For 16-byte fields, the low
 * 8 bytes go into `reg` and the high 8 bytes into `reg + 1`.
 *
 * When the field offset is not 8-byte aligned, 8- and 16-byte loads fall
 * back to 4-byte reads packed via shift/or. This clobbers `reg + 1` for
 * 8-byte loads and `reg + 2` for 16-byte loads.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param offset Byte offset into `struct bpf_sock_addr`.
 * @param size Field size in bytes: 1, 2, 4, 8, or 16.
 * @param reg BPF register to load the value into.
 * @return 0 on success, negative errno on error.
 */
static int _bf_cgroup_sock_addr_load_field(struct bf_program *program,
                                           size_t offset, size_t size, int reg)
{
    assert(program);

    switch (size) {
    case 1:
        EMIT(program, BPF_LDX_MEM(BPF_B, reg, BPF_REG_6, offset));
        break;
    case 2:
        EMIT(program, BPF_LDX_MEM(BPF_H, reg, BPF_REG_6, offset));
        break;
    case 4:
        EMIT(program, BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, offset));
        break;
    case 8:
        if (offset % 8 == 0) {
            EMIT(program, BPF_LDX_MEM(BPF_DW, reg, BPF_REG_6, offset));
        } else {
            EMIT(program, BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, offset));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 1, BPF_REG_6, offset + 4));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, reg + 1, 32));
            EMIT(program, BPF_ALU64_REG(BPF_OR, reg, reg + 1));
        }
        break;
    case 16:
        if (offset % 8 == 0) {
            EMIT(program, BPF_LDX_MEM(BPF_DW, reg, BPF_REG_6, offset));
            EMIT(program, BPF_LDX_MEM(BPF_DW, reg + 1, BPF_REG_6, offset + 8));
        } else {
            EMIT(program, BPF_LDX_MEM(BPF_W, reg, BPF_REG_6, offset));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 2, BPF_REG_6, offset + 4));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, reg + 2, 32));
            EMIT(program, BPF_ALU64_REG(BPF_OR, reg, reg + 2));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 1, BPF_REG_6, offset + 8));
            EMIT(program, BPF_LDX_MEM(BPF_W, reg + 2, BPF_REG_6, offset + 12));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, reg + 2, 32));
            EMIT(program, BPF_ALU64_REG(BPF_OR, reg + 1, reg + 2));
        }
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

/**
 * @brief Store a register value at an offset from `BPF_REG_10`.
 *
 * Counterpart to `_bf_cgroup_sock_addr_load_field`. For 16-byte stores,
 * `reg` holds the low 8 bytes and `reg + 1` the high 8 bytes, matching
 * the layout produced by `_bf_cgroup_sock_addr_load_field`.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param offset Byte offset from `BPF_REG_10` (use `BF_PROG_CTX_OFF`).
 * @param size Field size in bytes: 1, 2, 4, 8, or 16.
 * @param reg BPF register holding the value to store.
 * @return 0 on success, negative errno on error.
 */
static int _bf_cgroup_sock_addr_store_field(struct bf_program *program,
                                            int offset, size_t size, int reg)
{
    assert(program);

    switch (size) {
    case 1:
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, reg, offset));
        break;
    case 2:
        EMIT(program, BPF_STX_MEM(BPF_H, BPF_REG_10, reg, offset));
        break;
    case 4:
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, reg, offset));
        break;
    case 8:
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, reg, offset));
        break;
    case 16:
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, reg, offset));
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, reg + 1, offset + 8));
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int _bf_cgroup_sock_addr_load_and_cmp(struct bf_program *program,
                                             const struct bf_matcher *matcher,
                                             size_t offset, size_t size)
{
    int r;

    assert(program);
    assert(matcher);

    r = _bf_cgroup_sock_addr_load_field(program, offset, size, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_value(program, bf_matcher_get_op(matcher),
                        bf_matcher_payload(matcher), size, BPF_REG_1);
}

static int _bf_cgroup_sock_addr_generate_net(struct bf_program *program,
                                             const struct bf_matcher *matcher,
                                             size_t offset, size_t size)
{
    uint32_t prefixlen;
    const void *data;
    int r;

    assert(program);
    assert(matcher);

    prefixlen = *(const uint32_t *)bf_matcher_payload(matcher);
    data = (const uint8_t *)bf_matcher_payload(matcher) + sizeof(uint32_t);

    r = _bf_cgroup_sock_addr_load_field(program, offset, size, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_masked_value(program, bf_matcher_get_op(matcher), data,
                               prefixlen, size, BPF_REG_1);
}

/* `user_port` is a __u32 in network byte order with the upper 16 bits
 * guaranteed zero by the kernel ABI. Loaded as `BPF_W` so EQ/NE compare
 * the full 32-bit register (safe because upper bits are zero). For range
 * comparisons, `BSWAP` converts to host order (and zeroes the upper bits). */
static int _bf_cgroup_sock_addr_generate_port(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    int r;

    assert(program);
    assert(matcher);

    r = _bf_cgroup_sock_addr_load_field(
        program, offsetof(struct bpf_sock_addr, user_port), 4, BPF_REG_1);
    if (r)
        return r;

    if (bf_matcher_get_op(matcher) == BF_MATCHER_RANGE) {
        uint16_t *ports = (uint16_t *)bf_matcher_payload(matcher);
        EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
        return bf_cmp_range(program, ports[0], ports[1], BPF_REG_1);
    }

    return bf_cmp_value(program, bf_matcher_get_op(matcher),
                        bf_matcher_payload(matcher), 2, BPF_REG_1);
}

static int
_bf_cgroup_sock_addr_gen_inline_matcher(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_L3_PROTO:
    case BF_MATCHER_META_L4_PROTO:
    case BF_MATCHER_META_PROBABILITY:
        return bf_matcher_generate_meta(program, matcher);
    case BF_MATCHER_IP4_SADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip4), 4);
    case BF_MATCHER_IP4_SNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip4), 4);
    case BF_MATCHER_IP4_DADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip4), 4);
    case BF_MATCHER_IP4_DNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip4), 4);
    case BF_MATCHER_IP4_PROTO:
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_8));
        return bf_cmp_value(program, bf_matcher_get_op(matcher),
                            bf_matcher_payload(matcher), 1, BPF_REG_1);
    case BF_MATCHER_IP6_SADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip6), 16);
    case BF_MATCHER_IP6_SNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, msg_src_ip6), 16);
    case BF_MATCHER_IP6_DADDR:
        return _bf_cgroup_sock_addr_load_and_cmp(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip6), 16);
    case BF_MATCHER_IP6_DNET:
        return _bf_cgroup_sock_addr_generate_net(
            program, matcher, offsetof(struct bpf_sock_addr, user_ip6), 16);
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_UDP_DPORT:
        return _bf_cgroup_sock_addr_generate_port(program, matcher);
    default:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' not supported for cgroup_sock_addr",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    }
}

/**
 * @brief Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code Cgroup return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgroup_sock_addr_get_verdict(enum bf_verdict verdict,
                                            int *ret_code)
{
    assert(ret_code);

    switch (verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_NEXT:
        *ret_code = 1;
        return 0;
    case BF_VERDICT_DROP:
        *ret_code = 0;
        return 0;
    default:
        return -ENOTSUP;
    }
}

static int _bf_cgroup_sock_addr_gen_inline_log(struct bf_program *program,
                                               const struct bf_rule *rule)
{
    bool has_saddr = false;
    size_t addr_size = 0;
    size_t saddr_off = 0;
    size_t daddr_off = 0;
    int r;

    assert(program);
    assert(rule);

    // Zero the saddr staging area: connect hooks have no source address,
    // and IPv4 hooks only write 4 of the 16 bytes.
    EMIT(program,
         BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(sock_addr.saddr), 0));
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             BF_PROG_CTX_OFF(sock_addr.saddr) + 8, 0));

    switch (program->runtime.chain->hook) {
    case BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4:
        has_saddr = true;
        saddr_off = offsetof(struct bpf_sock_addr, msg_src_ip4);
        __attribute__((fallthrough));
    case BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4:
        addr_size = 4;
        daddr_off = offsetof(struct bpf_sock_addr, user_ip4);
        break;
    case BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6:
        has_saddr = true;
        saddr_off = offsetof(struct bpf_sock_addr, msg_src_ip6);
        __attribute__((fallthrough));
    case BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6:
        addr_size = 16;
        daddr_off = offsetof(struct bpf_sock_addr, user_ip6);
        break;
    default:
        return bf_err_r(-ENOTSUP, "unexpected hook: %s",
                        bf_hook_to_str(program->runtime.chain->hook));
    }

    if (has_saddr) {
        r = _bf_cgroup_sock_addr_load_field(program, saddr_off, addr_size,
                                            BPF_REG_1);
        if (r)
            return r;
        r = _bf_cgroup_sock_addr_store_field(
            program, BF_PROG_CTX_OFF(sock_addr.saddr), addr_size, BPF_REG_1);
        if (r)
            return r;
    }

    r = _bf_cgroup_sock_addr_load_field(program, daddr_off, addr_size,
                                        BPF_REG_1);
    if (r)
        return r;
    r = _bf_cgroup_sock_addr_store_field(
        program, BF_PROG_CTX_OFF(sock_addr.daddr), addr_size, BPF_REG_1);
    if (r)
        return r;

    /* Destination port: valid for all cgroup_sock_addr hooks.
     * user_port is __be32; BSWAP 16 converts to host order. */
    r = _bf_cgroup_sock_addr_load_field(
        program, offsetof(struct bpf_sock_addr, user_port), 4, BPF_REG_1);
    if (r)
        return r;
    EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
    r = _bf_cgroup_sock_addr_store_field(
        program, BF_PROG_CTX_OFF(sock_addr.dport), 2, BPF_REG_1);
    if (r)
        return r;

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, rule->index));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_3, rule->verdict));
    EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_7));
    EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 16));
    EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_8));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_SOCK_ADDR_LOG);

    return 0;
}

const struct bf_flavor_ops bf_flavor_ops_cgroup_sock_addr = {
    .gen_inline_prologue = _bf_cgroup_sock_addr_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_sock_addr_gen_inline_epilogue,
    .get_verdict = _bf_cgroup_sock_addr_get_verdict,
    .gen_inline_matcher = _bf_cgroup_sock_addr_gen_inline_matcher,
    .gen_inline_log = _bf_cgroup_sock_addr_gen_inline_log,
};
