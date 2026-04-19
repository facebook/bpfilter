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

#include <bpfilter/chain.h>
#include <bpfilter/flavor.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/runtime.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "cgen/matcher/cmp.h"
#include "cgen/matcher/meta.h"
#include "cgen/matcher/set.h"
#include "cgen/program.h"
#include "cgen/stub.h"
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

static ssize_t _bf_cgroup_sock_addr_ctx_offset(enum bf_matcher_type type)
{
    switch (type) {
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_SNET:
        return offsetof(struct bpf_sock_addr, msg_src_ip4);
    case BF_MATCHER_IP4_DADDR:
    case BF_MATCHER_IP4_DNET:
        return offsetof(struct bpf_sock_addr, user_ip4);
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_SNET:
        return offsetof(struct bpf_sock_addr, msg_src_ip6);
    case BF_MATCHER_IP6_DADDR:
    case BF_MATCHER_IP6_DNET:
        return offsetof(struct bpf_sock_addr, user_ip6);
    case BF_MATCHER_IP4_PROTO:
        return offsetof(struct bpf_sock_addr, protocol);
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_UDP_DPORT:
        return offsetof(struct bpf_sock_addr, user_port);
    default:
        return -ENOTSUP;
    }
}

static int _bf_cgroup_sock_addr_generate_set(struct bf_program *program,
                                             const struct bf_matcher *matcher)
{
    const struct bf_set *set;
    size_t offset = 0;
    int r;

    assert(program);
    assert(matcher);

    set = bf_chain_get_set_for_matcher(program->runtime.chain, matcher);
    if (!set) {
        return bf_err_r(-ENOENT, "set #%u not found in %s",
                        *(uint32_t *)bf_matcher_payload(matcher),
                        program->runtime.chain->name);
    }

    if (set->use_trie) {
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(set->key[0]);
        ssize_t ctx_off = _bf_cgroup_sock_addr_ctx_offset(set->key[0]);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for set component '%s'",
                            bf_matcher_type_to_str(set->key[0]));
        }

        if (ctx_off < 0) {
            return bf_err_r(
                (int)ctx_off,
                "set component '%s' not supported for cgroup_sock_addr",
                bf_matcher_type_to_str(set->key[0]));
        }

        return bf_set_generate_trie_lookup(program, matcher, (size_t)ctx_off,
                                           meta->hdr_payload_size);
    }

    for (size_t i = 0; i < set->n_comps; ++i) {
        enum bf_matcher_type type = set->key[i];
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);
        ssize_t ctx_off = _bf_cgroup_sock_addr_ctx_offset(type);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for set component '%s'",
                            bf_matcher_type_to_str(type));
        }

        if (ctx_off < 0) {
            return bf_err_r(
                (int)ctx_off,
                "set component '%s' not supported for cgroup_sock_addr",
                bf_matcher_type_to_str(type));
        }

        /* The BPF verifier enforces specific ctx access widths on
         * `bpf_sock_addr` fields. `bf_stub_load()` reads
         * `meta->hdr_payload_size` bytes from ctx:
         *   - Ports (`hdr_payload_size == 2`): `user_port` is a 4-byte
         *     `__u32`, but the 2-byte narrow read is accepted and rewritten
         *     to the NBO port value.
         *   - Protocol (`hdr_payload_size == 1`): only 4-byte reads are
         *     allowed, so a 1-byte `bf_stub_load()` would be rejected. Reuse
         *     `BPF_REG_8`, which the prologue loaded with a 4-byte read. */
        if (type == BF_MATCHER_IP4_PROTO) {
            EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_8,
                                      BF_PROG_SCR_OFF(offset)));
        } else {
            r = bf_stub_load(program, (size_t)ctx_off, meta->hdr_payload_size,
                             BF_PROG_SCR_OFF(offset));
            if (r)
                return r;
        }

        offset += meta->hdr_payload_size;
    }

    return bf_set_generate_map_lookup(program, matcher, BF_PROG_SCR_OFF(0));
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
    case BF_MATCHER_SET:
        return _bf_cgroup_sock_addr_generate_set(program, matcher);
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
    (void)program;
    (void)rule;

    return bf_err_r(-ENOTSUP,
                    "logging is not yet supported for cgroup_sock_addr");
}

const struct bf_flavor_ops bf_flavor_ops_cgroup_sock_addr = {
    .gen_inline_prologue = _bf_cgroup_sock_addr_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_sock_addr_gen_inline_epilogue,
    .get_verdict = _bf_cgroup_sock_addr_get_verdict,
    .gen_inline_matcher = _bf_cgroup_sock_addr_gen_inline_matcher,
    .gen_inline_log = _bf_cgroup_sock_addr_gen_inline_log,
};
