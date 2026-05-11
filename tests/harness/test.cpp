/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "test.hpp"

extern "C" {
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include <arpa/inet.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpfilter.h>
#include <bpfilter/flavor.h>
}

void bft_assert_prog_run(const char *chain_name, enum bf_hook hook,
                         const bft::Packet &pkt, int expected)
{
    _cleanup_close_ int fd = -1;
    int r;

    /* Mimic the kernel's struct nf_hook_state layout for BPF_PROG_TEST_RUN
     * context. Only hook and pf are read by the kernel; all pointer fields
     * must be zero. */
    struct nf_hook_state_ctx
    {
        uint8_t hook;
        uint8_t pf;
        void *in;
        void *out;
        void *sk;
        void *net;
        int (*okfn)(void *, void *, void *);
    };

    static_assert(sizeof(nf_hook_state_ctx) == 48);

    fd = bf_chain_prog_fd(bft_matcher_ctx, chain_name);
    assert_true(fd >= 0);

    if (bf_hook_to_flavor(hook) == BF_FLAVOR_NF) {
        struct nf_hook_state_ctx ctx = {};
        uint16_t ethertype;

        assert_true(pkt.len > ETH_HLEN);

        memcpy(&ethertype, pkt.data.data() + offsetof(struct ethhdr, h_proto),
               sizeof(ethertype));
        ethertype = ntohs(ethertype);

        ctx.hook = static_cast<uint8_t>(bf_hook_to_nf_hook(hook));
        ctx.pf = ethertype == 0x0800 ? NFPROTO_IPV4 : NFPROTO_IPV6;

        if (hook == BF_HOOK_NF_LOCAL_OUT) {
            r = bf_bpf_prog_run(fd, pkt.data.data() + ETH_HLEN,
                                pkt.len - ETH_HLEN, &ctx, sizeof(ctx));
        } else {
            r = bf_bpf_prog_run(fd, pkt.data.data(), pkt.len, &ctx,
                                sizeof(ctx));
        }
    } else {
        r = bf_bpf_prog_run(fd, pkt.data.data(), pkt.len, nullptr, 0);
    }

    assert_int_equal(expected, r);
}

namespace
{
// TCX_PASS/TCX_DROP/TCX_NEXT are enum values in linux/bpf.h, but may conflict
// with the C++ compilation depending on kernel headers version. Use literals.
constexpr int kTcxPass = 0;
constexpr int kTcxDrop = 2;
constexpr int kTcxNext = -1;

static int _bft_verdict(enum bf_hook hook, enum bf_verdict verdict)
{
    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
        return verdict == BF_VERDICT_ACCEPT ? XDP_PASS : XDP_DROP;
    case BF_FLAVOR_TC:
        return verdict == BF_VERDICT_ACCEPT ? kTcxPass : kTcxDrop;
    case BF_FLAVOR_NF:
        return verdict == BF_VERDICT_ACCEPT ? NF_ACCEPT : NF_DROP;
    case BF_FLAVOR_CGROUP_SKB: // fallthrough
    case BF_FLAVOR_CGROUP_SOCK_ADDR:
        return verdict == BF_VERDICT_ACCEPT ? 1 : 0;
    default:
        return -ENOTSUP;
    }
}
} // namespace

int bft_hook_accept(enum bf_hook hook)
{
    return _bft_verdict(hook, BF_VERDICT_ACCEPT);
}

int bft_hook_drop(enum bf_hook hook)
{
    return _bft_verdict(hook, BF_VERDICT_DROP);
}

int bft_hook_next(enum bf_hook hook)
{
    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_TC:
        return kTcxNext;
    case BF_FLAVOR_XDP:
        return XDP_PASS;
    case BF_FLAVOR_NF:
        return NF_ACCEPT;
    case BF_FLAVOR_CGROUP_SKB: // fallthrough
    case BF_FLAVOR_CGROUP_SOCK_ADDR:
        return 1;
    default:
        return -ENOTSUP;
    }
}

int bft_matcher_test_setup(void **state)
{
    (void)state;

    int r = bf_ruleset_flush(bft_matcher_ctx);
    if (r != 0)
        return bf_err_r(r, "failed to flush ruleset in test setup");

    return 0;
}

int bft_matcher_test_teardown(void **state)
{
    (void)state;

    int r = bf_ruleset_flush(bft_matcher_ctx);
    if (r != 0)
        return bf_err_r(r, "failed to flush ruleset in test teardown");

    return 0;
}
