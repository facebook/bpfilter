/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "bpfilter/cgen/runtime.h"

#define BF_IPV6_EXT_MAX_CHAIN   6

#define EH_COMMON_OFFSET        1
#define EH_COMMON_SHIFT         3
#define EH_AH_OFFSET            2
#define EH_AH_SHIFT             2
#define EH_FRAG_OFFSET          8
#define EH_FRAG_SHIFT           0

/* The following defines must follow the ones defined in src/core/matcher.h */
#define BF_IPV6_NH_HOPOPTS      (1 << 0)
#define BF_IPV6_NH_ROUTING      (1 << 1)
#define BF_IPV6_NH_FRAGMENT     (1 << 2)
#define BF_IPV6_NH_DSTOPTS      (1 << 3)
#define BF_IPV6_NH_MH           (1 << 4)
#define BF_IPV6_NH_AH           (1 << 5)
#define BF_IPV6_NH_TCP          (1 << 6)
#define BF_IPV6_NH_UDP          (1 << 7)
#define BF_IPV6_NH_ICMPV6       (1 << 8)

__u8 bf_parse_ipv6(struct bf_runtime *ctx)
{
    struct ipv6hdr *ip6hdr = ctx->l3_hdr;
    __u8 next_hdr_type = ip6hdr->nexthdr;
    __u16 nh_mask = 0;

    ctx->l4_offset = ctx->l3_offset + sizeof(struct ipv6hdr);

    for (int i = 0; i < BF_IPV6_EXT_MAX_CHAIN; ++i) {
        __u8 offset;
        __u8 shift;
        struct ipv6_opt_hdr _ext;
        struct ipv6_opt_hdr *ext =
            bpf_dynptr_slice(&ctx->dynptr, ctx->l4_offset, &_ext, sizeof(_ext));
        if (!ext) {
            next_hdr_type = 0;
            goto exit;
        }

        switch (next_hdr_type) {
        case IPPROTO_HOPOPTS:
            nh_mask |= BF_IPV6_NH_HOPOPTS;
            goto off;
        case IPPROTO_DSTOPTS:
            nh_mask |= BF_IPV6_NH_DSTOPTS;
            goto off;
        case IPPROTO_ROUTING:
            nh_mask |= BF_IPV6_NH_ROUTING;
            goto off;
        case IPPROTO_MH:
            nh_mask |= BF_IPV6_NH_MH;
off:
            offset = EH_COMMON_OFFSET; shift = EH_COMMON_SHIFT;
            break;
        case IPPROTO_AH:
            nh_mask |= BF_IPV6_NH_AH;
            offset = EH_AH_OFFSET; shift = EH_AH_SHIFT;
            break;
        case IPPROTO_FRAGMENT:
            nh_mask |= BF_IPV6_NH_FRAGMENT;
            offset = EH_FRAG_OFFSET; shift = EH_FRAG_SHIFT;
            break;
        case IPPROTO_TCP:
            nh_mask |= BF_IPV6_NH_TCP;
            goto exit;
        case IPPROTO_UDP:
            nh_mask |= BF_IPV6_NH_UDP;
            goto exit;
        case IPPROTO_ICMPV6:
            nh_mask |= BF_IPV6_NH_ICMPV6;
            goto exit;
        default:
            goto exit;
        }

        ctx->l4_offset += (ext->hdrlen + offset) << shift;
        next_hdr_type = ext->nexthdr;
    }

exit:
    ctx->ipv6_nh = nh_mask;

    return next_hdr_type;
}
