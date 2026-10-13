/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

#define BF_IPV6_EXT_MAX_CHAIN 6

// Fragment offset (in 8-byte units, shifted by 3) and More Fragments flag
#define BF_IPV6_FRAG_OFFSET 0xfff8
#define BF_IPV6_FRAG_MORE 0x0001

/* IPv6 Fragment header (RFC 8200, section 4.5): `struct frag_hdr` isn't part of
 * the kernel's uapi. */
struct bf_ipv6_frag_hdr
{
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

__u8 bf_parse_ipv6(struct bf_runtime *ctx)
{
    struct ipv6hdr *ip6hdr = ctx->l3_hdr;
    __u8 next_hdr_type = ip6hdr->nexthdr;

    ctx->l4_offset = ctx->l3_offset + sizeof(struct ipv6hdr);

    for (int i = 0; i < BF_IPV6_EXT_MAX_CHAIN; ++i) {
        struct ipv6_opt_hdr _ext;
        struct ipv6_opt_hdr *ext =
            bpf_dynptr_slice(&ctx->dynptr, ctx->l4_offset, &_ext, sizeof(_ext));
        if (!ext)
            return 0;

        switch (next_hdr_type) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_MH:
            next_hdr_type = ext->nexthdr;
            ctx->l4_offset += (ext->hdrlen + 1) * 8;
            break;
        case IPPROTO_AH:
            next_hdr_type = ext->nexthdr;
            ctx->l4_offset += (ext->hdrlen + 2) * 4;
            break;
        case IPPROTO_FRAGMENT: {
            struct bf_ipv6_frag_hdr _frag;
            const struct bf_ipv6_frag_hdr * const frag = bpf_dynptr_slice(
                &ctx->dynptr, ctx->l4_offset, &_frag, sizeof(_frag));

            if (!frag)
                return 0;

            const __u16 frag_off = bpf_ntohs(frag->frag_off);
            if (frag_off & BF_IPV6_FRAG_OFFSET) {
                // A non-first fragment carries payload, not headers
                ctx->frag = BF_FRAG_LATER;
                return frag->nexthdr;
            }
            if (frag_off & BF_IPV6_FRAG_MORE)
                ctx->frag = BF_FRAG_FIRST;

            // Fixed size: the second byte is reserved, not a length
            next_hdr_type = frag->nexthdr;
            ctx->l4_offset += sizeof(*frag);
            break;
        }
        default:
            return next_hdr_type;
        }
    }

    return next_hdr_type;
}
