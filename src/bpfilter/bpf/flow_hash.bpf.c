/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <stddef.h>

#include "cgen/runtime.h"

/// Number of 32-bit words in an IPv6 address.
#define IPV6_ADDR_WORDS 4

/// Mask to extract the 20-bit flow label from IPv6 header first word.
#define IPV6_FLOW_LABEL_MASK 0x000FFFFF

/// xxHash32 finalizer constants.
#define XXH32_PRIME1 0x85ebca77
#define XXH32_PRIME2 0xc2b2ae3d

/**
 * xxHash32 avalanche finalizer.
 *
 * Provides excellent bit mixing to ensure uniform distribution across all
 * 32 bits. Changing any single input bit will change approximately 50% of
 * output bits on average.
 *
 * @param hash Input hash value to finalize.
 * @return Finalized hash with improved distribution.
 */
static inline __u32 xxh32_avalanche(__u32 hash)
{
    hash ^= hash >> 15;
    hash *= XXH32_PRIME1;
    hash ^= hash >> 13;
    hash *= XXH32_PRIME2;
    hash ^= hash >> 16;

    return hash;
}

/**
 * Calculate flow hash from packet 5-tuple + IPv6 flow label.
 *
 * Computes a 32-bit hash by combining:
 * - Source and destination IP addresses
 * - Source and destination ports (TCP/UDP only)
 * - Protocol number
 * - IPv6 flow label (IPv6 only)
 *
 * The raw values are accumulated via XOR, then passed through an xxHash32
 * avalanche finalizer to ensure uniform distribution across all 32 bits.
 *
 * The hash uses packet source/destination addresses (not socket local/remote)
 * to ensure matching consistency between sender and receiver.
 *
 * @param ctx Runtime context with parsed packet headers.
 * @param l3_proto L3 protocol ID (network byte order, ETH_P_IP or ETH_P_IPV6).
 * @param l4_proto L4 protocol ID (IPPROTO_TCP, IPPROTO_UDP, etc.).
 * @return Computed 32-bit flow hash with uniform distribution.
 */
__u32 bf_flow_hash(struct bf_runtime *ctx, __u16 l3_proto, __u8 l4_proto)
{
    __u32 hash = 0;

    // Hash L3 addresses based on protocol
    if (l3_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip4 = ctx->l3_hdr;

        hash ^= ip4->saddr;
        hash ^= ip4->daddr;
        hash ^= (__u32)l4_proto << 16;
    } else if (l3_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = ctx->l3_hdr;
        __u32 *saddr = (__u32 *)&ip6->saddr;
        __u32 *daddr = (__u32 *)&ip6->daddr;

        // XOR all 4 words of source address
        for (int i = 0; i < IPV6_ADDR_WORDS; ++i)
            hash ^= saddr[i];

        // XOR all 4 words of destination address
        for (int i = 0; i < IPV6_ADDR_WORDS; ++i)
            hash ^= daddr[i];

        // Include flow label (20 bits from version/traffic class/flow label)
        // First 4 bytes contain: version (4) + traffic class (8) + flow label (20)
        // After ntohl, flow label is in the lower 20 bits
        hash ^= bpf_ntohl(*(__u32 *)ip6) & IPV6_FLOW_LABEL_MASK;

        hash ^= (__u32)l4_proto << 16;
    }

    // Hash L4 ports for TCP and UDP
    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = ctx->l4_hdr;
        hash ^= ((__u32)tcp->source << 16) | tcp->dest;
    } else if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udp = ctx->l4_hdr;
        hash ^= ((__u32)udp->source << 16) | udp->dest;
    }

    // Apply xxHash32 avalanche finalizer for uniform distribution
    return xxh32_avalanche(hash);
}
