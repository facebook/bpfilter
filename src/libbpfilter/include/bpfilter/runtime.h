/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define bf_aligned(x) __attribute__((aligned(x)))

// _Static_assert doesn't exist in C++
#ifndef __cplusplus
#define static_assert _Static_assert
#endif

#include <asm/types.h>

/**
 * @brief Size of the L2 header buffer.
 *
 * Only Ethernet is supported at L2, so the buffer should be as big as the
 * Ethernet header, aligned to 8 bytes.
 */
#define BF_L2_SLICE_LEN 16
static_assert(BF_L2_SLICE_LEN % 8 == 0,
              "BF_L2_SLICE_LEN should be aligned to 8 bytes");

/**
 * @brief Size of the L3 header buffer.
 *
 * The buffer should be able to contain the largest supported L3 protocol header
 * among, aligned on 8 bytes:
 * - IPv4: 20 bytes (ignoring the options)
 * - IPv6: 40 bytes (ignoring the extension headers)
 */
#define BF_L3_SLICE_LEN 40
static_assert(BF_L3_SLICE_LEN % 8 == 0,
              "BF_L3_SLICE_LEN should be aligned to 8 bytes");

/**
 * @brief Size of the L4 header buffer.
 *
 * The buffer should be able to contain the largest supported L4 protocol header
 * among, aligned to 8 bytes:
 * - UDP: 8 bytes
 * - TCP: 20 bytes
 * - ICMP: 8 bytes (ignoring the payload)
 * - ICMPV6: 4 bytes (ignoring the body)
 */
#define BF_L4_SLICE_LEN 24
static_assert(BF_L4_SLICE_LEN % 8 == 0,
              "BF_L4_SLICE_LEN should be aligned to 8 bytes");

/**
 * @brief Types of network packet headers.
 */
enum bf_pkthdr
{
    /**
     * Link layer header: Ethernet, ...
     */
    BF_PKTHDR_LINK,

    /**
     * Internet header: IPv4, IPv6, ...
     */
    BF_PKTHDR_INTERNET,

    /**
     * Transport header: TCP, UDP, ...
     *
     * ICMPv6 is an internet layer (L3) header, but it's encapsulated inside an
     * IPv6 packet, so it's considered a transport layer (L4) header in
     * bpfilter.
     */
    BF_PKTHDR_TRANSPORT,

    _BF_PKTHDR_MAX,
};

/**
 * @brief Log structure published by a chain when the `log` action is hit.
 *
 * The structure is published into a log buffer by the chain, when a hit rule
 * has a `log` action defined.
 *
 * Except for the raw packet headers (`l2hdr`, `l3hdr`, and `l4hdr`), all the
 * values are stored in host byteorder.
 */
struct bf_log
{
    /** Timestamp of the packet processing. */
    __u64 ts;

    /** Total size of the packet, including the payload. */
    __u64 pkt_size;

    /** ID of the rule triggering the log. */
    __u32 rule_id;

    /** Verdict of the rule triggering the log. */
    __u32 verdict;

    /** Layer 3 (internet) protocol identifier. */
    __u16 l3_proto;

    /** Layer 4 (transport) protocol identifier. */
    __u8 l4_proto;

    /** User-request headers, as defined in the rule. */
    __u8 req_headers:4;

    /** Logged headers, as not all hooks can access all headers. */
    __u8 headers:4;

    /** Layer 2 header. */
    bf_aligned(8) __u8 l2hdr[BF_L2_SLICE_LEN];

    /** Layer 3 header. */
    bf_aligned(8) __u8 l3hdr[BF_L3_SLICE_LEN];

    /** Layer 4 header. */
    bf_aligned(8) __u8 l4hdr[BF_L4_SLICE_LEN];
};

struct bf_ip4_lpm_key
{
    __u32 prefixlen;
    __u32 data;
};

struct bf_ip6_lpm_key
{
    __u32 prefixlen;
    __u8 data[16];
    __u32 _padding;
};
