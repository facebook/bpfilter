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

#include <linux/in6.h>

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

/** Size of the process name buffer, matches TASK_COMM_LEN. */
#define BF_COMM_LEN 16

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
 * @brief Log entry type discriminator.
 */
enum bf_log_type
{
    /** Packet-based log entry (XDP, TC, NF, cgroup_skb). */
    BF_LOG_TYPE_PACKET,

    /** Socket address log entry (cgroup_sock_addr). */
    BF_LOG_TYPE_SOCK_ADDR,

    _BF_LOG_TYPE_MAX,
};

/**
 * @brief Log structure published by a chain when the `log` action is hit.
 *
 * The structure is published into a log buffer by the chain, when a hit rule
 * has a `log` action defined.
 *
 * For packet-based hooks, the `pkt` variant contains raw headers in network
 * byteorder. For socket-based hooks, the `sock_addr` variant contains process
 * information. All other fields are stored in host byteorder.
 */
struct bf_log
{
    /** Timestamp of the event. */
    __u64 ts;

    /** ID of the rule triggering the log. */
    __u32 rule_id;

    /** Verdict of the rule triggering the log. */
    __u32 verdict;

    /** Layer 3 (internet) protocol identifier. */
    __u16 l3_proto;

    /** Layer 4 (transport) protocol identifier. */
    __u8 l4_proto;

    /** Log entry type. */
    __u8 log_type;

    union
    {
        struct
        {
            /** Total size of the packet, including the payload. */
            __u64 pkt_size;

            /** User-requested headers, as defined in the rule. */
            __u8 req_headers;

            /** Logged headers, as not all hooks can access all headers. */
            __u8 headers;

            /** Layer 2 header. */
            bf_aligned(8) __u8 l2hdr[BF_L2_SLICE_LEN];

            /** Layer 3 header. */
            bf_aligned(8) __u8 l3hdr[BF_L3_SLICE_LEN];

            /** Layer 4 header. */
            bf_aligned(8) __u8 l4hdr[BF_L4_SLICE_LEN];
        } pkt;

        struct
        {
            /** Root namespace PID (tgid) of the process. */
            __u32 pid;

            /** Destination port in host byteorder. */
            __u16 dport;

            /** User-requested log options bitmask. */
            __u8 req_log_opts;

            /** Process name. */
            bf_aligned(8) __u8 comm[BF_COMM_LEN];

            /** Source address (4 bytes for IPv4, 16 for IPv6). */
            bf_aligned(8) __u8 saddr[sizeof(struct in6_addr)];

            /** Destination address (4 bytes for IPv4, 16 for IPv6). */
            bf_aligned(8) __u8 daddr[sizeof(struct in6_addr)];
        } sock_addr;
    } payload;
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
