/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

__u8 bf_pkt_5_tuple_log(struct bf_runtime *ctx, __u32 rule_id, __u32 verdict,
                        __u32 l3_l4_proto)
{
    struct bf_log *log;
    __u16 l3_proto = (__u16)(l3_l4_proto >> 16);
    __u8 l4_proto = (__u8)l3_l4_proto;

    log = bpf_ringbuf_reserve(ctx->log_map, sizeof(struct bf_log), 0);
    if (!log) {
        bpf_printk("failed to reserve %d bytes in ringbuf",
                   sizeof(struct bf_log));
        return 1;
    }

    __builtin_memset(log, 0, sizeof(*log));

    log->ts = bpf_ktime_get_ns();
    log->rule_id = rule_id;
    log->verdict = verdict;
    log->l3_proto = bpf_ntohs(l3_proto);
    log->l4_proto = l4_proto;
    log->log_type = BF_LOG_TYPE_PACKET_5_TUPLE;

    if (l3_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip4 = ctx->l3_hdr;

        __builtin_memcpy(log->pkt_5_tuple.saddr, &ip4->saddr,
                         sizeof(ip4->saddr));
        __builtin_memcpy(log->pkt_5_tuple.daddr, &ip4->daddr,
                         sizeof(ip4->daddr));
    } else {
        struct ipv6hdr *ip6 = ctx->l3_hdr;

        __builtin_memcpy(log->pkt_5_tuple.saddr, &ip6->saddr,
                         sizeof(ip6->saddr));
        __builtin_memcpy(log->pkt_5_tuple.daddr, &ip6->daddr,
                         sizeof(ip6->daddr));
    }

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = ctx->l4_hdr;

        log->pkt_5_tuple.sport = bpf_ntohs(tcp->source);
        log->pkt_5_tuple.dport = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = ctx->l4_hdr;

        log->pkt_5_tuple.sport = bpf_ntohs(udp->source);
        log->pkt_5_tuple.dport = bpf_ntohs(udp->dest);
    }

    bpf_ringbuf_submit(log, 0);

    return 0;
}
