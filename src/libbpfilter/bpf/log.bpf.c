/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

__u8 bf_log(struct bf_runtime *ctx, __u32 rule_id, __u8 headers, __u32 verdict,
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

    log->ts = bpf_ktime_get_ns();
    log->rule_id = rule_id;
    log->verdict = verdict;
    log->pkt_size = ctx->pkt_size;
    log->req_headers = headers;
    log->headers = 0;
    log->l3_proto = bpf_ntohs(l3_proto);
    log->l4_proto = l4_proto;

    if (headers & (1 << BF_PKTHDR_LINK) && ctx->l2_hdr &&
        ctx->l2_size <= BF_L2_SLICE_LEN) {
        bpf_probe_read_kernel(log->l2hdr, ctx->l2_size, ctx->l2_hdr);
        log->headers |= (1 << BF_PKTHDR_LINK);
    }

    if (headers & (1 << BF_PKTHDR_INTERNET) && ctx->l3_hdr &&
        ctx->l3_size <= BF_L3_SLICE_LEN) {
        bpf_probe_read_kernel(log->l3hdr, ctx->l3_size, ctx->l3_hdr);
        log->headers |= (1 << BF_PKTHDR_INTERNET);
    }

    if (headers & (1 << BF_PKTHDR_TRANSPORT) && ctx->l4_hdr &&
        ctx->l4_size <= BF_L4_SLICE_LEN) {
        bpf_probe_read_kernel(log->l4hdr, ctx->l4_size, ctx->l4_hdr);
        log->headers |= (1 << BF_PKTHDR_TRANSPORT);
    }

    bpf_ringbuf_submit(log, 0);

    return 0;
}
