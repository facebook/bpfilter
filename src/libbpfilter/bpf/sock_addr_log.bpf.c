/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "cgen/runtime.h"

__u8 bf_sock_addr_log(struct bf_runtime *ctx, __u32 rule_id, __u32 verdict,
                      __u32 l3_l4_proto, __u8 captured_fields)
{
    const struct bf_runtime_sock_addr *sock_addr = (const void *)ctx->scratch;
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
    log->l3_proto = bpf_ntohs(l3_proto);
    log->l4_proto = l4_proto;
    log->log_type = BF_LOG_TYPE_SOCK_ADDR;

    log->sock_addr.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(log->sock_addr.comm, sizeof(log->sock_addr.comm));

    if (captured_fields & BF_LOG_SOCK_ADDR_SADDR) {
        __builtin_memcpy(log->sock_addr.saddr, sock_addr->saddr,
                         sizeof(sock_addr->saddr));
    }
    __builtin_memcpy(log->sock_addr.daddr, sock_addr->daddr,
                     sizeof(sock_addr->daddr));

    log->sock_addr.dport = sock_addr->dport;
    log->sock_addr.captured_fields = captured_fields;

    bpf_ringbuf_submit(log, 0);

    return 0;
}
