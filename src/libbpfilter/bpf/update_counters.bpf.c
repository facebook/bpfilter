/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

struct bf_counter
{
    __u64 count;
    __u64 size;
};

__u8 bf_update_counters(struct bf_runtime *ctx, void *map, __u64 key)
{
    struct bf_counter *counter;

    counter = bpf_map_lookup_elem(map, &key);
    if (!counter) {
        bpf_printk("failed to fetch the rule's counters");
        return 1;
    }

    counter->count += 1;
    counter->size += ctx->pkt_size;

    return 0;
}
