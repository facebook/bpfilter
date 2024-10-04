/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "cgroup_skb_ingress.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct counters);
    __uint(max_entries, 1);
} counters_map SEC(".maps");

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
	void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct counters *counters;
    __u32 key = 0;

    counters = bpf_map_lookup_elem(&counters_map, &key);
    if (counters) {
        counters->packets += 1;
        counters->bytes += (__u64)(data_end - data);
    }

    return 1;
}

char LICENSE[] SEC("license") = "GPL";
