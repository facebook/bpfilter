/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

/*
 * Drop all the packets coming from the IPv4 address stored as a key in the
 * map.
 *
 * Perform a lookup in the map for the source IPv4 address in the packet. If
 * the address is found, drop the packet, otherwise accept it.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} ip_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *s = (void *)(unsigned long)ctx->data;
    void *e = (void *)(unsigned long)ctx->data_end;
    struct ethhdr *eth = s;
    struct iphdr *iph;
    __u8 *value;

    if (s + sizeof(*eth) + sizeof(*iph) > e)
        return XDP_PASS;

    iph = (void *)(eth + 1);

    value = bpf_map_lookup_elem(&ip_map, &iph->saddr);
    if (value)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
