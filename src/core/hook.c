/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/hook.h"

#include "shared/helper.h"

const char *bf_hook_to_str(enum bf_hook hook)
{
    static const char *hooks_str[] = {
        [BF_HOOK_NFT_INGRESS] = "BF_HOOK_NFT_INGRESS",
        [BF_HOOK_TC_INGRESS] = "BF_HOOK_TC_INGRESS",
        [BF_HOOK_IPT_PRE_ROUTING] = "BF_HOOK_IPT_PRE_ROUTING",
        [BF_HOOK_IPT_LOCAL_IN] = "BF_HOOK_IPT_LOCAL_IN",
        [BF_HOOK_IPT_FORWARD] = "BF_HOOK_IPT_FORWARD",
        [BF_HOOK_IPT_LOCAL_OUT] = "BF_HOOK_IPT_LOCAL_OUT",
        [BF_HOOK_IPT_POST_ROUTING] = "BF_HOOK_IPT_POST_ROUTING",
        [BF_HOOK_TC_EGRESS] = "BF_HOOK_TC_EGRESS",
    };

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(hooks_str) == _BF_HOOK_MAX,
                  "missing entries in hooks_str array");

    return hooks_str[hook];
}

unsigned int bf_hook_to_bpf_prog_type(enum bf_hook hook)
{
    static const unsigned int prog_type[] = {
        [BF_HOOK_NFT_INGRESS] = BPF_PROG_TYPE_XDP,
        [BF_HOOK_TC_INGRESS] = BPF_PROG_TYPE_SCHED_CLS,
        [BF_HOOK_IPT_PRE_ROUTING] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_IPT_LOCAL_IN] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_IPT_FORWARD] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_IPT_LOCAL_OUT] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_IPT_POST_ROUTING] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_TC_EGRESS] = BPF_PROG_TYPE_SCHED_CLS,
    };

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(prog_type) == _BF_HOOK_MAX,
                  "missing entries in prog_type array");

    return prog_type[hook];
}

enum bf_flavor bf_hook_to_flavor(enum bf_hook hook)
{
    static const enum bf_flavor flavors[] = {
        [BF_HOOK_NFT_INGRESS] = BF_FLAVOR_XDP,
        [BF_HOOK_TC_INGRESS] = BF_FLAVOR_TC,
        [BF_HOOK_IPT_PRE_ROUTING] = BF_FLAVOR_NF,
        [BF_HOOK_IPT_LOCAL_IN] = BF_FLAVOR_NF,
        [BF_HOOK_IPT_FORWARD] = BF_FLAVOR_NF,
        [BF_HOOK_IPT_LOCAL_OUT] = BF_FLAVOR_NF,
        [BF_HOOK_IPT_POST_ROUTING] = BF_FLAVOR_NF,
        [BF_HOOK_TC_EGRESS] = BF_FLAVOR_TC,
    };

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(flavors) == _BF_HOOK_MAX,
                  "missing entries in flavors array");

    return flavors[hook];
}

enum bpf_attach_type bf_hook_to_attach_type(enum bf_hook hook)
{
    static const enum bpf_attach_type hooks[] = {
        [BF_HOOK_NFT_INGRESS] = 0,
        [BF_HOOK_TC_INGRESS] = 0,
        [BF_HOOK_IPT_PRE_ROUTING] = 0,
        [BF_HOOK_IPT_LOCAL_IN] = BPF_NETFILTER,
        [BF_HOOK_IPT_FORWARD] = BPF_NETFILTER,
        [BF_HOOK_IPT_LOCAL_OUT] = BPF_NETFILTER,
        [BF_HOOK_IPT_POST_ROUTING] = 0,
        [BF_HOOK_TC_EGRESS] = 0,
    };

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(hooks) == _BF_HOOK_MAX,
                  "missing entries in hooks array");

    return hooks[hook];
}
