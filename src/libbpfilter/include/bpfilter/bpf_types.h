// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

enum bf_bpf_cmd
{
    BF_BPF_PROG_LOAD = 5,
    BF_BPF_MAP_LOOKUP_ELEM = 1,
    BF_BPF_OBJ_PIN = 6,
    BF_BPF_OBJ_GET = 7,
    BF_BPF_PROG_TEST_RUN = 10,
    BF_BPF_TOKEN_CREATE = 36,
    BF_BPF_BTF_LOAD = 18,
    BF_BPF_MAP_CREATE = 0,
    BF_BPF_MAP_UPDATE_ELEM = 2,
    BF_BPF_MAP_UPDATE_BATCH = 26,
    BF_BPF_MAP_GET_FD_BY_ID = 14,
    BF_BPF_OBJ_GET_INFO_BY_FD = 15,
    BF_BPF_BTF_GET_FD_BY_ID = 19,
    BF_BPF_LINK_CREATE = 28,
    BF_BPF_LINK_UPDATE = 29,
    BF_BPF_LINK_DETACH = 34,
};

enum bf_bpf_prog_type
{
    BF_BPF_PROG_TYPE_XDP = 6,
    BF_BPF_PROG_TYPE_SCHED_CLS = 3,
    BF_BPF_PROG_TYPE_CGROUP_SKB = 8,
    BF_BPF_PROG_TYPE_NETFILTER = 32,
};

enum bf_bpf_attach_type
{
    BF_BPF_XDP = 37,
    BF_BPF_NETFILTER = 45,
    BF_BPF_TCX_INGRESS = 46,
    BF_BPF_TCX_ENGRESS = 47,
    BF_BPF_CGROUP_INET_INGRESS = 0,
    BF_BPF_CGROUP_INET_EGRESS = 1,
};

enum bf_bpf_map_type
{
    BF_BPF_MAP_TYPE_HASH = 1,
    BF_BPF_MAP_TYPE_ARRAY = 2,
    BF_BPF_MAP_TYPE_LPM_TRIE = 11,
    BF_BPF_MAP_TYPE_RINGBUF = 27,
};
