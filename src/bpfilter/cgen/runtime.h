/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include "core/runtime.h"

/**
 * @file runtime.h
 *
 * At runtime, the BPF programs have access to a 512 bytes stack. bpfilter will
 * use the stack to store runtime data, such as the program's argument, the
 * packet size...
 *
 * `bf_runtime` defines the layout of the data stored on the stack of the
 * BPF program and simplifies its access.
 *
 * This header can be included into C stubs to be integrated into the generated
 * BPF programs.
 */

/**
 * @brief Return the offset of a field in the runtime context, from `BPF_REG_10`.
 *
 * @param field Field to get the offset of.
 * @return Offset of `field` in the runtime context based on `BPF_REG_10`.
 */
#define BF_PROG_CTX_OFF(field)                                                 \
    (-(int)sizeof(struct bf_runtime) + (int)offsetof(struct bf_runtime, field))

/**
 * @brief Return the offset of an index in the scratch area, from `BPF_REG_10`.
 *
 * @param index Index of the scratch area entry to get the offset of.
 * @return Offset of `index` in the scratch area based on `BPF_REG_10`.
 */
#define BF_PROG_SCR_OFF(index)                                                 \
    (-(int)sizeof(struct bf_runtime) +                                         \
     (int)offsetof(struct bf_runtime, scratch) + (index))

#define bf_aligned(x) __attribute__((aligned(x)))

struct bf_ip4_lpm_key
{
    __u32 prefixlen;
    __u32 data;
};

struct bf_ip6_lpm_key
{
    __u32 prefixlen;
    __u8 data[16];
};

/**
 * @brief Runtime stack layout for the generated BPF programs.
 *
 * This runtime context is located at `r10 - sizeof(struct bf_runtime)`, it is
 * valid during the whole lifetime of the BPF program.
 *
 * Access to the packet data is performed through a BPF dynamic pointer, this
 * pointer is stored in the runtime context, as well as the scratch areas used
 * to store the header slices.
 *
 * Each slice storage area is big enough to store the largest protocol header
 * for a given layer. The BPF subsystem might copy the requested data into the
 * slice storage area or not. In any case, a pointer to the data is returned,
 * this pointer is stored in the runtime context and will be used to access the
 * data.
 *
 * L3 and L4 protocol identifiers are used to check which matcher should be
 * applied to a given packet. They can't be stored in the runtime context as
 * the verifier might not be able to keep track of them, leading to verification
 * failures.
 *
 * @warning Not all the BPF verifier versions are born equal, as older ones
 * might require stack access to be 8-bytes aligned to work properly. Hence, all
 * fields of the runtime context are aligned to 8 bytes, and `bf_runtime` size
 * must be a multiple of 8.
 */
struct bf_runtime
{
    /** Argument passed to the BPF program, its content depends on the BPF
     * program flavor:
     * - `BF_FLAVOR_XDP`: `struct xdp_md *`
     * - `BF_FLAVOR_TC`: `struct struct __sk_buff *`
     * - `BF_FLAVOR_CGROUP`: `struct __sk_buff *`
     * - `BF_FLAVOR_NF`: `struct bpf_nf_ctx *` */
    void *arg;

    /** BPF dynamic pointer to access the packet data. Dynamic pointers are
     * used with for program flavor. */
    struct bpf_dynptr dynptr;

    /** Ring buffer map containing the logged packets. */
    void *log_map;

    /** Total size of the packet. */
    __u64 pkt_size;

    /** IPv6 extension header mask */
    __u8 ipv6_eh;

    __u8 l2_size;
    __u8 l3_size;
    __u8 l4_size;

    /** Offset of the layer 3 protocol header. */
    __u32 bf_aligned(8) l3_offset;

    /** Offset of the layer 4 protocol header. */
    __u32 bf_aligned(8) l4_offset;

    /** On ingress, index of the input interface. On egress, index of the
     * output interface. */
    __u32 bf_aligned(8) ifindex;

    /** Pointer to the L2 protocol header (in a dynamic pointer slice). */
    void *l2_hdr;

    /** Pointer to the L3 protocol header (in a dynamic pointer slice). */
    void *l3_hdr;

    /** Pointer to the L4 protocol header (in a dynamic pointer slice). */
    void *l4_hdr;

    /** Layer 2 header. */
    __u8 bf_aligned(8) l2[BF_L2_SLICE_LEN];

    /** Layer 3 header. */
    __u8 bf_aligned(8) l3[BF_L3_SLICE_LEN];

    /** Layer 4 header. */
    __u8 bf_aligned(8) l4[BF_L4_SLICE_LEN];

    /** Scratch area. */
    __u8 bf_aligned(8) scratch[64];
};

_Static_assert(sizeof(struct bf_runtime) % 8 == 0,
               "bf_runtime should be aligned to 8 bytes");

extern void *bpf_dynptr_slice(const struct bpf_dynptr *, __u32, void *, __u32);
extern int bpf_dynptr_from_xdp(struct xdp_md *, __u64, struct bpf_dynptr *);
