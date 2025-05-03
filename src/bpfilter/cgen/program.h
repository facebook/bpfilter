/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/fixup.h"
#include "bpfilter/cgen/printer.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/list.h"

#include "external/filter.h"

/**
 * @file program.h
 *
 * @ref bf_program is used to represent a BPF program. It contains the BPF
 * bytecode, as well as the required maps and metadata.
 *
 * **Workflow**
 *
 * The program is composed of different steps:
 * 1. Initialize the generic context
 * 2. Preprocess the packet's headers: gather information about the packet's
 *    size, the protocols available, the input interface...
 * 3. Execute the filtering rules: execute all the rules defined in the program
 *    sequentially. If a rule matches the packet, apply its verdict and return.
 * 4. Apply the policy if no rule matched: if no rule matched the packet, return
 *    the chain's policy (default action).
 *
 * **Memory layout**
 *
 * The program will use the BPF registers to following way:
 * - @c r0 : return value
 * - @c r1 to @c r5 (included): general purpose registers
 * - @c r6 : address of the header currently filtered on
 * - @c r7 : L3 protocol ID
 * - @c r8 : L4 protocol ID
 * - @c r9 : unused
 * - @c r10 : frame pointer
 *
 * This convention is followed throughout the project and must be followed all
 * the time to prevent incompatibilities. Debugging this kind of issues is not
 * fun, so stick to it.
 *
 * @warning L3 and L4 protocol IDs **must** be stored in registers, no on the
 * stack, as older verifier aren't able to keep track of scalar values located
 * on the stack. This means the verification will fail because the verifier
 * can't verify branches properly.
 *
 * @ref bf_program_context is used to represent the layout of the first stack
 * frame in the program. It is filled during preprocessing and contains data
 * required for packet filtering.
 *
 * **About preprocessing**
 *
 * The packets are preprocessed according to the program type (i.e. BPF flavor).
 * Each flavor needs to perform the following steps during preprocessing:
 * - Store the packet size and the input interface index into the runtime context
 * - Create a BPF dynamic pointer for the packet
 * - Preprocess the L2, L3, and L4 headers
 *
 * The header's preprocessing is required to discover the protocols used in the
 * packet: processing L2 will provide us with information about L3, and so on. The
 * logic used to process layer X is responsible for discovering layer X+1: the L2
 * header preprocessing logic will discover the L3 protocol ID. When processing
 * layer X, if the protocol is not supported, the protocol ID is reset to 0 (so
 * we won't execute the rules for this layer) and subsequent layers are not
 * processed (because we can't discover their protocol).
 *
 * For example, assuming IPv6 and TCP are the only supported protocols:
 * - L2 processing: discover the packet's ethertype (IPv6), and store it into
 *   @c r7 .
 * - L3 processing: the protocol ID in @c r7 is supported (IPv6), so a slice is
 *   created, and the L4 protocol ID is read from the IPV6 header into @c r8 .
 * - L4 processing: the protocol ID in @c r8 is supported (TCP), so a slice
 *   is created.
 * - The program can now start executing the rules.
 *
 * However, assuming only IPv6 and UDP are supported:
 * - L2 processing: discover the packet's ethertype (IPv6), and store it into
 *   @c r7 .
 * - L3 processing: the protocol ID in @c r7 is supported (IPv6), so a slice is
 *   created, and the L4 protocol ID is read from the IPV6 header into @c r8 .
 * - L4 processing: the protocol ID in @c r8 is no supported (TCP), @c r8 is
 *   set to 0 and we stop processing this layer.
 * - The program can now start executing the rules. No layer 4 rule will be
 *   executed as @c r8 won't match any protocol ID.
 */

/** Convenience macro to get the offset of a field in @ref
 * bf_program_context based on the frame pointer in @c BPF_REG_10 .
 */
#define BF_PROG_CTX_OFF(field)                                                 \
    (-(int)sizeof(struct bf_program_context) +                                 \
     (int)offsetof(struct bf_program_context, field))

/** Convenience macro to get an address in the scratch area of
 * @ref bf_program_context . */
#define BF_PROG_SCR_OFF(offset)                                                \
    (-(int)sizeof(struct bf_program_context) +                                 \
     (int)offsetof(struct bf_program_context, scratch) + (offset))

#define EMIT(program, x)                                                       \
    ({                                                                         \
        int __r = bf_program_emit((program), (x));                             \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_KFUNC_CALL(program, function)                                     \
    ({                                                                         \
        int __r = bf_program_emit_kfunc_call((program), (function));           \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP(program, type, insn)                                        \
    ({                                                                         \
        int __r = bf_program_emit_fixup((program), (type), (insn), NULL);      \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP_CALL(program, function)                                     \
    ({                                                                         \
        int __r = bf_program_emit_fixup_call((program), (function));           \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP_JMP_NEXT_RULE(program, insn)                                \
    ({                                                                         \
        int __r = bf_program_emit_fixup(                                       \
            (program), BF_FIXUP_TYPE_JMP_NEXT_RULE, (insn), NULL);             \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_LOAD_COUNTERS_FD_FIXUP(program, reg)                              \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup(                                       \
            (program), BF_FIXUP_TYPE_COUNTERS_MAP_FD, ld_insn[0], NULL);       \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

/**
 * Load a specific set's file descriptor.
 *
 * @note Similarly to every @c EMIT_* macro, it must be called from a function
 * returning an @c int , if the call fails, the macro will return a negative
 * errno value.
 *
 * @param program Program to generate the bytecode for. Can't be NULL.
 * @param reg Register to store the set file descriptor in.
 * @param index Index of the set in the program.
 */
#define EMIT_LOAD_SET_FD_FIXUP(program, reg, index)                            \
    ({                                                                         \
        union bf_fixup_attr __attr = {.set_index = (index)};                   \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_FIXUP_TYPE_SET_MAP_FD,   \
                                        ld_insn[0], &__attr);                  \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

struct bf_chain;
struct bf_map;
struct bf_marsh;
struct bf_counter;
struct bf_link;
struct bf_hookopts;

/**
 * BPF program runtime context.
 *
 * This structure is used to easily read and write data from the program's
 * stack. At runtime, the first stack frame of each generated program will
 * contain data according to @ref bf_program_context .
 *
 * The generated programs uses BPF dynamic pointer slices to safely access the
 * packet's data. @c bpf_dynptr_slice requires a user-provided buffer into which
 * it might copy the requested data, depending on the BPF program type: that is
 * the purpose of the anonynous unions, big enough to store the supported
 * protocol headers. @c bpf_dynptr_slice returns the address of the requested
 * data, which is either the address of the user-buffer, or the address of the
 * data in the packet (if the data hasn't be copied). The program will store
 * this address into the runtime context (i.e. @c l2 , @c l3 , and
 * @c l4 ), and it will be used to access the packet's data.
 *
 * While earlier versions of this structure contained the L3 and L4 protocol IDs,
 * they have been move to registers instead, as old version of the verifier
 * can't keep track of scalar values in the stack, leading to verification
 * failures.
 *
 * @warning Not all the BPF verifier versions are born equal as older ones might
 * require stack access to be 8-bytes aligned to work properly.
 */
struct bf_program_context
{
    /** Argument passed to the BPF program, its content depends on the BPF
     * program type. */
    void *arg;

    /** BPF dynamic pointer representing the packet data. Dynamic pointers are
     * used with every program type. */
    struct bpf_dynptr dynptr;

    /** Total size of the packet. */
    uint64_t pkt_size;

    /** Offset of the layer 3 protocol. */
    uint32_t l3_offset;

    /** Offset of the layer 4 protocol. */
    uint32_t l4_offset;

    /** On ingress, index of the input interface. On egress, index of the
     * output interface. */
    uint32_t ifindex;

    /** Pointer to the L2 protocol header. */
    void *l2_hdr;

    /** Pointer to the L3 protocol header. */
    void *l3_hdr;

    /** Pointer to the L4 protocol header. */
    void *l4_hdr;

    /** Layer 2 header. */
    union _bf_l2
    {
        struct ethhdr eth;
    } bf_aligned(8) l2;

    /** Layer 3 header. */
    union _bf_l3
    {
        struct iphdr ip4;
        struct ipv6hdr ip6;
    } bf_aligned(8) l3;

    /** Layer 3 header. */
    union _bf_l4
    {
        struct icmphdr icmp;
        struct udphdr udp;
        struct tcphdr tcp;
        struct icmp6hdr icmp6;
    } bf_aligned(8) l4;

    uint8_t bf_aligned(8) scratch[64];
} bf_aligned(8);

static_assert(sizeof(struct bf_program_context) % 8 == 0,
              "struct bf_program_context must be 8-bytes aligned");

struct bf_program
{
    char prog_name[BPF_OBJ_NAME_LEN];
    enum bf_flavor flavor;

    /// Log messages printer
    struct bf_printer *printer;

    /// Counters map
    struct bf_map *cmap;
    /// Printer map
    struct bf_map *pmap;
    /// List of set maps
    bf_list sets;

    /// Link objects attaching the program to a hook.
    struct bf_link *link;

    /** Number of counters in the counters map. Not all of them are used by
     * the program, but this value is common for all the programs of a given
     * codegen. */
    size_t num_counters;

    /* Bytecode */
    uint32_t functions_location[_BF_FIXUP_FUNC_MAX];
    struct bpf_insn *img;
    size_t img_size;
    size_t img_cap;
    bf_list fixups;

    /** Runtime data used to interact with the program and cache information.
     * This data is not serialized. */
    struct
    {
        /** File descriptor of the program. */
        int prog_fd;

        /** File descriptor of the directory to pin the program into. Unused
         * in transient mode. */
        int pindir_fd;

        /** Hook-specific ops to use to generate the program. */
        const struct bf_flavor_ops *ops;

        /** Chain the program is generated from. This is a non-owning pointer:
         * the @ref bf_program doesn't have to manage its lifetime. */
        const struct bf_chain *chain;
    } runtime;
};

#define _cleanup_bf_program_ __attribute__((__cleanup__(bf_program_free)))

int bf_program_new(struct bf_program **program, const struct bf_chain *chain);
void bf_program_free(struct bf_program **program);
int bf_program_marsh(const struct bf_program *program, struct bf_marsh **marsh);
int bf_program_unmarsh(const struct bf_marsh *marsh,
                       struct bf_program **program,
                       const struct bf_chain *chain);
void bf_program_dump(const struct bf_program *program, prefix_t *prefix);
int bf_program_grow_img(struct bf_program *program);

int bf_program_emit(struct bf_program *program, struct bpf_insn insn);
int bf_program_emit_kfunc_call(struct bf_program *program, const char *name);
int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn,
                          const union bf_fixup_attr *attr);
int bf_program_emit_fixup_call(struct bf_program *program,
                               enum bf_fixup_func function);
int bf_program_generate(struct bf_program *program);

/**
 * Load the BPF program into the kernel.
 *
 * Prior to loading the BPF program, multiple BPF maps are created to store
 * the counters, the debug strings, and the sets. If the program can't be
 * loaded, all the maps are destroyed.
 *
 * Once the loading succeeds, the program and the maps are pinned to the
 * filesystem, unless the daemon is in transient mode. If the BPF objects can't
 * be pinned, the program is unloaded and the maps destroyed.
 *
 * @param prog Program to load into the kernel. Can't be NULL and must contain
 *        instructions.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_program_load(struct bf_program *prog);

/**
 * Attach a loaded program to a hook.
 *
 * @warning If the program hasn't been loaded (using `bf_program_load`),
 * `bf_program_attach` will fail.
 *
 * The program is attached to a hook using a `bf_link` object. In persistent
 * mode, the link will be pinned to the filesystem. If the link can't be pinned,
 * the program will be detached from the hook.
 *
 * @param prog Program to attach. Can't be NULL.
 * @param hookopts Hook-specific options to attach the program to the hook.
 *        Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_program_attach(struct bf_program *prog, struct bf_hookopts **hookopts);

/**
 * Detach the program from the kernel.
 *
 * The program is detached but not unloaded.
 *
 * @param prog Program to detach. Can't be NULL.
 */
void bf_program_detach(struct bf_program *prog);

/**
 * Unload the program.
 *
 * @param prog Program to unload. Must not be attached. Can't be NULL.
 */
void bf_program_unload(struct bf_program *prog);

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter);
int bf_program_set_counters(struct bf_program *program,
                            const struct bf_counter *counters);
