/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <net/if.h>

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <stddef.h>
#include <stdint.h>

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/verdict.h"
#include "generator/fixup.h"
#include "generator/reg.h"
#include "shared/front.h"

#include "external/filter.h"

#define PIN_PATH_LEN 64

/**
 * @brief Convenience macro to get the offset of a field in @ref
 * bf_program_context.
 */
#define BF_PROG_CTX_OFF(field) offsetof(struct bf_program_context, field)

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
        int __r = bf_program_emit_fixup((program), (type), (insn));            \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP_CALL(program, function)                                     \
    ({                                                                         \
        int __r = bf_program_emit_fixup_call((program), (function));           \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_LOAD_FD_FIXUP(program, reg)                                       \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_CODEGEN_FIXUP_MAP_FD,    \
                                        ld_insn[0]);                           \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

struct bf_marsh;
struct bf_rule;
struct bf_counter;

/**
 * @brief BPF program runtime context.
 *
 * This structure is used to map data located in the first frame of the
 * generated BPF program. Address to this structure will be stored in
 * @ref BF_REG_CTX register, and fields can be accessed using the convenience
 * macro @ref BF_PROG_CTX_OFF.
 *
 * Layer 2, 3, and 4 headers are stored in an anonymous union, accessed through
 * the field named `lXraw`. The various header structures stored in anonymous
 * union are used to ensure `lXraw` is big enough to store any supported header.
 *
 * @warning A static assertion is defined to ensure this structure is aligned
 * on 8-bytes boundaries. This is required by @ref bf_stub_memclear.
 */
struct bf_program_context
{
    /** Argument passed to the BPF program, it content depends on the BPF
     * program type. */
    void *arg;

    /** BPF dynamic pointer representing the packet data. Dynamic pointers are
     * used with every program type. */
    struct bpf_dynptr dynptr;

    /** Total size of the packet. */
    uint64_t pkt_size;

    /** Offset of the layer 3 header in the packet. */
    uint32_t l3_offset;

    /** Offset of the layer 4 header in the packet. */
    uint32_t l4_offset;

    /** Layer 4 protocol. Set when the L3 header is processed. Used to define
     * how many bytes to read when processing the packet. */
    uint8_t l4_proto;

    /** Layer 2 header. */
    union
    {
        struct ethhdr _ethhdr;
        char l2raw;
    };

    /** Layer 3 header. */
    union
    {
        struct iphdr _iphdr;
        char l3raw;
    };

    /** Layer 4 header. */
    union
    {
        struct icmphdr _icmphdr;
        struct udphdr _udphdr;
        struct tcphdr _tcphdr;
        char l4raw;
    };
} bf_aligned(8);

static_assert(sizeof(struct bf_program_context) % 8 == 0,
              "struct bf_program_context must be 8-bytes aligned");

struct bf_program
{
    uint32_t ifindex;
    enum bf_hook hook;
    enum bf_front front;
    char prog_name[BPF_OBJ_NAME_LEN];
    char map_name[BPF_OBJ_NAME_LEN];
    char prog_pin_path[PIN_PATH_LEN];
    char map_pin_path[PIN_PATH_LEN];

    /** Number of counters in the counters map. Not all of them are used by
     * the program, but this value is common for all the programs of a given
     * codegen. */
    size_t num_counters;

    /* Bytecode */
    uint32_t functions_location[_BF_CODEGEN_FIXUP_FUNCTION_MAX];
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
        /** File descriptor of the counters map. */
        int map_fd;
        /** Hook-specific ops to use to generate the program. */
        const struct bf_flavor_ops *ops;
    } runtime;
};

#define _cleanup_bf_program_ __attribute__((__cleanup__(bf_program_free)))

int bf_program_new(struct bf_program **program, int ifindex, enum bf_hook hook,
                   enum bf_front front);
void bf_program_free(struct bf_program **program);
int bf_program_marsh(const struct bf_program *program, struct bf_marsh **marsh);
int bf_program_unmarsh(const struct bf_marsh *marsh,
                       struct bf_program **program);
void bf_program_dump(const struct bf_program *program, prefix_t *prefix);
int bf_program_grow_img(struct bf_program *program);

int bf_program_emit(struct bf_program *program, struct bpf_insn insn);
int bf_program_emit_kfunc_call(struct bf_program *program, const char *name);
int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn);
int bf_program_emit_fixup_call(struct bf_program *program,
                               enum bf_fixup_function function);
int bf_program_generate(struct bf_program *program, bf_list *rules,
                        enum bf_verdict policy);

/**
 * @brief Load the program into the kernel.
 * @param program Program to load. Can not be NULL.
 * @param prev_program Previous program to unload. Can be NULL. If not NULL,
 *  @ref bf_program_load will unload @p prev_program between @ref
 *  attach_prog_pre_unload and @ref attach_prog_post_unload calls.
 * @return 0 on success, negative errno code on failure.
 */
int bf_program_load(struct bf_program *program,
                    struct bf_program *prev_program);

int bf_program_unload(struct bf_program *program);

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter);
int bf_program_set_counters(struct bf_program *program,
                            const struct bf_counter *counters);
