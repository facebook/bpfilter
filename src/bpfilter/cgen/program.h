/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/chain.h>
#include <bpfilter/dump.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/list.h>
#include <bpfilter/pack.h>

#include "cgen/elfstub.h"
#include "cgen/fixup.h"
#include "cgen/printer.h"
#include "cgen/runtime.h"
#include "filter.h"

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
 * `bf_runtime` is used to represent the layout of the first stack frame in the
 * program. It is filled during preprocessing and contains data required for
 * packet filtering.
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

#define EMIT_FIXUP_ELFSTUB(program, elfstub_id)                                \
    ({                                                                         \
        int __r = bf_program_emit_fixup_elfstub((program), (elfstub_id));      \
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

#define EMIT_LOAD_LOG_FD_FIXUP(program, reg)                                   \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_FIXUP_TYPE_LOG_MAP_FD,   \
                                        ld_insn[0], NULL);                     \
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
        union bf_fixup_attr __attr;                                            \
        memset(&__attr, 0, sizeof(__attr));                                    \
        __attr.set_index = (index);                                            \
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
struct bf_counter;
struct bf_hookopts;
struct bf_handle;

struct bf_program
{
    char prog_name[BPF_OBJ_NAME_LEN];
    enum bf_flavor flavor;

    /// Log messages printer
    struct bf_printer *printer;

    /** Handle containing BPF object references (prog_fd, maps, link).
     * Created in bf_program_new(), populated during load/attach.
     * Can be transferred to bf_cgen via bf_program_take_handle(). */
    struct bf_handle *handle;

    /* Bytecode */
    uint32_t elfstubs_location[_BF_ELFSTUB_MAX];
    struct bpf_insn *img;
    size_t img_size;
    size_t img_cap;
    bf_list fixups;

    /** Runtime data used to interact with the program and cache information.
     * This data is not serialized. */
    struct
    {
        /** Hook-specific ops to use to generate the program. */
        const struct bf_flavor_ops *ops;

        /** Chain the program is generated from. This is a non-owning pointer:
         * the @ref bf_program doesn't have to manage its lifetime. */
        const struct bf_chain *chain;
    } runtime;
};

#define _free_bf_program_ __attribute__((__cleanup__(bf_program_free)))

/**
 * @brief Allocate and initialize a new `bf_program` object.
 *
 * @param program `bf_program` object to allocate and initialize. Can't be NULL.
 * @param chain Chain the program is generated from. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_program_new(struct bf_program **program, const struct bf_chain *chain);

/**
 * @brief Allocate and initialize a new program from serialized data.
 *
 * @note The new bf_program object will represent a BPF map from bpfilter's
 * point of view, but it's not a BPF program.
 *
 * @todo `bf_program` should be recreated from the current system state by
 * using `BF_OBJ_INFO_BF_FD`, and not serialized.
 *
 * @param program Program object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*program` is
 *        unchanged. Can't be NULL.
 * @param chain Chain to restore the program for. Can't be NULL.
 * @param dir_fd File descriptor of the directory containing the program's pins.
 *        Must be a valid file descriptor, or -1 if the pin should not be opened.
 * @param node Node containing the serialized program. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_program_new_from_pack(struct bf_program **program,
                             const struct bf_chain *chain, int dir_fd,
                             bf_rpack_node_t node);

void bf_program_free(struct bf_program **program);

/**
 * @brief Serialize a program.
 *
 * @param program Program to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the program into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_program_pack(const struct bf_program *program, bf_wpack_t *pack);

void bf_program_dump(const struct bf_program *program, prefix_t *prefix);
int bf_program_grow_img(struct bf_program *program);

int bf_program_emit(struct bf_program *program, struct bpf_insn insn);
int bf_program_emit_kfunc_call(struct bf_program *program, const char *name);
int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn,
                          const union bf_fixup_attr *attr);
int bf_program_emit_fixup_elfstub(struct bf_program *program,
                                  enum bf_elfstub_id id);
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
 * @brief Pin the BPF program.
 *
 * The program and all the BPF objects it uses will be pinned into `dir_fd`.
 * The BPF link is only pinned if the program is attached to a hook.
 *
 * @param prog Program to pin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to pin the program and its
 *        BPF objects into.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_program_pin(struct bf_program *prog, int dir_fd);

/**
 * @brief Unpin the BPF program.
 *
 * This function never fails. If the program is not pinned, no file will be
 * removed.
 *
 * @param prog Program to unpin. Can't be NULL.
 * @param dir_fd File descriptor of the directory containing the pinned objects.
 */
void bf_program_unpin(struct bf_program *prog, int dir_fd);

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

/**
 * @brief Transfer ownership of the handle from the program.
 *
 * After this call, the program no longer owns the handle and the caller
 * becomes responsible for freeing it. The program's handle pointer is set
 * to NULL.
 *
 * @param prog Program to take the handle from. Can't be NULL.
 * @return The handle, or NULL if the program has no handle.
 */
struct bf_handle *bf_program_take_handle(struct bf_program *prog);

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter);
int bf_program_set_counters(struct bf_program *program,
                            const struct bf_counter *counters);

size_t bf_program_chain_counter_idx(const struct bf_program *program);
size_t bf_program_error_counter_idx(const struct bf_program *program);
