/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include <bpfilter/list.h>

/**
 * @file elfstub.h
 *
 * ELF stubs are a mechanism to integrate clang-compiled BPF bytecode into
 * bpfilter-generated BPF programs. Complex logic is more easily implemented
 * in C and integrated into the final program that developed in BPF bytecode
 * directly.
 *
 * ELF stubs source code is part of bpfilter's sources, they are compiled
 * using clang, the ELF file is stored in a C array and accessible to the
 * daemon at runtime.
 *
 * **Creating a new ELF stub**
 *
 * 1. Add a new source file for the BPF program in the daemon's codebase (in the
 *    `bpf` folder, as `$NAME.bpf.c`).
 * 2. Declare the ELF stub in the daemon's CMakeLists.txt (in
 *    `bf_target_add_elfstubs()`).
 * 3. Add a new ID for this stub in `bf_elfstub_id`.
 * 4. Write the BPF C code: define a single function (additional inline
 *    functions and macros are allowed).
 *
 * **Technicalities**
 *
 * At build time, ELF stubs are compiled by clang as BPF program. As such, they
 * are bound to the same limitations as any other BPF program. `xxd` is used to
 * convert the ELF file into a C array (with size), which is included in a
 * generated `rawstubs.h` header file.
 *
 * `rawstubs.h` defines an array of `bf_rawstub` structures containing:
 * - `const void *elf`: pointer to the ELF data.
 * - `size_t len`: size of the ELF file.
 *
 * Each ELF stub can be manipulated through an instance of `bf_rawstub`, all
 * the instances are stored in an array, which is as big as `_BF_ELFSTUB_MAX`.
 *
 * However, the ELF stubs are not accessed directly through the `bf_rawstub`
 * structure, as it's not usable as-is. Instead, the `bf_context` will extract
 * the actual bytecode from the ELF file, and relocate the kfunc calls. During
 * generation, `bf_ctx_get_elfstub` is used to retrieve a pointer to
 * `bf_elfstub` containing the BPF instructions to be copied in the program.
 *
 * **Limitations**
 *
 * Not any BPF program can be integrated into a bpfilter program, this section
 * lists the current set of limitations:
 * - Maps are not supported: BPF maps can be defined, but they are not
 *   integrated by bpfilter into the program, so the final BPF program won't
 *   be verifiable.
 * - Function are not supported: each ELF stub source code should contain a
 *   single function to be integrated. Inline functions are allowed, as they're
 *   not real functions in the final ELF file.
 *
 * Those limitations might evolve, as new BPF features are developed and the ELF
 * stub implementation is improved.
 *
 * While map are not supported, `bpf_printk()` can be used, as bpfilter is
 * able to add the strings to its own map.
 */

struct bpf_insn;

/**
 * @brief Identifiers for the ELF stubs.
 *
 * Each identifier represents a valid ELF stub. If an ELF stub doesn’t have its
 * identifier, it doesn’t exist from bpfilter’s standpoint.
 */
enum bf_elfstub_id
{
    /**
     * Parse IPv6 extension headers.
     *
     * `__u8 bf_parse_ipv6(struct bf_runtime *ctx)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     *
     * **Return** The L4 protocol on success, or 0 if the program fails creating
     *            a dynamic pointer slice.
     */
    BF_ELFSTUB_PARSE_IPV6_EH,

    /**
     * Parse IPv6 extension headers filling runtime context for ip6.nexthdr rule.
     *
     * `__u8 bf_parse_ipv6(struct bf_runtime *ctx)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     *
     * **Return** The L4 protocol on success, or 0 if the program fails creating
     *            a dynamic pointer slice.
     */
    BF_ELFSTUB_PARSE_IPV6_NH,

    /**
     * Update the counters for a given rule.
     *
     * `__u8 bf_update_counters(struct bf_runtime *ctx, void *map, __u64 key)`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `map`: address of the counters map.
     * - `key`: key of the map to update.
     *
     * **Return** 0 on success, or 1 on error.
     */
    BF_ELFSTUB_UPDATE_COUNTERS,

    /**
     * Log user-requested packet headers to a ring buffer.
     *
     * `__u8 bf_log(struct bf_runtime *ctx, void *map, __u8 headers, __u16 l3_proto, __u8 l4_proto))`
     *
     * **Parameters**
     * - `ctx`: address of the `bf_runtime` context of the program.
     * - `map`: pointer to the logs ring buffer.
     * - `layers`: user-requested headers to log.
     * - `l3_proto`: layer 3 (internet) protocol identifier.
     * - `l4_proto`: layer 4 (transport) protocol identifier.
     *
     * **Return** 0 on success, or 1 on error.
     */
    BF_ELFSTUB_LOG,

    _BF_ELFSTUB_MAX,
};

struct bf_printk_str
{
    size_t insn_idx;
    const char *str;
};

/**
 * @brief Processed ELF stub to be integrated into a BPF program.
 */
struct bf_elfstub
{
    enum bf_elfstub_id id;
    struct bpf_insn *insns;
    size_t ninsns;
    bf_list strs;
};

#define _free_bf_elfstub_ __attribute__((__cleanup__(bf_elfstub_free)))

/**
 * @brief Allocate and initialize a new ELF stub.
 *
 * The corresponding raw ELF stub will be read, its text section will be copied
 * into the final ELF, and the calls to kfuncs will be relocated according to
 * the host's kernel.
 *
 * @param stub ELF stub to allocate and initialize. Can't be NULL.
 * @param id Identifier of the raw ELF stub to initialize.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_elfstub_new(struct bf_elfstub **stub, enum bf_elfstub_id id);

/**
 * Deinitialise and deallocate an ELF stub.
 *
 * @param stub ELF stub. Can't be NULL.
 */
void bf_elfstub_free(struct bf_elfstub **stub);
