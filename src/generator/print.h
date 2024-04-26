/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

/**
 * @file print.h
 *
 * The \c bf_print_* functions relates to the message printing facilities
 * provided to the generated BPF programs. \c bpfilter provides a set of
 * predefined messages that can be printed from the BPF programs.
 *
 * During \c bpfilter initialization, the predefined messages are concatenated
 * into a unique buffer or nul-separated strings. The offset of each message
 * is saved in \c bpfilter runtime context for later use. The resulting strings
 * buffer is then stored in a BPF map.
 *
 * All the log messages defined in \c bpfilter prefixed with
 * \c "$IFINDEX:$HOOK:$FRONT: ", so log messages can be mapped back to a
 * specific BPF program.
 *
 * @note All the message strings are stored in a single BPF map entry in order
 * to benefit from \c BPF_PSEUDO_MAP_VALUE which allows lookup free direct
 * value access for maps. Hence, using a unique instruction, \c bpfilter can
 * load the map's file descriptor and get the address of a message in the
 * buffer. See
 * <https://lore.kernel.org/bpf/20190409210910.32048-2-daniel@iogearbox.net>.
 *
 * The file descriptor to the loaded BPF map is stored within \c bpfilter
 * runtime context. It is not pinned and will be closed when \c bpfilter is
 * stopped. If any BPF program refers to the map, the kernel will keep it until
 * the last BPF program using it is unloaded. This behaviour is compatible with
 * \c bpfilter transient mode:
 * - If \c --transient is used, \c bpfilter will create the map at startup,
 *   create zero or more BPF programs using it. When \c bpfilter is stopped,
 *   the map's file descriptor will be closed and all the BPF programs created
 *   by \c bpfilter will be unloaded. The map will be removed from the system.
 * - If \c --transient is not used, \c bpfilter will create the map at startup,
 *   create zero or more BPF programs using it. When \c bpfilter is stopped, the
 *   map's file descriptor will be closed. The map will remain on the system
 *   if any BPF program refers to it. On the next start, \c bpfilter will create
 *   a new map and use it for new BPF programs, while existing BPF program still
 *   refer to the old map.
 * This mechanism prevents conflict if \c bpfilter is updated and restarted:
 * existing programs use the old map, new programs use the new map.
 */

/**
 * @brief Emit BPF instructions to print a predefined message.
 *
 * This function will insert mulitple instruction into the BPF program to: load
 * the messages map's file descriptor, copy into the argument registers: the
 * message's length, the program's ifindex, hook and front. Then it will call
 * \c bpf_trace_printk() to print the message.
 *
 * @warning As every \c EMIT_* macro, \c EMIT_PRINT() will call \c return if
 * an error occurs. Hence, it must be used within a function that returns an
 * integer.
 *
 * @param program Program to emit the instructions to. Must not be NULL.
 * @param msg_id Identifier of the message to print. See @ref bf_print_msg for
 * the list of predefined messages.
 */
#define EMIT_PRINT(program, msg_id)                                            \
    ({                                                                         \
        int __r;                                                               \
        struct bpf_insn __ld_insn[2] = {                                       \
            BPF_LD_MAP_FD(BF_ARG_1, bf_print_fd()),                            \
        };                                                                     \
        __ld_insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;                           \
        __ld_insn[0].imm = bf_print_fd();                                      \
        __ld_insn[1].imm = bf_print_msg_offset(msg_id);                        \
        __r = bf_program_emit((program), __ld_insn[0]);                        \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), __ld_insn[1]);                        \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit(                                                 \
            (program), BPF_MOV64_IMM(BF_ARG_2, bf_print_msg_size(msg_id)));    \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program),                                       \
                              BPF_MOV64_IMM(BF_ARG_3, program->ifindex));      \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program),                                       \
                              BPF_MOV64_IMM(BF_ARG_4, program->hook));         \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program),                                       \
                              BPF_MOV64_IMM(BF_ARG_5, program->front));        \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit_kfunc_call((program), "bpf_trace_printk");       \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

/**
 * @brief Identifiers of the predefined printable messages.
 */
enum bf_print_msg
{
    BF_PRINT_NO_DYNPTR,
    BF_PRINT_NO_SLICE,
    BF_PRINT_NO_L2,
    BF_PRINT_NO_L3,
    BF_PRINT_NO_IPV4,
    _BF_PRINT_MAX,
};

/**
 * @brief Setup context to allow generated BPF programs to print messages.
 *
 * The various printable messages are stored in an array of strings, this
 * function will concatenate them into a unique nul-separated buffer of string
 * and store it in a BPF map.
 *
 * @return 0 on success, or negative errno value on error.
 */
int bf_print_setup(void);

/**
 * @brief Teardown the printing context.
 *
 * The file descriptor of the BPF map containing the printable messages will be
 * closed. The map will remain on the system until the last BPF program using it
 * is unloaded.
 */
void bf_print_teardown(void);

/**
 * @brief Get the file descriptor of the BPF map containing the printable
 * messages.
 *
 * @return File descriptor of the BPF map containing the printable messages.
 */
int bf_print_fd(void);

/**
 * @brief Get the size of a printable message.
 *
 * @param msg_id ID of the message to get the size of.
 * @return Size of the message.
 */
size_t bf_print_msg_size(enum bf_print_msg msg_id);

/**
 * @brief Get the offset of a printable message in the BPF map.
 * @param msg_id ID of the message to get the offset of.
 *
 * @return Offset of the message in the BPF map.
 */
size_t bf_print_msg_offset(enum bf_print_msg msg_id);
