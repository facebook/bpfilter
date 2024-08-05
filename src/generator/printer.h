/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/context.h"

/**
 * @file printer.h
 *
 * \c bpfilter defines a way for generated BPF programs to print log messages
 * through \c bpf_trace_printk . This requires:
 * - A set of \c bf_printer_* primitives to manipulate the printer context
 *   during the bytecode generation.
 * - A \c EMIT_PRINT macro to insert BPF instructions to print a given string.
 * - A BPF map, created by \c bpfilter before the BPF programs are attached
 *   to the kernel.
 *
 * The printer context \c bf_printer stores all the log messages to be printed
 * by the generated BPF programs. Log messages are deduplicated to limit memory
 * usage.
 *
 * During the BPF programs generation, \c EMIT_PRINT is used to print a given
 * log message from a BPF program. Under the hood, this macro will insert the
 * log message into the global printer context, so it can be used by the BPF
 * programs at runtime.
 *
 * Before the BPF programs are attached to their hook in the kernel, \c bpfilter
 * will create a BPF map to contain a unique string, which is the concatenation
 * of all the log messages defined during the generation step. The various BPF
 * programs will be updated to request their log messages from this map
 * directly.
 *
 * @note All the message strings are stored in a single BPF map entry in order
 * to benefit from \c BPF_PSEUDO_MAP_VALUE which allows lookup free direct
 * value access for maps. Hence, using a unique instruction, \c bpfilter can
 * load the map's file descriptor and get the address of a message in the
 * buffer. See
 * <https://lore.kernel.org/bpf/20190409210910.32048-2-daniel@iogearbox.net>.
 */

struct bf_marsh;
struct bf_printer;
struct bf_printer_msg;

#define _cleanup_bf_printer_ __attribute__((__cleanup__(bf_printer_free)))

/**
 * @brief Emit BPF instructions to print a log message.
 *
 * This function will insert mulitple instruction into the BPF program to load
 * a given log message from a BPF map into a register, store its size, and
 * call \c bpf_trace_printk() to print the message.
 *
 * @warning As every \c EMIT_* macro, \c EMIT_PRINT() will call \c return if
 * an error occurs. Hence, it must be used within a function that returns an
 * integer.
 *
 * @param program Program to emit the instructions to. Must not be NULL.
 * @param msg Log message to print.
 */
#define EMIT_PRINT(program, msg)                                               \
    ({                                                                         \
        int __r;                                                               \
        const struct bf_printer_msg *__msg =                                   \
            bf_printer_add_msg(bf_context_get_printer(), msg);                 \
        struct bpf_insn __ld_insn[2] = {                                       \
            BPF_LD_MAP_FD(BF_ARG_1, 0),                                        \
        };                                                                     \
        __ld_insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;                           \
        __ld_insn[1].imm = bf_printer_msg_offset(__msg);                       \
        __r = bf_program_emit_fixup(                                           \
            (program), BF_CODEGEN_FIXUP_PRINTER_MAP_FD, __ld_insn[0]);         \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), __ld_insn[1]);                        \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit(                                                 \
            (program), BPF_MOV64_IMM(BF_ARG_2, bf_printer_msg_len(__msg)));    \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r =                                                                  \
            bf_program_emit((program), BPF_EMIT_CALL(BPF_FUNC_trace_printk));  \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

/**
 * @brief Allocate and initialise a new printer context.
 *
 * @param printer On success, contains a valid printer context.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_printer_new(struct bf_printer **printer);

/**
 * @brief Allocate a new printer context and intialise it from serialised data.
 *
 * @param printer On success, points to the newly allocated and initialised
 *  printer context. Can't be NULL.
 * @param marsh Serialised data to use to initialise the printer message.
 * @return 0 on success, or negative errno value on error.
 */
int bf_printer_new_from_marsh(struct bf_printer **printer,
                              const struct bf_marsh *marsh);

/**
 * @brief Deinitialise and deallocate a printer context.
 *
 * @param printer Printer context. Can't be NULL.
 */
void bf_printer_free(struct bf_printer **printer);

/**
 * @brief Serialise a printer context.
 *
 * @param printer Printer context to serialise. Can't be NULL.
 * @param marsh On success, contains the serialised printer context. Can't be
 *  NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_printer_marsh(const struct bf_printer *printer, struct bf_marsh **marsh);

/**
 * @brief Get the printer map's file descriptor.
 *
 * @param printer Printer context. Can't be NULL.
 * @return File descriptor of the printer's BPF map.
 */
int bf_printer_get_fd(const struct bf_printer *printer);

/**
 * @brief Return the offset of a specific printer message.
 *
 * @param msg Printer message. Can't be NULL.
 * @return Offset of @p msg in the concatenated messages buffer.
 */
size_t bf_printer_msg_offset(const struct bf_printer_msg *msg);

/**
 * @brief Return the length of a specific printer message.
 *
 * @param msg Printer message. Can't be NULL.
 * @return Length of @p msg, including the trailing nul termination character.
 */
size_t bf_printer_msg_len(const struct bf_printer_msg *msg);

/**
 * @brief Add a new message to the printer.
 *
 * @param printer Printer context. Can't be NULL.
 * @param str Message to add to the context. A copy of the buffer is made.
 * @return The printer message if it was successfuly added to the context,
 *  NULL otherwise.
 */
const struct bf_printer_msg *bf_printer_add_msg(struct bf_printer *printer,
                                                const char *str);

/**
 * @brief Publish the printer's messages in the BPF map.
 *
 * @param printer Printer context. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_printer_publish(struct bf_printer *printer);

