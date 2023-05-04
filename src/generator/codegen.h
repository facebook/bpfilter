/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include "core/context.h"
#include "core/list.h"

#define __cleanup_bf_codegen__ __attribute__((cleanup(bf_codegen_free)))

#define CODEGEN_REG_RETVAL BPF_REG_0
#define CODEGEN_REG_SCRATCH1 BPF_REG_1
#define CODEGEN_REG_SCRATCH2 BPF_REG_2
#define CODEGEN_REG_SCRATCH3 BPF_REG_3
#define CODEGEN_REG_SCRATCH4 BPF_REG_4
#define CODEGEN_REG_SCRATCH5 BPF_REG_5
#define CODEGEN_REG_DATA_END CODEGEN_REG_SCRATCH5
#define CODEGEN_REG_L3 BPF_REG_6
#define CODEGEN_REG_L4 BPF_REG_7
#define CODEGEN_REG_RUNTIME_CTX BPF_REG_8
#define CODEGEN_REG_CTX BPF_REG_9

#define EMIT(codegen, x)                                                       \
    ({                                                                         \
        typeof(codegen) __codegen = codegen;                                   \
        (__codegen)->img[codegen->len_cur++] = (x);                            \
    })

#define EMIT_FIXUP(codegen, type, insn)                                        \
    bf_codegen_fixup_emit((codegen), (type), (insn))

struct bf_chain;

struct runtime_context
{
    uint32_t data_size;
    void *l3;
    void *l4;
};

#define STACK_RUNTIME_CONTEXT_OFFSET(field)                                    \
    (-(short)(offsetof(struct runtime_context, field) +                        \
              sizeof(((struct runtime_context *)NULL)->field)))

/**
 * @struct bf_codegen
 * @brief Codegen object. Contains a BPF program's source data, translated
 *  data, and BPF bytecode.
 *
 * @var bf_codegen::chain
 *  Filtering rules, in bpfilter format.
 * @var bf_codegen::src_data
 *  Source data, in front-end format.
 * @var bf_codegen::src_data_size
 *  Size of the source data, in bytes.
 */
struct bf_codegen
{
    struct bf_chain *chain;
    void *src_data;
    size_t src_data_size;

    /* BPF bytecode */
    struct bpf_insn *img;
    size_t len_cur;
    size_t len_max;

    /* Post processing */
    bf_list fixups;
};

/**
 * @brief Allocate and initialise a new codegen.
 *
 * @param codegen Codegen to initialise. Can't be NULL.
 * @return int 0 on success, negative error code on failure.
 */
int bf_codegen_new(struct bf_codegen **codegen);

/**
 * @brief Free a codegen.
 *
 * Data owned by the codegen will be freed, either with a dedicated function
 * (i.e. bf_chain_free() for bf_codegen.chain) or with free() (i.e.
 * bf_codegen.src_data).
 *
 * @param codegen Codegen to free. Can't be NULL.
 */
void bf_codegen_free(struct bf_codegen **codegen);

void bf_codegen_generate(enum bf_hooks hook, struct bf_codegen *codegen);

/**
 * @brief Dump BPF bytecode stored in the given codegen.
 * @param codegen Codegen to dump. Can't be NULL.
 */
void bf_codegen_dump_bytecode(struct bf_codegen *codegen);
