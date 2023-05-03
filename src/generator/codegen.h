/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#define __cleanup_bf_codegen__ __attribute__((cleanup(bf_codegen_free)))

#define EMIT(codegen, x)

struct bf_chain;

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
