/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define __cleanup_bf_codegen__ __attribute__((cleanup(bf_codegen_free)))

struct bf_codegen
{
    int placeholder;
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
 * @param codegen Codegen to free. Can't be NULL.
 */
void bf_codegen_free(struct bf_codegen **codegen);
