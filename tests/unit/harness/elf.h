/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"

#define _cleanup_bf_elf_sym_ __attribute__((cleanup(bf_elf_sym_free)))

struct bf_elf_sym
{
    const char *name;
    void *fn;
};

int bf_elf_sym_new(struct bf_elf_sym **sym, const char *name, void *fn);
void bf_elf_sym_free(struct bf_elf_sym **sym);
void bf_elf_sym_dump(struct bf_elf_sym *sym);

int bf_test_get_symbols(bf_list *symbols);
