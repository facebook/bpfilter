/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"

/**
 * @file sym.h
 *
 * `bpfilter` stores the test functions in a custom `.bf_test` section in the
 * ELF binary. This way, the tests can be fetched at runtime from the current
 * binary, allowing for tests autodiscovery (which CMocka doesn't support).
 *
 * `bf_test_get_symbols()` will read the sections in the ELF file it runs from
 * and return all the symbols located in the `.bf_test` section.
 */

struct bf_test_sym
{
    const char *name;
    void *cb;
};

#define _free_bf_test_sym_ __attribute__((cleanup(bf_test_sym_free)))

int bf_test_sym_new(struct bf_test_sym **sym, const char *name, void *cb);
void bf_test_sym_free(struct bf_test_sym **sym);
void bf_test_sym_dump(struct bf_test_sym *sym);

int bf_test_get_symbols(bf_list *symbols);
