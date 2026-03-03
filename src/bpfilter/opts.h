/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

enum bf_verbose
{
    BF_VERBOSE_DEBUG,
    BF_VERBOSE_BPF,
    BF_VERBOSE_BYTECODE,
    _BF_VERBOSE_MAX,
};

int bf_opts_init(int argc, char *argv[]);
bool bf_opts_transient(void);
bool bf_opts_persist(void);
bool bf_opts_with_bpf_token(void);
const char *bf_opts_bpffs_path(void);
bool bf_opts_is_verbose(enum bf_verbose opt);
void bf_opts_set_verbose(enum bf_verbose opt);
