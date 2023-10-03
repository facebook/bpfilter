/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

int bf_opts_init(int argc, char *argv[]);
bool bf_opts_transient(void);
unsigned int bf_opts_bpf_log_buf_len_pow(void);
bool bf_opts_verbose(void);
