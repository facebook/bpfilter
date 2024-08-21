/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include "shared/front.h"

int bf_opts_init(int argc, char *argv[]);
bool bf_opts_transient(void);
unsigned int bf_opts_bpf_log_buf_len_pow(void);
bool bf_opts_is_front_enabled(enum bf_front front);
bool bf_opts_verbose(void);
bool bf_opts_debug(void);
