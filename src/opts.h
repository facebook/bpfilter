/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

int bf_opts_init(int argc, char *argv[]);
bool bf_opts_verbose(void);
bool bf_opts_transient(void);