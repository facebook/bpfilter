/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

struct bf_program;

void bf_program_dump_bytecode(const struct bf_program *program, bool with_raw);
