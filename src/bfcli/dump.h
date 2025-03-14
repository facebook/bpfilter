
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include "core/marsh.h"

/**
 * @file dump.h
 *
 * Tools for printing CLI data to the console.
 */

/**
 * Get a codegen from the global context.
 *
 * @param hook Hook to get the codegen from.
 * @param opts Hook options. For hooks allowing multiple codegens, the hook
 *        options are used to find the right codegen.
 * @return The requested codegen, or NULL if not found.
 */

int bf_cli_dump_ruleset(struct bf_marsh *chains_and_counters_marsh,
                        bool with_counters);
