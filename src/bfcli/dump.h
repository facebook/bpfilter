
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
 * Print ruleset information and counters to the console.
 *
 * @param chains_and_counters_marsh Pointer to the marshalled chains and counters returned by the daemon.
 * @param with_counters Whether to print counters or not.
 * @return 0 on success, negative errno code on failure.
 */
int bf_cli_dump_ruleset(struct bf_marsh *chains_and_counters_marsh,
                        bool with_counters);
