
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include "core/list.h"

/**
 * Print ruleset information and counters to the console.
 *
 * @param chains List of chains to print.
 * @param hookopts List of hookoptions to print.
 * @param counters List of counters to print.
 * @return 0 on success, negative errno code on failure.
 */
int bf_cli_dump_ruleset(bf_list *chains, bf_list *hookopts, bf_list *counters);
