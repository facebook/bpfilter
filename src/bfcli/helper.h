
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"

struct bf_ruleset
{
    bf_list chains;
    bf_list sets;
    bf_list hookopts;
};

#define _clean_bf_ruleset_ __attribute__((__cleanup__(bf_ruleset_clean)))

void bf_ruleset_clean(struct bf_ruleset *ruleset);

int bfc_parse_file(const char *file, struct bf_ruleset *ruleset);
int bfc_parse_str(const char *str, struct bf_ruleset *ruleset);
