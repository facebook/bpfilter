
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"

struct bfc_ruleset
{
    bf_list chains;
    bf_list sets;
    bf_list hookopts;
};

#define _clean_bfc_ruleset_ __attribute__((__cleanup__(bfc_ruleset_clean)))

void bfc_ruleset_clean(struct bfc_ruleset *ruleset);
