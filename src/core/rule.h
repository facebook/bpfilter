/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "list.h"
#include "match.h"
#include "target.h"

#define __cleanup_bf_rule__ __attribute__((__cleanup__(bf_rule_free)))

struct bf_rule
{
    bf_list matches;
    struct bf_target *target;
};

int bf_rule_new(struct bf_rule **rule);
void bf_rule_free(struct bf_rule **rule);
