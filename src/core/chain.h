/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "list.h"
#include "rule.h"

#define __cleanup_bf_chain__ __attribute__((__cleanup__(bf_chain_free)))

struct bf_chain
{
    bf_list rules;
};

int bf_chain_new(struct bf_chain **chain);
void bf_chain_free(struct bf_chain **chain);
