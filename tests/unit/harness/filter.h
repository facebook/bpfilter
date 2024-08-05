/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include "core/list.h"

#define _cleanup_bf_test_filter_ __attribute__((cleanup(bf_test_filter_free)))

struct bf_test_filter
{
    bf_list patterns;
};

int bf_test_filter_new(struct bf_test_filter **filter);
void bf_test_filter_free(struct bf_test_filter **filter);
int bf_test_filter_add_pattern(struct bf_test_filter *filter,
                               const char *pattern);
bool bf_test_filter_matches(struct bf_test_filter *filter, const char *str);
