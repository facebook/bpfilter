/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define _cleanup_bf_test_opts_ __attribute__((cleanup(bf_test_opts_free)))

struct bf_test_filter;

struct bf_test_opts
{
    struct bf_test_filter *group_filter;
};

int bf_test_opts_new(struct bf_test_opts **opts, int argc, char *argv[]);
void bf_test_opts_free(struct bf_test_opts **opts);
