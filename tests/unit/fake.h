/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "bpfilter/front.h"
#include "bpfilter/hook.h"
#include "bpfilter/verdict.h"

struct bf_cgen;
struct bf_nfgroup;
struct bf_rule;
struct nlmsghdr;

#define bf_test_chain_quick() bf_test_chain(BF_HOOK_XDP, BF_VERDICT_ACCEPT)
#define bf_test_cgen_quick()                                                   \
    bf_test_cgen(BF_FRONT_CLI, BF_HOOK_XDP, BF_VERDICT_ACCEPT)

struct bf_chain *bf_test_chain(enum bf_hook hook, enum bf_verdict policy);
struct bf_cgen *bf_test_cgen(enum bf_front front, enum bf_hook hook,
                             enum bf_verdict verdict);
struct bf_rule *bf_test_get_rule(size_t nmatchers);
