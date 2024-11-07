/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/front.h"
#include "core/hook.h"
#include "core/verdict.h"

/**
 * @file fake.h
 *
 * Generate fake data to use during tests.
 */

struct bf_cgen;
struct bf_nfgroup;
struct bf_rule;
struct nlmsghdr;

#define bf_test_chain_quick() bf_test_chain(BF_HOOK_XDP, BF_VERDICT_ACCEPT)
#define bf_test_cgen_quick()                                                   \
    bf_test_cgen(BF_FRONT_CLI, BF_HOOK_XDP, BF_VERDICT_ACCEPT)

#define _cleanup_tmp_file_ __attribute__((cleanup(bf_test_remove_tmp_file)))

char *bf_test_get_readable_tmp_filepath(void);
void bf_test_remove_tmp_file(char **path);
struct bf_chain *bf_test_chain(enum bf_hook hook, enum bf_verdict policy);
struct bf_cgen *bf_test_cgen(enum bf_front front, enum bf_hook hook,
                             enum bf_verdict verdict);
struct nlmsghdr *bf_test_get_nlmsghdr(size_t nmsg, size_t *len);
struct bf_nfgroup *bf_test_get_nfgroup(size_t nmsg, size_t *len);
struct bf_rule *bf_test_get_rule(size_t nmatchers);
