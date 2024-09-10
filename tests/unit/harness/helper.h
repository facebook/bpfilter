/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/hook.h"

#define _cleanup_tmp_file_ __attribute__((cleanup(bf_test_remove_tmp_file)))

struct bf_cgen;
struct bf_nfgroup;
struct bf_rule;
struct nlmsghdr;

char *bf_test_get_readable_tmp_filepath(void);
void bf_test_remove_tmp_file(char **path);
int bf_test_make_cgen(struct bf_cgen **cgen, enum bf_hook hook,
                         int nprogs);
struct nlmsghdr *bf_test_get_nlmsghdr(size_t nmsg, size_t *len);
struct bf_nfgroup *bf_test_get_nfgroup(size_t nmsg, size_t *len);
struct bf_rule *bf_test_get_rule(void);
