/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define _cleanup_bf_target_ __attribute__((__cleanup__(bf_target_free)))

enum bf_target_standard_verdict
{
    BF_TARGET_STANDARD_ACCEPT,
    BF_TARGET_STANDARD_DROP,
    _BF_TARGET_STANDARD_MAX,
};

enum bf_target_type
{
    BF_TARGET_TYPE_STANDARD,
    BF_TARGET_TYPE_ERROR,
    _BF_TARGET_TYPE_MAX,
};

struct bf_target
{
    enum bf_target_type type;

    union
    {
        enum bf_target_standard_verdict verdict;
    };
};

struct bf_program;

struct bf_target_ops
{
    int (*generate)(struct bf_program *program, const struct bf_target *target);
};

const char *bf_target_type_to_str(enum bf_target_type type);
const char *
bf_target_standard_verdict_to_str(enum bf_target_standard_verdict verdict);

int bf_target_new(struct bf_target **target);
void bf_target_free(struct bf_target **target);
const struct bf_target_ops *bf_target_ops_get(enum bf_target_type type);
