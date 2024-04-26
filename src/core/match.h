/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define BF_MATCH_OPS_NAME 29

#define _cleanup_bf_match_ __attribute__((__cleanup__(bf_match_free)))

struct bf_match_ops
{
    char name[BF_MATCH_OPS_NAME];
    int (*check)(void);
    int (*generate)(void);
};

struct bf_match
{
    struct bf_match_ops *ops;
    void *data;
};

int bf_match_new(struct bf_match **match);
void bf_match_free(struct bf_match **match);
