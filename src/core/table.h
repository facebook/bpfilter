/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "chain.h"
#include "list.h"

#define BF_TABLE_NAME_LEN 31

#define __cleanup_bf_table__ __attribute__((__cleanup__(bf_table_free)))

struct bf_table
{
    const char name[BF_TABLE_NAME_LEN];
    bf_list chains;
};

int bf_table_new(struct bf_table **table);
void bf_table_free(struct bf_table **table);
