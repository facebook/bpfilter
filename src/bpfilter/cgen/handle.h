/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/dump.h>
#include <bpfilter/list.h>
#include <bpfilter/pack.h>

#define _free_bf_handle_ __attribute__((__cleanup__(bf_handle_free)))

#define BF_PROG_NAME "bf_prog"

struct bf_link;
struct bf_map;

struct bf_handle
{
    int prog_fd;
    struct bf_link *link;

    struct bf_map *counters;
    struct bf_map *logs;
    struct bf_map *messages;
    bf_list sets;
};

int bf_handle_new(struct bf_handle **handle);
int bf_handle_new_from_pack(struct bf_handle **handle, int dir_fd,
                            bf_rpack_node_t node);
void bf_handle_free(struct bf_handle **handle);
int bf_handle_pack(const struct bf_handle *handle, bf_wpack_t *pack);
void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix);
