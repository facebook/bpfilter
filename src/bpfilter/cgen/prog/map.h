/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#define BF_PIN_PATH_LEN 64

#define _cleanup_bf_bpf_map_ __attribute__((__cleanup__(bf_bpf_map_free)))

struct bf_bpf_map
{
    int fd;
    char name[BPF_OBJ_NAME_LEN];
    char path[BF_PIN_PATH_LEN];
};

/**
 * Allocates and initializes a new BPF map object.
 *
 * @note This function won't create a new BPF map, but a bpfilter-specific
 * object used to keep track of a BPF map on the system.
 *
 * @param map BPF map object to allocate and initialize. Can't be NULL. On
 *            success, @c *map points to a valid @ref bf_bpf_map . On failure,
 *            @c *map remain unchanged.
 * @param name_suffix Suffix to use for the map name. Usually specify the
 *                    hook, front-end, or program type the map is used for.
 *                    Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_bpf_map_new(struct bf_bpf_map **map, const char *name_suffix);

/**
 * Free a BPF map object.
 *
 * The BPF map's file descriptor contained in @c map is closed and set to
 * @c -1 . To prevent the BPF map from being destroyed, pin it beforehand.
 *
 * @param map @ref bf_bpf_map object to free. On success, @c *map is set to
 *            NULL. On failure, @c *map remain unchanged.
 */
void bf_bpf_map_free(struct bf_bpf_map **map);
