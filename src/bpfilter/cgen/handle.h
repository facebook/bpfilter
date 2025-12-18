/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/dump.h>
#include <bpfilter/hook.h>
#include <bpfilter/list.h>
#include <bpfilter/pack.h>

#define _free_bf_handle_ __attribute__((__cleanup__(bf_handle_free)))

#define BF_PROG_NAME "bf_prog"

struct bf_hookopts;
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

/**
 * @brief Pin the BPF objects.
 *
 * The program and all the BPF objects it uses will be pinned into `dir_fd`.
 * The BPF link is only pinned if the program is attached to a hook.
 *
 * @param handle Handle to pin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to pin the program and its
 *        BPF objects into.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_handle_pin(struct bf_handle *handle, int dir_fd);

/**
 * @brief Unpin the BPF objects.
 *
 * This function never fails. If the program is not pinned, no file will be
 * removed.
 *
 * @param handle Handle to unpin. Can't be NULL.
 * @param dir_fd File descriptor of the directory containing the pinned objects.
 */
void bf_handle_unpin(struct bf_handle *handle, int dir_fd);

/**
 * @brief Unload the program.
 *
 * @param handle Program to unload. Can't be NULL.
 */
void bf_handle_unload(struct bf_handle *handle);

/**
 * @brief Attach a loaded program to a hook.
 *
 * The program is attached to a hook using a `bf_link` object. In persistent
 * mode, the link will be pinned to the filesystem. If the link can't be pinned,
 * the program will be detached from the hook.
 *
 * @param handle Handle to attach. Can't be NULL.
 * @param hook Hook to attach the program to.
 * @param hookopts Hook-specific options to attach the program to the hook.
 *        Can't be NULL.
 * @return 0 on success, or negative error value on failure.
 */
int bf_handle_attach(struct bf_handle *handle, enum bf_hook hook,
                     struct bf_hookopts **hookopts);

/**
 * @brief Detach the program from the kernel.
 *
 * The program is detached but not unloaded.
 *
 * @param handle Handle to detach. Can't be NULL.
 */
void bf_handle_detach(struct bf_handle *handle);
