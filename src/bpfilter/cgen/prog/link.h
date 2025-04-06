/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"

struct bf_marsh;

/**
 * BPF link object.
 */
struct bf_link
{
    /** Name of the link. From the kernel perspective, BPF link objects don't
     * have a name like the programs, but this name will be used to pin the
     * link. */
    char name[BPF_OBJ_NAME_LEN];

    /** Hook options used for the link. Only valid if the link is materialized */
    struct bf_hookopts hookopts;

    /** File descriptor of the link, only valid once the link object has been
     * created. */
    int fd;
};

#define _free_bf_link_ __attribute__((__cleanup__(bf_link_free)))

/**
 * Allocate and initialize a `bf_link` object.
 *
 * @note This function won't create a new BPF link, but a bpfilter-specific
 * object used to keep track of a BPF link on the system.
 *
 * @param link `bf_link` object to allocate and initialize. On failure,
 *        this parameter is unchanged. Can't be NULL.
 * @param name Name of the link. Can't be empty or NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_new(struct bf_link **link, const char *name);

/**
 * Allocate and initialize a new `bf_link` object from serialized data.
 *
 * @param link `bf_link` object to allocate and initialize from `marsh`.
 *        On failure, this parameter is unchanged. Can't be NULL.
 * @param dir_fd File descriptor of the directory to open the pinned link from.
 *        BPF link objects are always pinned relative to a directory, if
 *        `dir_fd` is `-1`, `bf_link_new_from_marsh` assumes the link hasn't
 *        been pinned.
 * @param marsh Serialized data to read a `bf_link` from. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_link_new_from_marsh(struct bf_link **link, int dir_fd,
                           const struct bf_marsh *marsh);

/**
 * Deallocate a `bf_link` object.
 *
 * The BPF link's file descriptor contained in `link` is closed and set to
 * `-1`. To prevent the BPF link from being destroy (and the BPF program to be
 * detached from its hook), pin it beforehand.
 *
 * @param link `bf_link` object to cleanup and deallocate. If `*link`
 *        is NULL, this function has no effect. Can't be NULL.
 */
void bf_link_free(struct bf_link **link);

/**
 * Serialize a `bf_link` object.
 *
 * @param link `bf_link` object to serialize. Can't be NULL.
 * @param marsh On success, represents the serialized `bf_link` object. On
 *        failure, this parameter is unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_marsh(const struct bf_link *link, struct bf_marsh **marsh);

/**
 * Dump the content of a `bf_link` object.
 *
 * @param link `bf_link` object to print. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_link_dump(const struct bf_link *link, prefix_t *prefix);

/**
 * Attach a BPF program to a hook using a the link.
 *
 * @param link `bf_link` object to use to attach the program. Can't be NULL.
 * @param hook Hook to attach the program to.
 * @param hookopts Hook-specific options to use to attach the program to the
 *        hook. Can't be NULL.
 * @param prog_fd BPF program to attach.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_attach(struct bf_link *link, enum bf_hook hook,
                   const struct bf_hookopts *hookopts, int prog_fd);

/**
 * Replace the program attached to the link.
 *
 * BPF link allows for the program they attach to, to be replaced atomically
 * with another program.
 *
 * @param link Link to update. Can't be NULL.
 * @param hook Hook the link is already attached to.
 * @param prog_fd File descriptor of the new program to attach to the link.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_update(struct bf_link *link, enum bf_hook hook, int prog_fd);

/**
 * Detach the BPF link from the hook.
 *
 * @param link Link to detach. Can't be NULL.
 */
void bf_link_detach(struct bf_link *link);

/**
 * Pin the link to the system.
 *
 * @param link Link to pin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to pin the link into. Must be
 *        a valid file descriptor.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_link_pin(struct bf_link *link, int dir_fd);

/**
 * Unpin the link from the system.
 *
 * @param link Link to unpin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to unpin the link from. Must
 *        be a valid file descriptor.
 */
void bf_link_unpin(struct bf_link *link, int dir_fd);
