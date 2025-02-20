/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/bpf.h"
#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "linux/bpf.h"

/**
 * BPF link object.
 */
struct bf_link
{
    /** Name of the link. From the kernel perspective, BPF link objects don't
     * have a name the program does, but this name will be used to
     * pin the link. */
    char name[BPF_OBJ_NAME_LEN];
    /** Hook to attach the link to, this field will impact the
     * @c bpf_attach_type property of the link. */
    enum bf_hook hook;
    /** File descriptor of the link, only valide once the link object has been
     * created. */
    int fd;
};

struct bf_marsh;

#define _cleanup_bf_link_ __attribute__((__cleanup__(bf_link_free)))

/**
 * Convenience macro to intialize a list of @ref bf_link .
 *
 * @return An initialized @ref bf_list that can contain @ref bf_link objects,
 *         with its @ref bf_list_ops properly configured.
 */
#define bf_link_list()                                                         \
    ((bf_list) {.ops = {.free = (bf_list_ops_free)bf_link_free,                \
                        .marsh = (bf_list_ops_marsh)bf_link_marsh}})

/**
 * Allocate and initializes a new BPF link object.
 *
 * @note This function won't creae a new BPF link, but a bpfilter-specific
 * object used to keep track of a BPF link on the system.
 *
 * @param link Link to allocate and initialize. Can't be NULL. On success,
 *        @c *link points to a valid @ref bf_link . On failure, @c *link
 *        remain unchanged.
 * @param name Name of the link. See @ref bf_link for details.
 * @param hook Hook to attach the link to. See @ref bf_link for details.
 * @return 0 on success, or a negative errno value on success.
 */
int bf_link_new(struct bf_link **link, const char *name, enum bf_hook hook);

/**
 * Create a new BPF link object from serialized data.
 *
 * @param link BPF link object to allocated and initialize from the serialized
 *        data. The caller will own the object. On success, @c *link points to
 *        a valid BPF link object. On failure, @c *link is unchanged. Can't be
 *        NULL.
 * @param dir_fd File descriptor of the directory to open the pinned link from.
 *        BPF link objects are always pinned relative to a directory, if
 *        @p dir_fd is -1, @ref bf_link_new_from_marsh assumes the link hasn't
 *        been pinned.
 * @param marsh Serialized BPF link object data. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_link_new_from_marsh(struct bf_link **link, int dir_fd,
                           const struct bf_marsh *marsh);

/**
 * Free a bf_link object.
 *
 * The BPF link's file descriptor contained in @c link is closed and set to
 * @c -1 . To prevent the BPF link from being destroy (and the BPF program
 * detached from its hook), pin it beforehand.
 *
 * @param link @ref bf_link object to free. On success, @c *link is set to NULL,
 *        On failure, @c *link is unchanged.
 */
void bf_link_free(struct bf_link **link);

/**
 * Serializes a BPF link object.
 *
 * @param link BPF link object to serialize. The object itself won't be modified.
 *        Can't be NULL.
 * @param marsh Marsh object, will be allocated by this function and owned by
 *        the caller. On success, @c *marsh will point to the BPF link's
 *        serialized data. On failure, @c *marsh is unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_marsh(const struct bf_link *link, struct bf_marsh **marsh);

/**
 * Dump a @c bf_link object.
 *
 * @param link @c bf_link object to dump. Can't be NULL.
 * @param prefix String to prefix each log with. If no prefix is needed, use
 *               @ref EMPTY_PREFIX . Can't be NULL.
 */
void bf_link_dump(const struct bf_link *link, prefix_t *prefix);

/**
 * Attach a program to an XDP hook using the link.
 *
 * @param link Link to create on the system. Can't be NULL.
 * @param prog_fd File descriptor of the program to attach. Must be a valid
 *        file descriptor.
 * @param ifindex Index of the interface to attach the program to.
 * @param mode Attach mode, see @ref bf_xdp_attach_mode .
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_attach_xdp(struct bf_link *link, int prog_fd, unsigned int ifindex,
                       enum bf_xdp_attach_mode mode);

/**
 * Attach a program to a TC hook using the link.
 *
 * @param link Link to create on the system. Can't be NULL.
 * @param prog_fd File descriptor of the program to attach. Must be a valid
 *        file descriptor.
 * @param ifindex Index of the interface to attach the program to.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_attach_tc(struct bf_link *link, int prog_fd, unsigned int ifindex);

/**
 * Attach a program to a Netfilter hook using the link.
 *
 * @param link Link to create on the system. Can't be NULL.
 * @param prog_fd File descriptor of the program to attach. Must be a valid
 *        file descriptor.
 * @param family Packet family to use, either @c NFPROTO_IPV4 or @c NFPROTO_IPV6 .
 * @param priority Priority to assign to the link. Will fail if a link with
 *        the same priority is already attached to the same hook.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_attach_nf(struct bf_link *link, int prog_fd, unsigned int family,
                      int priority);

/**
 * Attach a program to a cgroup hook using the link.
 *
 * @param link Link to create on the system. Can't be NULL.
 * @param prog_fd File descriptor of the program to attach. Must be a valid
 *        file descriptor.
 * @param cgroup_path Path of the cgroup to attach the program to. Can't be
 *        NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_attach_cgroup(struct bf_link *link, int prog_fd,
                          const char *cgroup_path);

/**
 * Replace the program attached to the link.
 *
 * BPF link allows for the program they attach to, to be replaced atomically
 * with another program. Not all the hooks support this feature.
 *
 * @param link Link to update. Can't be NULL.
 * @param new_prog_fd File descriptor of the new program to attach to the link.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_update(struct bf_link *link, int new_prog_fd);

/**
 * Detach the BPF link from the hook.
 *
 * @param link Link to detach. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_link_detach(struct bf_link *link);

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
 * @param dir_fd File descriptor of the directory to unpin the link from. Must be
 *        a valid file descriptor.
 */
void bf_link_unpin(struct bf_link *link, int dir_fd);

int bf_link_get_info(struct bf_link *link, struct bpf_link_info *info);
