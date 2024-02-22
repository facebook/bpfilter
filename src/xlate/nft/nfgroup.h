/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once
#include <stddef.h>
struct nlmsghdr;
struct bf_nfgroup;
struct bf_nfmsg;

/**
 * Cleanup function for @ref bf_nfgroup.
 */
#define _cleanup_bf_nfgroup_ __attribute__((__cleanup__(bf_nfgroup_free)))

/**
 * Create a new Netlink messages group.
 *
 * @param group Pointer to the new messages group. Must not be NULL. Will be
 * allocated and initialised by this function. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_new(struct bf_nfgroup **group);

/**
 * Create a new Netlink messages group from a stream of @ref nlmsghdr.
 *
 * @param msg Pointer to the new message. Must not be NULL. Will be allocated
 * and initialised by this function.
 * @param nlh Pointer to the first @ref nlmsghdr in the stream. Must not be
 * NULL.
 * @param length Total length of the stream.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_new_from_stream(struct bf_nfgroup **group, struct nlmsghdr *nlh,
                               size_t length);

/**
 * Free a Netlink messages group.
 *
 * @param msg Pointer to the messages group to free. If @p msg is NULL, nothing
 * is done.
 */
void bf_nfgroup_free(struct bf_nfgroup **group);

/**
 * Add a Netlink message to the Netlink messages group.
 *
 * @param group Netlink messages group to add the message to. Can't be NULL.
 * @param group Message to add to the messages group. Can't be NULL. The Netlink
 * messages group takes onwership of the message.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_add_message(struct bf_nfgroup *group, struct bf_nfmsg *msg);
