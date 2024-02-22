/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "core/list.h"

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
 * Get the list of messages in the Netlink messages group.
 *
 * @param group Netlink messages group to get the list from. Can't be NULL.
 * @return @ref bf_list containing the @ref bf_nfmsg
 */
const bf_list *bf_nfgroup_messages(const struct bf_nfgroup *group);

/**
 * Get the total Netlink message size.
 *
 * The total size of the Netlink message is the sum of the size of all the
 * messages, including padding.
 *
 * @param group Netlink messages group to get the size of. Can't be NULL.
 * @return Total size of the Netlink messages group.
 */
size_t bf_nfgroup_size(const struct bf_nfgroup *group);

/**
 * Test if a Netlink message group is empty.
 *
 * @param group Netlink message to check. Can't be NULL.
 * @return True if the Netlink message is empty (no messages), false otherwise.
 */
bool bf_nfgroup_is_empty(const struct bf_nfgroup *group);

/**
 * Add a Netlink message to the Netlink messages group.
 *
 * @param group Netlink messages group to add the message to. Can't be NULL.
 * @param group Message to add to the messages group. Can't be NULL. The Netlink
 * messages group takes onwership of the message.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_add_message(struct bf_nfgroup *group, struct bf_nfmsg *msg);
