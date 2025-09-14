/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/list.h>

struct nlmsghdr;
struct bf_nfgroup;
struct bf_response;
struct bf_nfmsg;

/**
 * @file nfgroup.h
 *
 * Netlink allows data to be sent in multipart messages, which is a stream
 * of multiple Netlink messages (each with its own header), flagged with
 * @c NLM_F_MULTI and ending with a final message of type @c NLMSG_DONE
 *
 * @ref bf_nfgroup is an abstraction to represent multipart messages. It
 * contains a list of @ref bf_nfmsg, each of which is a Netlink message.
 *
 * The messages group can be converted into a single @ref bf_response, which
 * is a contiguous buffer containing all the messages in the group.
 */

/**
 * Cleanup function for @ref bf_nfgroup.
 */
#define _free_bf_nfgroup_ __attribute__((__cleanup__(bf_nfgroup_free)))

/**
 * Create a new Netlink messages group.
 *
 * @param group Pointer to the new messages group. Must not be NULL. Will be
 *        allocated and initialised by this function. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_new(struct bf_nfgroup **group);

/**
 * Create a new Netlink messages group from a stream of @p nlmsghdr.
 *
 * @param group Pointer to the new message group. Must not be NULL. Will be
 *        allocated and initialised by this function.
 * @param nlh Pointer to the first @p nlmsghdr in the stream. Must not be
 *        NULL.
 * @param length Total length of the stream.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_new_from_stream(struct bf_nfgroup **group, struct nlmsghdr *nlh,
                               size_t length);

/**
 * Free a Netlink messages group.
 *
 * @param group Pointer to the messages group to free. If @p msg is NULL, nothing
 *        is done.
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
 * @param msg Message to add to the messages group. Can't be NULL. The Netlink
 *        messages group takes onwership of the message.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_add_message(struct bf_nfgroup *group, struct bf_nfmsg *msg);

/**
 * Create a new Netfilter Netlink message and add it to a Netlink messages
 * group.
 *
 * The new Netfilter Netlink message is owned by the messages group and should
 * not be freed by the caller.
 *
 * @param group Netlink messages group to add the message to. Can't be NULL.
 * @param msg Pointer to the new message. Once the function succeeds, this
 *        pointer will be set to the new message. Can be NULL, in which case the
 *        caller won't have access to the new message.
 * @param command Netlink message command.
 * @param seqnr Netlink message sequence number.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_add_new_message(struct bf_nfgroup *group, struct bf_nfmsg **msg,
                               uint16_t command, uint16_t seqnr);

/**
 * Convert a Netlink messages group into a bf_response.
 *
 * All the Netfilter Netlink messages contained in the group will written
 * contiguously in the payload of a single @c bf_response .
 *
 * If only one message is present in the group, the response will contain only
 * the message payload. If more than one message is present, the response will
 * contain a multipart message, with the @c NLM_F_MULTI flag set on all the
 * messages and a final @c NLMSG_DONE message.
 *
 * If the group is empty, the reponse will contain a single @c NLMSG_DONE
 * message.
 *
 * @param group Netlink messages group to convert. Can't be NULL.
 * @param resp Pointer to the new response. Can't be NULL. A new response will
 *        be allocated by this function and the caller will be responsible for
 *        freeing it.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nfgroup_to_response(const struct bf_nfgroup *group,
                           struct bf_response **resp);
