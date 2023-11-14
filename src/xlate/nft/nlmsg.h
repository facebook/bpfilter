/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/dump.h"
#include "core/list.h"

struct bf_response;
struct bf_nlmsg;
struct bf_nlpart;
struct nlmsghdr;

#define _cleanup_bf_nlmsg_ __attribute__((__cleanup__(bf_nlmsg_free)))

/**
 * @brief Create a new Netlink message.
 *
 * @param msg Pointer to the new message. Must not be NULL. Will be allocated
 * and initialised by this function.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlmsg_new(struct bf_nlmsg **msg);

/**
 * @brief Create a new Netlink message object from a stream of @ref nlmsghdr.
 *
 * @param msg Pointer to the new message. Must not be NULL. Will be allocated
 * and initialised by this function.
 * @param nlh Pointer to the first @ref nlmsghdr in the stream. Must not be
 * NULL.
 * @param length Total length of the stream.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlmsg_new_from_stream(struct bf_nlmsg **msg, struct nlmsghdr *nlh,
                             size_t length);

/**
 * @brief Free a Netlink message.
 *
 * @param msg Pointer to the message to free. If @p msg is NULL, nothing is
 * done.
 */
void bf_nlmsg_free(struct bf_nlmsg **msg);

const bf_list *bf_nlmsg_parts(const struct bf_nlmsg *msg);

/**
 * @brief Get the total Netlink message size.
 *
 * The total size of the Netlink message is the sum of the size of all the
 * parts, including padding.
 *
 * @param msg Netlink message to get the size of. Can't be NULL.
 * @return Total size of the Netlink message.
 */
size_t bf_nlmsg_size(const struct bf_nlmsg *msg);

/**
 * @brief Check if the Netlink message is empty.
 *
 * @param msg Netlink message to check. Can't be NULL.
 * @return True if the Netlink message is empty (no parts), false otherwise.
 */
bool bf_nlmsg_is_empty(const struct bf_nlmsg *msg);

/**
 * @brief Add a Netlink part to the Netlink message.
 *
 * @param msg Netlink message to add the part to. Can't be NULL.
 * @param part Part to add to the message. Can't be NULL. The Netlink
 * message takes onwership of the part.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlmsg_add_part(struct bf_nlmsg *msg, struct bf_nlpart *part);

/**
 * @brief Create a new Netlink part and add it to a Netlink message.
 *
 * @param msg Netlink message to add the part to. Can't be NULL.
 * @param part Pointer to the new part. If NULL, then this parameter is ignored,
 * otherwise it contains a pointer to the new part on success.
 * @param family Netlink message family.
 * @param command Netlink message command.
 * @param flags Netlink message flags.
 * @param seqnr Netlink message sequence number.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlmsg_add_new_part(struct bf_nlmsg *msg, struct bf_nlpart **part,
                          uint16_t family, uint16_t command, uint16_t flags,
                          uint16_t seqnr);

/**
 * @brief Convert the Netlink message into a bf_response.
 *
 * @param msg Netlink message to convert. Can't be NULL.
 * @param resp Pointer to the new response. It can't be NULL, but the response
 * can't be allocated, otherwise the memory will be leaked.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlmsg_to_response(const struct bf_nlmsg *msg, struct bf_response **resp);

/**
 * @brief Dump a Netlink message content.
 *
 * @param msg Netlink message to dump. Can't be NULL.
 * @param extra_hdr_len Extra header length of the Netlink parts.
 * @param prefix Prefix to use for the dump.
 */
void bf_nlmsg_dump(const struct bf_nlmsg *msg, size_t extra_hdr_len,
                   prefix_t *prefix);
