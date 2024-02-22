/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @file nfmsg.h
 *
 * @c nftables communicates with the kernel using Netlink messages. To reduce
 * the work needed by @c nftables to support @c bpfilter the same communication
 * mechanism is used. Hence, @c bpfilter will receive Netlink messages from
 * @c nftables and will send Netlink messages to @c nftables.
 *
 * This file provides a set of functions to create, parse, and manipulate
 * Netlink messages. It also provides a set of Netlink validation policies for
 * the different Netlink attributes used by @c nftables.
 *
 * All the functions defined in this file are dedicated to Netfilter Netlink
 * messages and are not suitable for generic Netlink communication.
 */

struct nlmsghdr;
struct bf_nfmsg;

/**
 * Cleanup attribute for a @ref bf_nfmsg variable.
 */
#define _cleanup_bf_nfmsg_ __attribute__((__cleanup__(bf_nfmsg_free)))

/**
 * Create a new Netfilter Netlink message.
 *
 * @param msg The new message to allocate and initialise. Can't be NULL.
 * @param command Command to send, can be any of @c nf_tables_msg_types.
 * @param seqnr Sequence number for the message.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_nfmsg_new(struct bf_nfmsg **msg, uint8_t command, uint32_t seqnr);

/**
 * Create a new Netfilter Netlink message from an existing Netlink message.
 *
 * The provided @p nlmsghdr must be a valid Netlink message targeted to the
 * @c NFNL_SUBSYS_NFTABLES subsystem, and containing a @c nfgenmsg
 * header.
 *
 * @param msg The new message to allocate and initialise. Can't be NULL.
 * @param nlh Netlink message to create the Netfilter Netlink message from.
 * Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_nfmsg_new_from_nlmsghdr(struct bf_nfmsg **msg, struct nlmsghdr *nlh);

/**
 * Free a Netfilter Netlink message.
 *
 * If @c msg is NULL, this function has no effect. Before returning, @c msg is
 * set to NULL.
 *
 * @param msg Message to free. Must be non-NULL.
 */
void bf_nfmsg_free(struct bf_nfmsg **msg);

/**
 * Get the Netlink message header for a Netfilter Netlink message.
 *
 * @param msg Message to get the header from. Must be non-NULL.
 * @return The Netlink message header.
 */
struct nlmsghdr *bf_nfmsg_hdr(const struct bf_nfmsg *msg);

/**
 * Get a Netfilter Netlink message's size, including header and padding.
 *
 * @param msg Message to get the size of. Can't be NULL.
 * @return Message's size, including header and padding.
 */
size_t bf_nfmsg_len(const struct bf_nfmsg *msg);

/**
 * Get a Netfilter Netlink message's payload size, including padding.
 *
 * @param msg Message to get the payload size of. Can't be NULL.
 * @return Message's payload size, including padding.
 */
size_t bf_nfmsg_data_len(const struct bf_nfmsg *msg);

/**
 * Get a Netfilter Netlink message's command.
 *
 * @param msg Message to get the command from. Can't be NULL.
 * @return The message's command.
 */
uint8_t bf_nfmsg_command(const struct bf_nfmsg *msg);

/**
 * Get a Netfilter Netlink message's sequence number.
 *
 * @param msg Message to get the sequence number from. Can't be NULL.
 * @return The message's sequence number.
 */
uint32_t bf_nfmsg_seqnr(const struct bf_nfmsg *msg);

/**
 * Push a new attribute into a Netfilter Netlink message.
 *
 * @param msg Message to push the attribute to. Can't be NULL.
 * @param type Attribute type.
 * @param data Attribute data. Can't be NULL.
 * @param len Attribute data length.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_nfmsg_attr_push(struct bf_nfmsg *msg, uint16_t type, const void *data,
                       size_t len);

/**
 * Convenience macro to push a new attribute into a Netfilter Netlink message,
 * but jump to a label on failure.
 *
 * If the attribute push fails, this macro jumps to the label
 * @c bf_nfmsg_push_failure.
 *
 * @param msg Message to push the attribute to. Can't be NULL.
 * @param type Attribute type.
 * @param data Attribute data. Can't be NULL.
 * @param size Attribute data length.
 */
#define bf_nfmsg_attr_push_or_jmp(msg, type, data, size)                       \
    ({                                                                         \
        if (bf_nfmsg_attr_push(msg, type, data, size) < 0)                     \
            goto bf_nfmsg_push_failure;                                        \
    })

/**
 * Convenience macro to push a new string attribute into a Netfilter Netlink
 * message. See @ref bf_nfmsg_attr_push for more details.
 */
#define bf_nfmsg_push_str(msg, attr, data)                                     \
    bf_nfmsg_attr_push(msg, attr, data, strlen(data) + 1)

/**
 * Convenience macro to push a new string attribute into a Netfilter Netlink
 * message, and jump to a label on failure. See @ref bf_nfmsg_attr_push_or_jmp
 * for more details.
 */
#define bf_nfmsg_push_str_or_jmp(part, attr, value)                            \
    bf_nfmsg_attr_push_or_jmp(part, attr, value, strlen(value) + 1)

/**
 * Convenience macro to push a new uint8_t attribute into a Netfilter Netlink
 * message. See @ref bf_nfmsg_attr_push for more details.
 */
#define bf_nfmsg_push_u8(msg, attr, data)                                      \
    bf_nfmsg_attr_push(msg, attr, (&(uint8_t) {data}), sizeof(uint8_t))

/**
 * Convenience macro to push a new uint8_t attribute into a Netfilter Netlink
 * message, and jump to a label on failure. See @ref bf_nfmsg_attr_push_or_jmp
 * for more details.
 */
#define bf_nfmsg_push_u8_or_jmp(msg, attr, data)                               \
    bf_nfmsg_attr_push_or_jmp(msg, attr, (&(uint8_t) {data}), sizeof(uint8_t))

/**
 * Convenience macro to push a new uint16_t attribute into a Netfilter Netlink
 * message. See @ref bf_nfmsg_attr_push for more details.
 */
#define bf_nfmsg_push_u16(msg, attr, data)                                     \
    bf_nfmsg_attr_push(msg, attr, (&(uint16_t) {data}), sizeof(uint16_t))

/**
 * Convenience macro to push a new uint16_t attribute into a Netfilter Netlink
 * message, and jump to a label on failure. See @ref bf_nfmsg_attr_push_or_jmp
 * for more details.
 */
#define bf_nfmsg_push_u16_or_jmp(msg, attr, data)                              \
    bf_nfmsg_attr_push_or_jmp(msg, attr, (&(uint16_t) {data}), sizeof(uint16_t))

/**
 * Convenience macro to push a new uint32_t attribute into a Netfilter Netlink
 * message. See @ref bf_nfmsg_attr_push for more details.
 */
#define bf_nfmsg_push_u32(msg, attr, data)                                     \
    bf_nfmsg_attr_push(msg, attr, (&(uint32_t) {data}), sizeof(uint32_t))

/**
 * Convenience macro to push a new uint32_t attribute into a Netfilter Netlink
 * message, and jump to a label on failure. See @ref bf_nfmsg_attr_push_or_jmp
 * for more details.
 */
#define bf_nfmsg_push_u32_or_jmp(msg, attr, data)                              \
    bf_nfmsg_attr_push_or_jmp(msg, attr, (&(uint32_t) {data}), sizeof(uint32_t))

/**
 * Convenience macro to push a new uint64_t attribute into a Netfilter Netlink
 * message. See @ref bf_nfmsg_attr_push for more details.
 */
#define bf_nfmsg_push_u64(msg, attr, data)                                     \
    bf_nfmsg_attr_push(msg, attr, (&(uint64_t) {data}), sizeof(uint64_t))

/**
 * Convenience macro to push a new uint64_t attribute into a Netfilter Netlink
 * message, and jump to a label on failure. See @ref bf_nfmsg_attr_push_or_jmp
 * for more details.
 */
#define bf_nfmsg_push_u64_or_jmp(msg, attr, data)                              \
    bf_nfmsg_attr_push_or_jmp(msg, attr, (&(uint64_t) {data}), sizeof(uint64_t))
