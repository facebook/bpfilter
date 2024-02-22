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
