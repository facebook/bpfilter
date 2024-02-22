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
struct nlattr;
struct nla_policy;

typedef struct nlattr bf_nfattr;
typedef struct nla_policy bf_nfpolicy;

/// Netlink validation policy for @c nft_table_attributes
extern const bf_nfpolicy *bf_nf_table_policy;
/// Netlink validation policy for @c nft_chain_attributes
extern const bf_nfpolicy *bf_nf_chain_policy;
/// Netlink validation policy for @c nft_hook_attributes
extern const bf_nfpolicy *bf_nf_hook_policy;
/// Netlink validation policy for @c nft_rule_attributes
extern const bf_nfpolicy *bf_nf_rule_policy;
/// Netlink validation policy for @c nft_expr_attributes
extern const bf_nfpolicy *bf_nf_expr_policy;
/// Netlink validation policy for @c nft_counter_attributes
extern const bf_nfpolicy *bf_nf_counter_policy;
/// Netlink validation policy for @c nft_payload_attributes
extern const bf_nfpolicy *bf_nf_payload_policy;
/// Netlink validation policy for @c nft_cmp_attributes
extern const bf_nfpolicy *bf_nf_cmp_policy;
/// Netlink validation policy for @c nft_immediate_attributes
extern const bf_nfpolicy *bf_nf_immediate_policy;
/// Netlink validation policy for @c nft_data_attributes
extern const bf_nfpolicy *bf_nf_data_policy;
/// Netlink validation policy for @c nft_verdict_attributes
extern const bf_nfpolicy *bf_nf_verdict_policy;

/**
 * @file nfmsg.h
 * @section nfmsg_section Messages
 *
 * @ref bf_nfmsg is a structure used to represent Netlink messages. It is an
 * opaque structure, so the user must go through the dedicated API to create,
 * parse, and manipulate Netlink messages.
 *
 * Netlink attributes can be pushed into the message using the generic function
 * @ref bf_nfmsg_attr_push. However, for common types, convenience macros are
 * provided to push a string, a @c uint8_t, a @c uint16_t, a @c uint32_t, or a
 * @c uint64_t attribute.
 */

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

/**
 * Parse attributes from a Netfilter Netlink message.
 *
 * All the attributes contained in the message are parsed and stored in the
 * @p attrs array. Nested attributes (attributes contained within other) are
 * not parsed, see @ref bf_nfattr_parse instead.
 *
 * @param msg Message to parse the attributes from. Can't be NULL.
 * @param attrs Array of attributes to parse. Can't be NULL.
 * @param maxtype Maximum attribute type to parse.
 * @param policy Netlink validation policy to use. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_nfmsg_parse(const struct bf_nfmsg *msg, bf_nfattr **attrs, int maxtype,
                   const bf_nfpolicy *policy);

/**
 * @file nfmsg.h
 * @section nfattr_section Attributes
 *
 * @ref bf_nfattr is a structure used to represent Netlink attributes. It is an
 * opaque structure, so the user must go through the dedicated API to create,
 * parse, and manipulate Netlink attributes.
 */

/**
 * Parse attributes nested within a Netlink attribute.
 *
 * All the attributes contained in the @p attr are parsed and stored in the
 * @p attrs array.
 *
 * @param attr Attribute to parse the nested attributes from. Can't be NULL.
 * @param attrs Array of attributes to parse. Can't be NULL.
 * @param maxtype Maximum attribute type to parse.
 * @param policy Netlink validation policy to use. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_nfattr_parse(bf_nfattr *attr, bf_nfattr **attrs, int maxtype,
                    const bf_nfpolicy *policy);

/**
 * Get the data of a Netlink attribute.
 *
 * @param attr Attribute to get the data from. Can't be NULL.
 * @return Pointer to the attribute's data.
 */
void *bf_nfattr_data(bf_nfattr *attr);

/**
 * Get a Netlink attribute's data as a string.
 *
 * @param attr Attribute to get the data from. Can't be NULL.
 * @return Pointer to the attribute's data.
 */
#define bf_nfattr_get_str(attr) ((char *)bf_nfattr_data(attr))

/**
 * Get a Netlink attribute's data as a @c uint8_t.
 *
 * @param attr Attribute to get the data from. Can't be NULL.
 * @return Pointer to the attribute's data.
 */
#define bf_nfattr_get_u8(attr) (*(uint8_t *)bf_nfattr_data(attr))

/**
 * Get a Netlink attribute's data as a @c uint16_t.
 *
 * @param attr Attribute to get the data from. Can't be NULL.
 * @return Pointer to the attribute's data.
 */
#define bf_nfattr_get_u16(attr) (*(uint16_t *)bf_nfattr_data(attr))

/**
 * Get a Netlink attribute's data as a @c uint32_t.
 *
 * @param attr Attribute to get the data from. Can't be NULL.
 * @return Pointer to the attribute's data.
 */
#define bf_nfattr_get_u32(attr) (*(uint32_t *)bf_nfattr_data(attr))

/**
 * Get a Netlink attribute's data as a @c uint64_t.
 *
 * @param attr Attribute to get the data from. Can't be NULL.
 * @return Pointer to the attribute's data.
 */
#define bf_nfattr_get_u64(attr) (*(uint64_t *)bf_nfattr_data(attr))

/**
 * @file nfmsg.h
 * @section nfnest_section Nested attributes
 *
 * @ref bf_nfnest represent a virtual stack of nested attributes. It is used to
 * create and close nested attributes within a Netlink message.
 *
 * @ref bf_nfmsg_nest_init declares a new nested attribute within a
 * @ref bf_nfmsg. Every attribute added to the message after calling this
 * function will be pushed within the nested attribute. When complete, @ref
 * bf_nfnest_cleanup must be called to close the nested attribute.

 * The nested attribute is a stack, so it is possible to have nested attributes
 *within nested attributes.
 */

/**
 * Cleanup attribute for a @ref bf_nfnest variable.
 */
#define _cleanup_bf_nfnest_ __attribute__((__cleanup__(bf_nfnest_cleanup)))

/**
 * Convenience macro to create a new nested attribute context or jump to
 * @c bf_nfmsg_push_failure on failure.
 *
 * @param parent @ref bf_nfmsg to create the nested attribute into. Can't be
 * NULL.
 * @param type Type of the nested attribute.
 * @return 0 on success, or negative errno value on error.
 */
#define bf_nfnest_or_jmp(parent, type)                                         \
    ({                                                                         \
        struct bf_nfnest __nest;                                               \
        int __r = bf_nfmsg_nest_init(&__nest, parent, type);                   \
        if (__r)                                                               \
            goto bf_nfmsg_push_failure;                                        \
        __nest;                                                                \
    })

struct bf_nfnest
{
    struct bf_nfmsg *parent;
    bf_nfattr *attr;
};

/**
 * @brief Declares a new nested attribute within @p parent.
 *
 * Once a nested attribute has been defined, all the attributes added to the
 * part (@p parent here) will be added within the nested attribute, until it
 * is closed (@ref bf_nfnest_cleanup).
 *
 * @param nest Pointer to the nested attribute. Must be an allocated @ref
 * bf_nfmsg_next structure. Can't be NULL.
 * @param parent @ref bf_nfmsg containing the nested attribute.
 * @param type Type of the nested attribute.
 * @return 0 on success, negative errno value on error.
 */
int bf_nfmsg_nest_init(struct bf_nfnest *nest, struct bf_nfmsg *parent,
                       uint16_t type);

/**
 * @brief Close a nested attribute.
 *
 * @param nest Nested attribute to close. Can't be NULL.
 */
void bf_nfnest_cleanup(struct bf_nfnest *nest);
