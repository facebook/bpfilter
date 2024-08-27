/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/dump.h"

/**
 * @file matcher.h
 *
 * Matchers are criteria used to match a network packet against a specific
 * rule. For example, a matcher could be used to match the destination IP
 * field of an IPv4 packet to a specific IP address.
 *
 * Matchers are composed of:
 * - A type, defining which data in the network packet to match the payload
 *   against. In the example about, the type would be related to IPv4
 *   destination address field.
 * - An operator, to know how to compare the data in the packet defined by
 *   the @ref type to the payload contained in the matcher. For example, we
 *   want the matcher to match when the IPv4 destination address is equal to
 *   the IP address in the payload.
 * - A payload, which is compared to the similar value in the network packet.
 */

struct bf_matcher;
struct bf_marsh;

/// Automatically destroy @ref bf_matcher objects going out of the scope.
#define _cleanup_bf_matcher_ __attribute__((__cleanup__(bf_matcher_free)))

/**
 * @brief Matcher type.
 *
 * The matcher type define which header/field of a packet is to be used to
 * match against the payload.
 */
enum bf_matcher_type
{
    /// Matches IPv4 source address.
    BF_MATCHER_IP4_SRC_ADDR,
    /// Matches IPv4 destination address.
    BF_MATCHER_IP4_DST_ADDR,
    /// Matches against the IPv4 protocol field
    BF_MATCHER_IP4_PROTO,
    /// Matches against the TCP source port
    BF_MATCHER_TCP_SPORT,
    /// Matches against the TCP destination port
    BF_MATCHER_TCP_DPORT,
    /// Matchers against the TCP flags
    BF_MATCHER_TCP_FLAGS,
    /// Matches against the UDP source port
    BF_MATCHER_UDP_SPORT,
    /// Matches against the UDP destination port
    BF_MATCHER_UDP_DPORT,
    _BF_MATCHER_TYPE_MAX,
};

/**
 * @brief Defines the structure of the payload for bf_matcher's
 * BF_MATCHER_IP4_SRC_ADDR and BF_MATCHER_IP4_DST_ADDR types.
 */
struct bf_matcher_ip4_addr
{
    uint32_t addr;
    uint32_t mask;
};

/**
 * Define the TCP flags values as number of shifts of 1.
 */
enum bf_matcher_tcp_flag
{
    BF_MATCHER_TCP_FLAG_FIN = 0,
    BF_MATCHER_TCP_FLAG_SYN = 1,
    BF_MATCHER_TCP_FLAG_RST = 2,
    BF_MATCHER_TCP_FLAG_PSH = 3,
    BF_MATCHER_TCP_FLAG_ACK = 4,
    BF_MATCHER_TCP_FLAG_URG = 5,
    BF_MATCHER_TCP_FLAG_ECE = 6,
    BF_MATCHER_TCP_FLAG_CWR = 7,
    _BF_MATCHER_TCP_FLAG_MAX,
};

/**
 * @brief Matcher comparison operator.
 *
 * The matcher comparison operator defines the type of comparison to operator
 * for a specific matcher.
 */
enum bf_matcher_op
{
    /// Test for equality.
    BF_MATCHER_EQ,
    /// Test for inequality.
    BF_MATCHER_NE,
    /// Test for partial subset match
    BF_MATCHER_ANY,
    /// Test for complete subset match
    BF_MATCHER_ALL,
    _BF_MATCHER_OP_MAX,
};

/**
 * @brief Matcher definition.
 *
 * Matchers are criterias to match the packet against. A set of matcher defines
 * what a rule should match on.
 */
struct bf_matcher
{
    /// Matcher type.
    enum bf_matcher_type type;
    /// Comparison operator.
    enum bf_matcher_op op;
    /// Total matcher size (including payload).
    size_t len;
    /// Payload to match the packet against (if any).
    uint8_t payload[0];
};

/**
 * @brief Allocate and initalise a new matcher.
 *
 * @param matcher Matcher object to allocate and initialise. Can't be NULL. On
 *  success, contain a pointer to the matcher object, unchanged on error.
 * @param type Matcher type.
 * @param op Comparison operator.
 * @param payload Payload of the matcher, its content and size depends on @ref
 * type. Can be NULL but only if @ref payload_len is 0, in which case there is
 * no payload.
 * @param payload_len Length of the payload.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const void *payload,
                   size_t payload_len);

/**
 * @brief Allocate a new matcher and initialise it from serialised data.
 *
 * @param matcher On success, points to the newly allocated and initialised
 *  matcher. Can't be NULL.
 * @param marsh Serialised data to use to initialise the matcher.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_new_from_marsh(struct bf_matcher **matcher,
                              const struct bf_marsh *marsh);

/**
 * Deinitialise and deallocate a matcher.
 *
 * @param matcher Matcher. Can't be NULL.
 */
void bf_matcher_free(struct bf_matcher **matcher);

/**
 * @brief Serialise a matcher.
 *
 * @param matcher Matcher object to serialise. Can't be NULL.
 * @param marsh On success, contains the serialised matcher. Can't be NULL.
 */
int bf_matcher_marsh(const struct bf_matcher *matcher, struct bf_marsh **marsh);

/**
 * @brief Dump a matcher.
 *
 * @param matcher Matcher to dump.
 * @param prefix Prefix for each printed line.
 */
void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix);

/**
 * @brief Convert a matcher type to a string.
 *
 * @param op The matcher type to convert. Must be a valid @ref bf_matcher_type
 * @return String representation of the matcher type.
 */
const char *bf_matcher_type_to_str(enum bf_matcher_type type);

/**
 * Convert a string to the corresponding matcher type.
 *
 * @param str String containing the name of a matcher type.
 * @param hook Matcher type value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_type_from_str(const char *str, enum bf_matcher_type *type);

/**
 * @brief Convert a matcher operator to a string.
 *
 * @param op The matcher operator to convert. Must be a valid @ref bf_matcher_op
 * @return String representation of the matcher operator.
 */
const char *bf_matcher_op_to_str(enum bf_matcher_op op);

/**
 * Convert a string to the corresponding matcher operator.
 *
 * @param str String containing the name of a matcher operator.
 * @param hook Matcher operator value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_op_from_str(const char *str, enum bf_matcher_op *op);

/**
 * Convert a TCP flag to a string.
 *
 * @param flag TCP flag to convert.
 * @return String representation of the TCP flag.
 */
const char *bf_matcher_tcp_flag_to_str(enum bf_matcher_tcp_flag flag);

/**
 * Convert a string to the corresponding TCP flag.
 *
 * @param str String containing the name of the TCP flag.
 * @param flag TCP flag value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_tcp_flag_from_str(const char *str,
                                 enum bf_matcher_tcp_flag *flag);
