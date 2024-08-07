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
    /// Matches IP source address.
    BF_MATCHER_IP_SRC_ADDR,
    /// Matches IP destination address.
    BF_MATCHER_IP_DST_ADDR,
    /// Matches against the IP protocol field
    BF_MATCHER_IP_PROTO,
    _BF_MATCHER_TYPE_MAX,
};

/**
 * @brief Defines the structure of the payload for bf_matcher's
 * BF_MATCHER_IP_SRC_ADDR and BF_MATCHER_IP_DST_ADDR types.
 */
struct bf_matcher_ip_addr
{
    uint32_t addr;
    uint32_t mask;
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
    _BF_MATCHER_OP_MAX,
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
                   enum bf_matcher_op op, const uint8_t *payload,
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
 * @brief Convert a matcher operator to a string.
 *
 * @param op The matcher operator to convert. Must be a valid @ref bf_matcher_op
 * @return String representation of the operator.
 */
const char *bf_matcher_op_to_str(enum bf_matcher_op op);
