/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
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
 *   the type to the payload contained in the matcher. For example, we
 *   want the matcher to match when the IPv4 destination address is equal to
 *   the IP address in the payload.
 * - A payload, which is compared to the similar value in the network packet.
 */

struct bf_matcher;
struct bf_marsh;

/// Automatically destroy @ref bf_matcher objects going out of the scope.
#define _free_bf_matcher_ __attribute__((__cleanup__(bf_matcher_free)))

/**
 * Matcher type.
 *
 * The matcher type define which header/field of a packet is to be used to
 * match against the payload.
 */
enum bf_matcher_type
{
    /// Matches the packet's network interface index. On ingress it represents
    /// the input interface, on egress the output interface.
    BF_MATCHER_META_IFACE,
    /// Matches the L3 protocol.
    BF_MATCHER_META_L3_PROTO,
    /// Matches the L4 protocol, idependently from the L3 protocol.
    BF_MATCHER_META_L4_PROTO,
    /// Matches packets based on a random probability
    BF_MATCHER_META_PROBABILITY,
    /// Matches the source port for UDP and TCP packets.
    BF_MATCHER_META_SPORT,
    /// Matches the destination port for UDP and TCP packets.
    BF_MATCHER_META_DPORT,
    /// Matches IPv4 source address.
    BF_MATCHER_IP4_SADDR,
    /// Matches IPv4 source network.
    BF_MATCHER_IP4_SNET,
    /// Matches IPv4 destination address.
    BF_MATCHER_IP4_DADDR,
    /// Matches IPv4 destination network.
    BF_MATCHER_IP4_DNET,
    /// Matches against the IPv4 protocol field
    BF_MATCHER_IP4_PROTO,
    /// Matches IPv6 source address.
    BF_MATCHER_IP6_SADDR,
    /// Matches IPv6 source network.
    BF_MATCHER_IP6_SNET,
    /// Matches IPv6 destination address.
    BF_MATCHER_IP6_DADDR,
    /// Matches IPv6 destination network.
    BF_MATCHER_IP6_DNET,
    /// Matches IPv6 next header
    BF_MATCHER_IP6_NEXTHDR,
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
    /// Matches against the ICMP type
    BF_MATCHER_ICMP_TYPE,
    /// Matches against the ICMP code
    BF_MATCHER_ICMP_CODE,
    /// Matches against the ICMPv6 type
    BF_MATCHER_ICMPV6_TYPE,
    /// Matches against the ICMPv6 code
    BF_MATCHER_ICMPV6_CODE,
    /// Matches in a set, the set knows how to build the key from the packet
    BF_MATCHER_SET,
    _BF_MATCHER_TYPE_MAX,
};

/**
 * Defines the structure of the payload for bf_matcher's
 * @ref BF_MATCHER_IP4_SADDR and @ref BF_MATCHER_IP4_DADDR types.
 */
struct bf_matcher_ip4_addr
{
    uint32_t addr;
    uint32_t mask;
};

/**
 * Defines the payload for the IPv6 address matcher.
 */
struct bf_matcher_ip6_addr
{
    /// 128-bits IPv6 address.
    uint8_t addr[16];
    /// 128-bits IPv6 mask.
    uint8_t mask[16];
};

/**
 * Define the IPv6 next headers.
 */
enum bf_matcher_ipv6_nh
{
    BF_IPV6_NH_HOP = 0,
    BF_IPV6_NH_TCP = 6,
    BF_IPV6_NH_UDP = 17,
    BF_IPV6_NH_ROUTING = 43,
    BF_IPV6_NH_FRAGMENT = 44,
    BF_IPV6_NH_AH = 51,
    BF_IPV6_NH_ICMPV6 = 58,
    BF_IPV6_NH_DSTOPTS = 60,
    BF_IPV6_NH_MH = 135,
    _BF_MATCHER_IPV6_NH_MAX,
};

/**
 * Define the TCP flags values as number of shifts of 1.
 */
enum bf_tcp_flag
{
    BF_TCP_FIN = 0,
    BF_TCP_SYN = 1,
    BF_TCP_RST = 2,
    BF_TCP_PSH = 3,
    BF_TCP_ACK = 4,
    BF_TCP_URG = 5,
    BF_TCP_ECE = 6,
    BF_TCP_CWR = 7,
    _BF_TCP_MAX,
};

static_assert(_BF_TCP_MAX <= 8,
              "too many TCP flags, they can't be used as bitmask in uint8_t");

/**
 * Matcher comparison operator.
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
    /// Test if the value is in a set
    BF_MATCHER_IN,
    /// Test if the value is in a range
    BF_MATCHER_RANGE,
    _BF_MATCHER_OP_MAX,
};

/**
 * Matcher definition.
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
    uint8_t payload[];
};

/**
 * @brief TCP/IP layer a matcher is applied to.
 */
enum bf_matcher_layer
{
    /** Special layer value if the matcher meta is undefined. */
    _BF_MATCHER_LAYER_UNDEFINED = 0,

    /** Some matchers do not apply to the packet, but to its metadata. */
    BF_MATCHER_NO_LAYER = 1,

    BF_MATCHER_LAYER_2 = 2,
    BF_MATCHER_LAYER_3 = 3,
    BF_MATCHER_LAYER_4 = 4,
    _BF_MATCHER_LAYER_MAX,
};

/**
 * @brief Meta structure to support matchers processing.
 *
 * Defines characteristics for a specific meta type in order to support
 * generic-ish bytecode generation. Each matcher should have its associated
 * `bf_matcher_meta` structure so bpfilter can process it.
 */
struct bf_matcher_meta
{
    /** TCP/IP model layer to apply the matcher to. */
    enum bf_matcher_layer layer;

    /** Identifier of the protocol supported by the matcher. Used with `layer`,
     * this value will allow the BPF program to define if the matcher can be
     * applied to the processed packet. */
    uint32_t hdr_id;

    /** Size of the payload processed by the matcher. This payload is the data
     * read from the packet, not the user-provided data. */
    size_t hdr_payload_size;

    /** Offset of the payload in the packet header. */
    size_t hdr_payload_offset;

    /** Operator-specific parameters to process the user-specific data.
     * Undefined operators are considered unsupported. */
    struct bf_matcher_ops
    {
        /** Size of the payload to store in the matcher. This payload will be
         * compared against the packet's payload. In some cases, this payload
         * size is different from `hdr_payload_size` (e.g. ip4.snet). */
        size_t ref_payload_size;

        /** Callback function to parse the matcher's raw payload */
        int (*parse)(enum bf_matcher_type type, enum bf_matcher_op op,
                     void *payload, const char *raw_payload);

        /** Callback function to pretty print the matcher's payload. */
        void (*print)(const void *payload);
    } ops[_BF_MATCHER_OP_MAX];
};

/**
 * Allocate and initalise a new matcher.
 *
 * @param matcher Matcher object to allocate and initialise. Can't be NULL. On
 *        success, contain a pointer to the matcher object, unchanged on error.
 * @param type Matcher type.
 * @param op Comparison operator.
 * @param payload Payload of the matcher, its content and size depends on
 *        @p type . Can be NULL but only if @p payload_len is 0, in which case
 *        there is no payload.
 * @param payload_len Length of the payload.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const void *payload,
                   size_t payload_len);

/**
 * @brief Allocate and initialise a new matcher from a raw payload (string).
 *
 * @param matcher Matcher object to allocate and initialise. Can't be NULL. On
 *        success, contain a pointer to the matcher object, unchanged on error.
 * @param type Matcher type.
 * @param op Comparison operator.
 * @param payload Raw payload, as a string, to parse and populate the matcher
 *        with. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_new_from_raw(struct bf_matcher **matcher,
                            enum bf_matcher_type type, enum bf_matcher_op op,
                            const char *payload);

/**
 * Allocate a new matcher and initialise it from serialised data.
 *
 * @param matcher On success, points to the newly allocated and initialised
 *        matcher. Can't be NULL.
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
 * Serialise a matcher.
 *
 * @param matcher Matcher object to serialise. Can't be NULL.
 * @param marsh On success, contains the serialised matcher. Can't be NULL.
 */
int bf_matcher_marsh(const struct bf_matcher *matcher, struct bf_marsh **marsh);

/**
 * Dump a matcher.
 *
 * @param matcher Matcher to dump.
 * @param prefix Prefix for each printed line.
 */
void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix);

/**
 * @brief Get meta structure for a given matcher type.
 *
 * @param type Type of the matcher to get the meta for.
 * @return A pointer to a `bf_matcher_meta` structure, or NULL if not found.
 */
const struct bf_matcher_meta *bf_matcher_get_meta(enum bf_matcher_type type);

/**
 * @brief Get operations structure for a given (matcher type, matcher op) tuple.
 *
 * @param type Type of matcher to get the operations for.
 * @param op Operator to get the matcher for.
 * @return A pointer to a `bf_matcher_ops` structure, or NULL if not found.
 */
const struct bf_matcher_ops *bf_matcher_get_ops(enum bf_matcher_type type,
                                                enum bf_matcher_op op);

/**
 * Convert a matcher type to a string.
 *
 * @param type The matcher type to convert. Must be a valid
 *        @ref bf_matcher_type .
 * @return String representation of the matcher type.
 */
const char *bf_matcher_type_to_str(enum bf_matcher_type type);

/**
 * Convert a string to the corresponding matcher type.
 *
 * @param str String containing the name of a matcher type.
 * @param type Matcher type value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_type_from_str(const char *str, enum bf_matcher_type *type);

/**
 * Convert a matcher operator to a string.
 *
 * @param op The matcher operator to convert. Must be a valid @ref bf_matcher_op
 * @return String representation of the matcher operator.
 */
const char *bf_matcher_op_to_str(enum bf_matcher_op op);

/**
 * Convert a string to the corresponding matcher operator.
 *
 * @param str String containing the name of a matcher operator.
 * @param op Matcher operator value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_op_from_str(const char *str, enum bf_matcher_op *op);

/**
 * @brief Convert a TCP flag to a string.
 *
 * @param flag TCP flag to convert.
 * @return String representation of the TCP flag.
 */
const char *bf_tcp_flag_to_str(enum bf_tcp_flag flag);

/**
 * @brief Convert a string to the corresponding TCP flag.
 *
 * @param str String containing the name of the TCP flag.
 * @param flag TCP flag value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_tcp_flag_from_str(const char *str, enum bf_tcp_flag *flag);

/**
 * Convert a IPv6 next-header to a string.
 *
 * @param nexthdr IPv6 next-header to convert.
 * @return String representation of the IPv6 next-header.
 */
const char *bf_matcher_ipv6_nh_to_str(enum bf_matcher_ipv6_nh nexthdr);

/**
 * Convert a string to the corresponding IPv6 next-header.
 *
 * @param str String containing the name of the IPv6 next-header.
 * @param nexthdr IPv6 next-header value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_matcher_ipv6_nh_from_str(const char *str,
                                enum bf_matcher_ipv6_nh *nexthdr);

const char *bf_ethertype_to_str(uint16_t ethertype);
int bf_ethertype_from_str(const char *str, uint16_t *ethertype);

const char *bf_ipproto_to_str(uint8_t ipproto);
int bf_ipproto_from_str(const char *str, uint8_t *ipproto);

const char *bf_icmp_type_to_str(uint8_t type);
int bf_icmp_type_from_str(const char *str, uint8_t *type);

const char *bf_icmpv6_type_to_str(uint8_t type);
int bf_icmpv6_type_from_str(const char *str, uint8_t *type);
