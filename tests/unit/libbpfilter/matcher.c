/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/matcher.h>

#include <arpa/inet.h>

#include "bpfilter/dump.h"
#include "bpfilter/pack.h"
#include "fake.h"
#include "test.h"

static void new_and_free(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    uint8_t payload[] = {1, 2, 3, 4};

    (void)state;

    // Create matcher with payload
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                            payload, sizeof(payload)));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_get_type(matcher), BF_MATCHER_IP4_SADDR);
    assert_int_equal(bf_matcher_get_op(matcher), BF_MATCHER_EQ);
    assert_int_equal(bf_matcher_payload_len(matcher), sizeof(payload));
    bf_matcher_free(&matcher);
    assert_null(matcher);

    // Create matcher with small payload
    uint8_t proto = 6; // TCP
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                            &proto, sizeof(proto)));
    assert_non_null(matcher);
}

static void new_with_payload(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    uint32_t addr = htonl(0x01020304); // 1.2.3.4

    (void)state;

    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                            &addr, sizeof(addr)));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_payload_len(matcher), sizeof(addr));
    assert_int_equal(*(uint32_t *)bf_matcher_payload(matcher), addr);
}

static void getters(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};

    (void)state;

    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_TCP_DPORT, BF_MATCHER_NE,
                            payload, sizeof(payload)));

    // Test all getters
    assert_int_equal(bf_matcher_get_type(matcher), BF_MATCHER_TCP_DPORT);
    assert_int_equal(bf_matcher_get_op(matcher), BF_MATCHER_NE);
    assert_int_equal(bf_matcher_payload_len(matcher), sizeof(payload));
    assert_non_null(bf_matcher_payload(matcher));
    assert_true(bf_matcher_len(matcher) > 0);

    // Verify payload content
    const uint8_t *p = bf_matcher_payload(matcher);
    for (size_t i = 0; i < sizeof(payload); ++i)
        assert_int_equal(p[i], payload[i]);
}

static void pack_and_unpack(void **state)
{
    _free_bf_matcher_ struct bf_matcher *source = NULL;
    _free_bf_matcher_ struct bf_matcher *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    uint16_t port = htons(80);

    (void)state;

    // Create and pack source matcher
    assert_ok(bf_matcher_new(&source, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                            &port, sizeof(port)));
    assert_ok(bf_wpack_new(&wpack));
    assert_ok(bf_matcher_pack(source, wpack));
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_matcher_new_from_pack(&destination, bf_rpack_root(rpack)));

    // Verify they're equal
    assert_true(bft_matcher_equal(source, destination));
}

static void pack_and_unpack_small_payload(void **state)
{
    _free_bf_matcher_ struct bf_matcher *source = NULL;
    _free_bf_matcher_ struct bf_matcher *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    uint8_t proto = 6; // TCP

    (void)state;

    // Create matcher with small payload
    assert_ok(bf_matcher_new(&source, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                            &proto, sizeof(proto)));
    assert_ok(bf_wpack_new(&wpack));
    assert_ok(bf_matcher_pack(source, wpack));
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_matcher_new_from_pack(&destination, bf_rpack_root(rpack)));

    assert_true(bft_matcher_equal(source, destination));
}

static void dump(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    uint8_t payload[] = {0xaa, 0xbb, 0xcc, 0xdd};
    prefix_t prefix = {};

    (void)state;

    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                            payload, sizeof(payload)));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_small_payload(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};
    uint8_t proto = 17; // UDP

    (void)state;

    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                            &proto, sizeof(proto)));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_ipv4_addr(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test dumping IPv4 address matcher (tests _bf_print_ipv4_addr)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DADDR,
                                     BF_MATCHER_EQ, "10.0.0.1"));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_ipv6_addr(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test dumping IPv6 address matcher (tests _bf_print_ipv6_addr)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_SADDR,
                                     BF_MATCHER_EQ, "2001:db8::1"));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_port(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test dumping port matcher (tests _bf_print_port)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_DPORT,
                                     BF_MATCHER_EQ, "443"));
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_UDP_SPORT,
                                     BF_MATCHER_EQ, "53"));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_l4_proto(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test dumping L4 protocol matcher (tests _bf_print_l4_proto)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                     BF_MATCHER_EQ, "tcp"));
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                     BF_MATCHER_EQ, "icmp"));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_tcp_flags(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};
    uint8_t flags = (1 << BF_TCP_SYN) | (1 << BF_TCP_ACK);

    (void)state;

    // Test dumping TCP flags matcher (tests _bf_print_tcp_flags)
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY,
                            &flags, sizeof(flags)));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_icmp_type(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test dumping ICMP type matcher (tests _bf_print_icmp_type)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_TYPE,
                                     BF_MATCHER_EQ, "echo-request"));
    bf_matcher_dump(matcher, &prefix);
}

static void dump_various_ops(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test different operators
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_DPORT,
                                     BF_MATCHER_NE, "80"));
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                     BF_MATCHER_IN, "udp"));
    bf_matcher_dump(matcher, &prefix);
}

static void matcher_type_to_str(void **state)
{
    (void)state;

    // Test all valid matcher types
    for (enum bf_matcher_type type = 0; type < _BF_MATCHER_TYPE_MAX; ++type) {
        const char *str = bf_matcher_type_to_str(type);
        assert_non_null(str);
    }
}

static void matcher_type_from_str(void **state)
{
    enum bf_matcher_type type;

    (void)state;

    // Test round-trip conversion for all types
    for (enum bf_matcher_type t = 0; t < _BF_MATCHER_TYPE_MAX; ++t) {
        const char *str = bf_matcher_type_to_str(t);
        assert_ok(bf_matcher_type_from_str(str, &type));
        assert_int_equal(type, t);
    }

    // Test invalid strings
    assert_err(bf_matcher_type_from_str("invalid", &type));
    assert_err(bf_matcher_type_from_str("", &type));
    assert_err(bf_matcher_type_from_str("BF_MATCHER_INVALID", &type));
}

static void matcher_op_to_str(void **state)
{
    (void)state;

    // Test all valid matcher operators
    for (enum bf_matcher_op op = 0; op < _BF_MATCHER_OP_MAX; ++op) {
        const char *str = bf_matcher_op_to_str(op);
        assert_non_null(str);
    }
}

static void matcher_op_from_str(void **state)
{
    enum bf_matcher_op op;

    (void)state;

    // Test round-trip conversion for all operators
    for (enum bf_matcher_op o = 0; o < _BF_MATCHER_OP_MAX; ++o) {
        const char *str = bf_matcher_op_to_str(o);
        assert_ok(bf_matcher_op_from_str(str, &op));
        assert_int_equal(op, o);
    }

    // Test invalid strings
    assert_err(bf_matcher_op_from_str("invalid", &op));
    assert_err(bf_matcher_op_from_str("", &op));
    assert_err(bf_matcher_op_from_str("BF_MATCHER_INVALID", &op));
}

static void tcp_flag_conversions(void **state)
{
    enum bf_tcp_flag flag;

    (void)state;

    // Test round-trip for all TCP flags
    for (enum bf_tcp_flag f = 0; f < _BF_TCP_MAX; ++f) {
        const char *str = bf_tcp_flag_to_str(f);
        assert_non_null(str);
        assert_ok(bf_tcp_flag_from_str(str, &flag));
        assert_int_equal(flag, f);
    }

    // Test invalid strings
    assert_err(bf_tcp_flag_from_str("invalid", &flag));
    assert_err(bf_tcp_flag_from_str("", &flag));
}


static void ethertype_conversions(void **state)
{
    uint16_t ethertype;

    (void)state;

    // Test supported ethertypes (only IPv4 and IPv6 are supported)
    assert_non_null(bf_ethertype_to_str(0x0800)); // IPv4
    assert_non_null(bf_ethertype_to_str(0x86DD)); // IPv6

    // Test from string
    assert_ok(bf_ethertype_from_str("ipv4", &ethertype));
    assert_int_equal(ethertype, 0x0800);

    assert_ok(bf_ethertype_from_str("ipv6", &ethertype));
    assert_int_equal(ethertype, 0x86DD);

    // Test invalid
    assert_err(bf_ethertype_from_str("invalid", &ethertype));
}

static void ipproto_conversions(void **state)
{
    uint8_t ipproto;

    (void)state;

    // Test some common IP protocols
    assert_non_null(bf_ipproto_to_str(6));  // TCP
    assert_non_null(bf_ipproto_to_str(17)); // UDP
    assert_non_null(bf_ipproto_to_str(1));  // ICMP

    // Test from string
    assert_ok(bf_ipproto_from_str("tcp", &ipproto));
    assert_int_equal(ipproto, 6);

    assert_ok(bf_ipproto_from_str("udp", &ipproto));
    assert_int_equal(ipproto, 17);

    // Test invalid
    assert_err(bf_ipproto_from_str("invalid", &ipproto));
}

static void icmp_type_conversions(void **state)
{
    uint8_t type;

    (void)state;

    // Test some ICMP types
    assert_non_null(bf_icmp_type_to_str(0)); // Echo Reply
    assert_non_null(bf_icmp_type_to_str(8)); // Echo Request

    // Test from string
    assert_ok(bf_icmp_type_from_str("echo-reply", &type));
    assert_int_equal(type, 0);

    assert_ok(bf_icmp_type_from_str("echo-request", &type));
    assert_int_equal(type, 8);

    // Test invalid
    assert_err(bf_icmp_type_from_str("invalid", &type));
}

static void icmpv6_type_conversions(void **state)
{
    uint8_t type;

    (void)state;

    // Test some ICMPv6 types
    assert_non_null(bf_icmpv6_type_to_str(128)); // Echo Request
    assert_non_null(bf_icmpv6_type_to_str(129)); // Echo Reply

    // Test from string
    assert_ok(bf_icmpv6_type_from_str("echo-request", &type));
    assert_int_equal(type, 128);

    assert_ok(bf_icmpv6_type_from_str("echo-reply", &type));
    assert_int_equal(type, 129);

    // Test invalid
    assert_err(bf_icmpv6_type_from_str("invalid", &type));
}

static void get_meta(void **state)
{
    (void)state;

    // Test getting meta for various matcher types
    const struct bf_matcher_meta *meta;

    meta = bf_matcher_get_meta(BF_MATCHER_IP4_SADDR);
    assert_non_null(meta);

    meta = bf_matcher_get_meta(BF_MATCHER_TCP_DPORT);
    assert_non_null(meta);

    meta = bf_matcher_get_meta(BF_MATCHER_IP6_DADDR);
    assert_non_null(meta);

    // Just verify the function doesn't crash for all types
    // (not all types have meta defined, so some may return NULL)
    for (enum bf_matcher_type type = 0; type < _BF_MATCHER_TYPE_MAX; ++type)
        bf_matcher_get_meta(type);
}

static void get_ops(void **state)
{
    (void)state;

    // Test getting ops for various (type, op) combinations
    const struct bf_matcher_ops *ops;

    ops = bf_matcher_get_ops(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ);
    assert_non_null(ops);

    ops = bf_matcher_get_ops(BF_MATCHER_TCP_DPORT, BF_MATCHER_NE);
    assert_non_null(ops);

    // Not all combinations are valid, so some may return NULL
    // Just verify the function doesn't crash
    for (enum bf_matcher_type type = 0; type < _BF_MATCHER_TYPE_MAX; ++type) {
        for (enum bf_matcher_op op = 0; op < _BF_MATCHER_OP_MAX; ++op)
            bf_matcher_get_ops(type, op);
    }
}

static void meta_iface(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test with numeric interface index
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_IFACE,
                                     BF_MATCHER_EQ, "1"));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_get_type(matcher), BF_MATCHER_META_IFACE);
    assert_int_equal(bf_matcher_get_op(matcher), BF_MATCHER_EQ);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with interface index as string
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_IFACE,
                                     BF_MATCHER_EQ, "42"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void meta_iface_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test with invalid interface index (negative)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_IFACE,
                                      BF_MATCHER_EQ, "-1"));

    // Test with invalid interface index (too large)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_IFACE,
                                      BF_MATCHER_EQ, "999999999999"));

    // Test with invalid string
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_IFACE,
                                      BF_MATCHER_EQ, "invalid_iface_name"));
}

static void meta_l3_proto(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test with IPv4 ethertype string
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                     BF_MATCHER_EQ, "ipv4"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with IPv6 ethertype string
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                     BF_MATCHER_EQ, "ipv6"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with decimal ethertype
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                     BF_MATCHER_EQ, "2048")); // 0x0800 (IPv4)
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with hexadecimal ethertype
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                     BF_MATCHER_EQ, "0x86DD")); // IPv6
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void meta_probability(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test with 0%
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                     BF_MATCHER_EQ, "0%"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 0);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with 50%
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                     BF_MATCHER_EQ, "50%"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 50);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with 100%
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                     BF_MATCHER_EQ, "100%"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 100);
    bf_matcher_dump(matcher, &prefix);
}

static void meta_probability_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test with value over 100%
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                      BF_MATCHER_EQ, "101%"));

    // Test without % sign
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                      BF_MATCHER_EQ, "50"));

    // Test with negative value
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                      BF_MATCHER_EQ, "-10%"));
}

static void meta_sport_dport(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test META_SPORT with EQ
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                     BF_MATCHER_EQ, "8080"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test META_SPORT with NE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                     BF_MATCHER_NE, "22"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test META_DPORT with EQ
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_DPORT,
                                     BF_MATCHER_EQ, "443"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test META_DPORT with NE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_DPORT,
                                     BF_MATCHER_NE, "80"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void meta_sport_dport_range(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test META_SPORT with RANGE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                     BF_MATCHER_RANGE, "1024-65535"));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_payload_len(matcher), 2 * sizeof(uint16_t));
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test META_DPORT with RANGE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_DPORT,
                                     BF_MATCHER_RANGE, "8000-9000"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test single port range (min == max)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                     BF_MATCHER_RANGE, "80-80"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void meta_sport_dport_range_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test with reversed range (max < min)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                      BF_MATCHER_RANGE, "9000-8000"));

    // Test with missing end port
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                      BF_MATCHER_RANGE, "8000-"));

    // Test with missing start port
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                      BF_MATCHER_RANGE, "-9000"));

    // Test with no delimiter
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                      BF_MATCHER_RANGE, "8000"));

    // Test with invalid port number
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                      BF_MATCHER_RANGE, "1024-70000"));
}

static void meta_mark(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test with decimal mark
    assert_ok(
        bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK, BF_MATCHER_EQ, "42"));
    assert_non_null(matcher);
    assert_int_equal(*(uint32_t *)bf_matcher_payload(matcher), 42);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with hexadecimal mark
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK, BF_MATCHER_EQ,
                                     "0x1234"));
    assert_non_null(matcher);
    assert_int_equal(*(uint32_t *)bf_matcher_payload(matcher), 0x1234);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with NE operator
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK, BF_MATCHER_NE,
                                     "0"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void meta_mark_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test with negative value
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK,
                                      BF_MATCHER_EQ, "-1"));

    // Test with value too large (> UINT32_MAX)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK,
                                      BF_MATCHER_EQ, "0x100000000"));

    // Test with invalid string
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK,
                                      BF_MATCHER_EQ, "not_a_number"));
}

static void new_from_raw_ip4_addr(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test IPv4 address parsing
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SADDR,
                                     BF_MATCHER_EQ, "192.168.1.1"));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_get_type(matcher), BF_MATCHER_IP4_SADDR);
    assert_int_equal(bf_matcher_get_op(matcher), BF_MATCHER_EQ);
    bf_matcher_free(&matcher);

    // Test with CIDR notation (use SNET for network matching)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SNET,
                                     BF_MATCHER_IN, "10.0.0.0/8"));
    assert_non_null(matcher);
}

static void new_from_raw_ip6_addr(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test IPv6 address parsing
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_DADDR,
                                     BF_MATCHER_EQ, "::1"));
    assert_non_null(matcher);
    bf_matcher_free(&matcher);

    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_DADDR,
                                     BF_MATCHER_EQ, "2001:db8::1"));
    assert_non_null(matcher);
}

static void new_from_raw_port(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test port parsing
    assert_ok(
        bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ, "80"));
    assert_non_null(matcher);
    bf_matcher_free(&matcher);

    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_UDP_SPORT,
                                     BF_MATCHER_EQ, "53"));
    assert_non_null(matcher);
}

static void new_from_raw_proto(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test protocol parsing
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                     BF_MATCHER_EQ, "tcp"));
    assert_non_null(matcher);
    bf_matcher_free(&matcher);

    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                     BF_MATCHER_EQ, "udp"));
    assert_non_null(matcher);
    bf_matcher_free(&matcher);

    // Test with numeric value
    assert_ok(
        bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, "6"));
    assert_non_null(matcher);
}

static void new_from_raw_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test invalid IPv4 address
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SADDR,
                                      BF_MATCHER_EQ, "999.999.999.999"));

    // Test invalid port
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_DPORT,
                                      BF_MATCHER_EQ, "99999"));

    // Test invalid protocol
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                      BF_MATCHER_EQ, "invalid_proto"));
}

static void ipv4_network_matchers(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test IP4_SNET
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SNET,
                                     BF_MATCHER_IN, "192.168.0.0/16"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test IP4_DNET with /8
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DNET,
                                     BF_MATCHER_EQ, "10.0.0.0/8"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with /32 (single host)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SNET,
                                     BF_MATCHER_NE, "127.0.0.1/32"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with /24
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DNET,
                                     BF_MATCHER_IN, "172.16.0.0/12"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void ipv6_network_matchers(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test IP6_SNET
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_SNET,
                                     BF_MATCHER_IN, "2001:db8::/32"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test IP6_DNET
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_DNET,
                                     BF_MATCHER_EQ, "fe80::/10"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with /128 (single host)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_SNET,
                                     BF_MATCHER_NE, "::1/128"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with abbreviated IPv6
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_DNET,
                                     BF_MATCHER_IN, "ff00::/8"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void ipv4_network_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test with missing prefix length
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SNET,
                                      BF_MATCHER_IN, "192.168.0.0"));

    // Test with invalid prefix length (> 32)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SNET,
                                      BF_MATCHER_IN, "192.168.0.0/33"));

    // Test with invalid IP address
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DNET,
                                      BF_MATCHER_IN, "999.999.999.999/8"));
}

static void ipv6_network_invalid(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test with missing prefix length
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_SNET,
                                      BF_MATCHER_IN, "2001:db8::1"));

    // Test with invalid prefix length (> 128)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_SNET,
                                      BF_MATCHER_IN, "2001:db8::/129"));

    // Test with invalid IPv6 address
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_DNET,
                                      BF_MATCHER_IN, "gggg::/64"));
}

static void icmp_code(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test ICMP code with decimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_CODE,
                                     BF_MATCHER_EQ, "0"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with different code value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_CODE,
                                     BF_MATCHER_NE, "3"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with hexadecimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_CODE,
                                     BF_MATCHER_EQ, "0x0a"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void icmpv6_code(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test ICMPv6 code with decimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_CODE,
                                     BF_MATCHER_EQ, "0"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with NE operator
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_CODE,
                                     BF_MATCHER_NE, "1"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with hexadecimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_CODE,
                                     BF_MATCHER_IN, "0x05"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void icmpv6_type(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test ICMPv6 type with string name (tests _bf_parse_icmpv6_type)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                     BF_MATCHER_EQ, "echo-request"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 128);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with echo-reply
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                     BF_MATCHER_EQ, "echo-reply"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 129);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with decimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                     BF_MATCHER_NE, "128"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with hexadecimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                     BF_MATCHER_IN, "0x81"));  // 129 (echo-reply)
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test with another named type
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                     BF_MATCHER_EQ, "destination-unreachable"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 1);
    bf_matcher_dump(matcher, &prefix);
}

static void tcp_port_range(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test TCP_SPORT with RANGE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_SPORT,
                                     BF_MATCHER_RANGE, "1024-2048"));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_payload_len(matcher), 2 * sizeof(uint16_t));
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test TCP_DPORT with RANGE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_DPORT,
                                     BF_MATCHER_RANGE, "80-443"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void udp_port_range(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test UDP_SPORT with RANGE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_UDP_SPORT,
                                     BF_MATCHER_RANGE, "5000-6000"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test UDP_DPORT with RANGE
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_UDP_DPORT,
                                     BF_MATCHER_RANGE, "53-53"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
}

static void print_functions(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    const struct bf_matcher_ops *ops;

    (void)state;

    // Test _bf_print_iface via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_IFACE,
                                     BF_MATCHER_EQ, "1"));
    ops = bf_matcher_get_ops(BF_MATCHER_META_IFACE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l3_proto via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                     BF_MATCHER_EQ, "ipv4"));
    ops = bf_matcher_get_ops(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l4_proto via ops (using META_L4_PROTO)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L4_PROTO,
                                     BF_MATCHER_EQ, "tcp"));
    ops = bf_matcher_get_ops(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l4_proto via ops (using IP4_PROTO)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                     BF_MATCHER_EQ, "udp"));
    ops = bf_matcher_get_ops(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l4_port via ops (using TCP_SPORT)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_SPORT,
                                     BF_MATCHER_EQ, "8080"));
    ops = bf_matcher_get_ops(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l4_port_range via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_SPORT,
                                     BF_MATCHER_RANGE, "1024-65535"));
    ops = bf_matcher_get_ops(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_probability via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_PROBABILITY,
                                     BF_MATCHER_EQ, "50%"));
    ops = bf_matcher_get_ops(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_mark via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_MARK,
                                     BF_MATCHER_EQ, "0x1234"));
    ops = bf_matcher_get_ops(BF_MATCHER_META_MARK, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_ipv4_addr via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SADDR,
                                     BF_MATCHER_EQ, "192.168.1.1"));
    ops = bf_matcher_get_ops(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_ipv4_net via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_SNET,
                                     BF_MATCHER_IN, "192.168.0.0/16"));
    ops = bf_matcher_get_ops(BF_MATCHER_IP4_SNET, BF_MATCHER_IN);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_ipv6_addr via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_SADDR,
                                     BF_MATCHER_EQ, "2001:db8::1"));
    ops = bf_matcher_get_ops(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_ipv6_net via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP6_DNET,
                                     BF_MATCHER_IN, "2001:db8::/32"));
    ops = bf_matcher_get_ops(BF_MATCHER_IP6_DNET, BF_MATCHER_IN);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_tcp_flags via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_FLAGS,
                                     BF_MATCHER_ANY, "syn,ack"));
    ops = bf_matcher_get_ops(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_icmp_type via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_TYPE,
                                     BF_MATCHER_EQ, "echo-request"));
    ops = bf_matcher_get_ops(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_icmp_code via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_CODE,
                                     BF_MATCHER_EQ, "3"));
    ops = bf_matcher_get_ops(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_icmpv6_type via ops
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                     BF_MATCHER_EQ, "echo-request"));
    ops = bf_matcher_get_ops(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);
}

static void error_paths_parse(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;

    (void)state;

    // Test _bf_parse_l3_proto error path with completely invalid input
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                      BF_MATCHER_EQ, "not_a_protocol"));
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_META_L3_PROTO,
                                      BF_MATCHER_EQ, "99999"));  // Too large

    // Test _bf_parse_l4_proto error path with invalid protocol
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                      BF_MATCHER_EQ, "xyz"));
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_PROTO,
                                      BF_MATCHER_EQ, "256"));  // Too large for uint8_t

    // Test _bf_parse_tcp_flags error path with invalid flag
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_FLAGS,
                                      BF_MATCHER_ANY, "invalid_flag"));
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_TCP_FLAGS,
                                      BF_MATCHER_ANY, "syn,invalid,ack"));

    // Test _bf_parse_icmp_code error path with invalid code
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_CODE,
                                      BF_MATCHER_EQ, "not_a_number"));
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_CODE,
                                      BF_MATCHER_EQ, "256"));  // Too large

    // Test _bf_parse_icmp_type error path with invalid type
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_TYPE,
                                      BF_MATCHER_EQ, "invalid-type"));
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMP_TYPE,
                                      BF_MATCHER_EQ, "999"));  // Too large

    // Test _bf_parse_icmpv6_type error path with invalid type
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                      BF_MATCHER_EQ, "not-a-type"));
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_ICMPV6_TYPE,
                                      BF_MATCHER_EQ, "300"));  // Too large
}

static void error_paths_print(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    const struct bf_matcher_ops *ops;
    uint32_t invalid_ifindex = 999999;  // Very high interface index unlikely to exist
    uint16_t unknown_ethertype = 0x9999;  // Unknown ethertype
    uint8_t unknown_protocol = 255;  // Unknown IP protocol
    uint8_t unknown_icmp_type = 254;  // Unknown ICMP type (most likely)
    uint8_t unknown_icmpv6_type = 253;  // Unknown ICMPv6 type (most likely)

    (void)state;

    // Test _bf_print_iface error path with invalid ifindex (name lookup fails)
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_META_IFACE, BF_MATCHER_EQ,
                            &invalid_ifindex, sizeof(invalid_ifindex)));
    ops = bf_matcher_get_ops(BF_MATCHER_META_IFACE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    // This should print the numeric ifindex since name lookup fails
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l3_proto error path with unknown ethertype
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ,
                            &unknown_ethertype, sizeof(unknown_ethertype)));
    ops = bf_matcher_get_ops(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    // This should print the hex value since ethertype is unknown
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_l4_proto error path with unknown protocol
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                            &unknown_protocol, sizeof(unknown_protocol)));
    ops = bf_matcher_get_ops(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    // This should print the numeric value since protocol is unknown
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_icmp_type error path with unknown type
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ,
                            &unknown_icmp_type, sizeof(unknown_icmp_type)));
    ops = bf_matcher_get_ops(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    // This should print the numeric value since type is unknown
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);

    // Test _bf_print_icmpv6_type error path with unknown type
    assert_ok(bf_matcher_new(&matcher, BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_EQ,
                            &unknown_icmpv6_type, sizeof(unknown_icmpv6_type)));
    ops = bf_matcher_get_ops(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_EQ);
    assert_non_null(ops);
    assert_non_null(ops->print);
    // This should print the numeric value since type is unknown
    ops->print(bf_matcher_payload(matcher));
    bf_matcher_free(&matcher);
}

static void ip4_dscp(void **state)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    prefix_t prefix = {};

    (void)state;

    // Test ip4.dscp with decimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                     BF_MATCHER_EQ, "16"));
    assert_non_null(matcher);
    assert_int_equal(bf_matcher_get_type(matcher), BF_MATCHER_IP4_DSCP);
    bf_matcher_free(&matcher);

    // Test ip4.dscp with hexadecimal value
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                     BF_MATCHER_EQ, "0x10"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 0x10);
    bf_matcher_free(&matcher);

    // Test ip4.dscp with minimum value (0)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                     BF_MATCHER_EQ, "0"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 0);
    bf_matcher_free(&matcher);

    // Test ip4.dscp with maximum value (255)
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                     BF_MATCHER_EQ, "255"));
    assert_non_null(matcher);
    assert_int_equal(*(uint8_t *)bf_matcher_payload(matcher), 255);
    bf_matcher_free(&matcher);

    // Test ip4.dscp with NE operator
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                     BF_MATCHER_NE, "8"));
    assert_non_null(matcher);
    bf_matcher_free(&matcher);

    // Test ip4.dscp print function
    assert_ok(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                     BF_MATCHER_EQ, "0xff"));
    assert_non_null(matcher);
    bf_matcher_dump(matcher, &prefix);
    bf_matcher_free(&matcher);

    // Test ip4.dscp with invalid value (> 255)
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                       BF_MATCHER_EQ, "256"));

    // Test ip4.dscp with invalid string
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                       BF_MATCHER_EQ, "invalid"));

    // Test ip4.dscp with negative value
    assert_err(bf_matcher_new_from_raw(&matcher, BF_MATCHER_IP4_DSCP,
                                       BF_MATCHER_EQ, "-1"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(new_with_payload),
        cmocka_unit_test(getters),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(pack_and_unpack_small_payload),
        cmocka_unit_test(dump),
        cmocka_unit_test(dump_small_payload),
        cmocka_unit_test(dump_ipv4_addr),
        cmocka_unit_test(dump_ipv6_addr),
        cmocka_unit_test(dump_port),
        cmocka_unit_test(dump_l4_proto),
        cmocka_unit_test(dump_tcp_flags),
        cmocka_unit_test(dump_icmp_type),
        cmocka_unit_test(dump_various_ops),
        cmocka_unit_test(matcher_type_to_str),
        cmocka_unit_test(matcher_type_from_str),
        cmocka_unit_test(matcher_op_to_str),
        cmocka_unit_test(matcher_op_from_str),
        cmocka_unit_test(tcp_flag_conversions),
        cmocka_unit_test(ethertype_conversions),
        cmocka_unit_test(ipproto_conversions),
        cmocka_unit_test(icmp_type_conversions),
        cmocka_unit_test(icmpv6_type_conversions),
        cmocka_unit_test(get_meta),
        cmocka_unit_test(get_ops),
        cmocka_unit_test(meta_iface),
        cmocka_unit_test(meta_iface_invalid),
        cmocka_unit_test(meta_l3_proto),
        cmocka_unit_test(meta_probability),
        cmocka_unit_test(meta_probability_invalid),
        cmocka_unit_test(meta_sport_dport),
        cmocka_unit_test(meta_sport_dport_range),
        cmocka_unit_test(meta_sport_dport_range_invalid),
        cmocka_unit_test(meta_mark),
        cmocka_unit_test(meta_mark_invalid),
        cmocka_unit_test(new_from_raw_ip4_addr),
        cmocka_unit_test(new_from_raw_ip6_addr),
        cmocka_unit_test(new_from_raw_port),
        cmocka_unit_test(new_from_raw_proto),
        cmocka_unit_test(new_from_raw_invalid),
        cmocka_unit_test(ipv4_network_matchers),
        cmocka_unit_test(ipv6_network_matchers),
        cmocka_unit_test(ipv4_network_invalid),
        cmocka_unit_test(ipv6_network_invalid),
        cmocka_unit_test(icmp_code),
        cmocka_unit_test(icmpv6_code),
        cmocka_unit_test(icmpv6_type),
        cmocka_unit_test(tcp_port_range),
        cmocka_unit_test(udp_port_range),
        cmocka_unit_test(print_functions),
        cmocka_unit_test(error_paths_parse),
        cmocka_unit_test(error_paths_print),
        cmocka_unit_test(ip4_dscp),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
