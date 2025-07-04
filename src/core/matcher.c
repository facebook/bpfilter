/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/matcher.h"

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/if.h"
#include "core/logger.h"
#include "core/marsh.h"

#define INET4_ADDRSTRLEN 16

#define BF_PAYLOAD_OPS(type, size, parser_cb, printer_cb)                      \
    [type] = {size, parser_cb, printer_cb}

extern int inet_pton(int, const char *, void *);

enum bf_matcher_payload_type
{
    BF_MATCHER_PAYLOAD_IFACE,
    BF_MATCHER_PAYLOAD_L3_PROTO,
    BF_MATCHER_PAYLOAD_L4_PROTO,
    BF_MATCHER_PAYLOAD_L4_PORT,
    BF_MATCHER_PAYLOAD_L4_PORT_RANGE,
    BF_MATCHER_PAYLOAD_PROBABILITY,
    BF_MATCHER_PAYLOAD_IPV4_ADDR,
    _BF_MATCHER_PAYLOAD_MAX,
};

int _bf_parse_iface(const struct bf_matcher *matcher, void *payload,
                    const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    int idx;
    unsigned long ifindex;
    char *endptr;

    idx = bf_if_index_from_name(raw_payload);
    if (idx > 0) {
        *(uint32_t *)matcher->payload = (uint32_t)idx;
        return 0;
    }

    ifindex = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && 0 < ifindex && ifindex <= UINT32_MAX) {
        *(uint32_t *)matcher->payload = (uint32_t)ifindex;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects an interface name (e.g., \"eth0\", \"wlan0\") or a decimal interface index (e.g., \"1\", \"2\"), not '%s'",
        bf_matcher_type_to_str(matcher->type),
        bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_iface(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    const char *ifname;
    uint32_t ifindex = *(uint32_t *)matcher->payload;

    ifname = bf_if_name_from_index((int)ifindex);
    if (ifname)
        (void)fprintf(stdout, "%s", ifname);
    else
        (void)fprintf(stdout, "%" PRIu32, ifindex);
}

int _bf_parse_l3_proto(const struct bf_matcher *matcher, void *payload,
                       const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    unsigned long ethertype;
    char *endptr;
    int r;

    r = bf_ethertype_from_str(raw_payload, payload);
    if (!r)
        return 0;

    ethertype = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && ethertype <= UINT16_MAX) {
        *(uint16_t *)matcher->payload = (uint16_t)ethertype;
        return 0;
    }

    ethertype = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && ethertype <= UINT16_MAX) {
        *(uint16_t *)matcher->payload = (uint16_t)ethertype;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects an internet layer protocol name (e.g. \"IPv6\", case insensitive), or a valid decimal or hexadecimal IEEE 802 number, not '%s'",
        bf_matcher_type_to_str(matcher->type),
        bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_l3_proto(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    const char *ethertype = bf_ethertype_to_str(*(uint16_t *)matcher->payload);

    if (ethertype)
        (void)fprintf(stdout, "%s", ethertype);
    else
        (void)fprintf(stdout, "0x%04" PRIx16, *(uint16_t *)matcher->payload);
}

int _bf_parse_l4_proto(const struct bf_matcher *matcher, void *payload,
                       const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    unsigned long ipproto;
    char *endptr;
    int r;

    r = bf_ipproto_from_str(raw_payload, payload);
    if (!r)
        return 0;

    ipproto = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && ipproto <= UINT8_MAX) {
        *(uint8_t *)matcher->payload = (uint8_t)ipproto;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a transport layer protocol name (e.g. \"ICMP\", case insensitive), or a valid decimal internet protocol number, not '%s'",
        bf_matcher_type_to_str(matcher->type),
        bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_l4_proto(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    const char *ipproto = bf_ipproto_to_str(*(uint8_t *)matcher->payload);

    if (ipproto)
        (void)fprintf(stdout, "%s", ipproto);
    else
        (void)fprintf(stdout, "%" PRIu8, *(uint8_t *)matcher->payload);
}

int _bf_parse_l4_port(const struct bf_matcher *matcher, void *payload,
                      const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    unsigned long port;
    char *endptr;

    port = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && port <= UINT16_MAX) {
        *(uint16_t *)matcher->payload = (uint16_t)port;
        return 0;
    }

    bf_err("\"%s %s\" expects a valid decimal port number, not '%s'",
           bf_matcher_type_to_str(matcher->type),
           bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_l4_port(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    (void)fprintf(stdout, "%" PRIu16, *(uint16_t *)matcher->payload);
}

#define BF_PORT_RANGE_MAX_LEN 16 // 65535-65535, with nul char, round to **2

static int _bf_parse_l4_port_range(const struct bf_matcher *matcher,
                                   void *payload, const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    uint16_t *ports = (uint16_t *)matcher->payload;
    unsigned long port;
    char buf[BF_PORT_RANGE_MAX_LEN];
    char *first;
    char *second;
    char *endptr;

    bf_strncpy(buf, BF_PORT_RANGE_MAX_LEN, raw_payload);

    if (!isdigit(*raw_payload))
        goto err;

    first = strtok_r(buf, "-", &second);
    if (!first)
        goto err;

    if (!*second)
        goto err;

    port = strtoul(first, &endptr, BF_BASE_10);
    if (*endptr != '\0' || port > UINT16_MAX)
        goto err;
    ports[0] = (uint16_t)port;

    port = strtoul(second, &endptr, BF_BASE_10);
    if (*endptr != '\0' || port > UINT16_MAX)
        goto err;
    ports[1] = (uint16_t)port;

    if (ports[1] < ports[0])
        goto err;

    return 0;

err:
    bf_err(
        "\"%s %s\" expects two positive decimal port numbers as `$START-$END`, with `$START <= $END`, not '%s'",
        bf_matcher_type_to_str(matcher->type),
        bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_l4_port_range(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    uint16_t *ports = (uint16_t *)matcher->payload;

    (void)fprintf(stdout, "%" PRIu16 "-%" PRIu16, ports[0], ports[1]);
}

static int _bf_parse_probability(const struct bf_matcher *matcher,
                                 void *payload, const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    unsigned long proba;
    char *endptr;

    proba = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (endptr[0] == '%' && endptr[1] == '\0' && proba <= 100) {
        *(uint8_t *)payload = (uint8_t)proba;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a valid decimal percentage value (i.e., within [0%%, 100%%]), not '%s'",
        bf_matcher_type_to_str(matcher->type),
        bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_probability(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    (void)fprintf(stdout, "%" PRIu8 "%%", *(uint8_t *)matcher->payload);
}

static int _bf_parse_ipv4_addr(const struct bf_matcher *matcher, void *payload,
                               const char *raw_payload)
{
    bf_assert(matcher && payload && raw_payload);

    int r;

    r = inet_pton(AF_INET, raw_payload, payload);
    if (r == 1)
        return 0;

    bf_err(
        "\"%s %s\" expects an IPv4 address in dotted-decimal format, \"ddd.ddd.ddd.ddd\", where ddd is a decimal number of up to three digits in the range 0 to 255, not '%s' ",
        bf_matcher_type_to_str(matcher->type),
        bf_matcher_op_to_str(matcher->op), raw_payload);

    return -EINVAL;
}

void _bf_print_ipv4_addr(const struct bf_matcher *matcher)
{
    bf_assert(matcher);

    char str[INET4_ADDRSTRLEN];

    if (inet_ntop(AF_INET, matcher->payload, str, INET4_ADDRSTRLEN))
        (void)fprintf(stdout, "%s", str);
    else
        (void)fprintf(stdout, "<failed to print IPv4 address>");
}

static const struct bf_matcher_ops _bf_payload_ops[_BF_MATCHER_PAYLOAD_MAX] = {
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_IFACE, 4, _bf_parse_iface,
                   _bf_print_iface),
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_L3_PROTO, 2, _bf_parse_l3_proto,
                   _bf_print_l3_proto),
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_L4_PROTO, 1, _bf_parse_l4_proto,
                   _bf_print_l4_proto),
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_L4_PORT, 2, _bf_parse_l4_port,
                   _bf_print_l4_port),
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_L4_PORT_RANGE, 4, _bf_parse_l4_port_range,
                   _bf_print_l4_port_range),
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_PROBABILITY, 1, _bf_parse_probability,
                   _bf_print_probability),
    BF_PAYLOAD_OPS(BF_MATCHER_PAYLOAD_IPV4_ADDR, 4, _bf_parse_ipv4_addr,
                   _bf_print_ipv4_addr),
};

#define BF_MATCHER_OPS(type, op, payload_type)                                 \
    [type][op] = (&_bf_payload_ops[payload_type])

const struct bf_matcher_ops *bf_matcher_get_ops(enum bf_matcher_type type,
                                                enum bf_matcher_op op)
{
    static const struct bf_matcher_ops
        *_matcher_ops[_BF_MATCHER_TYPE_MAX][_BF_MATCHER_OP_MAX] = {
            BF_MATCHER_OPS(BF_MATCHER_META_IFACE, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_IFACE),
            BF_MATCHER_OPS(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L3_PROTO),
            BF_MATCHER_OPS(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PROTO),
            BF_MATCHER_OPS(BF_MATCHER_META_L4_PROTO, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PROTO),
            BF_MATCHER_OPS(BF_MATCHER_META_SPORT, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_META_SPORT, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE,
                           BF_MATCHER_PAYLOAD_L4_PORT_RANGE),
            BF_MATCHER_OPS(BF_MATCHER_META_DPORT, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_META_DPORT, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_META_DPORT, BF_MATCHER_RANGE,
                           BF_MATCHER_PAYLOAD_L4_PORT_RANGE),
            BF_MATCHER_OPS(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_PROBABILITY),
            BF_MATCHER_OPS(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_IPV4_ADDR),
            BF_MATCHER_OPS(BF_MATCHER_IP4_SADDR, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_IPV4_ADDR),
            BF_MATCHER_OPS(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_IPV4_ADDR),
            BF_MATCHER_OPS(BF_MATCHER_IP4_DADDR, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_IPV4_ADDR),
            BF_MATCHER_OPS(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PROTO),
            BF_MATCHER_OPS(BF_MATCHER_IP4_PROTO, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PROTO),
            BF_MATCHER_OPS(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_TCP_SPORT, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_TCP_SPORT, BF_MATCHER_RANGE,
                           BF_MATCHER_PAYLOAD_L4_PORT_RANGE),
            BF_MATCHER_OPS(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_TCP_DPORT, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE,
                           BF_MATCHER_PAYLOAD_L4_PORT_RANGE),
            BF_MATCHER_OPS(BF_MATCHER_UDP_SPORT, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_UDP_SPORT, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_UDP_SPORT, BF_MATCHER_RANGE,
                           BF_MATCHER_PAYLOAD_L4_PORT_RANGE),
            BF_MATCHER_OPS(BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_UDP_DPORT, BF_MATCHER_NE,
                           BF_MATCHER_PAYLOAD_L4_PORT),
            BF_MATCHER_OPS(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE,
                           BF_MATCHER_PAYLOAD_L4_PORT_RANGE),
        };

    return _matcher_ops[type][op];
}

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const void *payload,
                   size_t payload_len)
{
    _free_bf_matcher_ struct bf_matcher *_matcher = NULL;

    bf_assert(matcher);
    bf_assert((payload && payload_len) || (!payload && !payload_len));

    _matcher = malloc(sizeof(struct bf_matcher) + payload_len);
    if (!_matcher)
        return -ENOMEM;

    _matcher->type = type;
    _matcher->op = op;
    _matcher->len = sizeof(struct bf_matcher) + payload_len;
    bf_memcpy(_matcher->payload, payload, payload_len);

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

int bf_matcher_new_from_raw(struct bf_matcher **matcher,
                            enum bf_matcher_type type, enum bf_matcher_op op,
                            const char *payload)
{
    _free_bf_matcher_ struct bf_matcher *_matcher = NULL;
    const struct bf_matcher_ops *ops;
    int r;

    bf_assert(matcher && payload);

    ops = bf_matcher_get_ops(type, op);
    if (!ops) {
        return bf_err_r(-ENOENT, "payload ops not found for '%s %s'",
                        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op));
    }

    _matcher = malloc(sizeof(*_matcher) + ops->payload_size);
    if (!_matcher)
        return -ENOMEM;

    _matcher->type = type;
    _matcher->op = op;
    _matcher->len = sizeof(*_matcher) + ops->payload_size;

    r = ops->parser_cb(_matcher, &_matcher->payload, payload);
    if (r)
        return r;

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

int bf_matcher_new_from_marsh(struct bf_matcher **matcher,
                              const struct bf_marsh *marsh)
{
    struct bf_marsh *child = NULL;
    enum bf_matcher_type type;
    enum bf_matcher_op op;
    size_t payload_len;
    const void *payload;
    int r;

    bf_assert(matcher);
    bf_assert(marsh);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&type, child->data, sizeof(type));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&op, child->data, sizeof(op));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&payload_len, child->data, sizeof(payload_len));
    payload_len -= sizeof(struct bf_matcher);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    payload = child->data;

    r = bf_matcher_new(matcher, type, op, payload, payload_len);
    if (r)
        return bf_err_r(r, "failed to restore bf_matcher from serialised data");

    return 0;
}

void bf_matcher_free(struct bf_matcher **matcher)
{
    bf_assert(matcher);

    if (!*matcher)
        return;

    free(*matcher);
    *matcher = NULL;
}

int bf_matcher_marsh(const struct bf_matcher *matcher, struct bf_marsh **marsh)
{
    _free_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(matcher);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &matcher->type, sizeof(matcher->type));
    r |= bf_marsh_add_child_raw(&_marsh, &matcher->op, sizeof(matcher->op));
    r |= bf_marsh_add_child_raw(&_marsh, &matcher->len, sizeof(matcher->len));
    r |= bf_marsh_add_child_raw(&_marsh, matcher->payload,
                                matcher->len - sizeof(struct bf_matcher));
    if (r)
        return bf_err_r(r, "failed to serialise bf_matcher object");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix)
{
    bf_assert(matcher);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_matcher at %p", matcher);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "type: %s", bf_matcher_type_to_str(matcher->type));
    DUMP(prefix, "op: %s", bf_matcher_op_to_str(matcher->op));
    DUMP(prefix, "len: %ld", matcher->len);
    DUMP(bf_dump_prefix_last(prefix), "payload:");
    bf_dump_prefix_push(prefix);
    bf_dump_hex(prefix, matcher->payload,
                matcher->len - sizeof(struct bf_matcher));
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

static const char *_bf_matcher_type_strs[] = {
    [BF_MATCHER_META_IFACE] = "meta.iface",
    [BF_MATCHER_META_L3_PROTO] = "meta.l3_proto",
    [BF_MATCHER_META_L4_PROTO] = "meta.l4_proto",
    [BF_MATCHER_META_PROBABILITY] = "meta.probability",
    [BF_MATCHER_META_SPORT] = "meta.sport",
    [BF_MATCHER_META_DPORT] = "meta.dport",
    [BF_MATCHER_IP4_SADDR] = "ip4.saddr",
    [BF_MATCHER_IP4_SNET] = "ip4.snet",
    [BF_MATCHER_IP4_DADDR] = "ip4.daddr",
    [BF_MATCHER_IP4_DNET] = "ip4.dnet",
    [BF_MATCHER_IP4_PROTO] = "ip4.proto",
    [BF_MATCHER_IP6_SADDR] = "ip6.saddr",
    [BF_MATCHER_IP6_SNET] = "ip6.snet",
    [BF_MATCHER_IP6_DADDR] = "ip6.daddr",
    [BF_MATCHER_IP6_DNET] = "ip6.dnet",
    [BF_MATCHER_IP6_NEXTHDR] = "ip6.nexthdr",
    [BF_MATCHER_TCP_SPORT] = "tcp.sport",
    [BF_MATCHER_TCP_DPORT] = "tcp.dport",
    [BF_MATCHER_TCP_FLAGS] = "tcp.flags",
    [BF_MATCHER_UDP_SPORT] = "udp.sport",
    [BF_MATCHER_UDP_DPORT] = "udp.dport",
    [BF_MATCHER_SET_SRCIP6PORT] = "set.srcip6port",
    [BF_MATCHER_SET_SRCIP6] = "set.srcip6",
    [BF_MATCHER_ICMP_TYPE] = "icmp.type",
    [BF_MATCHER_ICMP_CODE] = "icmp.code",
    [BF_MATCHER_ICMPV6_TYPE] = "icmpv6.type",
    [BF_MATCHER_ICMPV6_CODE] = "icmpv6.code",
};

static_assert(ARRAY_SIZE(_bf_matcher_type_strs) == _BF_MATCHER_TYPE_MAX,
              "missing entries in the matcher type array");

const char *bf_matcher_type_to_str(enum bf_matcher_type type)
{
    bf_assert(0 <= type && type < _BF_MATCHER_TYPE_MAX);

    return _bf_matcher_type_strs[type];
}

int bf_matcher_type_from_str(const char *str, enum bf_matcher_type *type)
{
    bf_assert(str);
    bf_assert(type);

    for (size_t i = 0; i < _BF_MATCHER_TYPE_MAX; ++i) {
        if (bf_streq(_bf_matcher_type_strs[i], str)) {
            *type = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_matcher_ops_strs[] = {
    [BF_MATCHER_EQ] = "eq",   [BF_MATCHER_NE] = "not",
    [BF_MATCHER_ANY] = "any", [BF_MATCHER_ALL] = "all",
    [BF_MATCHER_IN] = "in",   [BF_MATCHER_RANGE] = "range",
};

static_assert(ARRAY_SIZE(_bf_matcher_ops_strs) == _BF_MATCHER_OP_MAX);

const char *bf_matcher_op_to_str(enum bf_matcher_op op)
{
    bf_assert(0 <= op && op < _BF_MATCHER_OP_MAX);

    return _bf_matcher_ops_strs[op];
}

int bf_matcher_op_from_str(const char *str, enum bf_matcher_op *op)
{
    bf_assert(str);
    bf_assert(op);

    for (size_t i = 0; i < _BF_MATCHER_OP_MAX; ++i) {
        if (bf_streq(_bf_matcher_ops_strs[i], str)) {
            *op = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_matcher_tcp_flags_strs[] = {
    [BF_MATCHER_TCP_FLAG_FIN] = "FIN", [BF_MATCHER_TCP_FLAG_SYN] = "SYN",
    [BF_MATCHER_TCP_FLAG_RST] = "RST", [BF_MATCHER_TCP_FLAG_PSH] = "PSH",
    [BF_MATCHER_TCP_FLAG_ACK] = "ACK", [BF_MATCHER_TCP_FLAG_URG] = "URG",
    [BF_MATCHER_TCP_FLAG_ECE] = "ECE", [BF_MATCHER_TCP_FLAG_CWR] = "CWR",
};

static_assert(ARRAY_SIZE(_bf_matcher_tcp_flags_strs) ==
              _BF_MATCHER_TCP_FLAG_MAX);

const char *bf_matcher_tcp_flag_to_str(enum bf_matcher_tcp_flag flag)
{
    bf_assert(0 <= flag && flag < _BF_MATCHER_TCP_FLAG_MAX);

    return _bf_matcher_tcp_flags_strs[flag];
}

int bf_matcher_tcp_flag_from_str(const char *str,
                                 enum bf_matcher_tcp_flag *flag)
{
    bf_assert(str);
    bf_assert(flag);

    for (size_t i = 0; i < _BF_MATCHER_TCP_FLAG_MAX; ++i) {
        if (bf_streq(_bf_matcher_tcp_flags_strs[i], str)) {
            *flag = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_matcher_ipv6_nh_strs[] = {
    [BF_IPV6_NH_HOP] = "hop",       [BF_IPV6_NH_TCP] = "tcp",
    [BF_IPV6_NH_UDP] = "udp",       [BF_IPV6_NH_ROUTING] = "route",
    [BF_IPV6_NH_FRAGMENT] = "frag", [BF_IPV6_NH_AH] = "ah",
    [BF_IPV6_NH_ICMPV6] = "icmpv6", [BF_IPV6_NH_DSTOPTS] = "dst",
    [BF_IPV6_NH_MH] = "mh",
};

static_assert(ARRAY_SIZE(_bf_matcher_ipv6_nh_strs) == _BF_MATCHER_IPV6_NH_MAX);

const char *bf_matcher_ipv6_nh_to_str(enum bf_matcher_ipv6_nh nexthdr)
{
    bf_assert(0 <= nexthdr && nexthdr < _BF_MATCHER_IPV6_NH_MAX);

    return _bf_matcher_ipv6_nh_strs[nexthdr];
}

int bf_matcher_ipv6_nh_from_str(const char *str,
                                enum bf_matcher_ipv6_nh *nexthdr)
{
    bf_assert(str && nexthdr);

    for (size_t i = 0; i < _BF_MATCHER_IPV6_NH_MAX; ++i) {
        /* sparse array */
        if (!_bf_matcher_ipv6_nh_strs[i])
            continue;
        if (bf_streq(_bf_matcher_ipv6_nh_strs[i], str)) {
            *nexthdr = i;
            return 0;
        }
    }

    return -EINVAL;
}

const char *bf_ethertype_to_str(uint16_t ethertype)
{
    switch (ethertype) {
    case ETH_P_IP:
        return "ipv4";
    case ETH_P_IPV6:
        return "ipv6";
    default:
        return NULL;
    }
}

int bf_ethertype_from_str(const char *str, uint16_t *ethertype)
{
    bf_assert(str && ethertype);

    if (bf_streq_i(str, "ipv4")) {
        *ethertype = ETH_P_IP;
        return 0;
    }

    if (bf_streq_i(str, "ipv6")) {
        *ethertype = ETH_P_IPV6;
        return 0;
    }

    return -EINVAL;
}

static const char *_bf_ipproto_strs[UINT8_MAX + 1] = {
    [IPPROTO_ICMP] = "icmp", [IPPROTO_IGMP] = "igmp",     [IPPROTO_TCP] = "tcp",
    [IPPROTO_UDP] = "udp",   [IPPROTO_ICMPV6] = "icmpv6",
};
static_assert(ARRAY_SIZE(_bf_ipproto_strs) == (UINT8_MAX + 1),
              "missing entries in IP protocols strings array");

const char *bf_ipproto_to_str(uint8_t ipproto)
{
    return _bf_ipproto_strs[ipproto];
}

int bf_ipproto_from_str(const char *str, uint8_t *ipproto)
{
    bf_assert(str && ipproto);

    for (size_t i = 0; i <= UINT8_MAX; ++i) {
        if (bf_streq_i(str, _bf_ipproto_strs[i])) {
            *ipproto = (uint8_t)i;
            return 0;
        }
    }

    return -EINVAL;
}
