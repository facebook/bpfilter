/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/matcher.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/if.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"
#include "bpfilter/runtime.h"

#define INET4_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define BF_PAYLOAD_OPS(type, size, parser_cb, printer_cb)                      \
    [type] = {size, parser_cb, printer_cb}

extern int inet_pton(int, const char *, void *);
extern const char *inet_ntop(int, const void *, char *, socklen_t);

/**
 * Matcher definition.
 *
 * Matchers are criterias to match the packet against. A set of matcher defines
 * what a rule should match on.
 *
 * @todo `bf_matcher`'s payload should be a union of all the possible payload
 * types.
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

int _bf_parse_int(enum bf_matcher_type type, enum bf_matcher_op op,
                  void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long value;
    char *endptr;

    value = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && value <= UINT32_MAX) {
        *(uint32_t *)payload = (uint32_t)value;
        return 0;
    }

    value = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && value <= UINT32_MAX) {
        *(uint32_t *)payload = (uint32_t)value;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a valid 32 bits integer value in decimal or hexadecimal notation, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_int(const void *payload)
{
    assert(payload);

    (void)fprintf(stdout, "0x%" PRIx32, *(uint32_t *)payload);
}

#define BF_INT_RANGE_MAX_LEN 32 /* 4294967295-4294967295 */

int _bf_parse_int_range(enum bf_matcher_type type, enum bf_matcher_op op,
                        void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    uint32_t *range = (uint32_t *)payload;
    unsigned long value;
    char buf[BF_INT_RANGE_MAX_LEN];
    char *first;
    char *second;
    char *endptr;

    bf_strncpy(buf, BF_INT_RANGE_MAX_LEN, raw_payload);

    if (!isdigit(*raw_payload))
        goto err;

    first = strtok_r(buf, "-", &second);
    if (!first)
        goto err;

    if (!*second)
        goto err;

    value = strtoul(first, &endptr, BF_BASE_10);
    if (*endptr != '\0' || value > UINT32_MAX) {
        value = strtoul(first, &endptr, BF_BASE_16);
        if (*endptr != '\0' || value > UINT32_MAX)
            goto err;
    }
    range[0] = (uint32_t)value;

    value = strtoul(second, &endptr, BF_BASE_10);
    if (*endptr != '\0' || value > UINT32_MAX) {
        value = strtoul(second, &endptr, BF_BASE_16);
        if (*endptr != '\0' || value > UINT32_MAX)
            goto err;
    }
    range[1] = (uint32_t)value;

    if (range[1] < range[0])
        goto err;

    return 0;

err:
    bf_err(
        "\"%s %s\" expects two positive decimal and hexadecimal integers as `$START-$END`, with `$START <= $END`, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_int_range(const void *payload)
{
    assert(payload);

    uint32_t *range = (uint32_t *)payload;

    (void)fprintf(stdout, "0x%" PRIx32 "-0x%" PRIx32, range[0], range[1]);
}

int _bf_parse_iface(enum bf_matcher_type type, enum bf_matcher_op op,
                    void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    int r;

    r = bf_if_index_from_str(raw_payload, (uint32_t *)payload);
    if (r) {
        return bf_err_r(
            r,
            "\"%s %s\" expects an interface name (e.g., \"eth0\", \"wlan0\") or a decimal interface index (e.g., \"1\", \"2\"), not '%s'",
            bf_matcher_type_to_str(type), bf_matcher_op_to_str(op),
            raw_payload);
    }

    return 0;
}

void _bf_print_iface(const void *payload)
{
    assert(payload);

    const char *ifname;
    uint32_t ifindex = *(uint32_t *)payload;

    ifname = bf_if_name_from_index((int)ifindex);
    if (ifname)
        (void)fprintf(stdout, "%s", ifname);
    else
        (void)fprintf(stdout, "%" PRIu32, ifindex);
}

int _bf_parse_l3_proto(enum bf_matcher_type type, enum bf_matcher_op op,
                       void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long ethertype;
    char *endptr;
    int r;

    r = bf_ethertype_from_str(raw_payload, payload);
    if (!r)
        return 0;

    ethertype = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && ethertype <= UINT16_MAX) {
        *(uint16_t *)payload = (uint16_t)ethertype;
        return 0;
    }

    ethertype = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && ethertype <= UINT16_MAX) {
        *(uint16_t *)payload = (uint16_t)ethertype;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects an internet layer protocol name (e.g. \"IPv6\", case insensitive), or a valid decimal or hexadecimal IEEE 802 number, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_l3_proto(const void *payload)
{
    assert(payload);

    const char *ethertype = bf_ethertype_to_str(*(uint16_t *)payload);

    if (ethertype)
        (void)fprintf(stdout, "%s", ethertype);
    else
        (void)fprintf(stdout, "0x%04" PRIx16, *(uint16_t *)payload);
}

int _bf_parse_l4_proto(enum bf_matcher_type type, enum bf_matcher_op op,
                       void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long ipproto;
    char *endptr;
    int r;

    r = bf_ipproto_from_str(raw_payload, payload);
    if (!r)
        return 0;

    ipproto = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && ipproto <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)ipproto;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a transport layer protocol name (e.g. \"ICMP\", case insensitive), or a valid decimal internet protocol number, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_l4_proto(const void *payload)
{
    assert(payload);

    const char *ipproto = bf_ipproto_to_str(*(uint8_t *)payload);

    if (ipproto)
        (void)fprintf(stdout, "%s", ipproto);
    else
        (void)fprintf(stdout, "%" PRIu8, *(uint8_t *)payload);
}

int _bf_parse_l4_port(enum bf_matcher_type type, enum bf_matcher_op op,
                      void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long port;
    char *endptr;

    port = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && port <= UINT16_MAX) {
        *(uint16_t *)payload = htobe16((uint16_t)port);
        return 0;
    }

    bf_err("\"%s %s\" expects a valid decimal port number, not '%s'",
           bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_l4_port(const void *payload)
{
    assert(payload);

    (void)fprintf(stdout, "%" PRIu16, (uint16_t)be16toh(*(uint16_t *)payload));
}

#define BF_PORT_RANGE_MAX_LEN 16 // 65535-65535, with nul char, round to **2

static int _bf_parse_l4_port_range(enum bf_matcher_type type,
                                   enum bf_matcher_op op, void *payload,
                                   const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    uint16_t *ports = (uint16_t *)payload;
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
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_l4_port_range(const void *payload)
{
    assert(payload);

    uint16_t *ports = (uint16_t *)payload;

    (void)fprintf(stdout, "%" PRIu16 "-%" PRIu16, ports[0], ports[1]);
}

static int _bf_parse_probability(enum bf_matcher_type type,
                                 enum bf_matcher_op op, void *payload,
                                 const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long proba;
    char *endptr;

    proba = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (endptr[0] == '%' && endptr[1] == '\0' && proba <= 100) {
        *(uint8_t *)payload = (uint8_t)proba;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a valid decimal percentage value (i.e., within [0%%, 100%%]), not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_probability(const void *payload)
{
    assert(payload);

    (void)fprintf(stdout, "%" PRIu8 "%%", *(uint8_t *)payload);
}

static int _bf_parse_flow_probability(enum bf_matcher_type type,
                                      enum bf_matcher_op op, void *payload,
                                      const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    double proba;
    char *endptr;

    proba = strtod(raw_payload, &endptr);
    if (endptr[0] == '%' && endptr[1] == '\0' && proba >= 0.0 &&
        proba <= 100.0) {
        *(float *)payload = (float)proba;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a valid percentage value (i.e., within [0%%, 100%%], e.g., \"50%%\" or \"33.33%%\"), not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

static void _bf_print_flow_probability(const void *payload)
{
    assert(payload);

    float proba = *(float *)payload;
    if (proba == floorf(proba))
        (void)fprintf(stdout, "%.0f%%", proba);
    else
        (void)fprintf(stdout, "%g%%", proba);
}

static int _bf_parse_mark(enum bf_matcher_type type, enum bf_matcher_op op,
                          void *payload, const char *raw_payload)
{
    long long mark;
    char *endptr;

    assert(payload);
    assert(raw_payload);

    (void)type;
    (void)op;

    mark = strtoll(raw_payload, &endptr, 0);
    if (*endptr) {
        return bf_err_r(-EINVAL,
                        "mark value '%s' can't be parsed as a positive integer",
                        raw_payload);
    }
    if (mark < 0) {
        return bf_err_r(-EINVAL, "mark should be positive, not '%s'",
                        raw_payload);
    }
    if (mark > UINT32_MAX)
        return bf_err_r(-EINVAL, "mark should be at most 0x%x", UINT32_MAX);

    *(uint32_t *)payload = (uint32_t)mark;

    return 0;
}

void _bf_print_mark(const void *payload)
{
    assert(payload);

    (void)fprintf(stdout, "0x%" PRIx32, *(uint32_t *)payload);
}

static int _bf_parse_ipv4_addr(enum bf_matcher_type type, enum bf_matcher_op op,
                               void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    int r;

    r = inet_pton(AF_INET, raw_payload, payload);
    if (r == 1)
        return 0;

    bf_err(
        "\"%s %s\" expects an IPv4 address in dotted-decimal format, \"ddd.ddd.ddd.ddd\", where ddd is a decimal number of up to three digits in the range 0 to 255, not '%s' ",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_ipv4_addr(const void *payload)
{
    assert(payload);

    char str[INET4_ADDRSTRLEN];

    if (inet_ntop(AF_INET, payload, str, INET4_ADDRSTRLEN))
        (void)fprintf(stdout, "%s", str);
    else
        (void)fprintf(stdout, "<failed to print IPv4 address>");
}

#define BF_IPV4_NET_MAX_LEN                                                    \
    32 // 255.255.255.255/32, with nul char, round to **2

static int _bf_parse_ipv4_net(enum bf_matcher_type type, enum bf_matcher_op op,
                              void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    struct bf_ip4_lpm_key *addr = payload;
    char buf[BF_IPV4_NET_MAX_LEN];
    char *strip, *strmask, *endptr;
    int r;

    bf_strncpy(buf, BF_IPV4_NET_MAX_LEN, raw_payload);

    if (!isdigit(*raw_payload))
        goto err;

    strip = strtok_r(buf, "/", &strmask);
    if (!strip || !*strmask)
        goto err;

    r = inet_pton(AF_INET, strip, &addr->data);
    if (r != 1)
        goto err;

    addr->prefixlen = strtoul(strmask, &endptr, BF_BASE_10);
    if (*endptr != '\0' || addr->prefixlen > 32)
        goto err;

    return 0;

err:
    bf_err(
        "\"%s %s\" expects an IPv4 network address in dotted-decimal format, \"ddd.ddd.ddd.ddd\", where ddd is a decimal number of up to three digits in the range 0 to 255 followed by a subnet mask (e.g., \"124.24.12.5/30\"), not '%s' ",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_ipv4_net(const void *payload)
{
    assert(payload);

    char str[INET4_ADDRSTRLEN];
    const struct bf_ip4_lpm_key *addr = payload;

    if (inet_ntop(AF_INET, &addr->data, str, INET4_ADDRSTRLEN))
        (void)fprintf(stdout, "%s/%u", str, addr->prefixlen);
    else
        (void)fprintf(stdout, "<failed to print IPv4 network>");
}

static int _bf_parse_ipv6_addr(enum bf_matcher_type type, enum bf_matcher_op op,
                               void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    int r;

    r = inet_pton(AF_INET6, raw_payload, payload);
    if (r == 1)
        return 0;

    bf_err(
        "\"%s %s\" expects an IPv6 address composed of 8 hexadecimal numbers (abbreviations are supported), not '%s' ",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_ipv6_addr(const void *payload)
{
    assert(payload);

    char str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, payload, str, INET6_ADDRSTRLEN))
        (void)fprintf(stdout, "%s", str);
    else
        (void)fprintf(stdout, "<failed to print IPv6 address>");
}

#define BF_IPV6_NET_MAX_LEN (INET6_ADDRSTRLEN + 4)

static int _bf_parse_ipv6_net(enum bf_matcher_type type, enum bf_matcher_op op,
                              void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    struct bf_ip6_lpm_key *addr = payload;
    char buf[BF_IPV6_NET_MAX_LEN];
    char *strip, *strmask, *endptr;
    int r;

    bf_strncpy(buf, BF_IPV6_NET_MAX_LEN, raw_payload);

    if (!isalpha(*raw_payload) && !isdigit(*raw_payload) && *raw_payload != ':')
        goto err;

    strip = strtok_r(buf, "/", &strmask);
    if (!strip || !*strmask)
        goto err;

    r = inet_pton(AF_INET6, strip, &addr->data);
    if (r != 1)
        goto err;

    addr->prefixlen = strtoul(strmask, &endptr, BF_BASE_10);
    if (*endptr != '\0' || addr->prefixlen > 128)
        goto err;

    return 0;

err:
    bf_err(
        "\"%s %s\" expects an IPv6 network address composed of 8 hexadecimal numbers (abbreviations are supported) followed by a subnet mask (e.g., \"2001:db8:85a3::/48\"), not '%s' ",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_ipv6_net(const void *payload)
{
    assert(payload);

    const struct bf_ip6_lpm_key *addr = payload;
    char str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr->data, str, INET6_ADDRSTRLEN))
        (void)fprintf(stdout, "%s/%u", str, addr->prefixlen);
    else
        (void)fprintf(stdout, "<failed to print IPv6 address>");
}

static int _bf_parse_tcp_flags(enum bf_matcher_type type, enum bf_matcher_op op,
                               void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    _cleanup_free_ char *_raw_payload = NULL;
    char *tmp;
    char *saveptr;
    char *token;
    uint8_t *flags = payload;

    _raw_payload = strdup(raw_payload);
    if (!_raw_payload)
        goto err;

    *flags = 0;
    tmp = _raw_payload;

    while ((token = strtok_r(tmp, ",", &saveptr))) {
        enum bf_tcp_flag new_flag;
        int r;

        r = bf_tcp_flag_from_str(token, &new_flag);
        if (r)
            goto err;

        *flags |= (uint8_t)(1 << new_flag);

        tmp = NULL;
    }

    return 0;

err:
    bf_err(
        "\"%s %s\" expects a comma-separated list of one or more TCP flags (fin, syn, rst, psh, ack, urg, ece, or cwr), not '%s' ",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_tcp_flags(const void *payload)
{
    assert(payload);

    uint8_t flag = *(uint8_t *)payload;

    for (uint32_t i = 0; i < _BF_TCP_MAX; ++i) {
        if (flag & (1 << i)) {
            flag &= ~(1 << i);
            (void)fprintf(stdout, "%s%s", bf_tcp_flag_to_str(i),
                          flag ? "," : "");
        }
    }
}

static int _bf_parse_icmp_type(enum bf_matcher_type type, enum bf_matcher_op op,
                               void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long icmptype;
    char *endptr;
    int r;

    r = bf_icmp_type_from_str(raw_payload, payload);
    if (!r)
        return 0;

    icmptype = strtoul(raw_payload, &endptr, BF_BASE_10);

    if (*endptr == '\0' && icmptype <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)icmptype;
        return 0;
    }

    icmptype = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && icmptype <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)icmptype;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects an ICMP type name (e.g. \"echo-reply\", case insensitive), or or a decimal or hexadecimal ICMP type value, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_icmp_type(const void *payload)
{
    assert(payload);

    const char *type = bf_icmp_type_to_str(*(uint8_t *)payload);

    if (type)
        (void)fprintf(stdout, "%s", type);
    else
        (void)fprintf(stdout, "%" PRIu8, *(uint8_t *)payload);
}

static int _bf_parse_icmp_code(enum bf_matcher_type type, enum bf_matcher_op op,
                               void *payload, const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long code;
    char *endptr;

    code = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && code <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)code;
        return 0;
    }

    code = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && code <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)code;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects a decimal or hexadecimal ICMP or ICMPv6 code value, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_icmp_code(const void *payload)
{
    assert(payload);

    (void)fprintf(stdout, "%" PRIu8, *(uint8_t *)payload);
}

static int _bf_parse_u8(enum bf_matcher_type type, enum bf_matcher_op op,
                        void *payload, const char *raw_payload)
{
    unsigned long value;
    char *endptr;

    assert(payload);
    assert(raw_payload);

    value = strtoul(raw_payload, &endptr, BF_BASE_10);
    if (*endptr == '\0' && value <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)value;
        return 0;
    }

    value = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && value <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)value;
        return 0;
    }

    bf_err("\"%s %s\" expects a decimal or hexadecimal value (0-255), not '%s'",
           bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

static void _bf_print_u8(const void *payload)
{
    assert(payload);

    (void)fprintf(stdout, "0x%02" PRIx8, *(uint8_t *)payload);
}

static int _bf_parse_icmpv6_type(enum bf_matcher_type type,
                                 enum bf_matcher_op op, void *payload,
                                 const char *raw_payload)
{
    assert(payload);
    assert(raw_payload);

    unsigned long icmptype;
    char *endptr;
    int r;

    r = bf_icmpv6_type_from_str(raw_payload, payload);
    if (!r)
        return 0;

    icmptype = strtoul(raw_payload, &endptr, BF_BASE_10);

    if (*endptr == '\0' && icmptype <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)icmptype;
        return 0;
    }

    icmptype = strtoul(raw_payload, &endptr, BF_BASE_16);
    if (*endptr == '\0' && icmptype <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)icmptype;
        return 0;
    }

    bf_err(
        "\"%s %s\" expects an ICMPv6 type name (e.g. \"echo-reply\", case insensitive), or a decimal or hexadecimal ICMPv6 type value, not '%s'",
        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op), raw_payload);

    return -EINVAL;
}

void _bf_print_icmpv6_type(const void *payload)
{
    assert(payload);

    const char *type = bf_icmpv6_type_to_str(*(uint8_t *)payload);

    if (type)
        (void)fprintf(stdout, "%s", type);
    else
        (void)fprintf(stdout, "%" PRIu8, *(uint8_t *)payload);
}

#define BF_MATCHER_OPS(op, payload_size, parse_cb, print_cb)                   \
    [op] = {payload_size, parse_cb, print_cb}

#define _BF_TCP_FLAGS_OFFSET 13

static struct bf_matcher_meta _bf_matcher_metas[_BF_MATCHER_TYPE_MAX] = {
    [BF_MATCHER_META_IFACE] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint32_t),
                                   _bf_parse_iface, _bf_print_iface),
                },
        },
    [BF_MATCHER_META_L3_PROTO] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l3_proto, _bf_print_l3_proto),
                },
        },
    [BF_MATCHER_META_L4_PROTO] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                },
        },
    [BF_MATCHER_META_SPORT] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint16_t),
                                   _bf_parse_l4_port_range,
                                   _bf_print_l4_port_range),
                },
        },
    [BF_MATCHER_META_DPORT] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint16_t),
                                   _bf_parse_l4_port_range,
                                   _bf_print_l4_port_range),
                },
        },
    [BF_MATCHER_META_PROBABILITY] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_probability,
                                   _bf_print_probability),
                },
        },
    [BF_MATCHER_META_MARK] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .unsupported_hooks = BF_FLAGS(BF_HOOK_XDP),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint32_t),
                                   _bf_parse_mark, _bf_print_mark),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint32_t),
                                   _bf_parse_mark, _bf_print_mark),
                },
        },
    [BF_MATCHER_META_FLOW_HASH] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .unsupported_hooks = BF_FLAGS(
                BF_HOOK_XDP, BF_HOOK_CGROUP_INGRESS, BF_HOOK_CGROUP_EGRESS,
                BF_HOOK_NF_FORWARD, BF_HOOK_NF_LOCAL_IN, BF_HOOK_NF_LOCAL_OUT,
                BF_HOOK_NF_POST_ROUTING, BF_HOOK_NF_PRE_ROUTING),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint32_t),
                                   _bf_parse_int, _bf_print_int),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint32_t),
                                   _bf_parse_int, _bf_print_int),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint32_t),
                                   _bf_parse_int_range, _bf_print_int_range),
                },
        },
    [BF_MATCHER_META_FLOW_PROBABILITY] =
        {
            .layer = BF_MATCHER_NO_LAYER,
            .unsupported_hooks = BF_FLAGS(
                BF_HOOK_NF_FORWARD, BF_HOOK_NF_LOCAL_IN, BF_HOOK_NF_LOCAL_OUT,
                BF_HOOK_NF_POST_ROUTING, BF_HOOK_NF_PRE_ROUTING),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(float),
                                   _bf_parse_flow_probability,
                                   _bf_print_flow_probability),
                },
        },
    [BF_MATCHER_IP4_SADDR] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IP,
            .hdr_payload_size = sizeof(uint32_t),
            .hdr_payload_offset = offsetof(struct iphdr, saddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint32_t),
                                   _bf_parse_ipv4_addr, _bf_print_ipv4_addr),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint32_t),
                                   _bf_parse_ipv4_addr, _bf_print_ipv4_addr),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint32_t),
                                   _bf_parse_ipv4_addr, _bf_print_ipv4_addr),
                },
        },
    [BF_MATCHER_IP4_DADDR] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IP,
            .hdr_payload_size = sizeof(uint32_t),
            .hdr_payload_offset = offsetof(struct iphdr, daddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint32_t),
                                   _bf_parse_ipv4_addr, _bf_print_ipv4_addr),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint32_t),
                                   _bf_parse_ipv4_addr, _bf_print_ipv4_addr),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint32_t),
                                   _bf_parse_ipv4_addr, _bf_print_ipv4_addr),
                },
        },
    [BF_MATCHER_IP4_SNET] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IP,
            .hdr_payload_size = sizeof(uint32_t),
            .hdr_payload_offset = offsetof(struct iphdr, saddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(struct bf_ip4_lpm_key),
                                   _bf_parse_ipv4_net, _bf_print_ipv4_net),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(struct bf_ip4_lpm_key),
                                   _bf_parse_ipv4_net, _bf_print_ipv4_net),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(struct bf_ip4_lpm_key),
                                   _bf_parse_ipv4_net, _bf_print_ipv4_net),
                },
        },
    [BF_MATCHER_IP4_DNET] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IP,
            .hdr_payload_size = sizeof(uint32_t),
            .hdr_payload_offset = offsetof(struct iphdr, daddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(struct bf_ip4_lpm_key),
                                   _bf_parse_ipv4_net, _bf_print_ipv4_net),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(struct bf_ip4_lpm_key),
                                   _bf_parse_ipv4_net, _bf_print_ipv4_net),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(struct bf_ip4_lpm_key),
                                   _bf_parse_ipv4_net, _bf_print_ipv4_net),
                },
        },
    [BF_MATCHER_IP4_PROTO] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IP,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct iphdr, protocol),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint8_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                },
        },
    [BF_MATCHER_IP4_DSCP] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IP,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct iphdr, tos),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t), _bf_parse_u8,
                                   _bf_print_u8),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t), _bf_parse_u8,
                                   _bf_print_u8),
                },
        },
    [BF_MATCHER_IP6_SADDR] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IPV6,
            .hdr_payload_size = sizeof(struct in6_addr),
            .hdr_payload_offset = offsetof(struct ipv6hdr, saddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(struct in6_addr),
                                   _bf_parse_ipv6_addr, _bf_print_ipv6_addr),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(struct in6_addr),
                                   _bf_parse_ipv6_addr, _bf_print_ipv6_addr),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(struct in6_addr),
                                   _bf_parse_ipv6_addr, _bf_print_ipv6_addr),
                },
        },
    [BF_MATCHER_IP6_DADDR] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IPV6,
            .hdr_payload_size = sizeof(struct in6_addr),
            .hdr_payload_offset = offsetof(struct ipv6hdr, daddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(struct in6_addr),
                                   _bf_parse_ipv6_addr, _bf_print_ipv6_addr),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(struct in6_addr),
                                   _bf_parse_ipv6_addr, _bf_print_ipv6_addr),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(struct in6_addr),
                                   _bf_parse_ipv6_addr, _bf_print_ipv6_addr),
                },
        },
    [BF_MATCHER_IP6_SNET] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IPV6,
            .hdr_payload_size = sizeof(struct in6_addr),
            .hdr_payload_offset = offsetof(struct ipv6hdr, saddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(struct bf_ip6_lpm_key),
                                   _bf_parse_ipv6_net, _bf_print_ipv6_net),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(struct bf_ip6_lpm_key),
                                   _bf_parse_ipv6_net, _bf_print_ipv6_net),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(struct bf_ip6_lpm_key),
                                   _bf_parse_ipv6_net, _bf_print_ipv6_net),
                },
        },
    [BF_MATCHER_IP6_DNET] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IPV6,
            .hdr_payload_size = sizeof(struct in6_addr),
            .hdr_payload_offset = offsetof(struct ipv6hdr, daddr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(struct bf_ip6_lpm_key),
                                   _bf_parse_ipv6_net, _bf_print_ipv6_net),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(struct bf_ip6_lpm_key),
                                   _bf_parse_ipv6_net, _bf_print_ipv6_net),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(struct bf_ip6_lpm_key),
                                   _bf_parse_ipv6_net, _bf_print_ipv6_net),
                },
        },
    [BF_MATCHER_IP6_NEXTHDR] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IPV6,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct ipv6hdr, nexthdr),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint8_t),
                                   _bf_parse_l4_proto, _bf_print_l4_proto),
                },
        },
    [BF_MATCHER_IP6_DSCP] =
        {
            .layer = BF_MATCHER_LAYER_3,
            .hdr_id = ETH_P_IPV6,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = 0,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t), _bf_parse_u8,
                                   _bf_print_u8),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t), _bf_parse_u8,
                                   _bf_print_u8),
                },
        },
    [BF_MATCHER_TCP_SPORT] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_TCP,
            .hdr_payload_size = sizeof(uint16_t),
            .hdr_payload_offset = offsetof(struct tcphdr, source),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint16_t),
                                   _bf_parse_l4_port_range,
                                   _bf_print_l4_port_range),
                },
        },
    [BF_MATCHER_TCP_DPORT] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_TCP,
            .hdr_payload_size = sizeof(uint16_t),
            .hdr_payload_offset = offsetof(struct tcphdr, dest),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint16_t),
                                   _bf_parse_l4_port_range,
                                   _bf_print_l4_port_range),
                },
        },
    [BF_MATCHER_TCP_FLAGS] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_TCP,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = _BF_TCP_FLAGS_OFFSET,
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_tcp_flags, _bf_print_tcp_flags),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_tcp_flags, _bf_print_tcp_flags),
                    BF_MATCHER_OPS(BF_MATCHER_ANY, sizeof(uint8_t),
                                   _bf_parse_tcp_flags, _bf_print_tcp_flags),
                    BF_MATCHER_OPS(BF_MATCHER_ALL, sizeof(uint8_t),
                                   _bf_parse_tcp_flags, _bf_print_tcp_flags),
                },
        },
    [BF_MATCHER_UDP_SPORT] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_UDP,
            .hdr_payload_size = sizeof(uint16_t),
            .hdr_payload_offset = offsetof(struct udphdr, source),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint16_t),
                                   _bf_parse_l4_port_range,
                                   _bf_print_l4_port_range),
                },
        },
    [BF_MATCHER_UDP_DPORT] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_UDP,
            .hdr_payload_size = sizeof(uint16_t),
            .hdr_payload_offset = offsetof(struct udphdr, dest),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint16_t),
                                   _bf_parse_l4_port, _bf_print_l4_port),
                    BF_MATCHER_OPS(BF_MATCHER_RANGE, 2 * sizeof(uint16_t),
                                   _bf_parse_l4_port_range,
                                   _bf_print_l4_port_range),
                },
        },
    [BF_MATCHER_ICMP_TYPE] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_ICMP,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct icmphdr, type),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_icmp_type, _bf_print_icmp_type),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_icmp_type, _bf_print_icmp_type),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint8_t),
                                   _bf_parse_icmp_type, _bf_print_icmp_type),
                },
        },
    [BF_MATCHER_ICMP_CODE] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_ICMP,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct icmphdr, code),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_icmp_code, _bf_print_icmp_code),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_icmp_code, _bf_print_icmp_code),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint8_t),
                                   _bf_parse_icmp_code, _bf_print_icmp_code),
                },
        },
    [BF_MATCHER_ICMPV6_TYPE] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_ICMPV6,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct icmp6hdr, icmp6_type),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_icmpv6_type,
                                   _bf_print_icmpv6_type),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_icmpv6_type,
                                   _bf_print_icmpv6_type),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint8_t),
                                   _bf_parse_icmpv6_type,
                                   _bf_print_icmpv6_type),
                },
        },
    [BF_MATCHER_ICMPV6_CODE] =
        {
            .layer = BF_MATCHER_LAYER_4,
            .hdr_id = IPPROTO_ICMPV6,
            .hdr_payload_size = sizeof(uint8_t),
            .hdr_payload_offset = offsetof(struct icmp6hdr, icmp6_code),
            .ops =
                {
                    BF_MATCHER_OPS(BF_MATCHER_EQ, sizeof(uint8_t),
                                   _bf_parse_icmp_code, _bf_print_icmp_code),
                    BF_MATCHER_OPS(BF_MATCHER_NE, sizeof(uint8_t),
                                   _bf_parse_icmp_code, _bf_print_icmp_code),
                    BF_MATCHER_OPS(BF_MATCHER_IN, sizeof(uint8_t),
                                   _bf_parse_icmp_code, _bf_print_icmp_code),
                },
        },
};

const struct bf_matcher_meta *bf_matcher_get_meta(enum bf_matcher_type type)
{
    if (type < 0 || _BF_MATCHER_TYPE_MAX <= type)
        return NULL;

    return _bf_matcher_metas[type].layer == _BF_MATCHER_LAYER_UNDEFINED ?
               NULL :
               &_bf_matcher_metas[type];
}

const struct bf_matcher_ops *bf_matcher_get_ops(enum bf_matcher_type type,
                                                enum bf_matcher_op op)
{
    const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);

    if (!meta)
        return NULL;

    return meta->ops[op].ref_payload_size ? &meta->ops[op] : NULL;
}

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const void *payload,
                   size_t payload_len)
{
    _free_bf_matcher_ struct bf_matcher *_matcher = NULL;

    assert(matcher);
    assert((payload && payload_len) || (!payload && !payload_len));

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

    assert(matcher);
    assert(payload);

    ops = bf_matcher_get_ops(type, op);
    if (!ops) {
        return bf_err_r(-ENOENT, "payload ops not found for '%s %s'",
                        bf_matcher_type_to_str(type), bf_matcher_op_to_str(op));
    }

    _matcher = malloc(sizeof(*_matcher) + ops->ref_payload_size);
    if (!_matcher)
        return -ENOMEM;

    _matcher->type = type;
    _matcher->op = op;
    _matcher->len = sizeof(*_matcher) + ops->ref_payload_size;

    r = ops->parse(_matcher->type, _matcher->op, &_matcher->payload, payload);
    if (r)
        return r;

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

int bf_matcher_new_from_pack(struct bf_matcher **matcher, bf_rpack_node_t node)
{
    _free_bf_matcher_ struct bf_matcher *_matcher = NULL;
    enum bf_matcher_type type;
    enum bf_matcher_op op;
    const void *payload;
    size_t payload_len;
    int r;

    assert(matcher);

    r = bf_rpack_kv_enum(node, "type", &type, 0, _BF_MATCHER_TYPE_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_matcher.type");

    r = bf_rpack_kv_enum(node, "op", &op, 0, _BF_MATCHER_OP_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_matcher.op");

    r = bf_rpack_kv_bin(node, "payload", &payload, &payload_len);
    if (r)
        return bf_rpack_key_err(r, "bf_matcher.payload");

    r = bf_matcher_new(&_matcher, type, op, payload, payload_len);
    if (r)
        return bf_err_r(r, "failed to create bf_matcher from pack");

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

void bf_matcher_free(struct bf_matcher **matcher)
{
    assert(matcher);

    if (!*matcher)
        return;

    free(*matcher);
    *matcher = NULL;
}

int bf_matcher_pack(const struct bf_matcher *matcher, bf_wpack_t *pack)
{
    assert(matcher);
    assert(pack);

    bf_wpack_kv_int(pack, "type", matcher->type);
    bf_wpack_kv_int(pack, "op", matcher->op);
    bf_wpack_kv_bin(pack, "payload", matcher->payload,
                    matcher->len - sizeof(*matcher));

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix)
{
    assert(matcher);
    assert(prefix);

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

enum bf_matcher_type bf_matcher_get_type(const struct bf_matcher *matcher)
{
    assert(matcher);
    return matcher->type;
}

enum bf_matcher_op bf_matcher_get_op(const struct bf_matcher *matcher)
{
    assert(matcher);
    return matcher->op;
}

const void *bf_matcher_payload(const struct bf_matcher *matcher)
{
    assert(matcher);
    return matcher->payload;
}

size_t bf_matcher_payload_len(const struct bf_matcher *matcher)
{
    assert(matcher);
    return matcher->len - sizeof(*matcher);
}

size_t bf_matcher_len(const struct bf_matcher *matcher)
{
    assert(matcher);
    return matcher->len;
}

static const char *_bf_matcher_type_strs[] = {
    [BF_MATCHER_META_IFACE] = "meta.iface",
    [BF_MATCHER_META_L3_PROTO] = "meta.l3_proto",
    [BF_MATCHER_META_L4_PROTO] = "meta.l4_proto",
    [BF_MATCHER_META_PROBABILITY] = "meta.probability",
    [BF_MATCHER_META_SPORT] = "meta.sport",
    [BF_MATCHER_META_DPORT] = "meta.dport",
    [BF_MATCHER_META_MARK] = "meta.mark",
    [BF_MATCHER_META_FLOW_HASH] = "meta.flow_hash",
    [BF_MATCHER_META_FLOW_PROBABILITY] = "meta.flow_probability",
    [BF_MATCHER_IP4_SADDR] = "ip4.saddr",
    [BF_MATCHER_IP4_SNET] = "ip4.snet",
    [BF_MATCHER_IP4_DADDR] = "ip4.daddr",
    [BF_MATCHER_IP4_DNET] = "ip4.dnet",
    [BF_MATCHER_IP4_PROTO] = "ip4.proto",
    [BF_MATCHER_IP4_DSCP] = "ip4.dscp",
    [BF_MATCHER_IP6_SADDR] = "ip6.saddr",
    [BF_MATCHER_IP6_SNET] = "ip6.snet",
    [BF_MATCHER_IP6_DADDR] = "ip6.daddr",
    [BF_MATCHER_IP6_DNET] = "ip6.dnet",
    [BF_MATCHER_IP6_NEXTHDR] = "ip6.nexthdr",
    [BF_MATCHER_IP6_DSCP] = "ip6.dscp",
    [BF_MATCHER_TCP_SPORT] = "tcp.sport",
    [BF_MATCHER_TCP_DPORT] = "tcp.dport",
    [BF_MATCHER_TCP_FLAGS] = "tcp.flags",
    [BF_MATCHER_UDP_SPORT] = "udp.sport",
    [BF_MATCHER_UDP_DPORT] = "udp.dport",
    [BF_MATCHER_ICMP_TYPE] = "icmp.type",
    [BF_MATCHER_ICMP_CODE] = "icmp.code",
    [BF_MATCHER_ICMPV6_TYPE] = "icmpv6.type",
    [BF_MATCHER_ICMPV6_CODE] = "icmpv6.code",
    [BF_MATCHER_SET] = "<set>",
};

static_assert(ARRAY_SIZE(_bf_matcher_type_strs) == _BF_MATCHER_TYPE_MAX,
              "missing entries in the matcher type array");

const char *bf_matcher_type_to_str(enum bf_matcher_type type)
{
    if (type < 0 || _BF_MATCHER_TYPE_MAX <= type)
        return "<invalid>";

    return _bf_matcher_type_strs[type];
}

int bf_matcher_type_from_str(const char *str, enum bf_matcher_type *type)
{
    assert(str);
    assert(type);

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

static_assert(ARRAY_SIZE(_bf_matcher_ops_strs) == _BF_MATCHER_OP_MAX,
              "missing entries in the matcher ops strings array");

const char *bf_matcher_op_to_str(enum bf_matcher_op op)
{
    assert(0 <= op && op < _BF_MATCHER_OP_MAX);

    return _bf_matcher_ops_strs[op];
}

int bf_matcher_op_from_str(const char *str, enum bf_matcher_op *op)
{
    assert(str);
    assert(op);

    for (size_t i = 0; i < _BF_MATCHER_OP_MAX; ++i) {
        if (bf_streq(_bf_matcher_ops_strs[i], str)) {
            *op = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_tcp_flags_strs[] = {
    [BF_TCP_FIN] = "fin", [BF_TCP_SYN] = "syn", [BF_TCP_RST] = "rst",
    [BF_TCP_PSH] = "psh", [BF_TCP_ACK] = "ack", [BF_TCP_URG] = "urg",
    [BF_TCP_ECE] = "ece", [BF_TCP_CWR] = "cwr",
};
static_assert(ARRAY_SIZE(_bf_tcp_flags_strs) == _BF_TCP_MAX,
              "missing entries in the TCP flags strings array");

const char *bf_tcp_flag_to_str(enum bf_tcp_flag flag)
{
    assert(0 <= flag && flag < _BF_TCP_MAX);

    return _bf_tcp_flags_strs[flag];
}

int bf_tcp_flag_from_str(const char *str, enum bf_tcp_flag *flag)
{
    assert(str);
    assert(flag);

    for (size_t i = 0; i < _BF_TCP_MAX; ++i) {
        if (bf_streq_i(_bf_tcp_flags_strs[i], str)) {
            *flag = i;
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
    assert(str);
    assert(ethertype);

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
    [IPPROTO_HOPOPTS] = "hop",   [IPPROTO_ICMP] = "icmp",
    [IPPROTO_IGMP] = "igmp",     [IPPROTO_TCP] = "tcp",
    [IPPROTO_UDP] = "udp",       [IPPROTO_ROUTING] = "routing",
    [IPPROTO_FRAGMENT] = "frag", [IPPROTO_AH] = "ah",
    [IPPROTO_DSTOPTS] = "dst",   [IPPROTO_ICMPV6] = "icmpv6",
    [IPPROTO_MH] = "mh",
};
static_assert(ARRAY_SIZE(_bf_ipproto_strs) == (UINT8_MAX + 1),
              "missing entries in IP protocols strings array");

const char *bf_ipproto_to_str(uint8_t ipproto)
{
    return _bf_ipproto_strs[ipproto];
}

int bf_ipproto_from_str(const char *str, uint8_t *ipproto)
{
    assert(str);
    assert(ipproto);

    for (size_t i = 0; i <= UINT8_MAX; ++i) {
        if (bf_streq_i(str, _bf_ipproto_strs[i])) {
            *ipproto = (uint8_t)i;
            return 0;
        }
    }

    return -EINVAL;
}

#define ICMP_ROUTERADVERT 9
#define ICMP_ROUTERSOLICIT 10

static const char *_bf_icmp_type_strs[UINT8_MAX + 1] = {
    [ICMP_ECHOREPLY] = "echo-reply",
    [ICMP_DEST_UNREACH] = "destination-unreachable",
    [ICMP_SOURCE_QUENCH] = "source-quench",
    [ICMP_REDIRECT] = "redirect",
    [ICMP_ECHO] = "echo-request",
    [ICMP_ROUTERADVERT] = "router-advertisement",
    [ICMP_ROUTERSOLICIT] = "router-solicitation",
    [ICMP_TIME_EXCEEDED] = "time-exceeded",
    [ICMP_PARAMETERPROB] = "parameter-problem",
    [ICMP_TIMESTAMP] = "timestamp-request",
    [ICMP_TIMESTAMPREPLY] = "timestamp-reply",
    [ICMP_INFO_REQUEST] = "info-request",
    [ICMP_INFO_REPLY] = "info-reply",
    [ICMP_ADDRESS] = "address-mask-request",
    [ICMP_ADDRESSREPLY] = "address-mask-reply",
};
static_assert(ARRAY_SIZE(_bf_icmp_type_strs) == (UINT8_MAX + 1),
              "missing entries in ICMP types strings array");

const char *bf_icmp_type_to_str(uint8_t type)
{
    return _bf_icmp_type_strs[type];
}

int bf_icmp_type_from_str(const char *str, uint8_t *type)
{
    assert(str);
    assert(type);

    for (size_t i = 0; i <= UINT8_MAX; ++i) {
        if (bf_streq_i(str, _bf_icmp_type_strs[i])) {
            *type = (uint8_t)i;
            return 0;
        }
    }

    return -EINVAL;
}

#define ICMPV6_ND_ROUTERSOLICIT 133
#define ICMPV6_ND_ROUTERADVERT 134
#define ICMPV6_ND_NEIGHSOLICIT 135
#define ICMPV6_ND_NEIGHADVERT 136

static const char *_bf_icmpv6_type_strs[UINT8_MAX + 1] = {
    [ICMPV6_DEST_UNREACH] = "destination-unreachable",
    [ICMPV6_PKT_TOOBIG] = "packet-too-big",
    [ICMPV6_TIME_EXCEED] = "time-exceeded",
    [ICMPV6_PARAMPROB] = "parameter-problem",
    [ICMPV6_ECHO_REQUEST] = "echo-request",
    [ICMPV6_ECHO_REPLY] = "echo-reply",
    [ICMPV6_MGM_QUERY] = "mld-listener-query",
    [ICMPV6_MGM_REPORT] = "mld-listener-report",
    [ICMPV6_MGM_REDUCTION] = "mld-listener-reduction",
    [ICMPV6_ND_ROUTERSOLICIT] = "nd-router-solicit",
    [ICMPV6_ND_ROUTERADVERT] = "nd-router-advert",
    [ICMPV6_ND_NEIGHSOLICIT] = "nd-neighbor-solicit",
    [ICMPV6_ND_NEIGHADVERT] = "nd-neighbor-advert",
    [ICMPV6_MLD2_REPORT] = "mld2-listener-report",
};
static_assert(ARRAY_SIZE(_bf_icmpv6_type_strs) == (UINT8_MAX + 1),
              "missing entries in ICMPv6 types strings array");

const char *bf_icmpv6_type_to_str(uint8_t type)
{
    return _bf_icmpv6_type_strs[type];
}

int bf_icmpv6_type_from_str(const char *str, uint8_t *type)
{
    assert(str);
    assert(type);

    for (size_t i = 0; i <= UINT8_MAX; ++i) {
        if (bf_streq_i(str, _bf_icmpv6_type_strs[i])) {
            *type = (uint8_t)i;
            return 0;
        }
    }

    return -EINVAL;
}
