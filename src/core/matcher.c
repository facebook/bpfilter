/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/matcher.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const void *payload,
                   size_t payload_len)
{
    _cleanup_bf_matcher_ struct bf_matcher *_matcher = NULL;

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
    memcpy(&payload_len, child->data, sizeof(op));
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
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
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
    [BF_MATCHER_META_IFINDEX] = "meta.ifindex",
    [BF_MATCHER_META_L3_PROTO] = "meta.l3_proto",
    [BF_MATCHER_META_L4_PROTO] = "meta.l4_proto",
    [BF_MATCHER_IP4_SRC_ADDR] = "ip4.saddr",
    [BF_MATCHER_IP4_DST_ADDR] = "ip4.daddr",
    [BF_MATCHER_IP4_PROTO] = "ip4.proto",
    [BF_MATCHER_IP6_SADDR] = "ip6.saddr",
    [BF_MATCHER_IP6_DADDR] = "ip6.daddr",
    [BF_MATCHER_TCP_SPORT] = "tcp.sport",
    [BF_MATCHER_TCP_DPORT] = "tcp.dport",
    [BF_MATCHER_TCP_FLAGS] = "tcp.flags",
    [BF_MATCHER_UDP_SPORT] = "udp.sport",
    [BF_MATCHER_UDP_DPORT] = "udp.dport",
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
    [BF_MATCHER_EQ] = "eq",   [BF_MATCHER_NE] = "not", [BF_MATCHER_ANY] = "any",
    [BF_MATCHER_ALL] = "all", [BF_MATCHER_IN] = "in",
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
