/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/matcher.h"

#include "core/marsh.h"
#include "shared/helper.h"

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

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const uint8_t *payload,
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
        return bf_err_code(r,
                           "failed to restore bf_matcher from serialised data");

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
        return bf_err_code(r, "failed to serialise bf_matcher object");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

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

const char *bf_matcher_type_to_str(enum bf_matcher_type type)
{
    static const char *types_str[] = {
        [BF_MATCHER_IP_SRC_ADDR] = "BF_MATCHER_IP_SRC_ADDR",
    };

    bf_assert(0 <= type && type < _BF_MATCHER_TYPE_MAX);
    static_assert(ARRAY_SIZE(types_str) == _BF_MATCHER_TYPE_MAX,
                  "missing entries in the types_str array");

    return types_str[type];
}

const char *bf_matcher_op_to_str(enum bf_matcher_op op)
{
    static const char *ops_str[] = {
        [BF_MATCHER_EQ] = "BF_MATCHER_EQ",
    };

    bf_assert(0 <= op && op < _BF_MATCHER_OP_MAX);
    static_assert(ARRAY_SIZE(ops_str) == _BF_MATCHER_OP_MAX,
                  "missing entries in the ops_str array");

    return ops_str[op];
}
