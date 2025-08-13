// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/set.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"

/// Mask value of matcher types supporting LPM trie maps.
#define _BF_SET_USE_TRIE_MASK                                                  \
    (BF_FLAGS(BF_MATCHER_IP4_SNET, BF_MATCHER_IP4_DNET, BF_MATCHER_IP6_SNET,   \
              BF_MATCHER_IP6_DNET))

int bf_set_new(struct bf_set **set, enum bf_matcher_type *key, size_t n_comps)
{
    bf_assert(set && key);

    _free_bf_set_ struct bf_set *_set = NULL;
    uint32_t mask = 0;

    bf_static_assert(_BF_MATCHER_TYPE_MAX < 8 * sizeof(uint32_t),
                     "matcher type bitmask won't fit in 32 bits");

    if (n_comps == 0)
        return bf_err_r(-EINVAL, "at least 1 key component is required");

    if (n_comps > BF_SET_MAX_N_COMPS) {
        return bf_err_r(-E2BIG,
                        "a set key can't contain more than %d components",
                        BF_SET_MAX_N_COMPS);
    }

    _set = malloc(sizeof(*_set));
    if (!_set)
        return -ENOMEM;

    memcpy(&(_set)->key, key, n_comps * sizeof(enum bf_matcher_type));
    _set->n_comps = n_comps;
    _set->elem_size = 0;
    _set->elems = bf_list_default(freep, NULL);

    for (size_t i = 0; i < n_comps; ++i) {
        const struct bf_matcher_ops *ops;

        ops = bf_matcher_get_ops(_set->key[i], BF_MATCHER_IN);
        if (!ops) {
            return bf_err_r(-ENOTSUP,
                            "matcher '%s' (%d) is not supported as a set key",
                            bf_matcher_type_to_str(_set->key[i]), _set->key[i]);
        }
        _set->elem_size += ops->ref_payload_size;

        mask |= BF_FLAG(_set->key[i]);
    }

    _set->use_trie = n_comps == 1 && mask & _BF_SET_USE_TRIE_MASK;

    if (n_comps > 1 && mask & _BF_SET_USE_TRIE_MASK) {
        return bf_err_r(
            -EINVAL,
            "network matchers can't be used in combination with other matchers in a set");
    }

    *set = TAKE_PTR(_set);

    return 0;
}

/**
 * @brief Parse a set's raw key into an array of `bf_matcher_type`.
 *
 * @param raw_key Raw set key, as a string of comma-separated matcher types
 *        enclosed in parentheses. Can't be NULL.
 * @param key Set key, parsed from `raw_key`. Can't be NULL.
 * @param n_comps Number of components in `key`. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
static int _bf_set_parse_key(const char *raw_key, enum bf_matcher_type *key,
                             size_t *n_comps)
{
    bf_assert(raw_key && key && n_comps);

    _cleanup_free_ char *_raw_key = NULL;
    char *tmp, *saveptr, *token;

    _raw_key = strdup(raw_key);
    if (!_raw_key) {
        return bf_err_r(-ENOMEM, "failed to duplicate set raw key '%s'",
                        raw_key);
    }

    *n_comps = 0;

    tmp = _raw_key;
    while ((token = strtok_r(tmp, "(),", &saveptr))) {
        int r;

        if (*n_comps == BF_SET_MAX_N_COMPS) {
            return bf_err_r(-E2BIG, "set keys are limited to %d components",
                            BF_SET_MAX_N_COMPS);
        }

        token = bf_trim(token);

        r = bf_matcher_type_from_str(token, &key[*n_comps]);
        if (r)
            return bf_err_r(r, "failed to parse set key component '%s'", token);

        tmp = NULL;
        ++*n_comps;
    }

    if (!*n_comps)
        return bf_err_r(-EINVAL, "set key can't have no component");

    return 0;
}

/**
 * @brief Parse a raw element and insert it into a set.
 *
 * The element is parsed according to `set->key`.
 *
 * @param set Set to parse the element for. Can't be NULL.
 * @param raw_elem Raw element to parse. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
static int _bf_set_parse_elem(struct bf_set *set, const char *raw_elem)
{
    bf_assert(set && raw_elem);

    _cleanup_free_ void *elem = NULL;
    _cleanup_free_ char *_raw_elem = NULL;
    char *tmp, *saveptr, *token;
    size_t elem_offset = 0;
    size_t comp_idx = 0;
    int r;

    _raw_elem = strdup(raw_elem);
    if (!_raw_elem) {
        return bf_err_r(-ENOMEM,
                        "failed to create a copy of the raw element '%s'",
                        raw_elem);
    }

    elem = malloc(set->elem_size);
    if (!elem)
        return bf_err_r(-ENOMEM, "failed to allocate a new set element");

    tmp = _raw_elem;
    while ((token = strtok_r(tmp, ",", &saveptr))) {
        const struct bf_matcher_ops *ops;

        if (comp_idx >= set->n_comps) {
            return bf_err_r(
                -EINVAL,
                "set element has more components than defined in the key '%s'",
                token);
        }

        token = bf_trim(token);

        ops = bf_matcher_get_ops(set->key[comp_idx], BF_MATCHER_IN);
        if (!ops) {
            return bf_err_r(-EINVAL, "matcher type '%s' has no matcher_ops",
                            bf_matcher_type_to_str(set->key[comp_idx]));
        }

        r = ops->parse(set->key[comp_idx], BF_MATCHER_IN, elem + elem_offset,
                       token);
        if (r) {
            return bf_err_r(r, "failed to parse set element component '%s'",
                            token);
        }

        elem_offset += ops->ref_payload_size;
        tmp = NULL;
        ++comp_idx;
    }

    if (comp_idx != set->n_comps) {
        return bf_err_r(-EINVAL, "missing component in set element '%s'",
                        raw_elem);
    }

    r = bf_list_add_tail(&set->elems, elem);
    if (r)
        return bf_err_r(r, "failed to insert element into set");
    TAKE_PTR(elem);

    return 0;
}

int bf_set_new_from_raw(struct bf_set **set, const char *raw_key,
                        const char *raw_payload)
{
    bf_assert(set && raw_key && raw_payload);

    _free_bf_set_ struct bf_set *_set = NULL;
    _cleanup_free_ char *_raw_payload = NULL;
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];
    char *raw_elem, *tmp, *saveptr;
    size_t n_comps;
    int r;

    r = _bf_set_parse_key(raw_key, key, &n_comps);
    if (r)
        return bf_err_r(r, "failed to parse set key '%s'", raw_key);

    r = bf_set_new(&_set, key, n_comps);
    if (r)
        return r;

    _raw_payload = strdup(raw_payload);
    if (!_raw_payload)
        return bf_err_r(-ENOMEM, "failed to copy set raw payload '%s'",
                        raw_payload);

    tmp = _raw_payload;
    while ((raw_elem = strtok_r(tmp, "{};\n", &saveptr))) {
        raw_elem = bf_trim(raw_elem);

        /* While strtok_r() won't return empty token, the trimmed version of the
         * token can be empty! */
        if (raw_elem[0] == '\0')
            continue;

        r = _bf_set_parse_elem(_set, raw_elem);
        if (r)
            return bf_err_r(r, "failed to parse set element '%s'", raw_elem);

        tmp = NULL;
    }

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_set_new_from_marsh(struct bf_set **set, const struct bf_marsh *marsh)
{
    bf_assert(set && marsh);

    _free_bf_set_ struct bf_set *_set = NULL;
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];
    struct bf_marsh *child = NULL;
    size_t n_comps;
    int r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&n_comps, child->data, sizeof(n_comps));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(key, child->data, n_comps * sizeof(enum bf_matcher_type));

    r = bf_set_new(&_set, key, n_comps);
    if (r < 0)
        return r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&_set->elem_size, child->data, sizeof(_set->elem_size));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    for (size_t i = 0; i < child->data_len / _set->elem_size; ++i) {
        _cleanup_free_ void *elem = malloc(_set->elem_size);
        if (!elem)
            return -ENOMEM;

        memcpy(elem, child->data + (i * _set->elem_size), _set->elem_size);
        r = bf_list_add_tail(&_set->elems, elem);
        if (r < 0)
            return r;

        TAKE_PTR(elem);
    }

    *set = TAKE_PTR(_set);

    return 0;
}

void bf_set_free(struct bf_set **set)
{
    bf_assert(set);

    if (!*set)
        return;

    bf_list_clean(&(*set)->elems);
    freep((void *)set);
}

int bf_set_marsh(const struct bf_set *set, struct bf_marsh **marsh)
{
    bf_assert(set && marsh);

    _free_bf_marsh_ struct bf_marsh *_marsh = NULL;
    _cleanup_free_ uint8_t *data = NULL;
    size_t elem_idx = 0;
    int r;

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &set->n_comps, sizeof(set->n_comps));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, set->key,
                               set->n_comps * sizeof(enum bf_matcher_type));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &set->elem_size,
                               sizeof(set->elem_size));
    if (r < 0)
        return r;

    data = malloc(set->elem_size * bf_list_size(&set->elems));
    if (!data)
        return bf_err_r(r, "failed to allocate memory for the set's content");

    bf_list_foreach (&set->elems, elem_node) {
        memcpy(data + (elem_idx * set->elem_size),
               bf_list_node_get_data(elem_node), set->elem_size);
        ++elem_idx;
    }

    r = bf_marsh_add_child_raw(&_marsh, data,
                               set->elem_size * bf_list_size(&set->elems));
    if (r < 0)
        return r;

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_set_dump(const struct bf_set *set, prefix_t *prefix)
{
    bf_assert(set && prefix);

    DUMP(prefix, "struct bf_set at %p", set);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "key: bf_matcher_type[%zu]", set->n_comps);
    bf_dump_prefix_push(prefix);
    for (size_t i = 0; i < set->n_comps; ++i) {
        if (i == set->n_comps - 1)
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "%s", bf_matcher_type_to_str(set->key[i]));
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "elem_size: %lu", set->elem_size);
    DUMP(bf_dump_prefix_last(prefix), "elems: bf_list<bytes>[%lu]",
         bf_list_size(&set->elems));

    bf_dump_prefix_push(prefix);
    bf_list_foreach (&set->elems, elem_node) {
        if (bf_list_is_tail(&set->elems, elem_node))
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "void * @ %p", bf_list_node_get_data(elem_node));
        bf_dump_prefix_push(prefix);
        bf_dump_hex(prefix, bf_list_node_get_data(elem_node), set->elem_size);
        bf_dump_prefix_pop(prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_set_add_elem(struct bf_set *set, void *elem)
{
    bf_assert(set && elem);

    _cleanup_free_ void *_elem = NULL;
    int r;

    _elem = malloc(set->elem_size);
    if (!_elem)
        return -ENOMEM;

    memcpy(_elem, elem, set->elem_size);

    r = bf_list_add_tail(&set->elems, _elem);
    if (r < 0)
        return r;

    TAKE_PTR(_elem);

    return 0;
}
