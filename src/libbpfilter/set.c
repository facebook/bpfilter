// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/set.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/list.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"

/// Mask value of matcher types supporting LPM trie maps.
#define _BF_SET_USE_TRIE_MASK                                                  \
    (BF_FLAGS(BF_MATCHER_IP4_SNET, BF_MATCHER_IP4_DNET, BF_MATCHER_IP6_SNET,   \
              BF_MATCHER_IP6_DNET))

int bf_set_new(struct bf_set **set, const char *name, enum bf_matcher_type *key,
               size_t n_comps)
{
    _free_bf_set_ struct bf_set *_set = NULL;
    uint32_t mask = 0;

    assert(set);
    assert(key);

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

    _set->name = NULL;
    if (name) {
        _set->name = strdup(name);
        if (!_set->name)
            return bf_err_r(-ENOMEM, "failed to allocate memory for set name");
    }

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
    _cleanup_free_ char *_raw_key = NULL;
    char *tmp, *saveptr, *token;

    assert(raw_key);
    assert(key);
    assert(n_comps);

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

int bf_set_add_elem_raw(struct bf_set *set, const char *raw_elem)
{
    _cleanup_free_ void *elem = NULL;
    _cleanup_free_ char *_raw_elem = NULL;
    char *tmp, *saveptr, *token;
    size_t elem_offset = 0;
    size_t comp_idx = 0;
    int r;

    assert(set);
    assert(raw_elem);

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

int bf_set_new_from_raw(struct bf_set **set, const char *name,
                        const char *raw_key, const char *raw_payload)
{
    _free_bf_set_ struct bf_set *_set = NULL;
    _cleanup_free_ char *_raw_payload = NULL;
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];
    char *raw_elem, *tmp, *saveptr;
    size_t n_comps;
    int r;

    assert(set);
    assert(raw_key);
    assert(raw_payload);

    r = _bf_set_parse_key(raw_key, key, &n_comps);
    if (r)
        return bf_err_r(r, "failed to parse set key '%s'", raw_key);

    r = bf_set_new(&_set, name, key, n_comps);
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

        r = bf_set_add_elem_raw(_set, raw_elem);
        if (r)
            return bf_err_r(r, "failed to parse set element '%s'", raw_elem);

        tmp = NULL;
    }

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_set_new_from_pack(struct bf_set **set, bf_rpack_node_t node)
{
    _free_bf_set_ struct bf_set *_set = NULL;
    _cleanup_free_ char *name = NULL;
    bf_rpack_node_t child, comp_node, elem_node;
    size_t n_comps = 0;
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];
    int r;

    assert(set);

    r = bf_rpack_kv_node(node, "name", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_set.name");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_str(child, &name);
        if (r)
            return bf_err_r(r, "failed to read set name from bf_set.name pack");
    }

    r = bf_rpack_kv_array(node, "key", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_set.key");
    bf_rpack_array_foreach (child, comp_node) {
        ++n_comps;
        if (n_comps > BF_SET_MAX_N_COMPS) {
            return bf_err_r(
                -E2BIG,
                "bf_set.key in pack contains %lu key components, only %d allowed",
                n_comps, BF_SET_MAX_N_COMPS);
        }

        r = bf_rpack_enum(comp_node, &key[i], 0, _BF_MATCHER_TYPE_MAX);
        if (r)
            return bf_rpack_key_err(r, "bf_set.key");
    }

    r = bf_set_new(&_set, name, key, n_comps);
    if (r)
        return bf_err_r(r, "failed to create bf_set from pack");

    r = bf_rpack_kv_array(node, "elements", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_set.elements");
    bf_rpack_array_foreach (child, elem_node) {
        const void *elem;
        size_t elem_len;

        r = bf_rpack_bin(elem_node, &elem, &elem_len);
        if (r)
            return bf_rpack_key_err(r, "bf_set.elements");

        if (elem_len != _set->elem_size) {
            return bf_err_r(-EINVAL,
                            "bf_set pack element is %lu bytes, it must be %lu",
                            elem_len, _set->elem_size);
        }

        r = bf_set_add_elem(_set, elem);
        if (r)
            return bf_err_r(r, "failed to insert element to bf_set");
    }

    *set = TAKE_PTR(_set);

    return 0;
}

void bf_set_free(struct bf_set **set)
{
    assert(set);

    if (!*set)
        return;

    bf_list_clean(&(*set)->elems);
    freep((void *)&(*set)->name);
    freep((void *)set);
}

int bf_set_pack(const struct bf_set *set, bf_wpack_t *pack)
{
    assert(set);
    assert(pack);

    if (set->name)
        bf_wpack_kv_str(pack, "name", set->name);
    else
        bf_wpack_kv_nil(pack, "name");

    bf_wpack_open_array(pack, "key");
    for (size_t i = 0; i < set->n_comps; ++i)
        bf_wpack_enum(pack, set->key[i]);
    bf_wpack_close_array(pack);

    bf_wpack_open_array(pack, "elements");
    bf_list_foreach (&set->elems, elem_node)
        bf_wpack_bin(pack, bf_list_node_get_data(elem_node), set->elem_size);
    bf_wpack_close_array(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_set_dump(const struct bf_set *set, prefix_t *prefix)
{
    assert(set);
    assert(prefix);

    DUMP(prefix, "struct bf_set at %p", set);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: %s", set->name ?: "<anonymous>");
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

int bf_set_add_elem(struct bf_set *set, const void *elem)
{
    _cleanup_free_ void *_elem = NULL;
    int r;

    assert(set);
    assert(elem);

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

bool bf_set_is_empty(const struct bf_set *set)
{
    assert(set);

    return bf_list_is_empty(&set->elems);
}

/**
 * @brief Check if two sets have the same key format.
 *
 * @param first First set. Can't be NULL.
 * @param second Second set. Can't be NULL.
 * @return 0 if sets have matching format, or -EINVAL on mismatch.
 */
static int _bf_set_cmp_key_format(const struct bf_set *first,
                                  const struct bf_set *second)
{
    assert(first);
    assert(second);

    if (first->n_comps != second->n_comps)
        return bf_err_r(
            -EINVAL,
            "set key format mismatch: first set has %lu components, second has %lu",
            first->n_comps, second->n_comps);

    if (memcmp(first->key, second->key,
               first->n_comps * sizeof(enum bf_matcher_type)) != 0)
        return bf_err_r(-EINVAL, "set key component type mismatch");

    return 0;
}

int bf_set_add_many(struct bf_set *dest, struct bf_set **to_add)
{
    int r;

    assert(dest);
    assert(to_add);
    assert(*to_add);

    r = _bf_set_cmp_key_format(dest, *to_add);
    if (r)
        return r;

    // @todo This has O(n * m) complexity. We could get to O(n log n + m) by
    // turning the linked list into an array and sorting it, but we should
    // just replace underlying bf_list with true hashset and enjoy O(m).
    bf_list_foreach (&(*to_add)->elems, elem_node) {
        void *elem_to_add = bf_list_node_get_data(elem_node);
        bool found = false;

        bf_list_foreach (&dest->elems, dest_elem_node) {
            const void *dest_elem = bf_list_node_get_data(dest_elem_node);

            if (memcmp(dest_elem, elem_to_add, dest->elem_size) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            r = bf_list_add_tail(&dest->elems,
                                 bf_list_node_get_data(elem_node));
            if (r)
                return bf_err_r(r, "failed to add element to set");
            // Take ownership of data to stop to_add cleanup from freeing it.
            bf_list_node_take_data(elem_node);
        }
    }

    bf_set_free(to_add);

    return 0;
}

int bf_set_remove_many(struct bf_set *dest, struct bf_set **to_remove)
{
    int r;

    assert(dest);
    assert(to_remove);
    assert(*to_remove);

    r = _bf_set_cmp_key_format(dest, *to_remove);
    if (r)
        return r;

    // @todo This has O(n * m) complexity. Could be O(m) if we used hashsets.
    bf_list_foreach (&(*to_remove)->elems, elem_node) {
        const void *elem_to_remove = bf_list_node_get_data(elem_node);

        bf_list_foreach (&dest->elems, dest_elem_node) {
            const void *dest_elem = bf_list_node_get_data(dest_elem_node);

            if (memcmp(dest_elem, elem_to_remove, dest->elem_size) == 0) {
                bf_list_delete(&dest->elems, dest_elem_node);
                break;
            }
        }
    }

    bf_set_free(to_remove);

    return 0;
}
