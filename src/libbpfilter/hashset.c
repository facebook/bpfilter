// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/hashset.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"
#include "bpfilter/vector.h"

enum _bf_slot_status
{
    _BF_SLOT_EMPTY = 0,
    _BF_SLOT_OCCUPIED,
    _BF_SLOT_TOMBSTONE,
};

static_assert(_BF_SLOT_OCCUPIED == _BF_HASHSET_SLOT_OCCUPIED,
              "header and internal slot-occupied values must match");

static_assert(_BF_MATCHER_TYPE_MAX < 8 * sizeof(uint32_t),
              "matcher type bitmask won't fit in 32 bits");

#define _BF_HASHSET_INIT_CAP 16
#define _BF_HASHSET_MAX_LOAD_NUM 7
#define _BF_HASHSET_MAX_LOAD_DEN 10

static size_t _bf_slot_size(size_t elem_size)
{
    return sizeof(uint8_t) + elem_size;
}

static size_t _bf_n_slots(const struct bf_hashset *set)
{
    return bf_vector_len(&set->slots);
}

static uint8_t *_bf_slot_at(const struct bf_hashset *set, size_t index)
{
    return bf_vector_get(&set->slots, index);
}

static uint8_t _bf_slot_status(const struct bf_hashset *set, size_t index)
{
    return *_bf_slot_at(set, index);
}

static void *_bf_slot_data(const struct bf_hashset *set, size_t index)
{
    return _bf_slot_at(set, index) + sizeof(uint8_t);
}

static void _bf_slot_set(struct bf_hashset *set, size_t index, uint8_t status,
                         const void *elem)
{
    uint8_t *slot = _bf_slot_at(set, index);

    *slot = status;
    if (elem)
        memcpy(slot + sizeof(uint8_t), elem, set->elem_size);
}

static size_t _bf_hashset_hash(const struct bf_hashset *set, const void *elem)
{
    return bf_fnv1a(elem, set->elem_size, BF_FNV1A_INIT) % _bf_n_slots(set);
}

/**
 * @brief Insert an element without duplicate or load-factor checks.
 *
 * The caller must guarantee that @p elem is not already present and that the
 * table has room. Used during rehash where both invariants hold by
 * construction.
 */
static void _bf_hashset_insert_unchecked(struct bf_hashset *set,
                                         const void *elem)
{
    size_t n = _bf_n_slots(set);
    size_t idx = _bf_hashset_hash(set, elem);

    while (_bf_slot_status(set, idx) == _BF_SLOT_OCCUPIED)
        idx = (idx + 1) % n;

    _bf_slot_set(set, idx, _BF_SLOT_OCCUPIED, elem);
    ++set->len;
    ++set->n_used;
}

static int _bf_hashset_grow(struct bf_hashset *set)
{
    size_t old_n_slots = _bf_n_slots(set);
    size_t slot_size = _bf_slot_size(set->elem_size);
    struct bf_vector old_slots;
    size_t new_n_slots;
    int r;

    if (old_n_slots > SIZE_MAX / 2)
        return -ENOMEM;

    new_n_slots = old_n_slots ? old_n_slots * 2 : _BF_HASHSET_INIT_CAP;

    old_slots = TAKE_STRUCT(set->slots);

    set->slots = bf_vector_default(slot_size);

    r = bf_vector_resize(&set->slots, new_n_slots);
    if (r) {
        bf_vector_clean(&set->slots);
        set->slots = old_slots;
        return r;
    }

    memset(bf_vector_data(&set->slots), 0, new_n_slots * slot_size);
    (void)bf_vector_set_len(&set->slots, new_n_slots);

    set->len = 0;
    set->n_used = 0;

    for (size_t i = 0; i < old_n_slots; ++i) {
        uint8_t *old_slot = bf_vector_get(&old_slots, i);

        if (*old_slot != _BF_SLOT_OCCUPIED)
            continue;

        _bf_hashset_insert_unchecked(set, old_slot + sizeof(uint8_t));
    }

    bf_vector_clean(&old_slots);

    return 0;
}

static bool _bf_hashset_needs_grow(const struct bf_hashset *set)
{
    size_t n = _bf_n_slots(set);

    if (n == 0)
        return true;

    return set->n_used * _BF_HASHSET_MAX_LOAD_DEN >=
           n * _BF_HASHSET_MAX_LOAD_NUM;
}

static bool _bf_hashset_find(const struct bf_hashset *set, const void *elem,
                             size_t *index)
{
    size_t n;
    size_t idx;

    assert(set);
    assert(elem);

    n = _bf_n_slots(set);
    if (n == 0)
        return false;

    idx = _bf_hashset_hash(set, elem);

    for (size_t i = 0; i < n; ++i) {
        uint8_t status = _bf_slot_status(set, idx);

        if (status == _BF_SLOT_EMPTY)
            return false;

        if (status == _BF_SLOT_OCCUPIED &&
            memcmp(_bf_slot_data(set, idx), elem, set->elem_size) == 0) {
            if (index)
                *index = idx;
            return true;
        }

        idx = (idx + 1) % n;
    }

    return false;
}

void bf_hashset_free(struct bf_hashset **set)
{
    assert(set);

    if (!*set)
        return;

    bf_vector_clean(&(*set)->slots);
    freep((void *)&(*set)->name);
    free(*set);
    *set = NULL;
}

size_t bf_hashset_size(const struct bf_hashset *set)
{
    assert(set);
    return set->len;
}

size_t bf_hashset_cap(const struct bf_hashset *set)
{
    assert(set);
    return _bf_n_slots(set);
}

bool bf_hashset_is_empty(const struct bf_hashset *set)
{
    assert(set);
    return set->len == 0;
}

const char *bf_hashset_get_name(const struct bf_hashset *set)
{
    assert(set);
    return set->name;
}

size_t bf_hashset_get_n_comps(const struct bf_hashset *set)
{
    assert(set);
    return set->n_comps;
}

enum bf_matcher_type bf_hashset_get_key_comp(const struct bf_hashset *set,
                                             size_t index)
{
    assert(set);
    assert(index < set->n_comps);
    return set->key[index];
}

int bf_hashset_add_elem(struct bf_hashset *set, const void *elem)
{
    size_t idx;
    bool was_tombstone;
    int r;

    assert(set);
    assert(elem);

    if (_bf_hashset_find(set, elem, NULL))
        return 0;

    if (_bf_hashset_needs_grow(set)) {
        r = _bf_hashset_grow(set);
        if (r)
            return r;
    }

    idx = _bf_hashset_hash(set, elem);

    for (size_t i = 0;
         i < _bf_n_slots(set) && _bf_slot_status(set, idx) == _BF_SLOT_OCCUPIED;
         ++i)
        idx = (idx + 1) % _bf_n_slots(set);

    was_tombstone = _bf_slot_status(set, idx) == _BF_SLOT_TOMBSTONE;
    _bf_slot_set(set, idx, _BF_SLOT_OCCUPIED, elem);
    ++set->len;

    if (!was_tombstone)
        ++set->n_used;

    return 0;
}

bool bf_hashset_contains(const struct bf_hashset *set, const void *elem)
{
    assert(set);
    assert(elem);

    return _bf_hashset_find(set, elem, NULL);
}

int bf_hashset_remove(struct bf_hashset *set, const void *elem)
{
    size_t idx;

    assert(set);
    assert(elem);

    if (!_bf_hashset_find(set, elem, &idx))
        return 0;

    _bf_slot_set(set, idx, _BF_SLOT_TOMBSTONE, NULL);
    --set->len;

    return 0;
}

#define _BF_HASHSET_USE_TRIE_MASK                                              \
    (BF_FLAGS(BF_MATCHER_IP4_SNET, BF_MATCHER_IP4_DNET, BF_MATCHER_IP6_SNET,   \
              BF_MATCHER_IP6_DNET))

int bf_hashset_new(struct bf_hashset **set, const char *name,
                   enum bf_matcher_type *key, size_t n_comps)
{
    _free_bf_hashset_ struct bf_hashset *_set = NULL;
    uint32_t mask = 0;
    size_t elem_size = 0;

    assert(set);
    assert(key);

    if (n_comps == 0)
        return bf_err_r(-EINVAL, "at least 1 key component is required");

    if (n_comps > BF_HASHSET_MAX_N_COMPS) {
        return bf_err_r(-E2BIG,
                        "a set key can't contain more than %d components",
                        BF_HASHSET_MAX_N_COMPS);
    }

    for (size_t i = 0; i < n_comps; ++i) {
        const struct bf_matcher_ops *ops;

        ops = bf_matcher_get_ops(key[i], BF_MATCHER_IN);
        if (!ops) {
            return bf_err_r(-ENOTSUP,
                            "matcher '%s' (%d) is not supported as a set key",
                            bf_matcher_type_to_str(key[i]), key[i]);
        }
        elem_size += ops->ref_payload_size;
        mask |= BF_FLAG(key[i]);
    }

    if (n_comps > 1 && mask & _BF_HASHSET_USE_TRIE_MASK) {
        return bf_err_r(
            -EINVAL,
            "network matchers can't be used in combination with other matchers in a set");
    }

    _set = calloc(1, sizeof(*_set));
    if (!_set)
        return -ENOMEM;

    _set->slots = bf_vector_default(_bf_slot_size(elem_size));
    _set->elem_size = elem_size;

    _set->name = NULL;
    if (name) {
        _set->name = strdup(name);
        if (!_set->name)
            return bf_err_r(-ENOMEM, "failed to allocate memory for set name");
    }

    memcpy(_set->key, key, n_comps * sizeof(enum bf_matcher_type));
    _set->n_comps = n_comps;
    _set->use_trie = n_comps == 1 && mask & _BF_HASHSET_USE_TRIE_MASK;

    *set = TAKE_PTR(_set);

    return 0;
}

/**
 * @brief Parse a hashset's raw key into an array of @c bf_matcher_type.
 *
 * @param raw_key Raw set key, as a string of comma-separated matcher types
 *        enclosed in parentheses. Can't be NULL.
 * @param key Parsed key components. Can't be NULL.
 * @param n_comps Number of components written to @p key. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_hashset_parse_key(const char *raw_key, enum bf_matcher_type *key,
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

        if (*n_comps == BF_HASHSET_MAX_N_COMPS) {
            return bf_err_r(-E2BIG, "set keys are limited to %d components",
                            BF_HASHSET_MAX_N_COMPS);
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

int bf_hashset_add_elem_raw(struct bf_hashset *set, const char *raw_elem)
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

    r = bf_hashset_add_elem(set, elem);
    if (r)
        return bf_err_r(r, "failed to insert element into set");

    return 0;
}

int bf_hashset_new_from_raw(struct bf_hashset **set, const char *name,
                            const char *raw_key, const char *raw_payload)
{
    _free_bf_hashset_ struct bf_hashset *_set = NULL;
    _cleanup_free_ char *_raw_payload = NULL;
    enum bf_matcher_type key[BF_HASHSET_MAX_N_COMPS];
    char *raw_elem, *tmp, *saveptr;
    size_t n_comps;
    int r;

    assert(set);
    assert(raw_key);
    assert(raw_payload);

    r = _bf_hashset_parse_key(raw_key, key, &n_comps);
    if (r)
        return bf_err_r(r, "failed to parse set key '%s'", raw_key);

    r = bf_hashset_new(&_set, name, key, n_comps);
    if (r)
        return r;

    _raw_payload = strdup(raw_payload);
    if (!_raw_payload)
        return bf_err_r(-ENOMEM, "failed to copy set raw payload '%s'",
                        raw_payload);

    tmp = _raw_payload;
    while ((raw_elem = strtok_r(tmp, "{};\n", &saveptr))) {
        raw_elem = bf_trim(raw_elem);

        if (raw_elem[0] == '\0')
            continue;

        r = bf_hashset_add_elem_raw(_set, raw_elem);
        if (r)
            return bf_err_r(r, "failed to parse set element '%s'", raw_elem);

        tmp = NULL;
    }

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_hashset_new_from_pack(struct bf_hashset **set, bf_rpack_node_t node)
{
    _free_bf_hashset_ struct bf_hashset *_set = NULL;
    _cleanup_free_ char *name = NULL;
    bf_rpack_node_t child, comp_node, elem_node;
    size_t n_comps = 0;
    enum bf_matcher_type key[BF_HASHSET_MAX_N_COMPS];
    int r;

    assert(set);

    r = bf_rpack_kv_node(node, "name", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hashset.name");
    if (!bf_rpack_is_nil(child)) {
        r = bf_rpack_str(child, &name);
        if (r)
            return bf_err_r(
                r, "failed to read set name from bf_hashset.name pack");
    }

    r = bf_rpack_kv_array(node, "key", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hashset.key");
    bf_rpack_array_foreach (child, comp_node) {
        ++n_comps;
        if (n_comps > BF_HASHSET_MAX_N_COMPS) {
            return bf_err_r(
                -E2BIG,
                "bf_hashset.key in pack contains %lu key components, only %d allowed",
                n_comps, BF_HASHSET_MAX_N_COMPS);
        }

        r = bf_rpack_enum(comp_node, &key[n_comps - 1], 0,
                          _BF_MATCHER_TYPE_MAX);
        if (r)
            return bf_rpack_key_err(r, "bf_hashset.key");
    }

    r = bf_hashset_new(&_set, name, key, n_comps);
    if (r)
        return bf_err_r(r, "failed to create bf_hashset from pack");

    r = bf_rpack_kv_array(node, "elements", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_hashset.elements");
    bf_rpack_array_foreach (child, elem_node) {
        const void *elem;
        size_t elem_len;

        r = bf_rpack_bin(elem_node, &elem, &elem_len);
        if (r)
            return bf_rpack_key_err(r, "bf_hashset.elements");

        if (elem_len != _set->elem_size) {
            return bf_err_r(
                -EINVAL, "bf_hashset pack element is %lu bytes, it must be %lu",
                elem_len, _set->elem_size);
        }

        r = bf_hashset_add_elem(_set, elem);
        if (r)
            return bf_err_r(r, "failed to insert element to bf_hashset");
    }

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_hashset_pack(const struct bf_hashset *set, bf_wpack_t *pack)
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
    bf_hashset_foreach (set, elem)
        bf_wpack_bin(pack, elem, set->elem_size);
    bf_wpack_close_array(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_hashset_dump(const struct bf_hashset *set, prefix_t *prefix)
{
    assert(set);
    assert(prefix);

    DUMP(prefix, "struct bf_hashset at %p", set);
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
    DUMP(bf_dump_prefix_last(prefix), "elems: bf_hashset<bytes>[%lu]",
         bf_hashset_size(set));

    bf_dump_prefix_push(prefix);
    size_t n = 0;
    size_t total = bf_hashset_size(set);
    bf_hashset_foreach (set, elem) {
        ++n;
        if (n == total)
            bf_dump_prefix_last(prefix);
        DUMP(prefix, "void * @ %p", elem);
        bf_dump_prefix_push(prefix);
        bf_dump_hex(prefix, elem, set->elem_size);
        bf_dump_prefix_pop(prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

/**
 * @brief Check if two hashsets have the same key format.
 *
 * @param first First hashset. Can't be NULL.
 * @param second Second hashset. Can't be NULL.
 * @return 0 if hashsets have matching format, or -EINVAL on mismatch.
 */
static int _bf_hashset_cmp_key_format(const struct bf_hashset *first,
                                      const struct bf_hashset *second)
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

int bf_hashset_add_many(struct bf_hashset *dest, struct bf_hashset **to_add)
{
    int r;

    assert(dest);
    assert(to_add);
    assert(*to_add);

    r = _bf_hashset_cmp_key_format(dest, *to_add);
    if (r)
        return r;

    bf_hashset_foreach (*to_add, elem) {
        r = bf_hashset_add_elem(dest, elem);
        if (r)
            return r;
    }

    bf_hashset_free(to_add);

    return 0;
}

int bf_hashset_remove_many(struct bf_hashset *dest,
                           struct bf_hashset **to_remove)
{
    int r;

    assert(dest);
    assert(to_remove);
    assert(*to_remove);

    r = _bf_hashset_cmp_key_format(dest, *to_remove);
    if (r)
        return r;

    bf_hashset_foreach (*to_remove, elem) {
        r = bf_hashset_remove(dest, elem);
        if (r)
            return r;
    }

    bf_hashset_free(to_remove);

    return 0;
}
