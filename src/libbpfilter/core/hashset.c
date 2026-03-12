// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/core/hashset.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/core/vector.h"
#include "bpfilter/helper.h"

#define _BF_HASHSET_TOMBSTONE ((void *)1)
#define _BF_HASHSET_INIT_CAP 16
#define _BF_HASHSET_MAX_LOAD_NUM 7
#define _BF_HASHSET_MAX_LOAD_DEN 10

static inline size_t _bf_n_slots(const bf_hashset *set)
{
    return bf_vector_len(&set->slots);
}

static inline void **_bf_slot_at(const bf_hashset *set, size_t index)
{
    return (void **)bf_vector_get(&set->slots, index);
}

static inline bool _bf_slot_is_live(void *slot)
{
    return slot && slot != _BF_HASHSET_TOMBSTONE;
}

static size_t _bf_hashset_index(const bf_hashset *set, const void *data)
{
    return set->ops.hash(data, set->ctx) % _bf_n_slots(set);
}

static void _bf_hashset_insert_unchecked(bf_hashset *set, void *data)
{
    size_t n = _bf_n_slots(set);
    size_t idx = _bf_hashset_index(set, data);

    while (_bf_slot_is_live(*_bf_slot_at(set, idx)))
        idx = (idx + 1) % n;

    *_bf_slot_at(set, idx) = data;
    ++set->len;
    ++set->n_used;
}

static int _bf_hashset_grow(bf_hashset *set)
{
    size_t old_n_slots = _bf_n_slots(set);
    struct bf_vector old_slots;
    size_t new_n_slots;
    int r;

    if (old_n_slots > SIZE_MAX / 2)
        return -ENOMEM;

    new_n_slots = old_n_slots ? old_n_slots * 2 : _BF_HASHSET_INIT_CAP;

    old_slots = TAKE_STRUCT(set->slots);

    set->slots = bf_vector_default(sizeof(void *));

    r = bf_vector_resize(&set->slots, new_n_slots);
    if (r) {
        bf_vector_clean(&set->slots);
        set->slots = old_slots;
        return r;
    }

    memset(bf_vector_data(&set->slots), 0, new_n_slots * sizeof(void *));
    (void)bf_vector_set_len(&set->slots, new_n_slots);

    set->len = 0;
    set->n_used = 0;

    for (size_t i = 0; i < old_n_slots; ++i) {
        void *ptr = *(void **)bf_vector_get(&old_slots, i);

        if (!_bf_slot_is_live(ptr))
            continue;

        _bf_hashset_insert_unchecked(set, ptr);
    }

    bf_vector_clean(&old_slots);

    return 0;
}

static bool _bf_hashset_needs_grow(const bf_hashset *set)
{
    size_t n = _bf_n_slots(set);

    if (n == 0)
        return true;

    return set->n_used * _BF_HASHSET_MAX_LOAD_DEN >=
           n * _BF_HASHSET_MAX_LOAD_NUM;
}

static bool _bf_hashset_find(const bf_hashset *set, const void *data,
                             size_t *index)
{
    size_t n;
    size_t idx;

    assert(set);
    assert(data);

    n = _bf_n_slots(set);
    if (n == 0)
        return false;

    idx = _bf_hashset_index(set, data);

    for (size_t i = 0; i < n; ++i) {
        void *slot = *_bf_slot_at(set, idx);

        if (!slot)
            return false;

        if (_bf_slot_is_live(slot) && set->ops.equal(slot, data, set->ctx)) {
            if (index)
                *index = idx;
            return true;
        }

        idx = (idx + 1) % n;
    }

    return false;
}

int bf_hashset_new(bf_hashset **set, const bf_hashset_ops *ops, void *ctx)
{
    _free_bf_hashset_ bf_hashset *_set = NULL;

    assert(set);
    assert(ops);
    assert(ops->hash);
    assert(ops->equal);

    _set = calloc(1, sizeof(*_set));
    if (!_set)
        return -ENOMEM;

    bf_hashset_init(_set, ops, ctx);

    *set = TAKE_PTR(_set);

    return 0;
}

void bf_hashset_free(bf_hashset **set)
{
    assert(set);

    if (!*set)
        return;

    bf_hashset_clean(*set);
    free(*set);
    *set = NULL;
}

void bf_hashset_init(bf_hashset *set, const bf_hashset_ops *ops, void *ctx)
{
    assert(set);
    assert(ops);
    assert(ops->hash);
    assert(ops->equal);

    set->slots = bf_vector_default(sizeof(void *));
    set->len = 0;
    set->n_used = 0;
    set->ops = *ops;
    set->ctx = ctx;
}

void bf_hashset_clean(bf_hashset *set)
{
    assert(set);

    if (set->ops.free) {
        size_t n = _bf_n_slots(set);
        for (size_t i = 0; i < n; ++i) {
            void **slot = _bf_slot_at(set, i);
            if (_bf_slot_is_live(*slot))
                set->ops.free(slot, set->ctx);
        }
    }

    bf_vector_clean(&set->slots);
    set->len = 0;
    set->n_used = 0;
}

int bf_hashset_add(bf_hashset *set, void *data)
{
    size_t idx;
    bool was_tombstone;
    int r;

    assert(set);
    assert(data);

    if (_bf_hashset_find(set, data, NULL))
        return -EEXIST;

    if (_bf_hashset_needs_grow(set)) {
        r = _bf_hashset_grow(set);
        if (r)
            return r;
    }

    idx = _bf_hashset_index(set, data);

    while (_bf_slot_is_live(*_bf_slot_at(set, idx)))
        idx = (idx + 1) % _bf_n_slots(set);

    was_tombstone = *_bf_slot_at(set, idx) == _BF_HASHSET_TOMBSTONE;
    *_bf_slot_at(set, idx) = data;
    ++set->len;

    if (!was_tombstone)
        ++set->n_used;

    return 0;
}

bool bf_hashset_contains(const bf_hashset *set, const void *data)
{
    assert(set);
    assert(data);

    return _bf_hashset_find(set, data, NULL);
}

void *bf_hashset_get(const bf_hashset *set, const void *data)
{
    size_t idx;

    assert(set);
    assert(data);

    if (!_bf_hashset_find(set, data, &idx))
        return NULL;

    return *_bf_slot_at(set, idx);
}

int bf_hashset_remove(bf_hashset *set, const void *data)
{
    size_t idx;

    assert(set);
    assert(data);

    if (!_bf_hashset_find(set, data, &idx))
        return 0;

    if (set->ops.free)
        set->ops.free(_bf_slot_at(set, idx), set->ctx);

    *_bf_slot_at(set, idx) = _BF_HASHSET_TOMBSTONE;
    --set->len;

    return 0;
}

struct bf_vector bf_hashset_take(bf_hashset *set)
{
    struct bf_vector slots;

    assert(set);

    slots = TAKE_STRUCT(set->slots);
    set->slots = bf_vector_default(sizeof(void *));
    set->len = 0;
    set->n_used = 0;

    return slots;
}
