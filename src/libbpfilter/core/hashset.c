// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/core/hashset.h"

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/helper.h"

#define _BF_HASHSET_TOMBSTONE ((void *)1)
#define _BF_HASHSET_INIT_CAP 16
#define _BF_HASHSET_MAX_LOAD_NUM 7
#define _BF_HASHSET_MAX_LOAD_DEN 10

bool bf_hashset_slot_is_tombstone(const void *slot)
{
    return slot == _BF_HASHSET_TOMBSTONE;
}

static inline bool _bf_hashset_slot_is_live(const void *slot)
{
    return slot && !bf_hashset_slot_is_tombstone(slot);
}

static size_t _bf_hashset_index(const bf_hashset *set, const void *data)
{
    assert(set);
    assert(data);

    return set->ops.hash(data, set->ctx) % set->cap;
}

static int _bf_hashset_grow(bf_hashset *set)
{
    void **old_slots;
    void **new_slots;
    size_t old_cap;
    size_t new_cap;
    size_t old_len;
    size_t old_slots_in_use;
    int r;

    assert(set);

    old_cap = set->cap;
    if (old_cap > SIZE_MAX / 2)
        return -ENOMEM;
    new_cap = old_cap ? old_cap * 2 : _BF_HASHSET_INIT_CAP;

    old_slots = set->slots;
    new_slots = (void **)calloc(new_cap, sizeof(void *));
    if (!new_slots)
        return -ENOMEM;

    old_len = set->len;
    old_slots_in_use = set->slots_in_use;

    set->slots = new_slots;
    set->cap = new_cap;
    set->len = 0;
    set->slots_in_use = 0;

    for (size_t i = 0; i < old_cap; ++i) {
        if (!_bf_hashset_slot_is_live(old_slots[i]))
            continue;
        r = bf_hashset_add(set, old_slots[i]);
        if (r) {
            set->slots = old_slots;
            set->cap = old_cap;
            set->len = old_len;
            set->slots_in_use = old_slots_in_use;
            freep((void *)&new_slots);
            return r;
        }
    }

    freep((void *)&old_slots);
    return 0;
}

static bool _bf_hashset_needs_grow(const bf_hashset *set)
{
    assert(set);

    if (set->cap == 0)
        return true;

    return set->slots_in_use * _BF_HASHSET_MAX_LOAD_DEN >=
           set->cap * _BF_HASHSET_MAX_LOAD_NUM;
}

static bool _bf_hashset_find(const bf_hashset *set, const void *data,
                             size_t *index)
{
    size_t idx;

    assert(set);
    assert(data);

    if (set->cap == 0)
        return false;

    idx = _bf_hashset_index(set, data);

    for (size_t i = 0; i < set->cap; ++i) {
        void *slot = set->slots[idx];

        if (!slot)
            return false;

        if (_bf_hashset_slot_is_live(slot) &&
            set->ops.equal(slot, data, set->ctx)) {
            if (index)
                *index = idx;
            return true;
        }

        idx = (idx + 1) % set->cap;
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

    set->slots = NULL;
    set->cap = 0;
    set->len = 0;
    set->slots_in_use = 0;
    set->ops = *ops;
    set->ctx = ctx;
}

void bf_hashset_clean(bf_hashset *set)
{
    assert(set);

    if (set->ops.free) {
        for (size_t i = 0; i < set->cap; ++i) {
            if (_bf_hashset_slot_is_live(set->slots[i]))
                set->ops.free(&set->slots[i], set->ctx);
        }
    }

    freep((void *)&set->slots);
    set->cap = 0;
    set->len = 0;
    set->slots_in_use = 0;
}

size_t bf_hashset_size(const bf_hashset *set)
{
    assert(set);
    return set->len;
}

size_t bf_hashset_cap(const bf_hashset *set)
{
    assert(set);
    return set->cap;
}

bool bf_hashset_is_empty(const bf_hashset *set)
{
    assert(set);
    return set->len == 0;
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

    while (_bf_hashset_slot_is_live(set->slots[idx]))
        idx = (idx + 1) % set->cap;

    was_tombstone = set->slots[idx] == _BF_HASHSET_TOMBSTONE;
    set->slots[idx] = data;
    ++set->len;

    if (!was_tombstone)
        ++set->slots_in_use;

    return 0;
}

bool bf_hashset_contains(const bf_hashset *set, const void *data)
{
    assert(set);
    assert(data);

    return _bf_hashset_find(set, data, NULL);
}

int bf_hashset_remove(bf_hashset *set, const void *data)
{
    size_t idx;

    assert(set);
    assert(data);

    if (!_bf_hashset_find(set, data, &idx))
        return 0;

    if (set->ops.free)
        set->ops.free(&set->slots[idx], set->ctx);

    set->slots[idx] = _BF_HASHSET_TOMBSTONE;
    --set->len;

    return 0;
}

void **bf_hashset_take(bf_hashset *set, size_t *n_slots)
{
    void **slots;

    assert(set);

    slots = set->slots;

    if (n_slots)
        *n_slots = set->cap;

    set->slots = NULL;
    set->cap = 0;
    set->len = 0;
    set->slots_in_use = 0;

    return slots;
}
