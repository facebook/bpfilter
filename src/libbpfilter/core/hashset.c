// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/core/hashset.h"

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

#define _BF_HASHSET_TOMBSTONE ((bf_hashset_elem *)1)
#define _BF_HASHSET_INIT_CAP 16
/* Maximum load factor before growing. Lowering this number reduces collisions
 * but causes higher memory usage. */
#define _BF_HASHSET_MAX_LOAD_NUM 5
#define _BF_HASHSET_MAX_LOAD_DEN 10
/* Largest power-of-two element count (2^60) that still leaves headroom for
 * load-factor arithmetic (slots_in_use * 10, cap * 5) without overflowing
 * size_t. */
#define _BF_HASHSET_MAX_CAP (SIZE_MAX / 16 + 1)

static inline bool _bf_hashset_slot_is_tombstone(const bf_hashset_elem *slot)
{
    return slot == _BF_HASHSET_TOMBSTONE;
}

static inline bool _bf_hashset_slot_is_live(const bf_hashset_elem *slot)
{
    return slot && !_bf_hashset_slot_is_tombstone(slot);
}

// Caller must ensure set->cap > 0 to avoid division by zero.
static size_t _bf_hashset_index(const bf_hashset *set, const void *data)
{
    assert(set);
    assert(data);

    return set->ops.hash(data, set->ctx) % set->cap;
}

static int _bf_hashset_resize(bf_hashset *set, size_t new_cap)
{
    bf_hashset_elem **new_slots;

    new_slots = (bf_hashset_elem **)calloc(new_cap, sizeof(*new_slots));
    if (!new_slots)
        return -ENOMEM;

    bf_hashset_foreach (set, elem) {
        size_t idx = set->ops.hash(elem->data, set->ctx) % new_cap;
        while (new_slots[idx])
            idx = (idx + 1) % new_cap;
        new_slots[idx] = elem;
    }

    freep((void *)&set->slots);
    set->slots = new_slots;
    set->cap = new_cap;
    set->slots_in_use = set->len;

    return 0;
}

static int _bf_hashset_grow(bf_hashset *set)
{
    size_t new_cap;

    assert(set);

    if (set->cap >= _BF_HASHSET_MAX_CAP)
        return -ENOMEM;
    new_cap = set->cap ? set->cap * 2 : _BF_HASHSET_INIT_CAP;

    return _bf_hashset_resize(set, new_cap);
}

static bool _bf_hashset_needs_grow(const bf_hashset *set)
{
    assert(set);

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
        bf_hashset_elem *slot = set->slots[idx];

        if (!slot)
            return false;

        if (_bf_hashset_slot_is_live(slot) &&
            set->ops.equal(slot->data, data, set->ctx)) {
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
    freep((void *)set);
}

void bf_hashset_init(bf_hashset *set, const bf_hashset_ops *ops, void *ctx)
{
    assert(set);
    assert(ops);
    assert(ops->hash);
    assert(ops->equal);

    *set = bf_hashset_default(ops, ctx);
}

void bf_hashset_clean(bf_hashset *set)
{
    assert(set);

    bf_hashset_foreach (set, elem) {
        if (set->ops.free)
            set->ops.free(&elem->data, set->ctx);
        freep((void *)&elem);
    }

    freep((void *)&set->slots);
    set->cap = 0;
    set->len = 0;
    set->slots_in_use = 0;
    set->head = NULL;
    set->tail = NULL;
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

int bf_hashset_reserve(bf_hashset *set, size_t count)
{
    size_t needed, new_cap;

    assert(set);

    if (count == 0)
        return 0;

    needed = count * _BF_HASHSET_MAX_LOAD_DEN / _BF_HASHSET_MAX_LOAD_NUM;
    if (needed <= set->cap)
        return 0;

    new_cap = set->cap ? set->cap : _BF_HASHSET_INIT_CAP;
    while (new_cap < needed) {
        if (new_cap >= _BF_HASHSET_MAX_CAP)
            return -ENOMEM;
        new_cap *= 2;
    }

    return _bf_hashset_resize(set, new_cap);
}

int bf_hashset_add(bf_hashset *set, void *data)
{
    bf_hashset_elem *elem;
    size_t idx;
    bool was_tombstone;
    int r;

    assert(set);
    assert(data);

    if (bf_hashset_contains(set, data))
        return -EEXIST;

    if (set->len >= _BF_HASHSET_MAX_CAP)
        return bf_err_r(-ENOMEM, "hashset reached maximum capacity");

    if (_bf_hashset_needs_grow(set)) {
        r = _bf_hashset_grow(set);
        if (r)
            return r;
    }

    elem = malloc(sizeof(*elem));
    if (!elem)
        return -ENOMEM;

    elem->data = data;

    idx = _bf_hashset_index(set, data);
    for (size_t i = 0; i < set->cap; ++i) {
        if (!_bf_hashset_slot_is_live(set->slots[idx]))
            break;
        idx = (idx + 1) % set->cap;
    }

    was_tombstone = _bf_hashset_slot_is_tombstone(set->slots[idx]);
    set->slots[idx] = elem;

    elem->prev = set->tail;
    elem->next = NULL;
    if (set->tail)
        set->tail->next = elem;
    else
        set->head = elem;
    set->tail = elem;

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

int bf_hashset_delete(bf_hashset *set, const void *data)
{
    bf_hashset_elem *elem;
    size_t idx;

    assert(set);
    assert(data);

    if (!_bf_hashset_find(set, data, &idx))
        return -ENOENT;

    elem = set->slots[idx];

    if (set->ops.free)
        set->ops.free(&elem->data, set->ctx);

    if (elem->prev)
        elem->prev->next = elem->next;
    else
        set->head = elem->next;

    if (elem->next)
        elem->next->prev = elem->prev;
    else
        set->tail = elem->prev;

    set->slots[idx] = _BF_HASHSET_TOMBSTONE;
    freep((void *)&elem);
    --set->len;

    return 0;
}
