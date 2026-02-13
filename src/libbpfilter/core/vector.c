// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/core/vector.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/helper.h"

#define _BF_VECTOR_INIT_CAP 8
#define _BF_VECTOR_MAX_CAP (SIZE_MAX / 2)

int bf_vector_new(bf_vector **vec, size_t elem_size)
{
    _free_bf_vector_ bf_vector *_vec = NULL;

    assert(vec);

    if (!elem_size)
        return -EINVAL;

    _vec = calloc(1, sizeof(*_vec));
    if (!_vec)
        return -ENOMEM;

    _vec->elem_size = elem_size;

    *vec = TAKE_PTR(_vec);

    return 0;
}

void bf_vector_free(bf_vector **vec)
{
    assert(vec);

    if (!*vec)
        return;

    bf_vector_clean(*vec);
    freep((void *)vec);
}

void bf_vector_clean(bf_vector *vec)
{
    assert(vec);

    freep((void *)&vec->data);
    vec->size = 0;
    vec->cap = 0;
}

void *bf_vector_get(const bf_vector *vec, size_t index)
{
    assert(vec);

    if (index >= vec->size)
        return NULL;

    return vec->data + (index * vec->elem_size);
}

int bf_vector_set(bf_vector *vec, size_t index, const void *elem)
{
    assert(vec);
    assert(elem);

    if (index >= vec->size)
        return -EINVAL;

    memcpy(vec->data + (index * vec->elem_size), elem, vec->elem_size);

    return 0;
}

int bf_vector_remove(bf_vector *vec, size_t index)
{
    assert(vec);

    if (index >= vec->size)
        return -EINVAL;

    --vec->size;

    if (index < vec->size) {
        memmove(vec->data + (index * vec->elem_size),
                vec->data + ((index + 1) * vec->elem_size),
                (vec->size - index) * vec->elem_size);
    }

    return 0;
}

static int _bf_vector_realloc(bf_vector *vec, size_t new_cap)
{
    size_t alloc_size;
    int r;

    assert(vec);

    if (!vec->elem_size)
        return -EINVAL;

    if (__builtin_mul_overflow(new_cap, vec->elem_size, &alloc_size))
        return -ENOMEM;

    r = bf_realloc(&vec->data, alloc_size);
    if (r)
        return r;

    vec->cap = new_cap;

    return 0;
}

int bf_vector_add(bf_vector *vec, const void *elem)
{
    int r;

    assert(vec);
    assert(elem);

    if (vec->size == vec->cap) {
        size_t new_cap;

        new_cap = bf_min(vec->cap ? vec->cap * 2 : _BF_VECTOR_INIT_CAP,
                         _BF_VECTOR_MAX_CAP);
        if (new_cap <= vec->cap)
            return -ENOMEM;

        r = _bf_vector_realloc(vec, new_cap);
        if (r)
            return r;
    }

    memcpy(vec->data + (vec->size * vec->elem_size), elem, vec->elem_size);
    ++vec->size;

    return 0;
}

int bf_vector_add_many(bf_vector *vec, const void *data, size_t count)
{
    size_t required;
    int r;

    assert(vec);
    assert(data);

    if (!count)
        return 0;

    if (__builtin_add_overflow(vec->size, count, &required))
        return -ENOMEM;

    if (required > vec->cap) {
        size_t new_cap;

        new_cap = bf_min(
            bf_max(vec->cap ? vec->cap * 2 : _BF_VECTOR_INIT_CAP, required),
            _BF_VECTOR_MAX_CAP);
        if (new_cap < required)
            return -ENOMEM;

        r = _bf_vector_realloc(vec, new_cap);
        if (r)
            return r;
    }

    memcpy(vec->data + (vec->size * vec->elem_size), data,
           count * vec->elem_size);
    vec->size += count;

    return 0;
}

int bf_vector_reserve(bf_vector *vec, size_t cap)
{
    assert(vec);

    if (cap <= vec->cap)
        return 0;

    if (cap > _BF_VECTOR_MAX_CAP)
        return -ENOMEM;

    return _bf_vector_realloc(vec, cap);
}

void *bf_vector_take(bf_vector *vec)
{
    assert(vec);

    vec->size = 0;
    vec->cap = 0;

    return TAKE_PTR(vec->data);
}
