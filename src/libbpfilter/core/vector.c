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
// Largest capacity where cap + cap / 2 does not exceed SIZE_MAX.
#define _BF_VECTOR_MAX_CAP (SIZE_MAX / 3 * 2)

bf_vector bf_vector_default(size_t elem_size)
{
    /* This is not a NULL check, but we don't want to let the caller
     * create a vector with elem_size zero. And yet we want to have
     * the API of `bf_vector x = bf_vector_default(y);`. */
    assert(elem_size > 0);

    return (bf_vector) {.elem_size = elem_size};
}

void bf_vector_init(bf_vector *vec, size_t elem_size)
{
    assert(vec);

    *vec = bf_vector_default(elem_size);
}

int bf_vector_new(bf_vector **vec, size_t elem_size)
{
    _free_bf_vector_ bf_vector *_vec = NULL;

    assert(vec);

    if (!elem_size)
        return -EINVAL;

    _vec = calloc(1, sizeof(*_vec));
    if (!_vec)
        return -ENOMEM;

    bf_vector_init(_vec, elem_size);

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

static int _bf_vector_resize(bf_vector *vec, size_t new_cap)
{
    size_t alloc_size;
    int r;

    assert(vec);

    if (__builtin_mul_overflow(new_cap, vec->elem_size, &alloc_size))
        return -EOVERFLOW;

    r = bf_realloc(&vec->data, alloc_size);
    if (r)
        return r;

    vec->cap = new_cap;

    return 0;
}

static int _bf_vector_grow(bf_vector *vec, size_t required)
{
    size_t new_cap;

    assert(vec);

    if (required <= vec->cap)
        return 0;

    if (vec->cap >= _BF_VECTOR_MAX_CAP)
        return -ENOMEM;

    new_cap = vec->cap ? vec->cap + (vec->cap / 2) : _BF_VECTOR_INIT_CAP;
    new_cap = bf_max(new_cap, required);
    new_cap = bf_min(new_cap, _BF_VECTOR_MAX_CAP);

    if (new_cap < required)
        return -ENOMEM;

    return _bf_vector_resize(vec, new_cap);
}

int bf_vector_add(bf_vector *vec, const void *elem)
{
    size_t required;
    int r;

    assert(vec);
    assert(elem);

    if (__builtin_add_overflow(vec->size, 1, &required))
        return -ENOMEM;

    r = _bf_vector_grow(vec, required);
    if (r)
        return r;

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

    r = _bf_vector_grow(vec, required);
    if (r)
        return r;

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

    return _bf_vector_resize(vec, cap);
}

void *bf_vector_take(bf_vector *vec)
{
    assert(vec);

    vec->size = 0;
    vec->cap = 0;

    return TAKE_PTR(vec->data);
}
