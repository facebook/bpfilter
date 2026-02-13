// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/core/vector.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/helper.h"

#define _BF_VECTOR_INIT_CAP 8

int bf_vector_new(struct bf_vector **vec, size_t elem_size)
{
    _free_bf_vector_ struct bf_vector *_vec = NULL;

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

void bf_vector_free(struct bf_vector **vec)
{
    assert(vec);

    if (!*vec)
        return;

    bf_vector_clean(*vec);
    freep((void *)vec);
}

void bf_vector_clean(struct bf_vector *vec)
{
    assert(vec);

    freep((void *)&vec->data);
    vec->len = 0;
    vec->cap = 0;
}

size_t bf_vector_len(const struct bf_vector *vec)
{
    assert(vec);
    return vec->len;
}

size_t bf_vector_cap(const struct bf_vector *vec)
{
    assert(vec);
    return vec->cap;
}

void *bf_vector_get(const struct bf_vector *vec, size_t index)
{
    assert(vec);

    if (index >= vec->len)
        return NULL;

    return vec->data + (index * vec->elem_size);
}

int bf_vector_add(struct bf_vector *vec, const void *elem)
{
    int r;

    assert(vec);
    assert(elem);

    if (vec->len == vec->cap) {
        size_t new_cap;

        if (vec->cap > SIZE_MAX / 2)
            return -ENOMEM;

        new_cap = vec->cap ? vec->cap * 2 : _BF_VECTOR_INIT_CAP;

        r = bf_vector_resize(vec, new_cap);
        if (r)
            return r;
    }

    memcpy(vec->data + (vec->len * vec->elem_size), elem, vec->elem_size);
    ++vec->len;

    return 0;
}

int bf_vector_resize(struct bf_vector *vec, size_t new_cap)
{
    size_t alloc_size;
    int r;

    assert(vec);

    if (new_cap < vec->len)
        return -EINVAL;

    if (new_cap == 0) {
        freep((void *)&vec->data);
        vec->cap = 0;
        return 0;
    }

    if (__builtin_mul_overflow(new_cap, vec->elem_size, &alloc_size))
        return -ENOMEM;

    r = bf_realloc(&vec->data, alloc_size);
    if (r)
        return r;

    vec->cap = new_cap;

    return 0;
}

void *bf_vector_data(const struct bf_vector *vec)
{
    assert(vec);
    return vec->data;
}

void *bf_vector_take(struct bf_vector *vec)
{
    assert(vec);

    vec->len = 0;
    vec->cap = 0;

    return TAKE_PTR(vec->data);
}

int bf_vector_set_len(struct bf_vector *vec, size_t len)
{
    assert(vec);

    if (len > vec->cap)
        return -EINVAL;

    vec->len = len;

    return 0;
}
