/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/marsh.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int bf_marsh_new(struct bf_marsh **marsh, const void *data, size_t data_len)
{
    struct bf_marsh *_marsh = NULL;

    assert(marsh);
    assert(!data ? !data_len : 1);

    _marsh = malloc(sizeof(struct bf_marsh) + data_len);
    if (!_marsh)
        return -ENOMEM;

    _marsh->data_len = data_len;
    bf_memcpy(_marsh->data, data, data_len);

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_marsh_free(struct bf_marsh **marsh)
{
    assert(marsh);

    if (!*marsh)
        return;

    free(*marsh);
    *marsh = NULL;
}

int bf_marsh_add_child_obj(struct bf_marsh **marsh, const struct bf_marsh *obj)
{
    _cleanup_bf_marsh_ struct bf_marsh *new = NULL;
    size_t new_data_len;

    assert(marsh && *marsh);
    assert(obj);

    new_data_len = (*marsh)->data_len + bf_marsh_size(obj);

    new = malloc(sizeof(struct bf_marsh) + new_data_len);
    if (!new)
        return -ENOMEM;

    memcpy(new->data, (*marsh)->data, (*marsh)->data_len);
    memcpy(new->data + (*marsh)->data_len, obj, bf_marsh_size(obj));
    new->data_len = new_data_len;

    bf_marsh_free(marsh);
    *marsh = TAKE_PTR(new);

    return 0;
}

int bf_marsh_add_child_raw(struct bf_marsh **marsh, const void *data,
                           size_t data_len)
{
    _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
    int r;

    assert(marsh && *marsh);
    assert(!data ? !data_len : 1);

    r = bf_marsh_new(&child, data, data_len);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_obj(marsh, child);
    if (r < 0)
        return r;

    return 0;
}
