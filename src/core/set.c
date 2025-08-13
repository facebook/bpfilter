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

int bf_set_new(struct bf_set **set)
{
    bf_assert(set);

    _free_bf_set_ struct bf_set *_set = NULL;

    _set = malloc(sizeof(*_set));
    if (!_set)
        return -ENOMEM;

    _set->elem_size = 0;
    _set->elems = bf_list_default(freep, NULL);

    *set = TAKE_PTR(_set);

    return 0;
}

int bf_set_new_from_marsh(struct bf_set **set, const struct bf_marsh *marsh)
{
    bf_assert(set && marsh);

    _free_bf_set_ struct bf_set *_set = NULL;
    struct bf_marsh *child = NULL;
    int r;

    r = bf_set_new(&_set);
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
    _cleanup_free_ void *_elem = NULL;
    int r;

    bf_assert(set);
    bf_assert(elem);

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
