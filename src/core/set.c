// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/set.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/marsh.h"

size_t _bf_set_type_elem_size(enum bf_set_type type)
{
    static const size_t sizes[_BF_SET_MAX] = {
        [BF_SET_IP4] = 4,
    };

    static_assert(ARRAY_SIZE(sizes) == _BF_SET_MAX,
                  "missing entries in set elems size array");

    return sizes[type];
}

int bf_set_new(struct bf_set **set, enum bf_set_type type)
{
    bf_assert(set);

    *set = malloc(sizeof(**set));
    if (!*set)
        return -ENOMEM;

    (*set)->type = type;
    (*set)->elem_size = _bf_set_type_elem_size(type);
    bf_list_init(&(*set)->elems,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)freep}});

    return 0;
}

int bf_set_new_from_marsh(struct bf_set **set, const struct bf_marsh *marsh)
{
    _cleanup_bf_set_ struct bf_set *_set = NULL;
    struct bf_marsh *child;
    enum bf_set_type type;
    int r;

    bf_assert(set);
    bf_assert(marsh);

    if (!(child = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    memcpy(&type, child->data, sizeof(type));

    r = bf_set_new(&_set, type);
    if (r < 0)
        return r;

    while ((child = bf_marsh_next_child(marsh, child))) {
        _cleanup_free_ void *elem = NULL;

        elem = malloc(_set->elem_size);
        if (!elem)
            return -ENOMEM;

        memcpy(elem, child->data, _set->elem_size);

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
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(set);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &set->type, sizeof(set->type));
    if (r < 0)
        return r;

    bf_list_foreach (&set->elems, elem_node) {
        r = bf_marsh_add_child_raw(&_marsh, bf_list_node_get_data(elem_node),
                                   set->elem_size);
        if (r < 0)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_set_dump(const struct bf_set *set, prefix_t *prefix)
{
    bf_assert(set && prefix);

    DUMP(prefix, "struct bf_set at %p", set);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "type: %s", bf_set_type_to_str(set->type));
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

static const char *_bf_set_type_strs[] = {
    [BF_SET_IP4] = "BF_SET_IP4",
};

static_assert(ARRAY_SIZE(_bf_set_type_strs) == _BF_SET_MAX, "");

const char *bf_set_type_to_str(enum bf_set_type type)
{
    bf_assert(0 <= type && type < _BF_SET_MAX);

    return _bf_set_type_strs[type];
}

int bf_set_type_from_str(const char *str, enum bf_set_type *type)
{
    bf_assert(str);
    bf_assert(type);

    for (size_t i = 0; i < _BF_SET_MAX; ++i) {
        if (bf_streq(_bf_set_type_strs[i], str)) {
            *type = i;
            return 0;
        }
    }

    return -EINVAL;
}
