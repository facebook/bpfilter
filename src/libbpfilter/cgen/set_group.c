/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/set_group.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/hashset.h>
#include <bpfilter/core/list.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/set.h>

#define _free_bf_set_group_ __attribute__((__cleanup__(_bf_set_group_free)))

static void _bf_set_group_free(struct bf_set_group **group)
{
    assert(group);

    if (!*group)
        return;

    bf_list_clean(&(*group)->sets);
    BF_FREEP(group);
}

static int _bf_set_group_new(struct bf_set_group **group, struct bf_set *set)
{
    _free_bf_set_group_ struct bf_set_group *_group = NULL;
    int r;

    assert(group);
    assert(set);

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    /* The list holds non-owning const struct bf_set * pointers; no free
     * callback. Groups are temporary (not serialized), so no pack callback
     * either. */
    _group->sets = bf_list_default(NULL, NULL);

    r = bf_list_add_tail(&_group->sets, set);
    if (r)
        return r;

    *group = TAKE_PTR(_group);

    return 0;
}

static bool _bf_set_needs_map(const struct bf_set *set)
{
    assert(set);

    return !bf_set_is_empty(set);
}

int bf_set_group_build(bf_list *groups, const struct bf_chain *chain)
{
    _clean_bf_list_ bf_list _groups = bf_list_default(_bf_set_group_free, NULL);
    int r;

    assert(groups);
    assert(chain);

    bf_list_foreach (&chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        struct bf_set_group *match = NULL;

        if (!_bf_set_needs_map(set))
            continue;

        // LPM trie sets are not grouped, see the file's documentation.
        if (!set->use_trie) {
            bf_list_foreach (&_groups, group_node) {
                struct bf_set_group *group = bf_list_node_get_data(group_node);
                const struct bf_set *head =
                    bf_list_node_get_data(bf_list_get_head(&group->sets));

                if (bf_set_same_key(set, head)) {
                    match = group;
                    break;
                }
            }
        }

        if (match) {
            r = bf_list_add_tail(&match->sets, set);
            if (r)
                return bf_err_r(r, "failed to add set to existing group");
        } else {
            _free_bf_set_group_ struct bf_set_group *new_group = NULL;

            r = _bf_set_group_new(&new_group, set);
            if (r)
                return bf_err_r(r, "failed to create set group");

            r = bf_list_push(&_groups, (void **)&new_group);
            if (r)
                return bf_err_r(r, "failed to register set group");
        }
    }

    *groups = bf_list_move(_groups);

    return 0;
}

const struct bf_set_group *bf_set_group_find(const bf_list *groups,
                                             const struct bf_set *set,
                                             size_t *group_idx, size_t *bit_idx)
{
    size_t _group_idx = 0;

    assert(groups);

    if (!set)
        return NULL;

    bf_list_foreach (groups, group_node) {
        const struct bf_set_group *group = bf_list_node_get_data(group_node);
        size_t _bit_idx = 0;

        bf_list_foreach (&group->sets, set_node) {
            if (bf_list_node_get_data(set_node) == set) {
                if (group_idx)
                    *group_idx = _group_idx;
                if (bit_idx)
                    *bit_idx = _bit_idx;
                return group;
            }
            ++_bit_idx;
        }
        ++_group_idx;
    }

    return NULL;
}

size_t bf_set_group_value_size(const struct bf_set_group *group)
{
    assert(group);

    return (bf_list_size(&group->sets) + CHAR_BIT - 1) / CHAR_BIT;
}

bool bf_set_group_elem_value(const struct bf_set_group *group, const void *elem,
                             uint8_t *value)
{
    size_t bit_idx = 0;
    bool found = false;

    assert(group);
    assert(elem);
    assert(value);

    memset(value, 0, bf_set_group_value_size(group));

    bf_list_foreach (&group->sets, set_node) {
        const struct bf_set *set = bf_list_node_get_data(set_node);

        if (bf_hashset_contains(&set->elems, elem)) {
            value[bit_idx / CHAR_BIT] |= (uint8_t)(1U << (bit_idx % CHAR_BIT));
            found = true;
        }
        ++bit_idx;
    }

    return found;
}
