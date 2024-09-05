// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "list.h"

#include <errno.h>
#include <stdlib.h>

#include "core/helper.h"

/**
 * Create a new list node, with the given data.
 *
 * @param node New node pointer. Must be non-NULL.. If the function fails, this
 * 	      parameter remains unchanged.
 * @param data Data to store in the new node. Can be NULL.
 * @return 0 on success or negative errno code on failure.
 */
static int bf_list_node_new(bf_list_node **node, void *data)
{
    bf_list_node *_node;

    bf_assert(node);

    _node = calloc(1, sizeof(*_node));
    if (!_node)
        return -ENOMEM;

    _node->data = data;
    *node = _node;

    return 0;
}

/**
 * Free a list node. Must be non-NULL.
 *
 * The data contained in the node will also be freed using the function provided
 * in the list's ops.
 *
 * @param node Node to free.
 * @param free_data Pointer to a function use to free the node's data.
 */
static void bf_list_node_free(bf_list_node **node,
                              void (*free_data)(void **data))
{
    bf_assert(node);

    free_data(&(*node)->data);
    free(*node);
    *node = NULL;
}

int bf_list_new(bf_list **list, const bf_list_ops *ops)
{
    _cleanup_bf_list_ bf_list *_list = NULL;

    bf_assert(list);
    bf_assert(ops);
    bf_assert(ops->free);

    _list = calloc(1, sizeof(*_list));
    if (!_list)
        return -ENOMEM;

    bf_list_init(_list, ops);

    *list = TAKE_PTR(_list);

    return 0;
}

void bf_list_free(bf_list **list)
{
    bf_assert(list);

    if (!*list)
        return;

    bf_list_clean(*list);
    free(*list);
    *list = NULL;
}

void bf_list_init(bf_list *list, const bf_list_ops *ops)
{
    bf_assert(list);
    bf_assert(ops);
    bf_assert(ops->free);

    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
    list->ops = *ops;
}

void bf_list_clean(bf_list *list)
{
    bf_assert(list);

    bf_list_foreach (list, node)
        bf_list_node_free(&node, list->ops.free);

    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

int bf_list_add_head(bf_list *list, void *data)
{
    bf_list_node *node = NULL;
    int r;

    bf_assert(list);

    r = bf_list_node_new(&node, data);
    if (r < 0)
        return r;

    node->next = list->head;
    if (list->head)
        list->head->prev = node;

    list->head = node;

    if (!list->tail)
        list->tail = node;

    ++list->len;

    return 0;
}

int bf_list_add_tail(bf_list *list, void *data)
{
    bf_list_node *node = NULL;
    int r;

    bf_assert(list);

    r = bf_list_node_new(&node, data);
    if (r < 0)
        return r;

    node->prev = list->tail;
    if (list->tail)
        list->tail->next = node;

    list->tail = node;

    if (!list->head)
        list->head = node;

    ++list->len;

    return 0;
}

void bf_list_delete(bf_list *list, bf_list_node *node)
{
    bf_assert(list);
    bf_assert(node);

    if (list->head == node)
        list->head = node->next;
    if (list->tail == node)
        list->tail = node->prev;

    if (node->prev)
        node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;

    bf_list_node_free(&node, list->ops.free);

    --list->len;
}
