// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "list.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

/**
 * @brief Create a new list node, with the given data.
 *
 * @param node New node pointer. Must be non-NULL.. If the function fails, this
 * 	parameter remains unchanged.
 * @param data Data to store in the new node. Can be NULL.
 * @return 0 on success or negative errno code on failure.
 */
static int bf_list_node_new(bf_list_node **node, void *data)
{
    bf_list_node *_node;

    assert(node);

    _node = calloc(1, sizeof(*_node));
    if (!_node)
        return -ENOMEM;

    _node->data = data;
    *node = _node;

    return 0;
}

/**
 * @brief Free a list node. Must be non-NULL.
 *
 * @param node Node to free.
 */
static void bf_list_node_free(bf_list_node **node)
{
    assert(node);

    (*node)->prev = NULL;
    (*node)->next = NULL;

    free(*node);
    *node = NULL;
}

void bf_list_init(bf_list *l)
{
    assert(l);

    l->len = 0;
    l->head = NULL;
    l->tail = NULL;
}

void bf_list_clean(bf_list *list)
{
    assert(list);

    bf_list_foreach (list, node) {
        bf_list_node_free(&node);
    }

    list->len = 0;
    list->head = NULL;
    list->tail = NULL;
}

int bf_list_add_head(bf_list *list, void *data)
{
    bf_list_node *node = NULL;
    int r;

    assert(list);

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

    assert(list);

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
    assert(list);
    assert(node);

    if (list->head == node)
        list->head = node->next;
    if (list->tail == node)
        list->tail = node->prev;

    if (node->prev)
        node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;

    bf_list_node_free(&node);

    --list->len;
}
