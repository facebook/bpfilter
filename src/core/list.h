/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

/* This has to be defined here, otherwise struct bf_list_node definition is
 * self-referencing... */
typedef struct bf_list_node bf_list_node;

typedef void (*bf_list_ops_free)(void **data);

/**
 * @struct bf_list_ops
 * @brief Operation to manipulate @ref bf_list data.
 *
 * @var bf_list_ops::free
 *  Free the data stored in a node. Should be able to handle NULL data.
 */
typedef struct
{
    bf_list_ops_free free;
} bf_list_ops;

/**
 * @struct bf_list_node
 * @brief Node composing a @ref bf_list.
 *
 * @warning From the user's perspective, the inside of this structure should
 * not be directly accessed. Directly modifying any of the fields should be
 * considered undefined behavior.
 *
 * @var bf_list_node::data
 * 	The node's data.
 * @var bf_list_node::prev
 * 	Pointer to the previous node. Can be NULL if node is first.
 * @var bf_list_node::next
 * 	Pointer to the next node. Can be NULL if node is last.
 */
struct bf_list_node
{
    void *data;
    bf_list_node *prev;
    bf_list_node *next;
};

/**
 * @struct bf_list
 * @brief Base structure for the doubly-linked-list data structure.
 *
 * @warning From the user's perspective, the inside of this structure should
 * not be directly accessed. Directly modifying any of the fields should be
 * considered undefined behavior.
 *
 * @var bf_list::len
 * 	Number of elements in the list.
 * @var bf_list::head
 * 	First element of the list, NULL if the list is empty.
 * @var bf_list::tail
 * 	Last element of the list, NULL if the list is empty.
 */
typedef struct
{
    size_t len;
    bf_list_node *head;
    bf_list_node *tail;
    bf_list_ops ops;
} bf_list;

#define _cleanup_bf_list_ __attribute__((cleanup(bf_list_free)))

/**
 * @brief Iterate over a @ref bf_list.
 *
 * Use a temporary variable to store the next node (if any). Hence, a node
 * can be removed from the list during iteration.
 *
 * @param list Pointer to the list to iterate over. Must be non-NULL.
 * @param node Name of the variable containing the current node. This variable
 * 	will be created automatically and the caller will be able to use it to
 * 	access the node.
 */
#define bf_list_foreach(list, node)                                            \
    for (bf_list_node *node = (list)->head,                                    \
                      *__next = (list)->head ? (list)->head->next : NULL;      \
         node; node = __next, __next = __next ? __next->next : NULL)

/**
 * @brief Reverse iterate over a @ref bf_list.
 *
 * Use a temporary variable to store the next node (if any). Hence, a node
 * can be removed from the list during iteration.
 *
 * @param list Pointer to the list to iterate over. Must be non-NULL.
 * @param node Name of the variable containing the current node. This variable
 * 	will be created automatically and the caller will be able to use it to
 * 	access the node.
 */
#define bf_list_foreach_rev(list, node)                                        \
    for (bf_list_node *node = (list)->tail,                                    \
                      *__next = (list)->tail ? (list)->tail->prev : NULL;      \
         node; node = __next, __next = __next ? __next->prev : NULL)

/**
 * @brief Returns an initialised @ref bf_list.
 *
 * @param ops Operations to use to manipulate the list's data. Must be non-NULL.
 * @return An initialised @ref bf_list.
 */
#define bf_list_default(list_ops) ((bf_list) {.ops = list_ops})

/**
 * @brief Allocate and initialise a new list.
 *
 * @param list Pointer to the list to initialise. Must be non-NULL.
 * @param ops Operations to use to manipulate the list's data. Must be non-NULL.
 * @return 0 on success or negative errno code on failure.
 */
int bf_list_new(bf_list **list, const bf_list_ops *ops);

/**
 * @brief Free a list.
 *
 * @param list Pointer to the list to free. Must be non-NULL.
 */
void bf_list_free(bf_list **list);

/**
 * @brief Initialize an allocated list.
 *
 * @param list List to initialise. Must be non-NULL.
 * @param ops Operations to use to manipulate the list's data. Must be non-NULL.
 *  @p ops shouldn't contain any NULL field.
 */
void bf_list_init(bf_list *list, const bf_list_ops *ops);

/**
 * @brief Clean up a list.
 *
 * Every node in the list is freed. The node's data is freed using the function
 * provided during initialisation (through @ref bf_list_ops).
 *
 * @param list Pointer to the initialised list to clean. Must be non-NULL.
 */
void bf_list_clean(bf_list *list);

/**
 * @brief Get the number of nodes in the list.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return Number of nodes in the list.
 */
static inline size_t bf_list_size(const bf_list *list)
{
    assert(list);
    return list->len;
}

/**
 * @brief Check if a list is empty.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return True if the list is empty, false otherwise.
 */
static inline bool bf_list_empty(bf_list *list)
{
    assert(list);
    return list->len == 0;
}

/**
 * @brief Check if @p node is the head of @p list.
 *
 * @param list List. Must be non NULL.
 * @param node Node. Must be non NULL.
 * @return True if @p node is the head of @p list, false otherwise.
 */
static inline bool bf_list_is_head(const bf_list *list,
                                   const bf_list_node *node)
{
    assert(list);
    assert(node);

    return node == list->head;
}

/**
 * @brief Check if @p node is the tail of @p list.
 *
 * @param list List. Must be non NULL.
 * @param node Node. Must be non NULL.
 * @return True if @p node is the tail of @p list, false otherwise.
 */
static inline bool bf_list_is_tail(const bf_list *list,
                                   const bf_list_node *node)
{
    assert(list);
    assert(node);

    return node == list->tail;
}

/**
 * @brief Add data at the beginning of the list.
 *
 * @param list List to append data to. Must be initialised and non-NULL.
 * @param data Data to append to the list. Can be NULL. @p list takes
 * 	ownership of the data: it should not be freed.
 * @return 0 on success or negative errno code on failure.
 */
int bf_list_add_head(bf_list *list, void *data);

/**
 * @brief Add data at the end of the list.
 *
 * @param list List to append data to. Must be initialised and non-NULL.
 * @param data Data to append to the list. Can be NULL. @p list takes
 * 	ownership of the data: it should not be freed.
 * @return 0 on success or negative errno code on failure.
 */
int bf_list_add_tail(bf_list *list, void *data);

/**
 * @brief Delete @p node from @p list.
 *
 * @p node is freed and shouldn't be used once the function returns. The node's
 * data will be freed using the function provided during initialisation (through
 * @ref bf_list_ops).
 *
 * @param list List to remove node from. Must be non-NULL.
 * @param node Node to remove from the list. Must be non-NULL.
 */
void bf_list_delete(bf_list *list, bf_list_node *node);

/**
 * @brief Returns the first element of the list.
 *
 * A @p bf_list_node object it returned. Use @ref bf_list_node_get_data to
 * get a pointer to the data.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return Pointer to the first node of the list, or NULL if empty.
 */
static inline bf_list_node *bf_list_get_head(const bf_list *list)
{
    assert(list);
    return list->head;
}

/**
 * @brief Returns the last element of the list.
 *
 * A @p bf_list_node object it returned. Use @ref bf_list_node_get_data to
 * get a pointer to the data.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return Pointer to the last node of the list, or NULL if empty.
 */
static inline bf_list_node *bf_list_get_tail(const bf_list *list)
{
    assert(list);
    return list->tail;
}

/**
 * @brief Get next node.
 *
 * @param node Current node. Must be non-NULL.
 * @return Pointer to the next node, or NULL if end of list.
 */
static inline bf_list_node *bf_list_node_next(const bf_list_node *node)
{
    assert(node);
    return node->next;
}

/**
 * @brief Get previous node.
 *
 * @param node Current node. Must be non-NULL.
 * @return Pointer to the previous node, or NULL if end of list.
 */
static inline bf_list_node *bf_list_node_prev(const bf_list_node *node)
{
    assert(node);
    return node->prev;
}

/**
 * @brief Get the node's data.
 *
 * Note that the pointer returned can be NULL, as nothing prevents NULL data
 * to be stored in the node.
 * The pointer returned is owned by the node and should not be freed.
 *
 * @param node Current node. Must be non-NULL.
 * @return Pointer to the data stored in the iterator.
 */
static inline void *bf_list_node_get_data(const bf_list_node *node)
{
    assert(node);
    return node->data;
}

/**
 * @brief Get the node's data and remove it from the node.
 *
 * Once the function returns, the node's data is set to NULL. The pointer
 * returned is then owned by the caller.
 *
 * @param node Current node. Must be non-NULL.
 * @return Pointer to the data stored in the node.
 */
static inline void *bf_list_node_take_data(bf_list_node *node)
{
    void *data;

    assert(node);

    data = node->data;
    node->data = NULL;

    return data;
}
