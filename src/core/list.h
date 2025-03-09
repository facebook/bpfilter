/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "core/helper.h"

struct bf_marsh;

/* This has to be defined here, otherwise struct bf_list_node definition is
 * self-referencing... */
typedef struct bf_list_node bf_list_node;

typedef void (*bf_list_ops_free)(void **data);
typedef int (*bf_list_ops_marsh)(const void *data, struct bf_marsh **marsh);

/**
 * @struct bf_list_ops
 * Operation to manipulate @ref bf_list data.
 *
 * @var bf_list_ops::free
 *  Free the data stored in a node. Should be able to handle NULL data.
 */
typedef struct
{
    /** Callback to free a node's data. If NULL, the data won't be freed. */
    bf_list_ops_free free;

    /** Callback to serialize the data from a node. If NULL, the data won't be
     * serialized. */
    bf_list_ops_marsh marsh;
} bf_list_ops;

/**
 * @struct bf_list_node
 * Node composing a @ref bf_list.
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
 * Base structure for the doubly-linked-list data structure.
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
#define _clean_bf_list_ __attribute__((cleanup(bf_list_clean)))

/**
 * Iterate over a @ref bf_list.
 *
 * Use a temporary variable to store the next node (if any). Hence, a node
 * can be removed from the list during iteration.
 *
 * @param list Pointer to the list to iterate over. Must be non-NULL.
 * @param node Name of the variable containing the current node. This variable
 *        will be created automatically and the caller will be able to use it to
 * 	      access the node.
 */
#define bf_list_foreach(list, node)                                            \
    for (bf_list_node * (node) = (list)->head,                                 \
                        *__next = (list)->head ? (list)->head->next : NULL;    \
         (node); (node) = __next, __next = __next ? __next->next : NULL)

/**
 * Reverse iterate over a @ref bf_list.
 *
 * Use a temporary variable to store the next node (if any). Hence, a node
 * can be removed from the list during iteration.
 *
 * @param list Pointer to the list to iterate over. Must be non-NULL.
 * @param node Name of the variable containing the current node. This variable
 * 	      will be created automatically and the caller will be able to use it to
 * 	      access the node.
 */
#define bf_list_foreach_rev(list, node)                                        \
    for (bf_list_node * (node) = (list)->tail,                                 \
                        *__next = (list)->tail ? (list)->tail->prev : NULL;    \
         (node); (node) = __next, __next = __next ? __next->prev : NULL)

/**
 * Returns an initialised @ref bf_list_ops structure.
 *
 * @param free_cb Callback to free the data contained in a node. If NULL, a
 *        node's data won't be freed when the list is destroyed.
 * @param marsh_cb Callback to marsh the data contained in a node. If NULL, a
 *        node's data won't be marshed when the list is marshed.
 * @return An initialised @ref bf_list_ops .
 */
#define bf_list_ops_default(free_cb, marsh_cb)                                 \
    ((bf_list_ops) {.free = (bf_list_ops_free)(free_cb),                       \
                    .marsh = (bf_list_ops_marsh)(marsh_cb)})

/**
 * Returns an initialised @ref bf_list .
 *
 * @param free_cb Callback to free the data contained in a node. If NULL, a
 *        node's data won't be freed when the list is destroyed.
 * @param marsh_cb Callback to marsh the data contained in a node. If NULL, a
 *        node's data won't be marshed when the list is marshed.
 * @return An initialised @ref bf_list .
 */
#define bf_list_default(free_cb, marsh_cb)                                     \
    ((bf_list) {.ops = bf_list_ops_default(free_cb, marsh_cb)})

/**
 * Move a list.
 *
 * Move a list from @p list and return it. Once moved, the original list will
 * be empty, and @ref bf_list_clean can be called on it safely. The list it
 * has been moved to will be overriden and @ref bf_list_clean should be
 * called on it.
 *
 * @param list List to move.
 * @return The moved list.
 */
#define bf_list_move(list)                                                     \
    ({                                                                         \
        bf_list *__list = &(list);                                             \
        bf_list _list = *__list;                                               \
        *__list = bf_list_default(NULL, NULL);                                 \
        _list;                                                                 \
    })

/**
 * Allocate and initialise a new list.
 *
 * @param list Pointer to the list to initialise. Must be non-NULL.
 * @param ops Operations to use to manipulate the list's data. If NULL, the
 *        list's ops are initialised to NULL: the node's data won't be free nor
 *        marshed.
 * @return 0 on success or negative errno code on failure.
 */
int bf_list_new(bf_list **list, const bf_list_ops *ops);

/**
 * Free a list.
 *
 * @param list Pointer to the list to free. Must be non-NULL.
 */
void bf_list_free(bf_list **list);

/**
 * Initialize an allocated list.
 *
 * @param list List to initialise. Must be non-NULL.
 * @param ops Operations to use to manipulate the list's data. If NULL, the
 *        list's ops are initialised to NULL: the node's data won't be free nor
 *        marshed.
 */
void bf_list_init(bf_list *list, const bf_list_ops *ops);

/**
 * Clean up a list.
 *
 * Every node in the list is freed. The node's data is freed using the function
 * provided during initialisation (through @ref bf_list_ops).
 *
 * @param list Pointer to the initialised list to clean. Must be non-NULL.
 */
void bf_list_clean(bf_list *list);

/**
 * Serialize a list.
 *
 * Allocate @c marsh and call @c list.ops.marsh for every node in the list. The
 * serialized node data is added to @c marsh .
 *
 * @c list.ops.marsh must be a pointer to a valid serializing function.
 *
 * @param list List to serialize. Can't be NULL.
 * @param marsh Serialized object. On success, @c *marsh points to the
 *        serialized list. On error, @c marsh is unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_list_marsh(const bf_list *list, struct bf_marsh **marsh);

/**
 * Get the number of nodes in the list.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return Number of nodes in the list.
 */
static inline size_t bf_list_size(const bf_list *list)
{
    bf_assert(list);
    return list->len;
}

/**
 * Check if a list is empty.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return True if the list is empty, false otherwise.
 */
static inline bool bf_list_is_empty(const bf_list *list)
{
    bf_assert(list);

    return list->len == 0;
}

/**
 * Check if @p node is the head of @p list.
 *
 * @param list List. Must be non NULL.
 * @param node Node. Must be non NULL.
 * @return True if @p node is the head of @p list, false otherwise.
 */
static inline bool bf_list_is_head(const bf_list *list,
                                   const bf_list_node *node)
{
    bf_assert(list);
    bf_assert(node);

    return node == list->head;
}

/**
 * Check if @p node is the tail of @p list.
 *
 * @param list List. Must be non NULL.
 * @param node Node. Must be non NULL.
 * @return True if @p node is the tail of @p list, false otherwise.
 */
static inline bool bf_list_is_tail(const bf_list *list,
                                   const bf_list_node *node)
{
    bf_assert(list);
    bf_assert(node);

    return node == list->tail;
}

/**
 * Add data at the beginning of the list.
 *
 * @param list List to append data to. Must be initialised and non-NULL.
 * @param data Data to append to the list. Can be NULL. @p list takes
 * 	      ownership of the data: it should not be freed.
 * @return 0 on success or negative errno code on failure.
 */
int bf_list_add_head(bf_list *list, void *data);

/**
 * Add data at the end of the list.
 *
 * @param list List to append data to. Must be initialised and non-NULL.
 * @param data Data to append to the list. Can be NULL. @p list takes
 * 	      ownership of the data: it should not be freed.
 * @return 0 on success or negative errno code on failure.
 */
int bf_list_add_tail(bf_list *list, void *data);

/**
 * Delete @p node from @p list.
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
 * Get the data of a node based on the node's index.
 *
 * @param list List to get the data from. Can't be NULL.
 * @param index Index of the node to get the data from. Index 0 would be the
 *              first node. If the node doesn't exist, NULL is returned.
 * @return Data containing in the node at index @c index , or NULL if the
 *         node doesn't exist.
 */
void *bf_list_get_at(const bf_list *list, size_t index);

/**
 * Returns the first element of the list.
 *
 * A @p bf_list_node object it returned. Use @ref bf_list_node_get_data to
 * get a pointer to the data.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return Pointer to the first node of the list, or NULL if empty.
 */
static inline bf_list_node *bf_list_get_head(const bf_list *list)
{
    bf_assert(list);
    return list->head;
}

/**
 * Returns the last element of the list.
 *
 * A @p bf_list_node object it returned. Use @ref bf_list_node_get_data to
 * get a pointer to the data.
 *
 * @param list Initialised list. Must be non-NULL.
 * @return Pointer to the last node of the list, or NULL if empty.
 */
static inline bf_list_node *bf_list_get_tail(const bf_list *list)
{
    bf_assert(list);
    return list->tail;
}

/**
 * Get next node.
 *
 * @param node Current node. Must be non-NULL.
 * @return Pointer to the next node, or NULL if end of list.
 */
static inline bf_list_node *bf_list_node_next(const bf_list_node *node)
{
    bf_assert(node);
    return node->next;
}

/**
 * Get previous node.
 *
 * @param node Current node. Must be non-NULL.
 * @return Pointer to the previous node, or NULL if end of list.
 */
static inline bf_list_node *bf_list_node_prev(const bf_list_node *node)
{
    bf_assert(node);
    return node->prev;
}

/**
 * Get the node's data.
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
    bf_assert(node);
    return node->data;
}

/**
 * Get the node's data and remove it from the node.
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

    bf_assert(node);

    data = node->data;
    node->data = NULL;

    return data;
}
