/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "core/helper.h"

/**
 * Marshalled data.
 *
 * @var bf_marsh::data_len
 *  Length of marshalled data. It doesn't include the length of the header.
 * @var bf_marsh::data
 *  Marshalled data.
 */
struct bf_marsh
{
    size_t data_len;
    char data[];
} bf_packed;

#define _free_bf_marsh_ __attribute__((__cleanup__(bf_marsh_free)))

/**
 * Returns true if a marsh object is empty (only contains a header).
 *
 * @param marsh Marsh object to check for empty. Can't be NULL.
 * @return True if the @c marsh object is empty, false otherwise.
 */
static inline bool bf_marsh_is_empty(const struct bf_marsh *marsh)
{
    bf_assert(marsh);

    return marsh->data_len == 0;
}

/**
 * Get the total size of marshalled data.
 *
 * @param marsh Marshalled data.
 * @return Total size of marshalled data, including the header.
 */
static inline size_t bf_marsh_size(const struct bf_marsh *marsh)
{
    bf_assert(marsh);

    return sizeof(struct bf_marsh) + marsh->data_len;
}

/**
 * Get pointer to the end of a @ref bf_marsh structure.
 *
 * "End" here, means the first byte after the content of the marshalled data.
 *
 * @param marsh Marshalled data.
 * @return Pointer to the end of the marshalled data.
 */
static inline void *bf_marsh_end(const struct bf_marsh *marsh)
{
    bf_assert(marsh);

    return (void *)(marsh->data + marsh->data_len);
}

/**
 * Check if `child` is a valid child for `marsh`.
 *
 * A valid marsh is defined by the following criteria:
 * - It starts within its parent's data.
 * - Its full length (including the header) is within its parent's data.
 * A marsh can only be validated relative to its parent. By recursively
 * validating all the children of a marsh, we can validate the whole marsh.
 *
 * @warning This function doesn't check if the marshalled data is valid. It
 * only checks if the marshalled data is within the parent's data and can be
 * accessed safely.
 *
 * @param marsh Parent marsh, must be valid.
 * @param child Child marsh to validate. Can be NULL.
 * @return true if `child` is a valid child of `marsh`, false otherwise.
 */
static inline bool bf_marsh_child_is_valid(const struct bf_marsh *marsh,
                                           const struct bf_marsh *child)
{
    bf_assert(marsh);

    if (!child)
        return false;

    // Child must start within the parent marsh.
    if ((void *)child < (void *)marsh->data ||
        (void *)child > bf_marsh_end(marsh))
        return false;

    /* Child's data_len field must be within the parent bf_marsh. This check
     * is required to safely access child->data_len. */
    if ((void *)child + sizeof(struct bf_marsh) > bf_marsh_end(marsh))
        return false;

    // Child's data must be within the parent bf_marsh.
    if (bf_marsh_end(child) > bf_marsh_end(marsh))
        return false;

    return true;
}

/**
 * Get `marsh`'s child located after `child`.
 *
 * @param marsh Parent marsh, must be valid.
 * @param child Child of `marsh`, must be a valid child of `marsh` or NULL. If
 *        `child` is NULL, the first child of `marsh` is returned.
 * @return Next child of `marsh` after `child`, or NULL if `child` is the
 *         last valid child of `marsh`.
 */
static inline struct bf_marsh *bf_marsh_next_child(const struct bf_marsh *marsh,
                                                   const struct bf_marsh *child)
{
    bf_assert(marsh);

    struct bf_marsh *next_child =
        child ? (struct bf_marsh *)(child->data + child->data_len) :
                (struct bf_marsh *)marsh->data;

    return bf_marsh_child_is_valid(marsh, next_child) ? next_child : NULL;
}

/**
 * Allocate and initialise a @ref bf_marsh structure.
 *
 * @param marsh Marsh to be allocated. On success, contains a pointer to the
 *        marsh structure, and is owned by the caller. If the function fails, it's
 *        left unchanged.
 * @param data Data to be marshalled.
 * @param data_len Length of @p data.
 * @return 0 on success, negative errno value on error.
 */
int bf_marsh_new(struct bf_marsh **marsh, const void *data, size_t data_len);

/**
 * Free a marsh, including its data.
 *
 * If @p marsh points to NULL, then nothing is done.
 *
 * @param marsh Marsh to free. Must not be NULL.
 */
void bf_marsh_free(struct bf_marsh **marsh);

/**
 * Add a child to a marsh, from another marsh.
 *
 * @p obj will be added to the data in @p marsh.
 *
 * @param marsh Parent marsh. Must be non NULL.
 * @param obj Marsh to be added as a child. Must be non NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_marsh_add_child_obj(struct bf_marsh **marsh, const struct bf_marsh *obj);

/**
 * Add a child to a marsh, from raw data.
 *
 * If @p data is NULL, nothing is done and @p marsh remain unchanged. In this
 * case, @p data_len must be 0.
 *
 * @param marsh Parent marsh. Must be non NULL.
 * @param data Data to add to the marsh.
 * @param data_len Length of the data to add to @p marsh.
 * @return 0 on success, negative errno value on error.
 */
int bf_marsh_add_child_raw(struct bf_marsh **marsh, const void *data,
                           size_t data_len);
