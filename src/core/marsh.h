/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#include "shared/helper.h"

/**
 * @brief Marshalled data.
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

#define _cleanup_bf_marsh_ __attribute__((__cleanup__(bf_marsh_free)))

/**
 * @brief Get the total size of marshalled data.
 *
 * @param marsh Marshalled data.
 * @return Total size of marshalled data, including the header.
 */
static inline size_t bf_marsh_size(const struct bf_marsh *marsh)
{
    assert(marsh);

    return sizeof(struct bf_marsh) + marsh->data_len;
}

/**
 * @brief Get pointer to the end of a @ref bf_marsh structure.
 *
 * "End" here, means the first byte after the content of the marshalled data.
 *
 * @param marsh Marshalled data.
 * @return Pointer to the end of the marshalled data.
 */
static inline void *bf_marsh_end(const struct bf_marsh *marsh)
{
    assert(marsh);

    return (void *)(marsh->data + marsh->data_len);
}

/**
 * @brief Check if @p child is a valid child of @p marsh.
 *
 * A valid child is a child that starts and ends in its parent.
 *
 * @param marsh Parent marshalled data.
 * @param child Child marshalled data.
 * @return True if @p child is a valid child of @p marsh, false otherwise.
 */
static inline bool bf_marsh_is_valid_child(const struct bf_marsh *marsh,
                                           const struct bf_marsh *child)
{
    assert(marsh);
    assert(child);

    // Ensure the child's header is within valid memory range before
    // dereferencing it.
    return child >= (struct bf_marsh *)marsh->data &&
           (void *)((void *)child + sizeof(struct bf_marsh)) <=
               bf_marsh_end(marsh) &&
           bf_marsh_end(child) <= bf_marsh_end(marsh);
}

/**
 * @brief Get the next child of @p ctx after @p child.
 *
 * @param marsh Marshalled data.
 * @param child Valid child of @p marsh.
 * @return Next child of @p marsh after @p child, or NULL if @p child is the
 *  last child of @p marsh.
 */
static inline struct bf_marsh *bf_marsh_next_child(const struct bf_marsh *marsh,
                                                   const struct bf_marsh *child)
{
    struct bf_marsh *next_child;

    assert(marsh);
    assert(child ? bf_marsh_is_valid_child(marsh, child) : 1);

    if (!child) {
        if (marsh->data_len >= sizeof(struct bf_marsh))
            return (struct bf_marsh *)marsh->data;

        return NULL;
    }

    next_child = (struct bf_marsh *)bf_marsh_end(child);

    return bf_marsh_is_valid_child(marsh, next_child) ? next_child : NULL;
}

/**
 * @brief Allocate and initialise a @ref bf_marsh structure.
 *
 * @param marsh Marsh to be allocated. On success, contains a pointer to the
 *  marsh structure, and is owned by the caller. If the function fails, it's
 *  left unchanged.
 * @param data Data to be marshalled.
 * @param data_len Length of @p data.
 * @return 0 on success, negative errno value on error.
 */
int bf_marsh_new(struct bf_marsh **marsh, const void *data, size_t data_len);

/**
 * @brief Free a marsh, including its data.
 *
 * If @p marsh points to NULL, then nothing is done.
 *
 * @param marsh Marsh to free. Must not be NULL.
 */
void bf_marsh_free(struct bf_marsh **marsh);

/**
 * @brief Add a child to a marsh, from another marsh.
 *
 * @p obj will be added to the data in @p marsh.
 *
 * @param marsh Parent marsh. Must be non NULL.
 * @param obj Marsh to be added as a child. Must be non NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_marsh_add_child_obj(struct bf_marsh **marsh, const struct bf_marsh *obj);

/**
 * @brief Add a child to a marsh, from raw data.
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
