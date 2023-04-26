/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define _GNU_SOURCE

#include <search.h>
#include <stddef.h>

/**
 * @struct bf_map
 * @brief Map object.
 *
 * This structure is opaque and should not be accessed directly. Use the
 * provided functions instead.
 *
 * @var bf_map::data
 *  Underlying data structure used to store the map.
 */
typedef struct
{
    struct hsearch_data data;
} bf_map;

/**
 * @brief Create a new map.
 *
 * Allocate and initialize a new map object.
 *
 * @param map Return argument to store the map's pointer into. If an error
 *  occur during map creating, this argument remain unchanged.
 * 	Must be non-NULL.
 * @param nelem Maximum number of element expected to be stored in the map.
 * @return 0 on success, or negative error code on failure.
 */
int bf_map_new(bf_map **map, size_t nelem);

/**
 * @brief Deinitialize and free a map.
 *
 * Data contained in the map is not modified or freed. Only the memory allocated
 * to maintain the map itself is freed. Once this function returns, the map
 * should not be used.
 *
 * @param map Map object to cleanup. Must be non-NULL.
 */
void bf_map_free(bf_map **map);

/**
 * @brief Look for a key in the map.
 *
 * @param map Map to search into. Must be non-NULL.
 * @param key Key to look for. Must be non-NULL.
 * @param value Return argument, used to store the address of the value, if
 *  found. This argument is not modified if the search fails. Must be non-NULL.
 * @return 0 on success, or negative error code on failure.
 */
int bf_map_find(bf_map *map, const char *key, void **value);

/**
 * @brief Insert a new key/value pair in the map, update the entry if the
 * 	key already exists.
 *
 * @param map Map to insert into. Must be non-NULL.
 * @param key Key to insert a value for. Must be non-NULL.
 * @param value Value to insert into the map. If the key already exists, its
 * 	value is replaced. The old value is discarded but not freed. Must be
 * 	non-NULL.
 * @return 0 on success, or negative error code on failure.
 */
int bf_map_upsert(bf_map *map, const char *key, void *value);
