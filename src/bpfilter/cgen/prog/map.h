/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include "core/bpf_types.h"
#include "core/dump.h"
#include "core/pack.h"
#include "core/set.h"

enum bf_map_type
{
    BF_MAP_TYPE_COUNTERS,
    BF_MAP_TYPE_PRINTER,
    BF_MAP_TYPE_LOG,
    BF_MAP_TYPE_SET,
    _BF_MAP_TYPE_MAX,
};

#define BF_PIN_PATH_LEN 64

#define BF_MAP_KEY_SIZE_UNKNOWN SIZE_MAX
#define BF_MAP_VALUE_SIZE_UNKNOWN SIZE_MAX
#define BF_MAP_N_ELEMS_UNKNOWN SIZE_MAX

struct bf_map
{
    enum bf_map_type type;
    enum bf_bpf_map_type bpf_type;
    char name[BPF_OBJ_NAME_LEN];
    size_t key_size;
    size_t value_size;
    size_t n_elems;
    int fd;
};

#define _free_bf_map_ __attribute__((__cleanup__(bf_map_free)))

/**
 * Allocates and initializes a new BPF map object.
 *
 * @note This function won't create a new BPF map, but a bpfilter-specific
 * object used to keep track of a BPF map on the system.
 *
 * @param map BPF map object to allocate and initialize. Can't be NULL. On
 *        success, @c *map points to a valid @ref bf_map . On failure,
 *        @c *map remain unchanged.
 * @param name Name of the map. Will be used as the name of the BPF object, but
 *        also as filename when pinning the map to the system. Can't be NULL or
 *        empty.
 * @param type Map type, defines the set of available operations.
 * @param key_size Size (in bytes) of a key in the map.
 * @param value_size Size (in bytes) of an element of the map.
 * @param n_elems Number of elements to reserve room for in the map. Can't be 0.
 *        If you don't yet know the number of elements in the map, use
 *        @ref BF_MAP_N_ELEMS_UNKNOWN , but @ref bf_map_create can't be called
 *        until you set an actual size with @ref bf_map_set_n_elems .
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_new(struct bf_map **map, const char *name, enum bf_map_type type,
               size_t key_size, size_t value_size, size_t n_elems);

/**
 * @brief Allocate and initialise a new BPF map object, from a set.
 *
 * @param map BPF map object to allocate and initialize. Can't be NULL. On
 *        success, @c *map points to a valid @ref bf_map . On failure, @c *map
 *        remain unchanged. Can't be NULL.
 * @param name Name of the map. Will be used as the name of the BPF object, but
 *        also as filename when pinning the map to the system. Can't be NULL or
 *        empty.
 * @param set Set to create the map from. Can't be NULL.
 * @return 0 on success, or a negative error value on error.
 */
int bf_map_new_from_set(struct bf_map **map, const char *name,
                        const struct bf_set *set);

/**
 * @brief Allocate and initialize a new map from serialized data.
 *
 * @note The new bf_map object will represent a BPF map from bpfilter's point
 * of view, but it's not a BPF map.
 *
 * @param map Map object to allocate and initialize from the serialized data.
 *        The caller will own the object. On failure, `*map` is unchanged.
 *        Can't be NULL.
 * @param dir_fd File descriptor of the directory containing the map's pin.
 *        Must be a valid file descriptor, or -1 is the pin should not be opened.
 * @param node Node containing the serialized map. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_new_from_pack(struct bf_map **map, int dir_fd, bf_rpack_node_t node);

/**
 * Free a BPF map object.
 *
 * The BPF map's file descriptor contained in @c map is closed and set to
 * @c -1 . To prevent the BPF map from being destroyed, pin it beforehand.
 *
 * @param map @ref bf_map object to free. On success, @c *map is set to
 *            NULL. On failure, @c *map remain unchanged.
 */
void bf_map_free(struct bf_map **map);

/**
 * @brief Serialize a map.
 *
 * @param map Map to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the map into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_map_pack(const struct bf_map *map, bf_wpack_t *pack);

/**
 * Dump a BPF map object.
 *
 * @param map BPF map object to dump. Can't be NULL.
 * @param prefix String to prefix each log with. If no prefix is needed, use
 *               @ref EMPTY_PREFIX . Can't be NULL.
 */
void bf_map_dump(const struct bf_map *map, prefix_t *prefix);

/**
 * Create the BPF map.
 *
 * @param map BPF map to create. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_create(struct bf_map *map);

/**
 * Destroy the BPF map.
 *
 * While this function will effectively close the file descriptor used to
 * reference the BPF map, it might survive if a BPF program uses it, or if
 * it is pinned to the filesystem.
 *
 * @param map BPF map to destroy. Can't be NULL.
 */
void bf_map_destroy(struct bf_map *map);

/**
 * Pin the map to the system.
 *
 * @param map Map to pin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to pin the map into. Must be
 *        a valid file descriptor.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_pin(const struct bf_map *map, int dir_fd);

/**
 * Unpin the map from the system.
 *
 * @param map Map to unpin. Can't be NULL.
 * @param dir_fd File descriptor of the directory to unpin the map from. Must be
 *        a valid file descriptor.
 */
void bf_map_unpin(const struct bf_map *map, int dir_fd);

/**
 * Set the size of the map's keys.
 *
 * This function can be used to change the size of the map's keys, up
 * until @ref bf_map_create is called. Once the map has been created, the size
 * of the keys can't be changed.
 *
 * @param map The map to modify Can't be NULL.
 * @param key_size Size of the keys. Can't be 0.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_set_key_size(struct bf_map *map, size_t key_size);

/**
 * Set the size of the map's values.
 *
 * This function can be used to change the size of the map's values, up
 * until @ref bf_map_create is called. Once the map has been created, the size
 * of the values can't be changed.
 *
 * @param map The map to modify Can't be NULL.
 * @param value_size Size of the values. Can't be 0.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_set_value_size(struct bf_map *map, size_t value_size);

/**
 * Set the number of elements in the map.
 *
 * This function can be used to change the number of element of a map, up
 * until @ref bf_map_create is called. Once the map has been created, the
 * number of elements can't be changed.
 *
 * @param map The map to set the number of elements for. Can't be NULL.
 * @param n_elems Number of elements in the map. Can't be 0.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_set_n_elems(struct bf_map *map, size_t n_elems);

/**
 * Insert or update an element to the map.
 *
 * If an element already exist in the map for key @c key it is replaced, other
 * it is inserted.
 *
 * @param map BPF map to update. Can't be NULL.
 * @param key Pointer to the element key. The key size has been defined with
 *            @ref bf_map_new . Can't be NULL.
 * @param value Pointer to the value. The value size has been defined with
 *              @ref bf_map_new . Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_set_elem(const struct bf_map *map, void *key, void *value);
