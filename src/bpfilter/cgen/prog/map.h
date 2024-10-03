/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include "core/dump.h"

enum bf_map_bpf_type
{
    BF_MAP_BPF_TYPE_ARRAY,
    BF_MAP_BPF_TYPE_HASH,
    _BF_MAP_BPF_TYPE_MAX,
};

enum bf_map_type
{
    BF_MAP_TYPE_COUNTERS,
    BF_MAP_TYPE_PRINTER,
    BF_MAP_TYPE_SET,
    _BF_MAP_TYPE_MAX,
};

#define BF_PIN_PATH_LEN 64

#define BF_MAP_N_ELEMS_UNKNOWN SIZE_MAX

struct bf_map
{
    enum bf_map_type type;
    int fd;
    char name[BPF_OBJ_NAME_LEN];
    char path[BF_PIN_PATH_LEN];
    enum bf_map_bpf_type bpf_type;
    size_t key_size;
    size_t value_size;
    size_t n_elems;
};

struct bf_marsh;

#define _cleanup_bf_map_ __attribute__((__cleanup__(bf_map_free)))

/**
 * Convenience macro to initialize a list of @ref bf_map .
 *
 * @return An initialized @ref bf_list that can contain @ref bf_map object,
 *         with its @ref bf_list_ops properly configured.
 */
#define bf_map_list()                                                          \
    ((bf_list) {.ops = {.free = (bf_list_ops_free)bf_map_free,                 \
                        .marsh = (bf_list_ops_marsh)bf_map_marsh}})

/**
 * Allocates and initializes a new BPF map object.
 *
 * @note This function won't create a new BPF map, but a bpfilter-specific
 * object used to keep track of a BPF map on the system.
 *
 * @param map BPF map object to allocate and initialize. Can't be NULL. On
 *            success, @c *map points to a valid @ref bf_map . On failure,
 *            @c *map remain unchanged.
 * @param type Map type, defines the set of available operations.
 * @param name_suffix Suffix to use for the map name. Usually specify the
 *                    hook, front-end, or program type the map is used for.
 *                    Can't be NULL.
 * @param bpf_type Map type. Not all BPF maps are supported, see
 *        @ref bf_map_bpf_type for the full list of supported types.
 * @param key_size Size (in bytes) of a key in the map. Can't be 0.
 * @param value_size Size (in bytes) of an element of the map. Can't be 0.
 * @param n_elems Number of elemets to reserve room for in the map. Can't be 0.
 *        If you don't yet know the number of elements in the map, use
 *        @ref BF_MAP_N_ELEMS_UNKNOWN , but @ref bf_map_create can't be called
 *        until you set an actual size with @ref bf_map_set_n_elems .
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_new(struct bf_map **map, enum bf_map_type type,
               const char *name_suffix, enum bf_map_bpf_type bpf_type,
               size_t key_size, size_t value_size, size_t n_elems);

/**
 * Create a new BPF map object from serialized data.
 *
 * @note The new BPF map object will represent a BPF map from bpfilter's point
 * of view, but it's not a BPF map.
 *
 * @param map BPF map object to allocate and initialize from the serialized
 *            data. The caller will own the object. On success, @c *map points
 *            to a valid BPF object map. On failure, @c *map is unchanged.
 *            Can't be NULL.
 * @param marsh Serialized BPF map object data. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_new_from_marsh(struct bf_map **map, const struct bf_marsh *marsh);

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
 * Serializes a BPF map object.
 *
 * @param map BPF map object to serialize. The object itself won't be modified.
 *            Can't be NULL.
 * @param marsh Marsh object, will be allocated by this function and owned by
 *              the caller. On success, @c *marsh will point to the BPF map's
 *              serialized data. On failure, @c *marsh is left unchanged. Can't
 *              be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_marsh(const struct bf_map *map, struct bf_marsh **marsh);

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
 * @param flags Flags to use during map creation. All the flags supported by
 *              @c BPF_MAP_CREATE can be used.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_create(struct bf_map *map, uint32_t flags);

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
 * Pin the map to the filesystem.
 *
 * @return 0 on success, or a negative errno value on error.
 */
int bf_map_pin(const struct bf_map *map);

/**
 * Unpin the map from the filesystem.
 */
void bf_map_unpin(const struct bf_map *map);

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

/**
 * Convert a @ref bf_map_bpf_type to a string.
 *
 * @param bpf_type Map type to convert to string. Must be a valid
 *        @ref bf_map_bpf_type (except for @ref _BF_MAP_BPF_TYPE_MAX ).
 * @return The map type, as a string.
 */
const char *bf_map_bpf_type_to_str(enum bf_map_bpf_type bpf_type);

/**
 * Convert a string into a @ref bf_map_bpf_type value.
 *
 * If the string is an invalid @ref bf_map_bpf_type string representation,
 * an error is returned.
 *
 * @param str String to convert to a @ref bf_map_bpf_type value. Can't be NULL.
 * @param bpf_type On success, contains the map type value. Unchanged on failure.
 *        Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_map_bpf_type_from_str(const char *str, enum bf_map_bpf_type *bpf_type);
