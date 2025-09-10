/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/logger.h"

/**
 * @file pack.h
 *
 * Serialization is used to send/receive bpfilter objects to and from the
 * daemon. While bpfilter originally used a custom logic to convert its objects
 * into binary data, it was inefficient and didn't support different versions of
 * the same object (when fields are added or removed). Instead, the new packing
 * logic provides an API to (de)serialize bpfilter objects using
 * [MessagePack](https://msgpack.org).
 *
 * The packing mechanism doesn't implement the MessagePack protocol directly,
 * but relies on the [MPack](https://ludocode.github.io/mpack/) implementation
 * instead. MPack provides the following advantages:
 * - Fast (de)serialization: 4x faster than the previous custom serialization
 *   logic, and 10x faster than Jansson.
 * - Named fields: each serialized field of an object is named, allowing the
 *   objects to evolve and introduce or remove new fields while maintaining
 *   backward compatibility.
 * - Can be used in place: existing objects format can be used as-is, without
 *   extra field dedicated to the serializer or schema file (hello Protobuf
 *   and Thrift).
 *
 * Two different packing objects are provided:
 * - `bf_wpack_t`: the writer object, to serialize data. To keep the
 *   the serialization as simple as possible, no error will be returned when
 *   a field is serialized. Instead, users must use `bf_wpack_is_valid` to
 *   validate the serialized data before it is exported. This behaviour is
 *   different for the rest of the core module, but is justified for usability
 *   reasons.
 * - `bf_rpack_t`: node-based API to read serialized data. Each serialized field
 *   can be represented as a node. The object deserialization functions should
 *   expect to receive a node which represents them.
 *
 * ## Serializing
 * `bf_wpack_t` always have a root node containing key-value pairs. Keys should
 * be strings, and values can be any primal type, array, or another object.
 * `bf_wpack_kv_TYPE` functions should be used to write both the key and the
 * value in an object, `bf_wpack_TYPE` functions should be used to write single
 * objects (without a key) into arrays.
 * To nest objects and arrays, use `bf_wpack_open_object` and
 * `bf_wpack_open_array`, they both allow the caller to provide a key: if the
 * object (or array) is inserted into an object you should provide a key, if the
 * object (or array) is inserted into an array you should not provide a key. In
 * any case, call `bf_wpack_close_object` or `bf_wpack_close_array` to complete
 * the nested object/array.
 * Before using the serialized data, ensure it is valid with `bf_wpack_is_valid`,
 * as not error will be returned during the pack creation.
 *
 * ## Deserializing
 * `bf_rpack_t` is the deserialization object, although we do not read directly
 * from it. Instead, one should get the root object with `bf_rpack_root`, then
 * query keys from it.
 * All the functions used to deserialize data from the pack are available in two
 * formats:
 * - `bf_rpack_TYPE`: read a typed value from a node.
 * - `bf_rpack_kv_TYPE`: read the value identified by a key in an object node.
 * To prevent any tempering or corruption, every function able to read data from
 * a node will return a value: 0 on success, or a negative integer on failure.
 *
 * @note To ensure compatibility of the binary data over time, the following
 * constraints must be followed:
 * - Every enumeration value is serialized as integer: it should support every
 *   possible enumeration value used by bpfilter, including negative values.
 * - `size_t` values are serialied as `uint64_t`: for similar reasons to he
 *   enumerations.
 *
 * @todo Only allow `bf_wpack_kv_TYPE` functions to write into objects.
 * @todo Only allow `bf_wpack_TYPE` functions to write into arrays.
 */

struct bf_wpack;
typedef struct bf_wpack bf_wpack_t;

struct bf_list;
typedef struct bf_list bf_list;

/// @brief Cleanup attribute for dynamically allocated `bf_wpack_t` objects.
#define _free_bf_wpack_ __attribute__((cleanup(bf_wpack_free)))

/**
 * @brief Allocate and initialize a new `bf_wpack_t` object.
 *
 * @param pack `bf_wpack_t` object to allocate an initialize. Can't be NULL.
 * @return 0 on sucess, or a negative error value on failure.
 */
int bf_wpack_new(bf_wpack_t **pack);

/**
 * @brief Deinitialize and deallocate a `bf_wpack_t` object.
 *
 * @param pack `bf_wpack_t` object to deallocate and deinitialize. Can't be
 *        NULL. If `*pack` is NULL, this function has no effect.
 */
void bf_wpack_free(bf_wpack_t **pack);

/**
 * @brief Check if the serialized data is valid.
 *
 * @param pack `bf_wpack_t` object to check. Can't be NULL.
 * @return True if the serialized data is valid, false otherwise.
 */
bool bf_wpack_is_valid(bf_wpack_t *pack);

/**
 * @brief Get the serialized data.
 *
 * Ensure the buffer is flushed and all the remaining data has been serialized.
 * On success, `*data` points to a buffer containing `data_len` bytes. The
 * caller do not own the data.
 *
 * @return 0 on success, or a negative error value on failure.
 */
int bf_wpack_get_data(bf_wpack_t *pack, const void **data, size_t *data_len);

void bf_wpack_nil(bf_wpack_t *pack);
void bf_wpack_int(bf_wpack_t *pack, int value);
void bf_wpack_uint(bf_wpack_t *pack, unsigned int value);
void bf_wpack_u8(bf_wpack_t *pack, uint8_t value);
void bf_wpack_u16(bf_wpack_t *pack, uint16_t value);
void bf_wpack_u32(bf_wpack_t *pack, uint32_t value);
void bf_wpack_u64(bf_wpack_t *pack, uint64_t value);
void bf_wpack_bool(bf_wpack_t *pack, bool value);
void bf_wpack_str(bf_wpack_t *pack, const char *value);
void bf_wpack_bin(bf_wpack_t *pack, const void *value, size_t len);
void bf_wpack_list(bf_wpack_t *pack, const bf_list *value);
#define bf_wpack_enum(pack, value) bf_wpack_int((pack), (value))

static inline void bf_wpack_kv_nil(bf_wpack_t *pack, const char *key)
{
    bf_wpack_str(pack, key);
    bf_wpack_nil(pack);
}

static inline void bf_wpack_kv_int(bf_wpack_t *pack, const char *key, int value)
{
    bf_wpack_str(pack, key);
    bf_wpack_int(pack, value);
}

static inline void bf_wpack_kv_uint(bf_wpack_t *pack, const char *key,
                                    unsigned int value)
{
    bf_wpack_str(pack, key);
    bf_wpack_uint(pack, value);
}

static inline void bf_wpack_kv_u8(bf_wpack_t *pack, const char *key,
                                  uint8_t value)
{
    bf_wpack_str(pack, key);
    bf_wpack_u8(pack, value);
}

static inline void bf_wpack_kv_u16(bf_wpack_t *pack, const char *key,
                                   uint16_t value)
{
    bf_wpack_str(pack, key);
    bf_wpack_u16(pack, value);
}

static inline void bf_wpack_kv_u32(bf_wpack_t *pack, const char *key,
                                   uint32_t value)
{
    bf_wpack_str(pack, key);
    bf_wpack_u32(pack, value);
}

static inline void bf_wpack_kv_u64(bf_wpack_t *pack, const char *key,
                                   uint64_t value)
{
    bf_wpack_str(pack, key);
    bf_wpack_u64(pack, value);
}

static inline void bf_wpack_kv_bool(bf_wpack_t *pack, const char *key,
                                    bool value)
{
    bf_wpack_str(pack, key);
    bf_wpack_bool(pack, value);
}

static inline void bf_wpack_kv_str(bf_wpack_t *pack, const char *key,
                                   const char *str)
{
    bf_wpack_str(pack, key);
    bf_wpack_str(pack, str);
}

static inline void bf_wpack_kv_bin(bf_wpack_t *pack, const char *key,
                                   const void *data, size_t data_len)
{
    bf_wpack_str(pack, key);
    bf_wpack_bin(pack, data, data_len);
}

static inline void bf_wpack_kv_enum(bf_wpack_t *pack, const char *key,
                                    int value)
{
    bf_wpack_str(pack, key);
    bf_wpack_enum(pack, value);
}

void bf_wpack_kv_list(bf_wpack_t *pack, const char *key, const bf_list *value);

/**
 * @brief Open a new object in the pack.
 *
 * Once this function returns, any call to `bf_wpack_TYPE` or `bf_wpack_kv_TYPE`
 * will insert data into the object.
 *
 * @param pack `bf_wpack_t` object to open the object in. Can't be NULL.
 * @param key Key to use for the object. If NULL, no key is inserted.
 */
void bf_wpack_open_object(bf_wpack_t *pack, const char *key);

/**
 * @brief Close the current object.
 *
 * Once the object is closed, any call to `bf_wpack_TYPE` or `bf_wpack_kv_TYPE`
 * will insert data into the parent object or array.
 *
 * @param pack `bf_wpack_t` object to close the object in. Can't be NULL.
 */
void bf_wpack_close_object(bf_wpack_t *pack);

/**
 * @brief Open a new array in the pack.
 *
 * Once this function returns, any call to `bf_wpack_TYPE` or `bf_wpack_kv_TYPE`
 * will insert data into the array.
 *
 * @param pack `bf_wpack_t` object to open the array in. Can't be NULL.
 * @param key Key to use for the array. If NULL, no key is inserted.
 */
void bf_wpack_open_array(bf_wpack_t *pack, const char *key);

/**
 * @brief Close the current array.
 *
 * Once the array is closed, any call to `bf_wpack_TYPE` or `bf_wpack_kv_TYPE`
 * will insert data into the parent object or array.
 *
 * @param pack `bf_wpack_t` object to close the array in. Can't be NULL.
 */
void bf_wpack_close_array(bf_wpack_t *pack);

struct bf_rpack;
typedef struct bf_rpack bf_rpack_t;

/**
 * @brief Opaque structure to pass nodes by value.
 */
typedef union
{
    char _opaque[16];
    void *_align;
} bf_rpack_node_t;

/// @brief Cleanup attribute for dynamically allocated `bf_rpack_t` objects.
#define _free_bf_rpack_ __attribute__((cleanup(bf_rpack_free)))

/**
 * @brief Loop over all the nodes in an array node.
 *
 * The counter `i` is accessible within the scope.
 *
 * @warning This loop must ensure we don't query the node for invalid data:
 * we should not request a node from the array if it's empty, of if the index
 * is out of the array. Otherwise, it would put the `bf_rpack_t` object in
 * failure mode.
 *
 * @param node Array node. If the node is not an array, the loop will be
 *        ignored.
 * @param value_node A node in the array, updated on each iteration.
 */
#define bf_rpack_array_foreach(node, value_node)                               \
    for (size_t i = ((bf_rpack_array_count(node) ?                             \
                          ((value_node) = bf_rpack_array_value_at(node, 0)) :  \
                          (bf_rpack_node_t) {}),                               \
                     0);                                                       \
         i < bf_rpack_array_count(node);                                       \
         ++i, (value_node) = (i < bf_rpack_array_count(node) ?                 \
                                  bf_rpack_array_value_at(node, i) :           \
                                  (bf_rpack_node_t) {}))

/**
 * @brief Read an named enumerator value from a node.
 *
 * This macro will ensure the enumerator value is properly casted from the
 * corresponding integer stored in the pack.
 *
 * @param node Node to read from.
 * @param key Key of the node to read. Can't be NULL.
 * @param value Pointer to the enumerator value to read into.
 * @return 0 on success, or a negative error value on failure.
 */
#define bf_rpack_kv_enum(node, key, value)                                     \
    ({                                                                         \
        int __value;                                                           \
        int __r = bf_rpack_kv_int(node, key, &__value);                        \
        if (!__r)                                                              \
            *(value) = __value;                                                \
        __r;                                                                   \
    })

/**
 * @brief Read an enumerator value from a node.
 *
 * Similar to `bf_rpack_kv_enum` but reads a node directly.
 *
 * @param node Node to read from.
 * @param value Pointer to the enumerator value to read into.
 * @return 0 on success, or a negative error value on failure.
 */
#define bf_rpack_enum(node, value)                                             \
    ({                                                                         \
        int __value;                                                           \
        int __r = bf_rpack_int(node, &__value);                                \
        if (!__r)                                                              \
            *(value) = __value;                                                \
        __r;                                                                   \
    })

/**
 * @brief Log a missing key error and return a negative error value.
 *
 * @param v The error value to return.
 * @param key The missing key, as a string.
 */
#define bf_rpack_key_err(v, key) bf_err_r(v, "failed to read %s from pack", key)

/**
 * @brief Allocate and initialize a new `bf_rpack_t` object.
 *
 * @param pack `bf_rpack_t` object to allocate and initialize. Can't be NULL.
 * @param data Serialized data. To prevent large copies, the deserialization
 *        object won't take ownership of the data. Can't be NULL.
 * @param data_len Length of `data`.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_rpack_new(bf_rpack_t **pack, const void *data, size_t data_len);

/**
 * @brief Deinitialize and deallocate a `bf_rpack_t` object.
 *
 * @param pack `bf_rpack_t` object to deallocate and deinitialize. Can't be
 *        NULL. If `*pack` is NULL, this function has no effect.
 */
void bf_rpack_free(bf_rpack_t **pack);

/**
 * @brief Get the root node of `pack`.
 *
 * @param pack `bf_rpack_t` object to get the root node from. Can't be NULL.
 * @return Root node for `pack`.
 */
bf_rpack_node_t bf_rpack_root(const bf_rpack_t *pack);

/**
 * @brief Returns true if the node is nil, false otherwise.
 *
 * Nil nodes are used to specific an absent value (e.g. optional `bf_hookopts`).
 *
 * @param node Node to check for nil.
 * @return True if `node` is nil, false otherwise.
 */
bool bf_rpack_is_nil(bf_rpack_node_t node);

/**
 * @brief Returns true if the node is an array, false otherwise.
 *
 * @param node Node to check for array type.
 * @return True if `node` is an array, false otherwise.
 */
bool bf_rpack_is_array(bf_rpack_node_t node);

/**
 * @brief Returns the number of elements in an array node.
 *
 * To ensure the returned value is relevant, the caller should ensure `node` is
 * an array.
 *
 * @param node Array node to get the number of elements of.
 * @return The number of elements in `node`, or 0 if `node` is not an array.
 */
size_t bf_rpack_array_count(bf_rpack_node_t node);

/**
 * @brief Get an array element by index.
 *
 * The caller is responsible for ensuring `node` is an array and `index` is a
 * valid index in `node`, otherwise the returned node will be invalid.
 *
 * @param node Array node to get elements from.
 * @param index Index of the node to get.
 * @return The node of the element as `index` in `node`. */
bf_rpack_node_t bf_rpack_array_value_at(bf_rpack_node_t node, size_t index);

/**
 * @brief Check if an object node contains a given key.
 *
 * The caller is responsible for ensuring `node` is a valid object node. If
 * `node` is invalid or the wrong type, false is returned.
 *
 * @param node Object node to check.
 * @param key Key to check in `node`. Can't be NULL.
 * @return True if `key` is a valid key in `node`, false otherwise. On error,
 *         false is returned.
 */
bool bf_rpack_kv_contains(bf_rpack_node_t node, const char *key);

int bf_rpack_int(bf_rpack_node_t node, int *value);
int bf_rpack_uint(bf_rpack_node_t node, unsigned int *value);
int bf_rpack_u8(bf_rpack_node_t node, uint8_t *value);
int bf_rpack_u16(bf_rpack_node_t node, uint16_t *value);
int bf_rpack_u32(bf_rpack_node_t node, uint32_t *value);
int bf_rpack_u64(bf_rpack_node_t node, uint64_t *value);
int bf_rpack_str(bf_rpack_node_t node, char **value);
int bf_rpack_bool(bf_rpack_node_t node, bool *value);
int bf_rpack_bin(bf_rpack_node_t node, const void **data, size_t *data_len);

int bf_rpack_kv_node(bf_rpack_node_t node, const char *key,
                     bf_rpack_node_t *child);
int bf_rpack_kv_int(bf_rpack_node_t node, const char *key, int *value);
int bf_rpack_kv_uint(bf_rpack_node_t node, const char *key,
                     unsigned int *value);
int bf_rpack_kv_u8(bf_rpack_node_t node, const char *key, uint8_t *value);
int bf_rpack_kv_u16(bf_rpack_node_t node, const char *key, uint16_t *value);
int bf_rpack_kv_u32(bf_rpack_node_t node, const char *key, uint32_t *value);
int bf_rpack_kv_u64(bf_rpack_node_t node, const char *key, uint64_t *value);
int bf_rpack_kv_str(bf_rpack_node_t node, const char *key, char **value);
int bf_rpack_kv_bool(bf_rpack_node_t node, const char *key, bool *value);
int bf_rpack_kv_bin(bf_rpack_node_t node, const char *key, const void **data,
                    size_t *data_len);
int bf_rpack_kv_obj(bf_rpack_node_t node, const char *key,
                    bf_rpack_node_t *child);
int bf_rpack_kv_array(bf_rpack_node_t node, const char *key,
                      bf_rpack_node_t *child);
