// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/dump.h"
#include "core/list.h"

/**
 * @file set.h
 *
 * A set represent a set of data of the same type. They allow bpfilter to
 * perform O(1) lookup in large pools of data of the same type.
 *
 * For example, a set would be useful to match a network packet against many
 * different IP addresses. Instead of create a different rule for each IP
 * address, they could be added into a set and the BPF program would comparing
 * the packet's IP address to the whole set a once.
 *
 * Sets are implemented as BPF hash maps, allowing for O(1) lookup for a given
 * key. @ref bf_set_type is used to define the set type and represent the type
 * of values contained in the set.
 *
 * From a BPF bytecode perspective, the set type affects how the packet's
 * data is processed to form the key to lookup into the BPF map. See @ref
 * bf_set_type for more details.
 */

struct bf_marsh;

#define _free_bf_set_ __attribute__((__cleanup__(bf_set_free)))

/**
 * Convenience macro to initialize a list of @ref bf_set .
 *
 * @return An initialized @ref bf_list that can contain @ref bf_set objects.
 */
#define bf_set_list()                                                          \
    ((bf_list) {.ops = {.free = (bf_list_ops_free)bf_set_free,                 \
                        .marsh = (bf_list_ops_marsh)bf_set_marsh}})

/**
 * Supported set types.
 *
 * The set's type define the size of the elements in the set, as well as how
 * the packet should be processed to generate the key to lookup for in the map.
 */
enum bf_set_type
{
    /// Keys are IPv4 addresses (4 bytes).
    BF_SET_IP4,
    /// Keys are (source IPv6 address, source port) (18 bytes).
    BF_SET_SRCIP6PORT,
    /// Keys are IPv6 addresses (16 bytes).
    BF_SET_SRCIP6,
    _BF_SET_MAX,
};

struct bf_set
{
    enum bf_set_type type;
    size_t elem_size;
    bf_list elems;
};

int bf_set_new(struct bf_set **set, enum bf_set_type type);
int bf_set_new_from_marsh(struct bf_set **set, const struct bf_marsh *marsh);
void bf_set_free(struct bf_set **set);
int bf_set_marsh(const struct bf_set *set, struct bf_marsh **marsh);
void bf_set_dump(const struct bf_set *set, prefix_t *prefix);

int bf_set_add_elem(struct bf_set *set, void *elem);

const char *bf_set_type_to_str(enum bf_set_type type);
int bf_set_type_from_str(const char *str, enum bf_set_type *type);
