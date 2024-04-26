// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/if_link.h>

#include <stddef.h>
#include <stdint.h>

#include "core/hook.h"

enum bf_xdp_attach_mode
{
    BF_XDP_MODE_SKB = XDP_FLAGS_SKB_MODE,
    BF_XDP_MODE_DRV = XDP_FLAGS_DRV_MODE,
    BF_XDP_MODE_HW = XDP_FLAGS_HW_MODE,
};

/**
 * @brief Load a BPF program.
 *
 * @param name Name of the BPF program. Can't be NULL.
 * @param prog_type BPF program type.
 * @param img BPF program itself. Can't be NULL.
 * @param img_len Size of the BPF program, as a number of instructions.
 * @param expected_attach_type Expected attach type of the BPF program. Use
 *  @ref bf_hook_to_attach_type to get the proper attach type. 0 is a valid
 *  value.
 * @param fd If the call succeed, this parameter will contain the loaded
 * program's file descriptor.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_prog_load(const char *name, unsigned int prog_type, void *img,
                     size_t img_len, enum bpf_attach_type attach_type, int *fd);

/**
 * @brief Create a BPF map.
 *
 * @param name Name of the map. Can't be NULL.
 * @param type Map type.
 * @param key_size Size of a key.
 * @param value_size Size of a value.
 * @param max_entries Number of entries in the map.
 * @param flags Map creation flags.
 * @param fd If the call succeed, this parameter will contain the map's
 * file descriptor.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_create(const char *name, unsigned int type, size_t key_size,
                      size_t value_size, size_t max_entries, uint32_t flags,
                      int *fd);

/**
 * @brief Freeze a BPF map.
 *
 * A frozen map can't be modified from userspace.
 *
 * @param fd File descriptor of the map.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_freeze(int fd);

/**
 * @brief Get an element from a map.
 *
 * @param fd File descriptor of the map to search in.
 * @param key Key to get the value for. Can't be NULL.
 * @param value Pointer to the value.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_lookup_elem(int fd, const void *key, void *value);

/**
 * @brief Update (or insert) an element in a map.
 *
 * @param fd File descriptor of the map to search in.
 * @param key Key to get the value for. Can't be NULL.
 * @param value Pointer to the value.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_update_elem(int fd, const void *key, void *value);

/**
 * @brief Pin a BPF object to a given path.
 *
 * @param path Path to pin the object to. Can't be NULL.
 * @param fd File descriptor of the map.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_obj_pin(const char *path, int fd);

/**
 * @brief Get a BPF object, from a path.
 *
 * @param path Path of the BPF object to get. Can't be NULL.
 * @param fd On success, contains a file descriptor to the BPF object.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_obj_get(const char *path, int *fd);

/**
 * @brief Create a Netfilter BPF link.
 *
 * @param prog_fd File descriptor of the program to attach to the link.
 * @param hook Netfilter hook to attach the program to.
 * @param priority Priority of the program on the hook.
 * @param link_fd Link file descriptor, only valid if the return value of the
 *  function is 0.
 * @return 0 on success or negative errno value on failure.
 */
int bf_bpf_nf_link_create(int prog_fd, enum bf_hook hook, int priority,
                          int *link_fd);

/**
 * @brief Create a XDP BPF link.
 *
 * @param prog_fd File descriptor of the program to attach to the link.
 * @param ifindex Interface index to attach the program to.
 * @param link_fd Link file descriptor, only valid if the return value of the
 *  function is 0.
 * @param mode XDP program attach mode. See @ref bf_xdp_attach_mode.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_xdp_link_create(int prog_fd, int ifindex, int *link_fd,
                           enum bf_xdp_attach_mode mode);

/**
 * @brief Detach a BPF link using its file descriptor.
 * @param link_fd File descriptor of the link to detach. You can get a file
 *  descriptor using @ref bf_bpf_obj_get.
 * @return 0 on success or negative errno value on failure.
 */
int bf_bpf_link_detach(int link_fd);
