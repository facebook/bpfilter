// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

/**
 * @brief Load a BPF program.
 *
 * @param name Name of the BPF program. Can't be NULL.
 * @param prog_type BPF program type.
 * @param img BPF program itself. Can't be NULL.
 * @param img_len Size of the BPF program, as a number of instructions.
 * @param log Log buffer. If the call fails, this buffer will contain more
 * context about the error.
 * @param log_len Length of @p log.
 * @param fd If the call succeed, this parameter will contain the loaded
 * program's file descriptor.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_prog_load(const char *name, unsigned int prog_type, void *img,
                     size_t img_len, char *log, size_t log_len, int *fd);

/**
 * @brief Create a BPF map.
 *
 * @param name Name of the map. Can't be NULL.
 * @param type Map type.
 * @param key_size Size of a key.
 * @param value_size Size of a value.
 * @param max_entries Number of entries in the map.
 * @param fd If the call succeed, this parameter will contain the map's
 * file descriptor.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_create(const char *name, unsigned int type, size_t key_size,
                      size_t value_size, size_t max_entries, int *fd);

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
