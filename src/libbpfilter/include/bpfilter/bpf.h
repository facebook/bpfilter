// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/bpf_types.h>
#include <bpfilter/hook.h>

#define bf_ptr_to_u64(ptr) ((unsigned long long)(ptr))

struct bf_btf;
union bpf_attr;

int bf_bpf(enum bf_bpf_cmd cmd, union bpf_attr *attr);

/**
 * Load a BPF program.
 *
 * @param name Name of the BPF program. Can't be NULL.
 * @param prog_type BPF program type.
 * @param img BPF program itself. Can't be NULL.
 * @param img_len Size of the BPF program, as a number of instructions.
 * @param attach_type Expected attach type of the BPF program. Use
 *        `bf_hook_to_bpf_attach_type` to get the proper attach type. 0 is a
 *        valid value.
 * @param log_buf Buffer to write the loading logs to. If NULL, logs are not
 *        collected.
 * @param log_size Size of `log_buf`. If `log_buf` is NULL, `log_size` must be 0.
 * @param token_fd File descriptor of the BPF token to use. If `token_fd` is -1,
 *        no token will be used.
 * @param fd If the call succeed, this parameter will contain the loaded
 *        program's file descriptor.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_prog_load(const char *name, enum bf_bpf_prog_type prog_type,
                     void *img, size_t img_len,
                     enum bf_bpf_attach_type attach_type, const char *log_buf,
                     size_t log_size, int token_fd, int *fd);

/**
 * Get an element from a map.
 *
 * @param fd File descriptor of the map to search in.
 * @param key Key to get the value for. Can't be NULL.
 * @param value Pointer to the value.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_lookup_elem(int fd, const void *key, void *value);

/**
 * Pin a BPF object to the system.
 *
 * If @p path is relative, then it is interpreted relative to the directory
 * referred to by the file descriptor @p dir_fd . If @p path is absolute, then
 * @p dir_fd must be 0.
 *
 * @param path Path to pin the object to. Can't be NULL.
 * @param fd File descriptor of the BPF object. Must be valid.
 * @param dir_fd File descriptor of the parent directory. Must be a valid file
 *        file descriptor or 0.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_bpf_obj_pin(const char *path, int fd, int dir_fd);

/**
 * Get a file descriptor to a BPF object from a path.
 *
 * If @p path is relative, then it is interpreted relative to the directory
 * referred to by the file descriptor @p dir_fd . If @p path is absolute, then
 * @p dir_fd must be 0.
 *
 * @param path Path to the pinned BPF object. Can't be NULL.
 * @param dir_fd File descriptor of the parent directory. Must be a valid file
 *        descriptor or 0.
 * @param fd On success, contains a valid file descriptor to the BPF object
 *        pinned at @p path . Unchanged on failure. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_bpf_obj_get(const char *path, int dir_fd, int *fd);

/**
 * Call `BPF_PROG_TEST_RUN` on @p prog_fd .
 *
 * @param prog_fd File descriptor of the program to test. Must be valid.
 * @param pkt Test packet to send to the BPF program. Can't be NULL.
 * @param pkt_len Size (in bytes) of the test packet. Can't be 0.
 * @param ctx Context to run the program from. If NULL, @p ctx_len must be 0.
 * @param ctx_len Size of the progra's context. If 0, @p ctx must be NULL.
 * @return The return value of the BPF program, or a negative errno value on
 *         failure.
 */
int bf_bpf_prog_run(int prog_fd, const void *pkt, size_t pkt_len,
                    const void *ctx, size_t ctx_len);

/**
 * @brief Create a new BPF token.
 *
 * @param bpffs_fd File descriptor of the BPF filesystem to create the token
 *        for.
 * @return A valid token file descriptor on success (owned by the caller),
 *         or a negative error value on failure.
 */
int bf_bpf_token_create(int bpffs_fd);

/**
 * @brief Load BTF data into the kernel.
 *
 * @param btf_data Raw BTF data to send to the kernel. Can't be NULL.
 * @param btf_data_len Length of `btf_data`.
 * @param token_fd File descriptor of the BPF token to use, or -1 if no token
 *        should be used.
 * @return A valid BTF file descriptor on success (owned by the caller),
 *         or a negative error value on failure.
 */
int bf_bpf_btf_load(const void *btf_data, size_t btf_data_len, int token_fd);

/**
 * @brief Create a new BPF map.
 *
 * @param name Name of the map. Can't be NULL.
 * @param type BPF map type, see `bf_map_type`.
 * @param key_size Size of the key, in bytes.
 * @param value_size Size of the map's values, in bytes.
 * @param n_elems Number of elements in the map.
 * @param btf BTF data, ignored if `NULL`.
 * @param token_fd BPF token to use to create the map. Ignored if -1.
 * @return A valid BPF map file descriptor on success (owned by the caller),
 *         or a negative error value on failure.
 */
int bf_bpf_map_create(const char *name, enum bf_bpf_map_type type,
                      size_t key_size, size_t value_size, size_t n_elems,
                      const struct bf_btf *btf, int token_fd);

/**
 * @brief Create or update a BPF map element.
 *
 * @param map_fd File descriptor of the map to update.
 * @param key Key of the element to create or update. Can't be NULL.
 * @param value Value to set for the element. Can't be NULL.
 * @param flags Flags to pass to the system call. 0 if no flag.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_bpf_map_update_elem(int map_fd, const void *key, const void *value,
                           int flags);

/**
 * @brief Create or update multiple elements in a BPF map at once.
 *
 * @param map_fd File descriptor of the map to update.
 * @param keys Array of keys to insert or update in the map. Can't be NULL.
 * @param values Array of values to insert or update in the map. Can't be NULL.
 * @param count Number of elements in `keys` and `values`.
 * @param flags Extra flags, passed directly to the system call. 0 if no flags.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_bpf_map_update_batch(int map_fd, const void *keys, const void *values,
                            size_t count, int flags);

/**
 * @brief Get information about a BPF object from its file descriptor.
 *
 * Uses `BPF_OBJ_GET_INFO_BY_FD` to query the kernel for information about
 * a BPF object (map, program, BTF, or link). The caller must provide the
 * appropriate info structure for the object type (e.g. `struct bpf_map_info`
 * for maps, `struct bpf_btf_info` for BTF).
 *
 * @param fd File descriptor of the BPF object to query. Must be valid.
 * @param info Pointer to the info structure to fill. Can't be NULL.
 * @param info_len Size of the info structure.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_bpf_obj_get_info(int fd, void *info, uint32_t info_len);

/**
 * @brief Get a file descriptor for a BPF map from its ID.
 *
 * @param id Map ID to look up.
 * @return A valid map file descriptor on success (owned by the caller),
 *         or a negative errno value on failure.
 */
int bf_bpf_map_get_fd_by_id(uint32_t id);

/**
 * @brief Get a file descriptor for a BTF object from its ID.
 *
 * @param id BTF ID to look up.
 * @return A valid BTF file descriptor on success (owned by the caller),
 *         or a negative errno value on failure.
 */
int bf_bpf_btf_get_fd_by_id(uint32_t id);

/**
 * @brief Create a new BPF link.
 *
 * @param prog_fd File descriptor of the program to attach to the link.
 * @param target_fd Link target. 0 if no target.
 * @param hook Hook to attach the link to.
 * @param flags Extra flags, passed directly to the system call. 0 if no flags.
 * @param family Protocol family, used for Netfilter hooks. Ignored otherwise.
 * @param priority Hook priority, used for Netfilter hooks. Ignored otherwise.
 * @return A valid BPF link file descriptor on success (owned by the caller),
 *         or a negative error value on failure.
 */
int bf_bpf_link_create(int prog_fd, int target_fd, enum bf_hook hook, int flags,
                       uint32_t family, int32_t priority);

/**
 * @brief Update the program attached to a BPF link.
 *
 * @param link_fd File descriptor of the link to update.
 * @param new_prog_fd File descriptor of the new program to attach to the link.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_bpf_link_update(int link_fd, int new_prog_fd);

/**
 * @brief Detach a BPF link.
 *
 * @param link_fd File descriptor of the link to detach.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_bpf_link_detach(int link_fd);
