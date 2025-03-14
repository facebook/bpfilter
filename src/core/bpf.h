// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <stddef.h>
#include <stdint.h>

enum bf_xdp_attach_mode
{
    BF_XDP_MODE_SKB = XDP_FLAGS_SKB_MODE,
    BF_XDP_MODE_DRV = XDP_FLAGS_DRV_MODE,
    BF_XDP_MODE_HW = XDP_FLAGS_HW_MODE,
};

#define bf_ptr_to_u64(ptr) ((unsigned long long)(ptr))

/**
 * BPF system call.
 *
 * @param cmd BPF command to run.
 * @param attr Attributes of the system call.
 * @return System call return value on success, or negative errno value on
 *         failure.
 */
int bf_bpf(enum bpf_cmd cmd, union bpf_attr *attr);

/**
 * Load a BPF program.
 *
 * @param name Name of the BPF program. Can't be NULL.
 * @param prog_type BPF program type.
 * @param img BPF program itself. Can't be NULL.
 * @param img_len Size of the BPF program, as a number of instructions.
 * @param attach_type Expected attach type of the BPF program. Use
 *        @ref bf_hook_to_attach_type to get the proper attach type. 0 is a
 *        valid value.
 * @param fd If the call succeed, this parameter will contain the loaded
 *        program's file descriptor.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_prog_load(const char *name, unsigned int prog_type, void *img,
                     size_t img_len, enum bpf_attach_type attach_type, int *fd);

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
 * Update (or insert) an element in a map.
 *
 * @param fd File descriptor of the map to search in.
 * @param key Key to get the value for. Can't be NULL.
 * @param value Pointer to the value.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_bpf_map_update_elem(int fd, const void *key, void *value);

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
int bf_prog_run(int prog_fd, const void *pkt, size_t pkt_len, const void *ctx,
                size_t ctx_len);
