// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

struct bf_btf
{
    struct btf *btf;
    int key_type_id;
    int value_type_id;
    int fd;
};

/**
 * Load current kernel's BTF data.
 *
 * This function has to be called early, so BPF program generation can access
 * kernel's BTF data and use the kfunc's BTF ID.
 *
 * @return 0 on success, or negative errno value on failure.
 */
int bf_btf_setup(void);

/**
 * Free current kernel's BTF data.
 */
void bf_btf_teardown(void);

/**
 * Get BTF ID of a kernel function.
 *
 * Linux' BTF data must be loaded with @ref bf_btf_setup before calling this
 * function.
 *
 * @param name Name of the kernel function.
 * @return BTF ID on success, or negative errno value on failure.
 */
int bf_btf_get_id(const char *name);

/**
 * Get a type name from a BTF ID from the kernel BTF data.
 *
 * Linux BTF data must be loaded with @ref bf_btf_setup before calling this
 * function. If @c id is invalid, or not part of the kernel's BTF data, @c NULL
 * is returned.
 *
 * @param id Type ID to look for.
 * @return Name of the type represented by @c id or @c NULL .
 */
const char *bf_btf_get_name(int id);

/**
 * Check if BPF token is supported by the current system.
 *
 * Read the kernel's BTF data to check if `prog_token_fd` is a valid field, if
 * so it is assume BPF token is supported by the current kernel.
 *
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: `prog_token_fd` can't be found, meaning BPF token is likely
 *   unsupported.
 */
int bf_btf_kernel_has_token(void);

/**
 * Get the offset of a field in a kernel structure.
 *
 * Use Linux' BTF data to find the offset of a specific field in a structure.
 * This function will fail if the offset of a bitfield is requested.
 *
 * @param struct_name Name of the structure to find the offset in. Can't be
 *        NULL.
 * @param field_name Name of the field to get the offset of. Can't be NULL.
 * @return Offset of @p field_name if found, negative error value on failure.
 */
int bf_btf_get_field_off(const char *struct_name, const char *field_name);
