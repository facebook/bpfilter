// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

struct btf;

struct bf_btf
{
    struct btf *btf;
    uint32_t key_type_id;
    uint32_t value_type_id;
    int fd;
};

/**
 * @brief Get BTF ID of a kernel function.
 *
 * @pre
 *  - `btf` is not NULL.
 *  - `name` is not NULL.
 *
 * @param btf Loaded kernel BTF object.
 * @param name Name of the kernel function.
 * @return BTF ID on success, or negative errno value on failure.
 */
int bf_btf_get_id(const struct btf *btf, const char *name);

/**
 * @brief Get a type name from a BTF ID from the kernel BTF data.
 *
 * @pre
 *  - `btf` is not NULL.
 *
 * @param btf Loaded kernel BTF object.
 * @param id Type ID to look for.
 * @return Name of the type represented by @p id, or NULL if @p id is
 *         invalid or not part of @p btf.
 */
const char *bf_btf_get_name(const struct btf *btf, int id);

/**
 * @brief Check if BPF token is supported by the current system.
 *
 * Read the kernel's BTF data to check if `prog_token_fd` is a valid field;
 * if so, BPF token is assumed to be supported by the current kernel.
 *
 * @pre
 *  - `btf` is not NULL.
 *
 * @param btf Loaded kernel BTF object.
 * @return 0 on success, or a negative errno value on failure, including:
 *         `-ENOENT` if `prog_token_fd` can't be found (BPF token likely
 *         unsupported).
 */
int bf_btf_kernel_has_token(const struct btf *btf);

/**
 * @brief Get the offset of a field in a kernel structure.
 *
 * Use the kernel BTF data to find the offset of a specific field in a
 * structure. Fails if the offset of a bitfield is requested.
 *
 * @pre
 *  - `btf` is not NULL.
 *  - `struct_name` is not NULL.
 *  - `field_name` is not NULL.
 *
 * @param btf Loaded kernel BTF object.
 * @param struct_name Name of the structure to find the offset in.
 * @param field_name Name of the field to get the offset of.
 * @return Offset of @p field_name (in bytes) if found, or a negative errno
 *         value on failure.
 */
int bf_btf_get_field_off(const struct btf *btf, const char *struct_name,
                         const char *field_name);
