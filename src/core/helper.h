/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

/**
 * @brief Read the contents of a file into a buffer.
 *
 * @param path Path to the file to read. Can't be NULL.
 * @param buf Pointer to a pointer to a buffer. The buffer will be allocated
 *  automatically. The caller is responsible to free it. If @ref bf_read_file
 *  fails, @p buf is left unchanged.
 * @param len Length of the allocated buffer. Populated by the function.
 * @return 0 on success, negative errno value on error.
 */
int bf_read_file(const char *path, void **buf, size_t *len);

/**
 * @brief Write the contents of a buffer into a file.
 *
 * @param path Path to the file to write. Can't be NULL.
 * @param buf Buffer to write.
 * @param len Number of bytes to write the to file.
 * @return 0 on success, negative errno value on error.
 */
int bf_write_file(const char *path, const void *buf, size_t len);
