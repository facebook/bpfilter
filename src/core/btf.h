// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

/**
 * @brief Load current kernel's BTF data.
 *
 * This function has to be called early, so BPF program generation can access
 * kernel's BTF data and use the kfunc's BTF ID.
 *
 * @return 0 on success, or negative errno value on failure.
 */
int bf_btf_setup(void);

/**
 * @brief Free current kernel's BTF data.
 */
void bf_btf_teardown(void);

/**
 * @brief Get BTF ID of a kernel function.
 *
 * Linux' BTF data must be loaded with @ref bf_btf_setup before calling this
 * function.
 *
 * @param name Name of the kernel function.
 * @return BTF ID on success, or negative errno value on failure.
 */
int bf_btf_get_id(const char *name);
