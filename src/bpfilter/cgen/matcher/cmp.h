/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include <bpfilter/matcher.h>

struct bf_program;

/**
 * @brief Compare the value in `reg` against a reference value.
 *
 * For size 16, the value spans `reg` (low 64 bits) and `reg + 1`
 * (high 64 bits). Clobbers `BPF_REG_2` for size 4/8 and
 * `BPF_REG_3`/`BPF_REG_4` for size 16.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param op `BF_MATCHER_EQ` or `BF_MATCHER_NE`.
 * @param ref Pointer to reference value. Can't be NULL.
 * @param size Comparison width in bytes: 1, 2, 4, 8, or 16.
 * @param reg BPF register holding the value to compare.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_value(struct bf_program *program, enum bf_matcher_op op,
                 const void *ref, unsigned int size, int reg);

/**
 * @brief Mask the value in `reg` by `prefixlen`, then compare.
 *
 * For size 16, the value spans `reg` and `reg + 1`. Modifies `reg`
 * (and `reg + 1`) in-place. Clobbers `BPF_REG_2`/`BPF_REG_3` for
 * size 4 and `BPF_REG_3`/`BPF_REG_4` for size 16.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param op `BF_MATCHER_EQ` or `BF_MATCHER_NE`.
 * @param ref Pointer to unmasked reference value. Can't be NULL.
 * @param prefixlen Prefix length in bits (1-32 for size 4, 1-128 for size 16).
 * @param size Comparison width in bytes: 4 or 16.
 * @param reg BPF register holding the value to compare.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_masked_value(struct bf_program *program, enum bf_matcher_op op,
                        const void *ref, unsigned int prefixlen,
                        unsigned int size, int reg);

/**
 * @brief Check `min <= reg <= max`, for values up to 32 bits.
 *
 * All values must be in host byte order; the caller is responsible for
 * any conversion (e.g., `BSWAP` for network-order port values).
 *
 * @param program Program to emit into. Can't be NULL.
 * @param min Minimum value.
 * @param max Maximum value.
 * @param reg BPF register holding the value to compare.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_range(struct bf_program *program, uint32_t min, uint32_t max,
                 int reg);

/**
 * @brief Check `reg` against a bitmask, for values up to 32 bits.
 *
 * ANY: `(reg & flags) != 0`
 * ALL: `(reg & flags) == flags`
 *
 * @param program Program to emit into. Can't be NULL.
 * @param op `BF_MATCHER_ANY` or `BF_MATCHER_ALL`.
 * @param flags Bitmask to check against.
 * @param reg BPF register holding the value to check.
 * @return 0 on success, negative errno on error.
 */
int bf_cmp_bitfield(struct bf_program *program, enum bf_matcher_op op,
                    uint32_t flags, int reg);
