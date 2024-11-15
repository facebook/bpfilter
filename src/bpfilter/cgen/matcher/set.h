/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_matcher;
struct bf_program;

/**
 * Generate the bytecode for the BF_MATCHER_SET_* matcher types.
 *
 * @param program Program to generate the bytecode into. Can't be NULL.
 * @param matcher Matcher to generate the bytecode for. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_matcher_generate_set(struct bf_program *program,
                            const struct bf_matcher *matcher);
