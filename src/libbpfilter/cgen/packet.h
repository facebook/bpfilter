/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_matcher;
struct bf_program;

/**
 * @brief Generate bytecode for a packet-based matcher.
 *
 * Dispatches to the appropriate matcher codegen function based on the matcher
 * type. Handles all matchers that operate on packet headers or metadata common
 * to all packet-based flavors.
 *
 * `BF_MATCHER_META_MARK` and `BF_MATCHER_META_FLOW_HASH` are not supported
 * by this function and return `-ENOTSUP`, as they require flavor-specific
 * context access.
 *
 * @param program Program being generated. Can't be NULL.
 * @param matcher Matcher to generate code for. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_packet_gen_inline_matcher(struct bf_program *program,
                                 const struct bf_matcher *matcher);
