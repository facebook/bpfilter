/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_matcher;
struct bf_program;

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher);

/**
 * @brief Generate bytecode to compare a packet mark.
 *
 * The mark value must already be loaded into `BPF_REG_1`.
 *
 * @param program Program being generated. Can't be NULL.
 * @param matcher Matcher to generate comparison for. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_matcher_generate_meta_mark_cmp(struct bf_program *program,
                                      const struct bf_matcher *matcher);

/**
 * @brief Generate bytecode to compute and compare a flow hash.
 *
 * The skb pointer must already be loaded into `BPF_REG_1`. Calls
 * `bpf_get_hash_recalc` on the skb, then compares the result against the
 * matcher's payload.
 *
 * @param program Program being generated. Can't be NULL.
 * @param matcher Matcher to generate comparison for. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_matcher_generate_meta_flow_hash_cmp(struct bf_program *program,
                                           const struct bf_matcher *matcher);
