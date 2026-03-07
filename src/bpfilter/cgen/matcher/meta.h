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
 * @brief Generate bytecode to compare a mark value already loaded in
 * @c BPF_REG_1 against the matcher's payload.
 *
 * The caller is responsible for loading the mark value into @c BPF_REG_1
 * before calling this function.
 *
 * @param program Program being generated. Can't be NULL.
 * @param matcher Matcher to generate comparison for. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_matcher_generate_meta_mark(struct bf_program *program,
                                  const struct bf_matcher *matcher);

/**
 * @brief Generate bytecode to compute and compare a flow hash.
 *
 * The skb pointer must already be loaded in @c BPF_REG_1 before calling this
 * function. Calls @c bpf_get_hash_recalc on the skb, then compares the result
 * against the matcher's payload.
 *
 * @param program Program being generated. Can't be NULL.
 * @param matcher Matcher to generate comparison for. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_matcher_generate_meta_flow_hash(struct bf_program *program,
                                       const struct bf_matcher *matcher);
