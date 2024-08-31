/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_matcher;
struct bf_program;

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher);
