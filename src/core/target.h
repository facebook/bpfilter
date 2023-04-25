/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define __cleanup_bf_target__ __attribute__((__cleanup__(bf_target_free)))

struct bf_target
{};

/**
 * @brief Restore verdict's special value(ACCEPT, DROP, etc.) from its negative
 * representation.
 *
 * @param verdict Verdict value to convert.
 * @return Correct verdict value.
 */
static inline int convert_verdict(int verdict)
{
    return -verdict - 1;
}

int bf_target_new(struct bf_target **target);
void bf_target_free(struct bf_target **target);
