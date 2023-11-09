/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

/**
 * @brief Verdict to apply for a rule or chain.
 */
enum bf_verdict
{
    /** Accept the packet. */
    BF_VERDICT_ACCEPT,
    /** Drop the packet. */
    BF_VERDICT_DROP,
    _BF_VERDICT_MAX,
};

const char *bf_verdict_to_str(enum bf_verdict verdict);
