/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

/**
 * Verdict to apply for a rule or chain.
 * Chains can only use terminal verdicts, rules can use all verdicts.
 */
enum bf_verdict
{
    /** Terminal verdicts that stop further packet processing. */
    /** Accept the packet. */
    BF_VERDICT_ACCEPT,
    /** Drop the packet. */
    BF_VERDICT_DROP,
    /** Non-terminal verdicts that allow further packet processing. */
    /** Continue processing the next rule. */
    BF_VERDICT_CONTINUE,
    _BF_VERDICT_MAX,
    _BF_TERMINAL_VERDICT_MAX = BF_VERDICT_CONTINUE,
};

/**
 * Convert a verdict value into a string.
 *
 * @param verdict The verdict to convert, must be valid.
 * @return String representation of the verdict.
 */
const char *bf_verdict_to_str(enum bf_verdict verdict);

/**
 * Convert a string into a verdict value.
 *
 * @param str String to convert to a verdict. Can't be NULL.
 * @param verdict String representation of the verdict. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_verdict_from_str(const char *str, enum bf_verdict *verdict);
