/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/verdict.h"

#include "bpfilter/shared/helper.h"

const char *bf_verdict_to_str(enum bf_verdict verdict)
{
    static const char *str[] = {
        [BF_VERDICT_ACCEPT] = "ACCEPT",
        [BF_VERDICT_DROP] = "DROP",
    };

    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_VERDICT_MAX);

    return str[verdict];
}
