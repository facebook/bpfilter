/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/verdict.h"

#include "bpfilter/shared/helper.h"

static const char *_bf_verdict_strs[] = {
    [BF_VERDICT_ACCEPT] = "ACCEPT",
    [BF_VERDICT_DROP] = "DROP",
};

static_assert(ARRAY_SIZE(_bf_verdict_strs) == _BF_VERDICT_MAX,
              "missing entries in the verdict array");

const char *bf_verdict_to_str(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);

    return _bf_verdict_strs[verdict];
}

int bf_verdict_from_str(const char *str, enum bf_verdict *verdict)
{
    bf_assert(str);
    bf_assert(verdict);

    for (size_t i = 0; i < _BF_VERDICT_MAX; ++i) {
        if (bf_streq(_bf_verdict_strs[i], str)) {
            *verdict = i;
            return 0;
        }
    }

    return -EINVAL;
}
