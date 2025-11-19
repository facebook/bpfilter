/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/verdict.h"

#include <errno.h>
#include <stddef.h>

#include "bpfilter/helper.h"

static const char *_bf_verdict_strs[] = {
    [BF_VERDICT_ACCEPT] = "ACCEPT",
    [BF_VERDICT_DROP] = "DROP",
    [BF_VERDICT_CONTINUE] = "CONTINUE",
};
static_assert(ARRAY_SIZE(_bf_verdict_strs) == _BF_VERDICT_MAX,
              "missing entries in the verdict array");

const char *bf_verdict_to_str(enum bf_verdict verdict)
{
    if (verdict < 0 || verdict >= _BF_VERDICT_MAX)
        return "<bf_verdict unknown>";

    return _bf_verdict_strs[verdict];
}

int bf_verdict_from_str(const char *str, enum bf_verdict *verdict)
{
    bf_assert(verdict);

    for (size_t i = 0; i < _BF_VERDICT_MAX; ++i) {
        if (bf_streq(_bf_verdict_strs[i], str)) {
            *verdict = i;
            return 0;
        }
    }

    return -EINVAL;
}
