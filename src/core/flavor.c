/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/flavor.h"

#include "core/helper.h"

const char *bf_flavor_to_str(enum bf_flavor flavor)
{
    static const char *flavor_str[] = {
        [BF_FLAVOR_TC] = "BF_FLAVOR_TC",
        [BF_FLAVOR_NF] = "BF_FLAVOR_NF",
        [BF_FLAVOR_XDP] = "BF_FLAVOR_XDP",
    };

    bf_assert(0 <= flavor && flavor < _BF_FLAVOR_MAX);
    static_assert(ARRAY_SIZE(flavor_str) == _BF_FLAVOR_MAX,
                  "missing entries in flavor_str array");

    return flavor_str[flavor];
}
