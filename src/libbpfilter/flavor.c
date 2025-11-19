/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/flavor.h"

#include "bpfilter/helper.h"

const char *bf_flavor_to_str(enum bf_flavor flavor)
{
    static const char *flavor_str[] = {
        [BF_FLAVOR_TC] = "BF_FLAVOR_TC",
        [BF_FLAVOR_NF] = "BF_FLAVOR_NF",
        [BF_FLAVOR_XDP] = "BF_FLAVOR_XDP",
        [BF_FLAVOR_CGROUP] = "BF_FLAVOR_CGROUP",
    };
    static_assert(ARRAY_SIZE(flavor_str) == _BF_FLAVOR_MAX,
                  "missing entries in flavor_str array");

    if (flavor < 0 || flavor >= _BF_FLAVOR_MAX)
        return "<bf_flavor unknown>";

    return flavor_str[flavor];
}
