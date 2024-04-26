/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/flavor.h"

#include "generator/nf.h"
#include "generator/tc.h"
#include "generator/xdp.h"
#include "shared/helper.h"

const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_flavor flavor)
{
    static const struct bf_flavor_ops *flavor_ops[] = {
        [BF_FLAVOR_TC] = &bf_flavor_ops_tc,
        [BF_FLAVOR_NF] = &bf_flavor_ops_nf,
        [BF_FLAVOR_XDP] = &bf_flavor_ops_xdp,
    };

    bf_assert(0 <= flavor && flavor < _BF_FLAVOR_MAX);
    static_assert(ARRAY_SIZE(flavor_ops) == _BF_FLAVOR_MAX,
                  "missing entries in fronts array");

    return flavor_ops[flavor];
}

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
