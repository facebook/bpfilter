/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "front.h"

#include "shared/helper.h"

extern const struct bf_front_ops ipt_front;

const struct bf_front_ops *bf_front_ops_get(enum bf_front front)
{
    bf_assert(0 <= front && front < _BF_FRONT_MAX);

    static const struct bf_front_ops *fronts[] = {
        [BF_FRONT_IPT] = &ipt_front,
    };

    // We need to have an entry for each value in `bf_front` enumeration.
    static_assert(ARRAY_SIZE(fronts) == _BF_FRONT_MAX,
                  "missing entries in fronts array");

    return fronts[front];
}
