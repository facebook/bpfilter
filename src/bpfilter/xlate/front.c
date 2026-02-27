/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/front.h"

#include <bpfilter/front.h>
#include <bpfilter/helper.h>

extern const struct bf_front_ops ipt_front;
extern const struct bf_front_ops nft_front;
extern const struct bf_front_ops cli_front;

const struct bf_front_ops *bf_front_ops_get(enum bf_front front)
{
    assert(0 <= front && front < _BF_FRONT_MAX);

    static const struct bf_front_ops *fronts[] = {
        [BF_FRONT_IPT] = &ipt_front,
        [BF_FRONT_NFT] = &nft_front,
        [BF_FRONT_CLI] = &cli_front,
    };

    // We need to have an entry for each value in `bf_front` enumeration.
    static_assert_enum_mapping(fronts, _BF_FRONT_MAX);

    return fronts[front];
}
