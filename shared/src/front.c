/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "shared/front.h"

#include "shared/helper.h"

const char *bf_front_to_str(enum bf_front front)
{
    bf_assert(front >= 0 && front < _BF_FRONT_MAX);

    static const char * const names[] = {
        [BF_FRONT_IPT] = "BF_FRONT_IPT",
        [BF_FRONT_NFT] = "BF_FRONT_NFT",
    };

    return names[front];
}
