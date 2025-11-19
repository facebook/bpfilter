/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/front.h"

#include "bpfilter/helper.h"

const char *bf_front_to_str(enum bf_front front)
{
    static const char * const names[] = {
        [BF_FRONT_IPT] = "BF_FRONT_IPT",
        [BF_FRONT_NFT] = "BF_FRONT_NFT",
        [BF_FRONT_CLI] = "BF_FRONT_CLI",
    };
    static_assert(ARRAY_SIZE(names) == _BF_FRONT_MAX,
                  "missing fronts in bf_front_to_str()");

    if (front < 0 || front >= _BF_FRONT_MAX)
        return "<bf_front unknown>";

    return names[front];
}
