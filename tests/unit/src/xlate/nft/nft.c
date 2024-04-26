/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nft.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(nft, check_front_ops)
{
    assert_ptr_equal(&nft_front, bf_front_ops_get(BF_FRONT_NFT));
}
