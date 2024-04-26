/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "src/opts.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(opts, no_nftables)
{
    char *opt0[] = {"tests_unit", "--no-nftables"};

    _opts.fronts = 0xffff;
    assert_int_equal(0, bf_opts_init(ARRAY_SIZE(opt0), opt0));
    assert(0 == (_opts.fronts & (1 << BF_FRONT_NFT)));
}
