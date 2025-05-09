/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/opts.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(opts, no_nftables)
{
    char *opt0[] = {"tests_unit", "--no-nftables"};

    _bf_opts.fronts = 0xffff;
    assert_success(bf_opts_init(ARRAY_SIZE(opt0), opt0));
    assert(0 == (_bf_opts.fronts & BF_FLAG(BF_FRONT_NFT)));
}
