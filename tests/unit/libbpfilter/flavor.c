/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/flavor.c"

#include "harness/test.h"
#include "mock.h"

Test(flavor, flavor_to_str)
{
    for (int i = 0; i < _BF_FLAVOR_MAX; ++i)
        assert_non_null(bf_flavor_to_str(i));
}
