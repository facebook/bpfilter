/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/program.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(program, can_get_flavor_from_hook)
{
    for (enum bf_flavor flavor = 0; flavor < _BF_FLAVOR_MAX; ++flavor)
        assert_non_null(bf_flavor_ops_get(flavor));
}
