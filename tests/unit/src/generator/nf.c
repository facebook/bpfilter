/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/nf.c"

#include "harness/cmocka.h"
#include "harness/mock.h"

Test(nf, all_verdicts_valid)
{
    const struct bf_flavor_ops *ops = bf_flavor_ops_get(BF_FLAVOR_NF);

    assert_non_null(ops);

    for (int i = 0; i < _BF_VERDICT_MAX; ++i)
        ops->convert_return_code(i);
}
