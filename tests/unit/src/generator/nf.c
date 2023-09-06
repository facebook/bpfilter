/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include <criterion/criterion.h>

#include "core/flavor.h"
#include "test.h"

Test(src_generator_nf, all_verdicts_valid)
{
    const struct bf_flavor_ops *ops = bf_flavor_ops_get(BF_FLAVOR_NF);

    cr_assert_not_null(ops);

    for (int i = 0; i < _BF_TARGET_STANDARD_MAX; ++i)
        ops->convert_return_code(i);
}
