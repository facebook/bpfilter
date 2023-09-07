/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "test.h"

#include <assert.h>

#include "core/hook.h"
#include "core/list.h"
#include "generator/program.h"

int bf_test_make_codegen(struct bf_codegen **codegen, enum bf_hook hook,
                         int nprogs)
{
    _cleanup_bf_codegen_ struct bf_codegen *c = NULL;
    int r;

    assert(codegen);

    // So ifindex start a 1
    ++nprogs;

    r = bf_codegen_new(&c);
    if (r < 0)
        return r;

    for (int i = 1; i < nprogs; ++i) {
        _cleanup_bf_program_ struct bf_program *p = NULL;

        r = bf_program_new(&p, i, hook, BF_FRONT_IPT);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&c->programs, p);
        if (r < 0)
            return r;

        TAKE_PTR(p);
    }

    *codegen = TAKE_PTR(c);

    return 0;
}
