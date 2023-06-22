/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/hook.c"

#include <criterion/criterion.h>

#include "test.h"

TestAssert(src_core_hook, bf_hook_to_str, 0, (-1));
TestAssert(src_core_hook, bf_hook_to_str, 1, (_BF_HOOK_MAX));
TestAssert(src_core_hook, bf_hook_to_bpf_prog_type, 0, (-1));
TestAssert(src_core_hook, bf_hook_to_bpf_prog_type, 1, (_BF_HOOK_MAX));
TestAssert(src_core_hook, bf_hook_to_flavor, 0, (-1));
TestAssert(src_core_hook, bf_hook_to_flavor, 1, (_BF_HOOK_MAX));

Test(src_core_hook, can_get_str_from_hook)
{
    for (int i = 0; i < _BF_HOOK_MAX; ++i)
        cr_assert_not_null(bf_hook_to_str(i));
}

Test(src_core_hook, can_get_prog_type_from_hook)
{
    unsigned int prog_type;

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        prog_type = bf_hook_to_bpf_prog_type(i);
        cr_assert(BPF_PROG_TYPE_UNSPEC <= prog_type);
        cr_assert(prog_type <= BPF_PROG_TYPE_SYSCALL);
    }
}

Test(src_core_hook, can_get_flavor_from_hook)
{
    enum bf_flavor flavor;

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        flavor = bf_hook_to_flavor(i);
        cr_assert(0 <= flavor);
        cr_assert(flavor < _BF_FLAVOR_MAX);
    }
}
