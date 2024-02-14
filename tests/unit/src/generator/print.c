/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/print.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

/* bf_print_* function are not easy to unit test as a standard user. root
 * permission are required to use the bpf() syscall.
 */

Test(print, setup_fails_malloc)
{
    _cleanup_bf_mock_ bf_mock _ = bf_mock_get(malloc, NULL);

    assert_int_equal(ARRAY_SIZE(_bf_print_strings), _BF_PRINT_MAX);
    assert_int_not_equal(bf_print_setup(), 0);
}
