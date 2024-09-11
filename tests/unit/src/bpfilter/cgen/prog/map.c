/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/map.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(map, create_delete_assert)
{
    expect_assert_failure(bf_bpf_map_new(NULL, NOT_NULL));
    expect_assert_failure(bf_bpf_map_new(NOT_NULL, NULL));
    expect_assert_failure(bf_bpf_map_free(NULL));
}

Test(map, create_delete)
{
    // Rely on the cleanup attribute
    _cleanup_bf_bpf_map_ struct bf_bpf_map *map0 = NULL;

    assert_success(bf_bpf_map_new(&map0, ""));
    assert_non_null(map0);

    // Use the cleanup attribute, but free manually
    _cleanup_bf_bpf_map_ struct bf_bpf_map *map1 = NULL;

    assert_success(bf_bpf_map_new(&map1, ""));
    assert_non_null(map1);

    bf_bpf_map_free(&map1);
    assert_null(map1);

    // Free manually
    struct bf_bpf_map *map2;

    assert_success(bf_bpf_map_new(&map2, ""));
    assert_non_null(map2);

    bf_bpf_map_free(&map2);
    assert_null(map2);
    bf_bpf_map_free(&map2);
}
