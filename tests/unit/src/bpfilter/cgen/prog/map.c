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

Test(map, marsh_unmarsh_assert)
{
    expect_assert_failure(bf_bpf_map_new_from_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_bpf_map_new_from_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_bpf_map_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_bpf_map_marsh(NOT_NULL, NULL));
}

Test(map, marsh_unmarsh)
{
    _cleanup_bf_bpf_map_ struct bf_bpf_map *map0 = NULL;
    _cleanup_bf_bpf_map_ struct bf_bpf_map *map1 = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _cleanup_bf_mock_ bf_mock _ = bf_mock_get(bf_bpf_obj_get, 1);

    assert_success(bf_bpf_map_new(&map0, "012345"));

    assert_success(bf_bpf_map_marsh(map0, &marsh));
    assert_success(bf_bpf_map_new_from_marsh(&map1, marsh));

    // Ensure we won't try to close a garbage FD
    map1->fd = -1;

    assert_string_equal(map0->name, map1->name);
    assert_string_equal(map0->path, map1->path);
}
