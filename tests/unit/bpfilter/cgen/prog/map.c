/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/map.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(map, create_delete_assert)
{
    expect_assert_failure(bf_map_new(NULL, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    expect_assert_failure(bf_map_new(NOT_NULL, NULL, BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    expect_assert_failure(bf_map_new(NOT_NULL, "", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    expect_assert_failure(bf_map_new(NOT_NULL, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 0, 1, 1));
    expect_assert_failure(bf_map_new(NOT_NULL, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 0, 1));
    expect_assert_failure(bf_map_new(NOT_NULL, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 0));
    expect_assert_failure(bf_map_free(NULL));
}

Test(map, create_delete)
{
    // Rely on the cleanup attribute
    _cleanup_bf_map_ struct bf_map *map0 = NULL;

    assert_success(bf_map_new(&map0, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    assert_non_null(map0);

    // Use the cleanup attribute, but free manually
    _cleanup_bf_map_ struct bf_map *map1 = NULL;

    assert_success(bf_map_new(&map1, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    assert_non_null(map1);

    bf_map_free(&map1);
    assert_null(map1);

    // Free manually
    struct bf_map *map2;

    assert_success(bf_map_new(&map2, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    assert_non_null(map2);

    bf_map_free(&map2);
    assert_null(map2);
    bf_map_free(&map2);
}

Test(map, marsh_unmarsh_assert)
{
    expect_assert_failure(bf_map_new_from_marsh(NULL, 0, NOT_NULL));
    expect_assert_failure(bf_map_new_from_marsh(NOT_NULL, 0, NULL));
    expect_assert_failure(bf_map_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_map_marsh(NOT_NULL, NULL));
}

Test(map, marsh_unmarsh)
{
    _cleanup_bf_map_ struct bf_map *map0 = NULL;
    _cleanup_bf_map_ struct bf_map *map1 = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(bf_bpf_obj_get, 0);

    assert_success(bf_map_new(&map0, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 2, 3));

    assert_success(bf_map_marsh(map0, &marsh));
    assert_success(bf_map_new_from_marsh(&map1, 0, marsh));

    // Ensure we won't try to close a garbage FD
    map1->fd = -1;

    assert_string_equal(map0->name, map1->name);
    assert_string_equal(map0->name, map1->name);
    assert_int_equal(map0->bpf_type, map1->bpf_type);
    assert_int_equal(map0->key_size, map1->key_size);
    assert_int_equal(map0->value_size, map1->value_size);
    assert_int_equal(map0->n_elems, map1->n_elems);
}

Test(map, dump_assert)
{
    expect_assert_failure(bf_map_dump(NULL, NOT_NULL));
    expect_assert_failure(bf_map_dump(NOT_NULL, NULL));
}

Test(map, dump)
{
    _cleanup_bf_map_ struct bf_map *map = NULL;

    assert_success(bf_map_new(&map, "012345", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    bf_map_dump(map, EMPTY_PREFIX);
}

Test(map, bpf_map_type_to_kernel_type_assert)
{
    expect_assert_failure(_bf_map_bpf_type_to_kernel_type(-1));
    expect_assert_failure(_bf_map_bpf_type_to_kernel_type(_BF_MAP_BPF_TYPE_MAX));
}

Test(map, btf_create_delete_assert)
{
    expect_assert_failure(_bf_btf_new(NULL));
    expect_assert_failure(_bf_btf_free(NULL));
}

Test(map, btf_create_delete)
{
    // Rely on the cleanup attribute
    _cleanup_bf_btf_ struct bf_btf *btf0 = NULL;

    assert_success(_bf_btf_new(&btf0));
    assert_non_null(btf0);

    // Use the cleanup attribute, but free manually
    _cleanup_bf_btf_ struct bf_btf *btf1 = NULL;

    assert_success(_bf_btf_new(&btf1));
    assert_non_null(btf1);

    _bf_btf_free(&btf1);
    assert_null(btf1);

    // Free manually
    struct bf_btf *btf2;

    assert_success(_bf_btf_new(&btf2));
    assert_non_null(btf2);

    _bf_btf_free(&btf2);
    assert_null(btf2);
    _bf_btf_free(&btf2);
}

Test(map, map_create_assert)
{
    expect_assert_failure(bf_map_create(NULL, 0));
}

Test(map, map_create)
{
    _cleanup_bf_map_ struct bf_map *map = NULL;
    _clean_bf_test_mock_ bf_test_mock _0 = bf_test_mock_get(bf_bpf, 16);
    _clean_bf_test_mock_ bf_test_mock _1 = bf_test_mock_get(bf_ctx_token, -1);

    assert_success(bf_map_new(&map, "suffix", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, BF_MAP_N_ELEMS_UNKNOWN));
    assert_error(bf_map_create(map, 0));
    assert_success(bf_map_set_n_elems(map, 1));
    assert_success(bf_map_create(map, 0));
    assert_error(bf_map_set_n_elems(map, 1));

    // So bf_map_free() doesn't try to close a random FD value
    map->fd = -1;
}

Test(map, map_create_failure)
{
    _cleanup_bf_map_ struct bf_map *map = NULL;
    _clean_bf_test_mock_ bf_test_mock _0 = bf_test_mock_get(bf_bpf, -1);
    _clean_bf_test_mock_ bf_test_mock _1 = bf_test_mock_get(bf_ctx_token, -1);

    assert_success(bf_map_new(&map, "suffix", BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_ARRAY, 1, 1, 1));
    assert_error(bf_map_create(map, 0));
}

Test(map, map_destroy_assert)
{
    expect_assert_failure(bf_map_destroy(NULL));
}

Test(map, map_set_elem_assert)
{
    expect_assert_failure(bf_map_set_elem(NULL, NOT_NULL, NOT_NULL));
    expect_assert_failure(bf_map_set_elem(NOT_NULL, NULL, NOT_NULL));
    expect_assert_failure(bf_map_set_elem(NOT_NULL, NOT_NULL, NULL));
}

Test(map, bpf_map_type_to_from_assert)
{
    expect_assert_failure(bf_map_bpf_type_to_str(-1));
    expect_assert_failure(bf_map_bpf_type_to_str(_BF_MAP_BPF_TYPE_MAX));
    expect_assert_failure(bf_map_bpf_type_from_str(NULL, NOT_NULL));
    expect_assert_failure(bf_map_bpf_type_from_str(NOT_NULL, NULL));
}

Test(map, bpf_map_type_to_from)
{
    enum bf_map_bpf_type type;

    for (size_t i = 0; i < _BF_MAP_BPF_TYPE_MAX; ++i) {
        enum bf_map_bpf_type type;
        const char *str = bf_map_bpf_type_to_str(i);
        assert_non_null(str);
        assert_success(bf_map_bpf_type_from_str(str, &type));
        assert_int_equal(i, type);
    }

    assert_error(bf_map_bpf_type_from_str("invalid", &type));
}
