/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/prog/map.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(map, create_delete_assert)
{
    expect_assert_failure(bf_map_new(NULL, "012345", BF_MAP_TYPE_LOG, 1, 1, 1));
    expect_assert_failure(bf_map_new(NOT_NULL, NULL, BF_MAP_TYPE_LOG, 1, 1, 1));
    expect_assert_failure(bf_map_free(NULL));
    assert_error(bf_map_new(NOT_NULL, "", BF_MAP_TYPE_LOG, 1, 1, 1));
    assert_error(bf_map_new(NOT_NULL, "012345", BF_MAP_TYPE_LOG, 1, 1, 0));
}

Test(map, create_delete)
{
    // Rely on the cleanup attribute
    _free_bf_map_ struct bf_map *map0 = NULL;

    assert_success(bf_map_new(&map0, "012345", BF_MAP_TYPE_LOG, 1, 1, 1));
    assert_non_null(map0);

    // Use the cleanup attribute, but free manually
    _free_bf_map_ struct bf_map *map1 = NULL;

    assert_success(bf_map_new(&map1, "012345", BF_MAP_TYPE_LOG, 1, 1, 1));
    assert_non_null(map1);

    bf_map_free(&map1);
    assert_null(map1);

    // Free manually
    struct bf_map *map2;

    assert_success(bf_map_new(&map2, "012345", BF_MAP_TYPE_LOG, 1, 1, 1));
    assert_non_null(map2);

    bf_map_free(&map2);
    assert_null(map2);
    bf_map_free(&map2);
}

Test(map, pack_unpack)
{
    _free_bf_map_ struct bf_map *map0 = NULL;
    _free_bf_map_ struct bf_map *map1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(bf_bpf_obj_get, 0);

    expect_assert_failure(bf_map_pack(NULL, NOT_NULL));
    expect_assert_failure(bf_map_pack(NOT_NULL, NULL));

    assert_success(bf_map_new(&map0, "012345", BF_MAP_TYPE_LOG, 1, 2, 3));

    assert_success(bf_wpack_new(&wpack));
    assert_success(bf_map_pack(map0, wpack));
    assert_success(bf_wpack_get_data(wpack, &data, &data_len));

    assert_success(bf_rpack_new(&rpack, data, data_len));
    assert_success(bf_map_new_from_pack(&map1, 0, bf_rpack_root(rpack)));

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
    _free_bf_map_ struct bf_map *map = NULL;

    assert_success(bf_map_new(&map, "012345", BF_MAP_TYPE_LOG, 1, 1, 1));
    bf_map_dump(map, EMPTY_PREFIX);
}

Test(map, btf_create_delete_assert)
{
    expect_assert_failure(_bf_btf_new(NULL));
    expect_assert_failure(_bf_btf_free(NULL));
}

Test(map, btf_create_delete)
{
    // Rely on the cleanup attribute
    _free_bf_btf_ struct bf_btf *btf0 = NULL;

    assert_success(_bf_btf_new(&btf0));
    assert_non_null(btf0);

    // Use the cleanup attribute, but free manually
    _free_bf_btf_ struct bf_btf *btf1 = NULL;

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
    expect_assert_failure(bf_map_create(NULL));
}

Test(map, map_create)
{
    _free_bf_map_ struct bf_map *map = NULL;
    _clean_bf_test_mock_ bf_test_mock _0 = bf_test_mock_get(bf_bpf_map_create, 16);
    _clean_bf_test_mock_ bf_test_mock _1 = bf_test_mock_get(bf_ctx_token, -1);

    assert_success(bf_map_new(&map, "suffix", BF_MAP_TYPE_LOG, 1, 1, BF_MAP_N_ELEMS_UNKNOWN));
    assert_error(bf_map_create(map));
    assert_success(bf_map_set_n_elems(map, 1));
    assert_success(bf_map_create(map));
    assert_error(bf_map_set_n_elems(map, 1));

    // So bf_map_free() doesn't try to close a random FD value
    map->fd = -1;
}

Test(map, map_create_failure)
{
    _free_bf_map_ struct bf_map *map = NULL;
    _clean_bf_test_mock_ bf_test_mock _0 = bf_test_mock_get(bf_bpf_map_create, -1);
    _clean_bf_test_mock_ bf_test_mock _1 = bf_test_mock_get(bf_ctx_token, -1);

    assert_success(bf_map_new(&map, "suffix", BF_MAP_TYPE_LOG, 1, 1, 1));
    assert_error(bf_map_create(map));
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
