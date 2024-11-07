/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/marsh.c"

#include "harness/test.h"
#include "harness/mock.h"

Test(marsh, new)
{
    {
        // Call bf_marsh_free() with NULL marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    }

    {
        // Create a new empty marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        assert_int_equal(0, marsh->data_len);
        assert_int_equal(sizeof(struct bf_marsh), bf_marsh_size(marsh));
    }

    {
        // Create a new marsh with data but size 0.
        int a = 3;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_success(bf_marsh_new(&marsh, &a, 0));
        assert_int_equal(0, marsh->data_len);
        assert_int_equal(sizeof(struct bf_marsh), bf_marsh_size(marsh));
    }

    {
        // Create a new marsh with data.
        int a = 3;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_success(bf_marsh_new(&marsh, &a, sizeof(a)));
        assert_int_equal(sizeof(a), marsh->data_len);
        assert_int_equal(sizeof(struct bf_marsh) + sizeof(a),
                         bf_marsh_size(marsh));
        assert_int_equal(0, memcmp(&a, marsh->data, marsh->data_len));
    }
}

Test(marsh, new_failure)
{
    expect_assert_failure(bf_marsh_new(NULL, NULL, 0));
    expect_assert_failure(bf_marsh_new(NOT_NULL, NULL, 1));

    {
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(malloc, NULL);

        assert_true(bf_marsh_new(NOT_NULL, NULL, 0) < 0);
    }
}

Test(marsh, add_child_obj)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *child0 = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *child1 = NULL;

    assert_success(bf_marsh_new(&marsh, NULL, 0));
    assert_success(bf_marsh_new(&child0, NULL, 0));
    assert_success(bf_marsh_new(&child1, NULL, 0));

    assert_success(bf_marsh_add_child_obj(&marsh, child0));
    assert_int_equal(bf_marsh_size(child0), marsh->data_len);
    assert_int_equal(0, memcmp(child0, marsh->data, marsh->data_len));

    assert_success(bf_marsh_add_child_obj(&marsh, child1));
    assert_int_equal(bf_marsh_size(child0) + bf_marsh_size(child1),
                     marsh->data_len);
    assert_int_equal(0, memcmp(child1, marsh->data + bf_marsh_size(child0),
                               bf_marsh_size(child1)));
}

Test(marsh, add_child_raw)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    struct bf_marsh *child0;
    struct bf_marsh *child1;
    struct bf_marsh *child2;
    const char *child1_str = "hello";
    const char *child2_str = "world";

    assert_success(bf_marsh_new(&marsh, NULL, 0));

    assert_success(bf_marsh_add_child_raw(&marsh, NULL, 0));
    assert_int_equal(sizeof(struct bf_marsh), marsh->data_len);

    assert_int_equal(
        0, bf_marsh_add_child_raw(&marsh, child1_str, strlen(child1_str) + 1));
    assert_non_null(child0 = bf_marsh_next_child(marsh, NULL));
    assert_non_null(child1 = bf_marsh_next_child(marsh, child0));
    assert_int_equal(strlen(child1_str) + 1, child1->data_len);
    assert_int_equal(0, memcmp(child1_str, child1->data, child1->data_len));

    // Fetch child2 now. We need to fetch child0 and child1 first because marsh
    // will be realloc()ed by bf_marsh_add_child_raw().
    assert_int_equal(
        0, bf_marsh_add_child_raw(&marsh, child2_str, strlen(child2_str)));
    assert_non_null(child0 = bf_marsh_next_child(marsh, NULL));
    assert_non_null(child1 = bf_marsh_next_child(marsh, child0));
    assert_non_null(child2 = bf_marsh_next_child(marsh, child1));
    assert_int_equal(strlen(child2_str), child2->data_len);
    assert_int_equal(0, memcmp(child2_str, child2->data, child2->data_len));
}

Test(marsh, add_child_assert_failure)
{
    expect_assert_failure(bf_marsh_add_child_obj(NULL, NOT_NULL));
    expect_assert_failure(bf_marsh_add_child_raw(NULL, NOT_NULL, 0));
}

Test(marsh, next_child)
{
    {
        // Empty marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        assert_null(bf_marsh_next_child(marsh, NULL));
    }

    {
        // Access all childs
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child;
        const char *str = "hello, world";

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        assert_success(bf_marsh_add_child_raw(&marsh, str, 2));
        assert_success(bf_marsh_add_child_raw(&marsh, &str[2], 3));

        assert_non_null(child = bf_marsh_next_child(marsh, NULL));
        assert_non_null(child = bf_marsh_next_child(marsh, child));
        assert_null(bf_marsh_next_child(marsh, child));
    }

    {
        // Modify childs
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child0;
        struct bf_marsh *child1;
        const char *str = "hello, world";

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        assert_success(bf_marsh_add_child_raw(&marsh, str, 2));
        assert_success(bf_marsh_add_child_raw(&marsh, &str[2], 3));

        assert_non_null(child0 = bf_marsh_next_child(marsh, NULL));
        assert_non_null(child1 = bf_marsh_next_child(marsh, child0));

        // Make child1->data_len field overflow from marsh.
        assert_non_null(child0 = bf_marsh_next_child(marsh, NULL));
        child0->data_len = 2 + sizeof(struct bf_marsh) + 2;
        assert_null(bf_marsh_next_child(marsh, child0));
        child0->data_len = 2;

        // Make child1->data field overflow from marsh.
        assert_non_null(child1 = bf_marsh_next_child(marsh, child0));
        child1->data_len += 1;
        assert_null(bf_marsh_next_child(marsh, child0));
    }
}

Test(marsh, child_assert_failure)
{
    expect_assert_failure(bf_marsh_next_child(NULL, NOT_NULL));
    expect_assert_failure(bf_marsh_child_is_valid(NULL, NOT_NULL));

    {
        // bf_marsh_add_child_obj() will call assert() on *marsh, so we need to
        // have a valid marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        expect_assert_failure(bf_marsh_add_child_obj(&marsh, NULL));
    }

    {
        // bf_marsh_add_child_raw() will call assert() on *marsh, so we need to
        // have a valid marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        expect_assert_failure(bf_marsh_add_child_raw(&marsh, NULL, 1));
    }
}

Test(marsh, child_is_valid)
{
    {
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child0;

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        assert_success(bf_marsh_add_child_raw(&marsh, "hello", 6));
        assert_non_null(child0 = bf_marsh_next_child(marsh, NULL));

        assert_int_equal(0, bf_marsh_child_is_valid(marsh, NULL));

        // child is not in marsh.
        assert_int_equal(0, bf_marsh_child_is_valid(marsh, (void *)marsh - 1));
        assert_int_equal(
            0, bf_marsh_child_is_valid(marsh, bf_marsh_end(marsh) + 1));

        // child->data_len is overflowing
        assert_int_equal(
            0, bf_marsh_child_is_valid(marsh, bf_marsh_end(marsh) - 1));

        // child's data is overflowing
        child0->data_len = 100;
        assert_int_equal(0, bf_marsh_child_is_valid(marsh, child0));
        child0->data_len = 6;
    }

    {
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child0;

        assert_success(bf_marsh_new(&marsh, NULL, 0));
        assert_success(bf_marsh_add_child_raw(&marsh, NULL, 0));
        assert_non_null(child0 = bf_marsh_next_child(marsh, NULL));
        assert_int_equal(child0, marsh->data);
        assert_int_equal(bf_marsh_end(child0), bf_marsh_end(marsh));
    }
}

Test(marsh, add_child_obj_failure)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

    assert_success(bf_marsh_new(&marsh, NULL, 0));
    assert_success(bf_marsh_new(&child, NULL, 0));

    _cleanup_bf_mock_ bf_mock _ = bf_mock_get(malloc, NULL);
    assert_true(bf_marsh_add_child_obj(&marsh, child) < 0);
}
