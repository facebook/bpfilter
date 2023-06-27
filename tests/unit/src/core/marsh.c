/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/marsh.h"

#include <criterion/criterion.h>

#include "core/marsh.c"
#include "test.h"

Test(src_core_marsh, new)
{
    {
        // Call bf_marsh_free() with NULL marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    }

    {
        // Create a new empty marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
        cr_assert_eq(0, marsh->data_len);
        cr_assert_eq(sizeof(struct bf_marsh), bf_marsh_size(marsh));
    }

    {
        // Create a new marsh with data but size 0.
        int a = 3;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        cr_assert_eq(0, bf_marsh_new(&marsh, &a, 0));
        cr_assert_eq(0, marsh->data_len);
        cr_assert_eq(sizeof(struct bf_marsh), bf_marsh_size(marsh));
    }

    {
        // Create a new marsh with data.
        int a = 3;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        cr_assert_eq(0, bf_marsh_new(&marsh, &a, sizeof(a)));
        cr_assert_eq(sizeof(a), marsh->data_len);
        cr_assert_eq(sizeof(struct bf_marsh) + sizeof(a), bf_marsh_size(marsh));
        cr_assert_eq(0, memcmp(&a, marsh->data, marsh->data_len));
    }
}

Test(src_core_marsh, add_child_obj)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *child0 = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *child1 = NULL;

    cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
    cr_assert_eq(0, bf_marsh_new(&child0, NULL, 0));
    cr_assert_eq(0, bf_marsh_new(&child1, NULL, 0));

    cr_assert_eq(0, bf_marsh_add_child_obj(&marsh, child0));
    cr_assert_eq(bf_marsh_size(child0), marsh->data_len);
    cr_assert_eq(0, memcmp(child0, marsh->data, marsh->data_len));

    cr_assert_eq(0, bf_marsh_add_child_obj(&marsh, child1));
    cr_assert_eq(bf_marsh_size(child0) + bf_marsh_size(child1),
                 marsh->data_len);
    cr_assert_eq(0, memcmp(child1, marsh->data + bf_marsh_size(child0),
                           bf_marsh_size(child1)));
}

Test(src_core_marsh, add_child_raw)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    struct bf_marsh *child0;
    struct bf_marsh *child1;
    struct bf_marsh *child2;
    const char *child1_str = "hello";
    const char *child2_str = "world";

    cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));

    cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, NULL, 0));
    cr_assert_eq(sizeof(struct bf_marsh), marsh->data_len);

    cr_assert_eq(
        0, bf_marsh_add_child_raw(&marsh, child1_str, strlen(child1_str) + 1));
    cr_assert_not_null(child0 = bf_marsh_next_child(marsh, NULL));
    cr_assert_not_null(child1 = bf_marsh_next_child(marsh, child0));
    cr_assert_eq(strlen(child1_str) + 1, child1->data_len);
    cr_assert_eq(0, memcmp(child1_str, child1->data, child1->data_len));

    // Fetch child2 now. We need to fetch child0 and child1 first because marsh
    // will be realloc()ed by bf_marsh_add_child_raw().
    cr_assert_eq(
        0, bf_marsh_add_child_raw(&marsh, child2_str, strlen(child2_str)));
    cr_assert_not_null(child0 = bf_marsh_next_child(marsh, NULL));
    cr_assert_not_null(child1 = bf_marsh_next_child(marsh, child0));
    cr_assert_not_null(child2 = bf_marsh_next_child(marsh, child1));
    cr_assert_eq(strlen(child2_str), child2->data_len);
    cr_assert_eq(0, memcmp(child2_str, child2->data, child2->data_len));
}

Test(src_core_marsh, next_child)
{
    {
        // Empty marsh.
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
        cr_assert_null(bf_marsh_next_child(marsh, NULL));
    }

    {
        // Access all childs
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child;
        const char *str = "hello, world";

        cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
        cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, str, 2));
        cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, &str[2], 3));

        cr_assert_not_null(child = bf_marsh_next_child(marsh, NULL));
        cr_assert_not_null(child = bf_marsh_next_child(marsh, child));
        cr_assert_null(bf_marsh_next_child(marsh, child));
    }

    {
        // Modify childs
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child0;
        struct bf_marsh *child1;
        const char *str = "hello, world";

        cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
        cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, str, 2));
        cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, &str[2], 3));

        cr_assert_not_null(child0 = bf_marsh_next_child(marsh, NULL));
        cr_assert_not_null(child1 = bf_marsh_next_child(marsh, child0));

        // Make child1->data_len field overflow from marsh.
        cr_assert_not_null(child0 = bf_marsh_next_child(marsh, NULL));
        child0->data_len = 2 + sizeof(struct bf_marsh) + 2;
        cr_assert_null(bf_marsh_next_child(marsh, child0));
        child0->data_len = 2;

        // Make child1->data field overflow from marsh.
        cr_assert_not_null(child1 = bf_marsh_next_child(marsh, child0));
        child1->data_len += 1;
        cr_assert_null(bf_marsh_next_child(marsh, child0));
    }
}

Test(src_core_marsh, child_is_valid)
{
    {
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child0;

        cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
        cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, "hello", 6));
        cr_assert_not_null(child0 = bf_marsh_next_child(marsh, NULL));

        cr_assert_not(bf_marsh_child_is_valid(marsh, NULL));

        // child is not in marsh.
        cr_assert_not(bf_marsh_child_is_valid(marsh, (void *)marsh - 1));
        cr_assert_not(bf_marsh_child_is_valid(marsh, bf_marsh_end(marsh) + 1));

        // child->data_len is overflowing
        cr_assert_not(bf_marsh_child_is_valid(marsh, bf_marsh_end(marsh) - 1));

        // child's data is overflowing
        child0->data_len = 100;
        cr_assert_not(bf_marsh_child_is_valid(marsh, child0));
        child0->data_len = 6;
    }

    {
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
        struct bf_marsh *child0;

        cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
        cr_assert_eq(0, bf_marsh_add_child_raw(&marsh, NULL, 0));
        cr_assert_not_null(child0 = bf_marsh_next_child(marsh, NULL));
        cr_assert_eq(child0, marsh->data);
        cr_assert_eq(bf_marsh_end(child0), bf_marsh_end(marsh));
    }
}

TestAssert(src_core_marsh, bf_marsh_new, 0, (NULL, NOT_NULL, 0));
TestAssert(src_core_marsh, bf_marsh_new, 1, (NOT_NULL, NULL, 1));
TestAssert(src_core_marsh, bf_marsh_add_child_obj, 0, (NULL, NOT_NULL));
TestAssert(src_core_marsh, bf_marsh_add_child_raw, 0, (NULL, NOT_NULL, 0));
TestAssert(src_core_marsh, bf_marsh_next_child, 0, (NULL, NOT_NULL));
TestAssert(src_core_marsh, bf_marsh_child_is_valid, 0, (NULL, NOT_NULL));

Test(src_core_marsh, bf_marsh_add_child_obj_1, .signal = SIGABRT)
{
    // TestAssert() can't be used here because bf_marsh_add_child_obj() will
    // call assert() on *marsh, so it needs to point to valid memory.

    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

    cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
    bf_marsh_add_child_obj(&marsh, NULL);
}

Test(src_core_marsh, bf_marsh_add_child_raw_1, .signal = SIGABRT)
{
    // TestAssert() can't be used here because bf_marsh_add_child_obj() will
    // call assert() on *marsh, so it needs to point to valid memory.

    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

    cr_assert_eq(0, bf_marsh_new(&marsh, NULL, 0));
    bf_marsh_add_child_raw(&marsh, NULL, 1);
}
