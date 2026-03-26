/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <stdint.h>

#include <bpfilter/core/vector.h>
#include <bpfilter/helper.h>

#include "test.h"

static void new_and_free(void **state)
{
    (void)state;

    {
        // Allocate and free
        bf_vector *vec;

        assert_ok(bf_vector_new(&vec, sizeof(int)));
        assert_int_equal(vec->size, 0);
        assert_int_equal(vec->cap, 0);
        assert_null(vec->data);

        bf_vector_free(&vec);
        assert_null(vec);
    }

    {
        // Auto-free via cleanup attribute
        _free_bf_vector_ bf_vector *vec = NULL;
        assert_ok(bf_vector_new(&vec, sizeof(int)));
    }

    {
        // Auto-free on NULL
        _free_bf_vector_ bf_vector *vec = NULL;
    }
}

static void init_and_clean(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));
    int val = 42;

    (void)state;

    assert_int_equal(vec.size, 0);
    assert_int_equal(vec.cap, 0);
    assert_null(vec.data);

    assert_ok(bf_vector_add(&vec, &val));
    assert_int_equal(vec.size, 1);

    bf_vector_clean(&vec);
    assert_int_equal(vec.size, 0);
    assert_int_equal(vec.cap, 0);
    assert_null(vec.data);
}

static void add_and_get(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    for (int i = 0; i < 100; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    assert_int_equal(vec.size, 100);
    assert_int_gte(vec.cap, 100);

    for (int i = 0; i < 100; ++i) {
        int *p = bf_vector_get(&vec, i);
        assert_non_null(p);
        assert_int_equal(*p, i);
    }
}

static void remove_elem(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    for (int i = 0; i < 5; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    // Remove from the middle: [0,1,2,3,4] -> [0,1,3,4]
    assert_ok(bf_vector_remove(&vec, 2));
    assert_int_equal(vec.size, 4);
    assert_int_equal(*(int *)bf_vector_get(&vec, 0), 0);
    assert_int_equal(*(int *)bf_vector_get(&vec, 1), 1);
    assert_int_equal(*(int *)bf_vector_get(&vec, 2), 3);
    assert_int_equal(*(int *)bf_vector_get(&vec, 3), 4);

    // Remove last element: [0,1,3,4] -> [0,1,3]
    assert_ok(bf_vector_remove(&vec, 3));
    assert_int_equal(vec.size, 3);

    // Remove first element: [0,1,3] -> [1,3]
    assert_ok(bf_vector_remove(&vec, 0));
    assert_int_equal(vec.size, 2);
    assert_int_equal(*(int *)bf_vector_get(&vec, 0), 1);
    assert_int_equal(*(int *)bf_vector_get(&vec, 1), 3);

    // Out of bounds
    assert_err(bf_vector_remove(&vec, 2));
    assert_err(bf_vector_remove(&vec, 99));
}

static void foreach(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));
    int expected = 0;

    (void)state;

    for (int i = 0; i < 50; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    bf_vector_foreach (&vec, elem) {
        assert_int_equal(*(int *)elem, expected);
        ++expected;
    }

    assert_int_equal(expected, 50);
}

static void foreach_empty(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));
    int count = 0;

    (void)state;

    bf_vector_foreach (&vec, elem) {
        (void)elem;
        ++count;
    }

    assert_int_equal(count, 0);
}

static void reserve(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    // Initial capacity should be 0 and data NULL.
    assert_int_equal(vec.cap, 0);
    assert_null(vec.data);

    // Reserve on a fresh empty vector (exercises realloc(NULL, size) path).
    assert_ok(bf_vector_reserve(&vec, 10));
    assert_int_gte(vec.cap, 10);
    assert_int_equal(vec.size, 0);
    assert_non_null(vec.data);

    // Add elements after the initial reserve.
    for (int i = 0; i < 10; ++i)
        assert_ok(bf_vector_add(&vec, &i));
    assert_int_equal(vec.size, 10);

    // Reserve more capacity on a non-empty vector.
    assert_ok(bf_vector_reserve(&vec, 64));
    assert_int_gte(vec.cap, 64);
    assert_int_equal(vec.size, 10);

    // Add elements after the second reserve.
    for (int i = 10; i < 20; ++i)
        assert_ok(bf_vector_add(&vec, &i));
    assert_int_gte(vec.cap, 64);
    assert_int_equal(vec.size, 20);

    // All elements should be present.
    for (int i = 0; i < 20; ++i)
        assert_int_equal(*(int *)bf_vector_get(&vec, i), i);
}

static void new_zero_elem_size(void **state)
{
    bf_vector *vec = NULL;

    (void)state;

    assert_err(bf_vector_new(&vec, 0));
    assert_null(vec);
}

static void set(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    for (int i = 0; i < 5; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    // Overwrite element at index 2: [0,1,2,3,4] -> [0,1,99,3,4]
    int val = 99;
    assert_ok(bf_vector_set(&vec, 2, &val));
    assert_int_equal(*(int *)bf_vector_get(&vec, 2), 99);

    // Other elements unchanged
    assert_int_equal(*(int *)bf_vector_get(&vec, 0), 0);
    assert_int_equal(*(int *)bf_vector_get(&vec, 1), 1);
    assert_int_equal(*(int *)bf_vector_get(&vec, 3), 3);
    assert_int_equal(*(int *)bf_vector_get(&vec, 4), 4);
    assert_int_equal(vec.size, 5);

    // Out of bounds
    assert_null(bf_vector_get(&vec, 5));
    assert_null(bf_vector_get(&vec, 99));
    assert_err(bf_vector_set(&vec, 5, &val));
    assert_err(bf_vector_set(&vec, 99, &val));
}

static void add_many(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));
    int vals[] = {10, 20, 30, 40, 50};

    (void)state;

    // Bulk-append into empty vector
    assert_ok(bf_vector_add_many(&vec, vals, ARRAY_SIZE(vals)));
    assert_int_equal(vec.size, 5);

    for (size_t i = 0; i < ARRAY_SIZE(vals); ++i)
        assert_int_equal(*(int *)bf_vector_get(&vec, i), vals[i]);

    // Bulk-append on top of existing elements
    int more[] = {60, 70};
    assert_ok(bf_vector_add_many(&vec, more, ARRAY_SIZE(more)));
    assert_int_equal(vec.size, 7);
    assert_int_equal(*(int *)bf_vector_get(&vec, 5), 60);
    assert_int_equal(*(int *)bf_vector_get(&vec, 6), 70);

    // Zero-count is a no-op
    assert_ok(bf_vector_add_many(&vec, vals, 0));
    assert_int_equal(vec.size, 7);
}

static void add_many_bytes(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(1);
    uint8_t chunk1[] = {0xaa, 0xbb, 0xcc};
    uint8_t chunk2[] = {0xdd, 0xee};

    (void)state;

    assert_ok(bf_vector_add_many(&vec, chunk1, sizeof(chunk1)));
    assert_ok(bf_vector_add_many(&vec, chunk2, sizeof(chunk2)));
    assert_int_equal(vec.size, 5);

    uint8_t *p = vec.data;
    assert_int_equal(p[0], 0xaa);
    assert_int_equal(p[1], 0xbb);
    assert_int_equal(p[2], 0xcc);
    assert_int_equal(p[3], 0xdd);
    assert_int_equal(p[4], 0xee);
}

static void take(void **state)
{
    _clean_bf_vector_ bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    // Take from empty vector returns NULL
    assert_null(bf_vector_take(&vec));

    for (int i = 0; i < 5; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    assert_int_equal(vec.size, 5);

    _cleanup_free_ void *buf = bf_vector_take(&vec);
    assert_non_null(buf);

    // Vector is reset after take
    assert_int_equal(vec.size, 0);
    assert_int_equal(vec.cap, 0);
    assert_null(vec.data);

    // Taken buffer still has the data
    for (int i = 0; i < 5; ++i)
        assert_int_equal(((int *)buf)[i], i);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(add_and_get),
        cmocka_unit_test(remove_elem),
        cmocka_unit_test(foreach),
        cmocka_unit_test(foreach_empty),
        cmocka_unit_test(reserve),
        cmocka_unit_test(new_zero_elem_size),
        cmocka_unit_test(set),
        cmocka_unit_test(add_many),
        cmocka_unit_test(add_many_bytes),
        cmocka_unit_test(take),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
