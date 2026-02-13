/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/helper.h>
#include <bpfilter/vector.h>

#include "test.h"

static void new_and_free(void **state)
{
    (void)state;

    {
        // Allocate and free, empty vector
        struct bf_vector *vec;

        assert_ok(bf_vector_new(&vec, sizeof(int)));
        assert_int_equal(bf_vector_len(vec), 0);
        assert_int_equal(bf_vector_cap(vec), 0);
        bf_vector_free(&vec);
        assert_null(vec);
    }

    {
        // Auto-free via cleanup attribute
        _free_bf_vector_ struct bf_vector *vec = NULL;

        assert_ok(bf_vector_new(&vec, sizeof(int)));
        assert_int_equal(bf_vector_len(vec), 0);
    }
}

static void init_and_clean(void **state)
{
    _clean_bf_vector_ struct bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    assert_int_equal(bf_vector_len(&vec), 0);
    assert_int_equal(bf_vector_cap(&vec), 0);
    assert_null(vec.data);

    int val = 42;
    assert_ok(bf_vector_add(&vec, &val));
    assert_int_equal(bf_vector_len(&vec), 1);
    bf_vector_clean(&vec);
    assert_int_equal(bf_vector_len(&vec), 0);
    assert_int_equal(bf_vector_cap(&vec), 0);
    assert_null(vec.data);
}

static void default_macro(void **state)
{
    _clean_bf_vector_ struct bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    assert_int_equal(vec.len, 0);
    assert_int_equal(vec.cap, 0);
    assert_int_equal(vec.elem_size, sizeof(int));
    assert_null(vec.data);
}

static void add_and_get(void **state)
{
    _clean_bf_vector_ struct bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    for (int i = 0; i < 100; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    assert_int_equal(bf_vector_len(&vec), 100);
    assert_int_gte(bf_vector_cap(&vec), 100);

    for (int i = 0; i < 100; ++i) {
        int *p = bf_vector_get(&vec, i);
        assert_non_null(p);
        assert_int_equal(*p, i);
    }

    // Out of bounds returns NULL
    assert_null(bf_vector_get(&vec, 100));
    assert_null(bf_vector_get(&vec, 9999));
}

static void foreach(void **state)
{
    _clean_bf_vector_ struct bf_vector vec = bf_vector_default(sizeof(int));
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
    _clean_bf_vector_ struct bf_vector vec = bf_vector_default(sizeof(int));
    int count = 0;

    (void)state;

    bf_vector_foreach (&vec, elem) {
        (void)elem;
        ++count;
    }

    assert_int_equal(count, 0);
}

static void resize(void **state)
{
    _clean_bf_vector_ struct bf_vector vec = bf_vector_default(sizeof(int));

    (void)state;

    // Resize up from empty
    assert_ok(bf_vector_resize(&vec, 32));
    assert_int_equal(bf_vector_cap(&vec), 32);
    assert_int_equal(bf_vector_len(&vec), 0);

    // Add some elements
    for (int i = 0; i < 10; ++i)
        assert_ok(bf_vector_add(&vec, &i));

    assert_int_equal(bf_vector_len(&vec), 10);

    // Shrink to fit
    assert_ok(bf_vector_resize(&vec, 10));
    assert_int_equal(bf_vector_cap(&vec), 10);
    assert_int_equal(bf_vector_len(&vec), 10);

    // Data is preserved after resize
    for (int i = 0; i < 10; ++i)
        assert_int_equal(*(int *)bf_vector_get(&vec, i), i);

    // Can't shrink below current length
    assert_err(bf_vector_resize(&vec, 5));
    assert_int_equal(bf_vector_cap(&vec), 10);

    // Resize to 0 when empty
    bf_vector_clean(&vec);
    vec = bf_vector_default(sizeof(int));
    assert_ok(bf_vector_resize(&vec, 0));
    assert_int_equal(bf_vector_cap(&vec), 0);
    assert_null(vec.data);
}

static void large_elements(void **state)
{
    struct big
    {
        char buf[256];
    };

    _clean_bf_vector_ struct bf_vector vec =
        bf_vector_default(sizeof(struct big));

    (void)state;

    for (int i = 0; i < 20; ++i) {
        struct big b;
        memset(b.buf, i, sizeof(b.buf));
        assert_ok(bf_vector_add(&vec, &b));
    }

    assert_int_equal(bf_vector_len(&vec), 20);

    for (int i = 0; i < 20; ++i) {
        struct big *p = bf_vector_get(&vec, i);
        assert_non_null(p);

        for (size_t j = 0; j < sizeof(p->buf); ++j)
            assert_int_equal((unsigned char)p->buf[j], (unsigned char)i);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),  cmocka_unit_test(init_and_clean),
        cmocka_unit_test(default_macro), cmocka_unit_test(add_and_get),
        cmocka_unit_test(foreach),       cmocka_unit_test(foreach_empty),
        cmocka_unit_test(resize),        cmocka_unit_test(large_elements),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
