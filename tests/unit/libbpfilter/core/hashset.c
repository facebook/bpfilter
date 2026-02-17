/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/core/hashset.h>
#include <bpfilter/helper.h>

#include "test.h"

static uint64_t _bf_uint32_hash(const void *data, void *ctx)
{
    (void)ctx;
    return bf_fnv1a(data, sizeof(uint32_t), BF_FNV1A_INIT);
}

static bool _bf_uint32_equal(const void *lhs, const void *rhs, void *ctx)
{
    (void)ctx;
    return *(const uint32_t *)lhs == *(const uint32_t *)rhs;
}

static void _bf_uint32_free(void **data, void *ctx)
{
    (void)ctx;
    freep((void *)data);
}

static const bf_hashset_ops _bf_uint32_ops = {
    .hash = _bf_uint32_hash,
    .equal = _bf_uint32_equal,
    .free = _bf_uint32_free,
};

static uint32_t *_make_u32(uint32_t val)
{
    uint32_t *p = malloc(sizeof(*p));
    assert_non_null(p);
    *p = val;
    return p;
}

static void new_and_free(void **state)
{
    _free_bf_hashset_ bf_hashset *set = NULL;

    (void)state;

    assert_ok(bf_hashset_new(&set, &_bf_uint32_ops, NULL));
    assert_non_null(set);
    assert_true(bf_hashset_is_empty(set));
    bf_hashset_free(&set);
    assert_null(set);

    // Auto-free via cleanup attribute
    assert_ok(bf_hashset_new(&set, &_bf_uint32_ops, NULL));
}

static void init_and_clean(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);
    assert_true(bf_hashset_is_empty(&set));
    assert_int_equal(bf_hashset_size(&set), 0);
    assert_int_equal(bf_hashset_cap(&set), 0);
}

static void add_and_contains(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    key = 42;
    assert_false(bf_hashset_contains(&set, &key));
    assert_ok(bf_hashset_add(&set, _make_u32(42)));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, &key));
}

static void add_multiple(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 5; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i * 100)));

    assert_int_equal(bf_hashset_size(&set), 5);

    for (uint32_t i = 0; i < 5; ++i) {
        uint32_t key = i * 100;
        assert_true(bf_hashset_contains(&set, &key));
    }
}

static void add_duplicate(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t *dup;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    assert_ok(bf_hashset_add(&set, _make_u32(42)));

    // Duplicate; hashset returns -EEXIST and doesn't take ownership
    dup = _make_u32(42);
    assert_int_equal(bf_hashset_add(&set, dup), -EEXIST);
    assert_int_equal(bf_hashset_size(&set), 1);
    free(dup);
}

static void remove_elem(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    assert_ok(bf_hashset_add(&set, _make_u32(10)));
    assert_ok(bf_hashset_add(&set, _make_u32(20)));
    assert_int_equal(bf_hashset_size(&set), 2);

    key = 10;
    assert_ok(bf_hashset_delete(&set, &key));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_false(bf_hashset_contains(&set, &key));

    key = 20;
    assert_true(bf_hashset_contains(&set, &key));

    key = 99;
    assert_int_equal(bf_hashset_delete(&set, &key), -ENOENT);
    assert_int_equal(bf_hashset_size(&set), 1);
}

static void remove_and_readd(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    assert_ok(bf_hashset_add(&set, _make_u32(42)));

    key = 42;
    assert_ok(bf_hashset_delete(&set, &key));
    assert_false(bf_hashset_contains(&set, &key));

    assert_ok(bf_hashset_add(&set, _make_u32(42)));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, &key));
}

static void foreach(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t expected[] = {100, 200, 300, 400, 500};
    size_t idx;
    size_t count;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    // foreach on empty set does nothing
    count = 0;
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 0);

    // Insertion order is preserved
    for (uint32_t i = 0; i < 5; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(expected[i])));

    idx = 0;
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, expected[idx]);
        ++idx;
    }
    assert_int_equal(idx, 5);
}

static void foreach_after_removal(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t expected[] = {1, 2, 4, 5};
    uint32_t key;
    size_t idx = 0;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 1; i <= 5; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i)));

    key = 3;
    assert_ok(bf_hashset_delete(&set, &key));

    // Removed element is skipped, order preserved
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, expected[idx]);
        ++idx;
    }
    assert_int_equal(idx, 4);
}

static void foreach_break(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 3; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i + 1)));

    count = 0;
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        ++count;
        break;
    }
    assert_int_equal(count, 1);
}

static void foreach_remove(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count = 0;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 1; i <= 5; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i)));

    // Remove every element during iteration
    bf_hashset_foreach (&set, elem) {
        assert_ok(bf_hashset_delete(&set, elem->data));
        ++count;
    }

    assert_int_equal(count, 5);
    assert_true(bf_hashset_is_empty(&set));
}

static void reserve(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    assert_ok(bf_hashset_reserve(&set, 0));
    assert_int_equal(bf_hashset_cap(&set), 0);

    assert_ok(bf_hashset_reserve(&set, 100));
    assert_true(bf_hashset_cap(&set) >= 200);

    size_t cap_after = bf_hashset_cap(&set);
    for (uint32_t i = 0; i < 100; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i)));
    assert_int_equal(bf_hashset_cap(&set), cap_after);
    assert_int_equal(bf_hashset_size(&set), 100);

    assert_ok(bf_hashset_reserve(&set, 10));
    assert_int_equal(bf_hashset_cap(&set), cap_after);
}

static void grow(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t idx;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);
    assert_true(bf_hashset_cap(&set) <= 16);

    for (uint32_t i = 0; i < 20; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i)));

    assert_int_equal(bf_hashset_size(&set), 20);
    assert_true(bf_hashset_cap(&set) > 16);

    for (uint32_t i = 0; i < 20; ++i) {
        uint32_t key = i;
        assert_true(bf_hashset_contains(&set, &key));
    }

    // Insertion order is preserved across grow
    idx = 0;
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, idx);
        ++idx;
    }
    assert_int_equal(idx, 20);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(add_and_contains),
        cmocka_unit_test(add_multiple),
        cmocka_unit_test(add_duplicate),
        cmocka_unit_test(remove_elem),
        cmocka_unit_test(remove_and_readd),
        cmocka_unit_test(foreach),
        cmocka_unit_test(foreach_after_removal),
        cmocka_unit_test(foreach_break),
        cmocka_unit_test(foreach_remove),
        cmocka_unit_test(reserve),
        cmocka_unit_test(grow),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
