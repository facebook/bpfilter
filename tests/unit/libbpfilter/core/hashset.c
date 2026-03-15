/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>

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

static const bf_hashset_ops _bf_uint32_ops_nofree = {
    .hash = _bf_uint32_hash,
    .equal = _bf_uint32_equal,
    .free = NULL,
};

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
    uint32_t *val;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    val = malloc(sizeof(*val));
    assert_non_null(val);
    *val = 42;

    assert_false(bf_hashset_contains(&set, val));
    assert_ok(bf_hashset_add(&set, val));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, val));
}

static void add_multiple(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 5; ++i) {
        uint32_t *val = malloc(sizeof(*val));
        assert_non_null(val);
        *val = i * 100;
        assert_ok(bf_hashset_add(&set, val));
    }

    assert_int_equal(bf_hashset_size(&set), 5);

    for (uint32_t i = 0; i < 5; ++i) {
        uint32_t key = i * 100;
        assert_true(bf_hashset_contains(&set, &key));
    }
}

static void add_duplicate(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t *val1, *val2;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    val1 = malloc(sizeof(*val1));
    assert_non_null(val1);
    *val1 = 42;

    val2 = malloc(sizeof(*val2));
    assert_non_null(val2);
    *val2 = 42;

    assert_ok(bf_hashset_add(&set, val1));
    // val2 is a duplicate; hashset returns -EEXIST and doesn't take ownership
    assert_int_equal(bf_hashset_add(&set, val2), -EEXIST);
    assert_int_equal(bf_hashset_size(&set), 1);

    free(val2);
}

static void get(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t *val;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    val = malloc(sizeof(*val));
    assert_non_null(val);
    *val = 42;
    assert_ok(bf_hashset_add(&set, val));

    key = 42;
    assert_ptr_equal(bf_hashset_get(&set, &key), val);

    key = 99;
    assert_null(bf_hashset_get(&set, &key));
}

static void remove_elem(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t *val1, *val2;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    val1 = malloc(sizeof(*val1));
    assert_non_null(val1);
    *val1 = 10;

    val2 = malloc(sizeof(*val2));
    assert_non_null(val2);
    *val2 = 20;

    assert_ok(bf_hashset_add(&set, val1));
    assert_ok(bf_hashset_add(&set, val2));
    assert_int_equal(bf_hashset_size(&set), 2);

    key = 10;
    assert_ok(bf_hashset_remove(&set, &key));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_false(bf_hashset_contains(&set, &key));

    key = 20;
    assert_true(bf_hashset_contains(&set, &key));

    // Remove nonexistent is a no-op
    key = 99;
    assert_ok(bf_hashset_remove(&set, &key));
    assert_int_equal(bf_hashset_size(&set), 1);
}

static void remove_and_readd(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t *val, *val2;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    val = malloc(sizeof(*val));
    assert_non_null(val);
    *val = 42;
    assert_ok(bf_hashset_add(&set, val));

    key = 42;
    assert_ok(bf_hashset_remove(&set, &key));
    assert_false(bf_hashset_contains(&set, &key));

    // Re-add after removal (tombstone reuse)
    val2 = malloc(sizeof(*val2));
    assert_non_null(val2);
    *val2 = 42;
    assert_ok(bf_hashset_add(&set, val2));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, &key));
}

static void foreach_basic(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
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

    for (uint32_t i = 0; i < 3; ++i) {
        uint32_t *val = malloc(sizeof(*val));
        assert_non_null(val);
        *val = i + 1;
        assert_ok(bf_hashset_add(&set, val));
    }

    count = 0;
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 3);
}

static void foreach_after_removal(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 3; ++i) {
        uint32_t *val = malloc(sizeof(*val));
        assert_non_null(val);
        *val = i + 1;
        assert_ok(bf_hashset_add(&set, val));
    }

    uint32_t key = 2;
    assert_ok(bf_hashset_remove(&set, &key));

    // Tombstoned slot must be skipped
    count = 0;
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 2);
}

static void foreach_break(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 3; ++i) {
        uint32_t *val = malloc(sizeof(*val));
        assert_non_null(val);
        *val = i + 1;
        assert_ok(bf_hashset_add(&set, val));
    }

    count = 0;
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        ++count;
        break;
    }
    assert_int_equal(count, 1);
}

static void grow(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 20; ++i) {
        uint32_t *val = malloc(sizeof(*val));
        assert_non_null(val);
        *val = i;
        assert_ok(bf_hashset_add(&set, val));
    }

    assert_int_equal(bf_hashset_size(&set), 20);
    assert_true(bf_hashset_cap(&set) > 16);

    for (uint32_t i = 0; i < 20; ++i) {
        uint32_t key = i;
        assert_true(bf_hashset_contains(&set, &key));
    }
}

static void nofree_ops(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t stack_vals[] = {100, 200, 300};

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops_nofree, NULL);

    for (size_t i = 0; i < ARRAY_SIZE(stack_vals); ++i)
        assert_ok(bf_hashset_add(&set, &stack_vals[i]));

    assert_int_equal(bf_hashset_size(&set), 3);
    assert_true(bf_hashset_contains(&set, &stack_vals[0]));
    assert_true(bf_hashset_contains(&set, &stack_vals[1]));
    assert_true(bf_hashset_contains(&set, &stack_vals[2]));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(add_and_contains),
        cmocka_unit_test(add_multiple),
        cmocka_unit_test(add_duplicate),
        cmocka_unit_test(get),
        cmocka_unit_test(remove_elem),
        cmocka_unit_test(remove_and_readd),
        cmocka_unit_test(foreach_basic),
        cmocka_unit_test(foreach_after_removal),
        cmocka_unit_test(foreach_break),
        cmocka_unit_test(grow),
        cmocka_unit_test(nofree_ops),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
