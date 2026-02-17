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
    return bf_fnv1a(data, sizeof(uint32_t), bf_fnv1a_init());
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

/* Hash function that always returns 0, forcing every element into the same
 * bucket so that all insertions collide and exercise linear probing. */
static uint64_t _bf_uint32_collide_hash(const void *data, void *ctx)
{
    (void)data;
    (void)ctx;
    return 0;
}

static const bf_hashset_ops _bf_uint32_collide_ops = {
    .hash = _bf_uint32_collide_hash,
    .equal = _bf_uint32_equal,
    .free = _bf_uint32_free,
};

static uint32_t *_make_u32(uint32_t val)
{
    uint32_t *ptr = malloc(sizeof(*ptr));
    assert_non_null(ptr);
    *ptr = val;
    return ptr;
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
}

static void add_and_contains(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key = 42;
    uint32_t *dup;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    // Single add + contains
    assert_false(bf_hashset_contains(&set, &key));
    ptr = _make_u32(key);
    assert_ok(bf_hashset_add(&set, &ptr));
    assert_null(ptr);
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, &key));

    // Duplicate returns -EEXIST and doesn't take ownership
    dup = _make_u32(key);
    ptr = dup;
    assert_int_equal(bf_hashset_add(&set, &ptr), -EEXIST);
    assert_ptr_equal(ptr, dup);
    assert_int_equal(bf_hashset_size(&set), 1);
    free(dup);

    // Add more elements
    for (uint32_t i = 0; i < 4; ++i) {
        ptr = _make_u32(i * 100);
        assert_ok(bf_hashset_add(&set, &ptr));
        assert_null(ptr);
    }

    assert_int_equal(bf_hashset_size(&set), 5);
    assert_true(bf_hashset_contains(&set, &key));
    for (uint32_t i = 0; i < 4; ++i) {
        uint32_t other = i * 100;
        assert_true(bf_hashset_contains(&set, &other));
    }
}

static void delete_elem(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    ptr = _make_u32(10);
    assert_ok(bf_hashset_add(&set, &ptr));
    ptr = _make_u32(20);
    assert_ok(bf_hashset_add(&set, &ptr));
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

static void delete_and_readd(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key = 42;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    ptr = _make_u32(key);
    assert_ok(bf_hashset_add(&set, &ptr));

    assert_ok(bf_hashset_delete(&set, &key));
    assert_false(bf_hashset_contains(&set, &key));

    ptr = _make_u32(key);
    assert_ok(bf_hashset_add(&set, &ptr));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, &key));
}

static void take(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key = 42;
    void *ptr;
    void *taken = NULL;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    ptr = _make_u32(key);
    assert_ok(bf_hashset_add(&set, &ptr));

    assert_ok(bf_hashset_take(&set, &key, &taken));
    assert_non_null(taken);
    assert_int_equal(*(uint32_t *)taken, key);
    assert_false(bf_hashset_contains(&set, &key));
    assert_int_equal(bf_hashset_size(&set), 0);
    free(taken);

    taken = NULL;
    assert_int_equal(bf_hashset_take(&set, &key, &taken), -ENOENT);
    assert_null(taken);
}

static void foreach(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t expected[] = {100, 200, 300, 400, 500};
    size_t idx;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    // foreach on empty set does nothing
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        assert_true(0);
    }

    // Insertion order is preserved
    for (uint32_t i = 0; i < 5; ++i) {
        ptr = _make_u32(expected[i]);
        assert_ok(bf_hashset_add(&set, &ptr));
    }

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
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 1; i <= 5; ++i) {
        ptr = _make_u32(i);
        assert_ok(bf_hashset_add(&set, &ptr));
    }

    key = 3;
    assert_ok(bf_hashset_delete(&set, &key));
    assert_int_equal(bf_hashset_size(&set), 4);

    // Removed element is skipped, order preserved
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, expected[idx]);
        ++idx;
    }
    assert_int_equal(idx, 4);
}

static void foreach_remove(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count = 0;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 1; i <= 5; ++i) {
        ptr = _make_u32(i);
        assert_ok(bf_hashset_add(&set, &ptr));
    }

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
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    assert_ok(bf_hashset_reserve(&set, 0));
    assert_ok(bf_hashset_reserve(&set, 10));
    assert_ok(bf_hashset_reserve(&set, 100));

    for (uint32_t i = 0; i < 100; ++i) {
        ptr = _make_u32(i);
        assert_ok(bf_hashset_add(&set, &ptr));
    }
    assert_int_equal(bf_hashset_size(&set), 100);

    // These are no-ops now.
    assert_ok(bf_hashset_reserve(&set, 0));
    assert_ok(bf_hashset_reserve(&set, 10));
    assert_ok(bf_hashset_reserve(&set, 100));

    for (uint32_t i = 0; i < 100; ++i) {
        uint32_t key = i;
        assert_true(bf_hashset_contains(&set, &key));
    }
}

static void grow(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t idx;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 100; ++i) {
        ptr = _make_u32(i);
        assert_ok(bf_hashset_add(&set, &ptr));
    }

    assert_int_equal(bf_hashset_size(&set), 100);

    for (uint32_t i = 0; i < 100; ++i) {
        uint32_t key = i;
        assert_true(bf_hashset_contains(&set, &key));
    }

    // Insertion order is preserved across grow
    idx = 0;
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, idx);
        ++idx;
    }
    assert_int_equal(idx, 100);
}

static void collisions(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    uint32_t key;
    size_t idx;
    void *ptr;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_collide_ops, NULL);

    for (uint32_t i = 1; i <= 6; ++i) {
        ptr = _make_u32(i * 10);
        assert_ok(bf_hashset_add(&set, &ptr));
    }

    assert_int_equal(bf_hashset_size(&set), 6);

    for (uint32_t i = 1; i <= 6; ++i) {
        uint32_t other = i * 10;
        assert_true(bf_hashset_contains(&set, &other));
    }

    // Insertion order preserved despite all hashes colliding
    idx = 0;
    uint32_t expected_before[] = {10, 20, 30, 40, 50, 60};
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, expected_before[idx]);
        ++idx;
    }
    assert_int_equal(idx, 6);

    // Delete from the middle of the probe chain to create tombstones
    key = 20;
    assert_ok(bf_hashset_delete(&set, &key));
    key = 40;
    assert_ok(bf_hashset_delete(&set, &key));

    assert_int_equal(bf_hashset_size(&set), 4);

    // Lookups must still find elements past the tombstones
    key = 10;
    assert_true(bf_hashset_contains(&set, &key));
    key = 30;
    assert_true(bf_hashset_contains(&set, &key));
    key = 50;
    assert_true(bf_hashset_contains(&set, &key));
    key = 60;
    assert_true(bf_hashset_contains(&set, &key));

    // Deleted elements must not be found
    key = 20;
    assert_false(bf_hashset_contains(&set, &key));
    key = 40;
    assert_false(bf_hashset_contains(&set, &key));

    // Re-add into tombstone slots
    ptr = _make_u32(20);
    assert_ok(bf_hashset_add(&set, &ptr));
    ptr = _make_u32(40);
    assert_ok(bf_hashset_add(&set, &ptr));
    assert_int_equal(bf_hashset_size(&set), 6);

    for (uint32_t i = 1; i <= 6; ++i) {
        key = i * 10;
        assert_true(bf_hashset_contains(&set, &key));
    }

    // Insertion order: 10,30,50,60 (survivors) then 20,40 (re-added)
    uint32_t expected_after[] = {10, 30, 50, 60, 20, 40};
    idx = 0;
    bf_hashset_foreach (&set, elem) {
        assert_int_equal(*(uint32_t *)elem->data, expected_after[idx]);
        ++idx;
    }
    assert_int_equal(idx, 6);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(add_and_contains),
        cmocka_unit_test(delete_elem),
        cmocka_unit_test(delete_and_readd),
        cmocka_unit_test(take),
        cmocka_unit_test(foreach),
        cmocka_unit_test(foreach_after_removal),
        cmocka_unit_test(foreach_remove),
        cmocka_unit_test(reserve),
        cmocka_unit_test(grow),
        cmocka_unit_test(collisions),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
