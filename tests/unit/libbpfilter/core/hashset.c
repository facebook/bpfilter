/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    assert_ok(bf_hashset_add(&set, _make_u32(42)));

    key = 42;
    assert_ok(bf_hashset_remove(&set, &key));
    assert_false(bf_hashset_contains(&set, &key));

    // Re-add after removal (tombstone reuse)
    assert_ok(bf_hashset_add(&set, _make_u32(42)));
    assert_int_equal(bf_hashset_size(&set), 1);
    assert_true(bf_hashset_contains(&set, &key));
}

static void foreach_basic(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count;
    uint32_t sum;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    // foreach on empty set does nothing
    count = 0;
    bf_hashset_foreach (&set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 0);

    for (uint32_t i = 0; i < 3; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i + 1)));

    count = 0;
    sum = 0;
    bf_hashset_foreach (&set, elem) {
        sum += *(uint32_t *)elem;
        ++count;
    }
    assert_int_equal(count, 3);
    assert_int_equal(sum, 1 + 2 + 3);
}

static void foreach_after_removal(void **state)
{
    _clean_bf_hashset_ bf_hashset set;
    size_t count;
    uint32_t key;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    for (uint32_t i = 0; i < 3; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i + 1)));

    key = 2;
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

static void grow(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

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
}

static void take(void **state)
{
    _clean_bf_hashset_ bf_hashset set;

    (void)state;

    bf_hashset_init(&set, &_bf_uint32_ops, NULL);

    // Take from empty set returns NULL
    {
        size_t n = 42;
        _cleanup_free_ void **slots = bf_hashset_take(&set, &n);
        assert_null(slots);
        assert_int_equal(n, 0);
        assert_true(bf_hashset_is_empty(&set));
    }

    for (uint32_t i = 0; i < 3; ++i)
        assert_ok(bf_hashset_add(&set, _make_u32(i + 1)));

    assert_int_equal(bf_hashset_size(&set), 3);

    {
        size_t n = 0;
        _cleanup_free_ void **slots = bf_hashset_take(&set, &n);

        // Set is reset after take
        assert_true(bf_hashset_is_empty(&set));
        assert_int_equal(bf_hashset_size(&set), 0);
        assert_int_equal(bf_hashset_cap(&set), 0);

        // Taken array has slots; count live elements and free them
        assert_non_null(slots);
        assert_true(n > 0);
        size_t count = 0;
        for (size_t i = 0; i < n; ++i) {
            if (!slots[i] || bf_hashset_slot_is_tombstone(slots[i]))
                continue;
            ++count;
            free(slots[i]);
        }
        assert_int_equal(count, 3);
    }
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
        cmocka_unit_test(foreach_basic),
        cmocka_unit_test(foreach_after_removal),
        cmocka_unit_test(foreach_break),
        cmocka_unit_test(grow),
        cmocka_unit_test(take),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
