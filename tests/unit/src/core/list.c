/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/list.c"

#include <criterion/criterion.h>

#include "test.h"

static void noop_free(void **data)
{
    UNUSED(data);
}

static void dummy_free(void **data)
{
    free(*data);
    *data = NULL;
}

static int _dummy_filler(bf_list *l, void *data,
                         int (*add)(bf_list *l, void *data))
{
    _cleanup_free_ int *_data;
    int r;

    _data = malloc(sizeof(*_data));
    if (!_data)
        return -ENOMEM;

    *_data = *(int *)data;

    r = add(l, _data);
    if (r < 0)
        return r;

    TAKE_PTR(_data);

    return 0;
}

static int dummy_filler_head(bf_list *l, void *data)
{
    return _dummy_filler(l, data, bf_list_add_head);
}

static int dummy_filler_tail(bf_list *l, void *data)
{
    return _dummy_filler(l, data, bf_list_add_tail);
}

static void new_and_fill(bf_list **l, size_t count, const bf_list_ops *ops,
                         int (*filler)(bf_list *l, void *data))
{
    cr_assert_eq(0, bf_list_new(l, ops));

    for (size_t i = 1; i <= count; ++i)
        cr_assert_eq(0, filler(*l, &i));

    cr_assert_eq(count, bf_list_size(*l));
}

static void init_and_fill(bf_list *l, size_t count, const bf_list_ops *ops,
                          int (*filler)(bf_list *l, void *data))
{
    bf_list_init(l, ops);

    for (size_t i = 1; i <= count; ++i)
        cr_assert_eq(0, filler(l, &i));

    cr_assert_eq(count, bf_list_size(l));
}

static bf_list_ops noop_ops = {.free = noop_free};
static bf_list_ops dummy_ops = {.free = dummy_free};

TestAssert(src_core_list, bf_list_new, 0, (NULL, NOT_NULL));
TestAssert(src_core_list, bf_list_new, 1, (NOT_NULL, NULL));
TestAssert(src_core_list, bf_list_free, 0, (NULL));
TestAssert(src_core_list, bf_list_init, 0, (NULL, NOT_NULL));
TestAssert(src_core_list, bf_list_init, 1, (NOT_NULL, NULL));
TestAssert(src_core_list, bf_list_clean, 0, (NULL));
TestAssert(src_core_list, bf_list_size, 0, (NULL));
TestAssert(src_core_list, bf_list_add_head, 0, (NULL, NOT_NULL));
TestAssert(src_core_list, bf_list_add_tail, 0, (NULL, NOT_NULL));
TestAssert(src_core_list, bf_list_get_head, 0, (NULL));
TestAssert(src_core_list, bf_list_get_tail, 0, (NULL));
TestAssert(src_core_list, bf_list_node_next, 0, (NULL));
TestAssert(src_core_list, bf_list_node_prev, 0, (NULL));
TestAssert(src_core_list, bf_list_node_get_data, 0, (NULL));
TestAssert(src_core_list, bf_list_node_take_data, 0, (NULL));

Test(src_core_list, new_and_free)
{
    bf_list *l = NULL;

    {
        // With noop operators
        cr_assert_eq(0, bf_list_new(&l, &noop_ops));
        cr_assert_eq(0, l->len);
        cr_assert_null(l->head);
        cr_assert_null(l->tail);

        bf_list_free(&l);
        cr_assert_null(l);

        new_and_fill(&l, 3, &noop_ops, bf_list_add_head);
        cr_assert_eq(3, l->len);
        cr_assert_not_null(l->head);
        cr_assert_not_null(l->tail);

        bf_list_free(&l);
        cr_assert_null(l);
    }

    {
        // With dummy operators which allocate memory
        bf_list_new(&l, &dummy_ops);
        cr_assert_eq(0, l->len);
        cr_assert_null(l->head);
        cr_assert_null(l->tail);

        bf_list_free(&l);
        cr_assert_null(l);

        new_and_fill(&l, 3, &dummy_ops, dummy_filler_head);
        cr_assert_eq(3, l->len);
        cr_assert_not_null(l->head);
        cr_assert_not_null(l->tail);

        bf_list_free(&l);
        cr_assert_null(l);
    }
}

Test(src_core_list, init_and_clean)
{
    bf_list l;

    {
        // With noop operators
        bf_list_init(&l, &noop_ops);
        cr_assert_eq(0, l.len);
        cr_assert_null(l.head);
        cr_assert_null(l.tail);

        bf_list_clean(&l);
        cr_assert_eq(0, l.len);
        cr_assert_null(l.head);
        cr_assert_null(l.tail);

        init_and_fill(&l, 3, &noop_ops, bf_list_add_head);
        cr_assert_eq(3, l.len);
        cr_assert_not_null(l.head);
        cr_assert_not_null(l.tail);

        bf_list_clean(&l);
        cr_assert_eq(0, l.len);
        cr_assert_null(l.head);
        cr_assert_null(l.tail);
    }

    {
        // With dummy operators which allocate memory
        bf_list_init(&l, &dummy_ops);
        cr_assert_eq(0, l.len);
        cr_assert_null(l.head);
        cr_assert_null(l.tail);

        bf_list_clean(&l);
        cr_assert_eq(0, l.len);
        cr_assert_null(l.head);
        cr_assert_null(l.tail);

        init_and_fill(&l, 3, &dummy_ops, dummy_filler_head);
        cr_assert_eq(3, l.len);
        cr_assert_not_null(l.head);
        cr_assert_not_null(l.tail);

        bf_list_clean(&l);
        cr_assert_eq(0, l.len);
        cr_assert_null(l.head);
        cr_assert_null(l.tail);
    }
}

Test(src_core_list, fill_from_head_and_check)
{
    bf_list list;
    size_t i;

    bf_list_init(&list, &dummy_ops);

    cr_assert_null(bf_list_get_head(&list));

    // Fill list at head with values from 1 to 10, expecting:
    // 10 -> 9 -> ... -> 2 -> 1
    init_and_fill(&list, 10, &dummy_ops, dummy_filler_head);

    // Validate content of the list
    i = bf_list_size(&list);

    bf_list_foreach (&list, it) {
        cr_assert_not_null(it);
        cr_assert_eq(i, *(int *)bf_list_node_get_data(it));
        --i;
    }

    i = 1;

    bf_list_foreach_rev (&list, it) {
        cr_assert_not_null(it);
        cr_assert_eq(i, *(int *)bf_list_node_get_data(it));
        ++i;
    }

    bf_list_clean(&list);
}

Test(src_core_list, iterate_and_remove)
{
    bf_list l;

    init_and_fill(&l, 10, &dummy_ops, dummy_filler_head);

    bf_list_foreach (&l, node)
        bf_list_delete(&l, node);

    cr_assert_eq(0, bf_list_size(&l));
    cr_assert_null(l.head);
    cr_assert_null(l.tail);

    bf_list_clean(&l);

    bf_list_foreach_rev (&l, node)
        bf_list_delete(&l, node);

    cr_assert_eq(0, bf_list_size(&l));
    cr_assert_null(l.head);
    cr_assert_null(l.tail);

    bf_list_clean(&l);
}

Test(src_core_list, fill_from_tail_and_check)
{
    bf_list list;
    size_t i;

    bf_list_init(&list, &dummy_ops);

    cr_assert_null(bf_list_get_head(&list));

    // Fill list at tail with values from 1 to 10, expecting:
    // 1 -> 2 -> ... -> 9 -> 10
    init_and_fill(&list, 10, &dummy_ops, dummy_filler_tail);

    // Validate content of the list
    i = 1;

    bf_list_foreach (&list, it) {
        cr_assert_not_null(it);
        cr_assert_eq(i, *(int *)bf_list_node_get_data(it));
        ++i;
    }

    i = bf_list_size(&list);

    bf_list_foreach_rev (&list, it) {
        cr_assert_not_null(it);
        cr_assert_eq(i, *(int *)bf_list_node_get_data(it));
        --i;
    }

    bf_list_clean(&list);
}
