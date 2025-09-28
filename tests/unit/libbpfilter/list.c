/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/list.c"

#include "harness/test.h"
#include "harness/filters.h"
#include "mock.h"

static int _dummy_filler(bf_list *l, void *data,
                         int (*add)(bf_list *l, void *data))
{
    _cleanup_free_ int *_data = NULL;
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
    assert_success(bf_list_new(l, ops));

    for (size_t i = 1; i <= count; ++i)
        assert_success(filler(*l, &i));

    assert_int_equal(count, bf_list_size(*l));
}

static void init_and_fill(bf_list *l, size_t count, const bf_list_ops *ops,
                          int (*filler)(bf_list *l, void *data))
{
    bf_list_init(l, ops);

    for (size_t i = 1; i <= count; ++i)
        assert_success(filler(l, &i));

    assert_int_equal(count, bf_list_size(l));
}

Test(list, new_and_free)
{
    bf_list *l = NULL;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    expect_assert_failure(bf_list_new(NULL, NOT_NULL));
    expect_assert_failure(bf_list_free(NULL));
    expect_assert_failure(bf_list_add_head(NULL, NOT_NULL));

    {
        // With noop operators
        assert_success(bf_list_new(&l, NULL));
        assert_int_equal(0, l->len);
        assert_null(l->head);
        assert_null(l->tail);

        bf_list_free(&l);
        assert_null(l);

        new_and_fill(&l, 3, NULL, bf_list_add_head);
        assert_int_equal(3, l->len);
        assert_non_null(l->head);
        assert_non_null(l->tail);

        bf_list_free(&l);
        assert_null(l);
    }

    {
        // With dummy operators which allocate memory
        bf_list_new(&l, &free_ops);
        assert_int_equal(0, l->len);
        assert_null(l->head);
        assert_null(l->tail);

        bf_list_free(&l);
        assert_null(l);

        new_and_fill(&l, 3, &free_ops, dummy_filler_head);
        assert_int_equal(3, l->len);
        assert_non_null(l->head);
        assert_non_null(l->tail);

        bf_list_free(&l);
        assert_null(l);
    }
}

Test(list, init_and_clean)
{
    bf_list l;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    expect_assert_failure(bf_list_init(NULL, NOT_NULL));
    expect_assert_failure(bf_list_clean(NULL));

    {
        // Automatically cleanup
        _clean_bf_list_ bf_list list;
        init_and_fill(&list, 3, &free_ops, dummy_filler_head);
    }

    {
        // With noop operators
        bf_list_init(&l, NULL);
        assert_int_equal(0, l.len);
        assert_null(l.head);
        assert_null(l.tail);

        bf_list_clean(&l);
        assert_int_equal(0, l.len);
        assert_null(l.head);
        assert_null(l.tail);

        init_and_fill(&l, 3, NULL, bf_list_add_head);
        assert_int_equal(3, l.len);
        assert_non_null(l.head);
        assert_non_null(l.tail);

        bf_list_clean(&l);
        assert_int_equal(0, l.len);
        assert_null(l.head);
        assert_null(l.tail);
    }

    {
        // With dummy operators which allocate memory
        bf_list_init(&l, &free_ops);
        assert_int_equal(0, l.len);
        assert_null(l.head);
        assert_null(l.tail);

        bf_list_clean(&l);
        assert_int_equal(0, l.len);
        assert_null(l.head);
        assert_null(l.tail);

        init_and_fill(&l, 3, &free_ops, dummy_filler_head);
        assert_int_equal(3, l.len);
        assert_non_null(l.head);
        assert_non_null(l.tail);

        bf_list_clean(&l);
        assert_int_equal(0, l.len);
        assert_null(l.head);
        assert_null(l.tail);
    }
}

Test(list, pack_unpack)
{
    _free_bf_list_ bf_list *l0 = NULL;
    _clean_bf_list_ bf_list l1 = bf_list_default(freep, bft_list_dummy_data_pack);
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t list_node, list_elem_node;
    const void *data;
    size_t data_len;

    expect_assert_failure(bf_list_pack(NULL, NOT_NULL));
    expect_assert_failure(bf_list_pack(NOT_NULL, NULL));

    assert_non_null(l0 = bft_list_get(10, 50));

    assert_success(bf_wpack_new(&wpack));
    bf_wpack_open_array(wpack, "list");
    assert_success(bf_list_pack(l0, wpack));
    bf_wpack_close_array(wpack);
    assert_success(bf_wpack_get_data(wpack, &data, &data_len));

    assert_success(bf_rpack_new(&rpack, data, data_len));
    assert_success(bf_rpack_kv_array(bf_rpack_root(rpack), "list", &list_node));
    bf_rpack_array_foreach (list_node, list_elem_node) {
        _cleanup_free_ struct bft_list_dummy_data *data = NULL;
        assert_success(bf_list_emplace(&l1, bft_list_dummy_data_new_from_pack, data, list_elem_node));
    }

    assert_true(bft_list_eq(l0, &l1, (bft_list_eq_cb)bft_list_dummy_data_compare));
}

Test(list, fill_from_head_and_check)
{
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);
    bf_list list;
    size_t i;

    expect_assert_failure(bf_list_size(NULL));
    expect_assert_failure(bf_list_get_head(NULL));
    expect_assert_failure(bf_list_node_get_data(NULL));

    bf_list_init(&list, &free_ops);

    assert_null(bf_list_get_head(&list));

    // Fill list at head with values from 1 to 10, expecting:
    // 10 -> 9 -> ... -> 2 -> 1
    init_and_fill(&list, 10, &free_ops, dummy_filler_head);

    // Validate content of the list
    i = bf_list_size(&list);

    bf_list_foreach (&list, it) {
        assert_non_null(it);
        assert_int_equal(i, *(int *)bf_list_node_get_data(it));
        --i;
    }

    i = 1;

    bf_list_foreach_rev (&list, it) {
        assert_non_null(it);
        assert_int_equal(i, *(int *)bf_list_node_get_data(it));
        ++i;
    }

    bf_list_clean(&list);
}

Test(list, iterate_and_remove)
{
    bf_list l;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    init_and_fill(&l, 10, &free_ops, dummy_filler_head);

    bf_list_foreach (&l, node)
        bf_list_delete(&l, node);

    assert_int_equal(0, bf_list_size(&l));
    assert_null(l.head);
    assert_null(l.tail);

    bf_list_clean(&l);

    bf_list_foreach_rev (&l, node)
        bf_list_delete(&l, node);

    assert_int_equal(0, bf_list_size(&l));
    assert_null(l.head);
    assert_null(l.tail);

    bf_list_clean(&l);
}

Test(list, get_at)
{
    bf_list l;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    expect_assert_failure(bf_list_get_at(NULL, 1));

    // Fill the list with values from 1 to 10
    init_and_fill(&l, 10, &free_ops, dummy_filler_tail);

    // Index 0 contains value 1 and so on
    assert_int_equal(1, *(int *)bf_list_get_at(&l, 0));
    assert_int_equal(5, *(int *)bf_list_get_at(&l, 4));
    assert_int_equal(10, *(int *)bf_list_get_at(&l, 9));

    // Index 20 is out of the list
    assert_null(bf_list_get_at(&l, 20));

    bf_list_clean(&l);
}

Test(list, fill_from_tail_and_check)
{
    bf_list list;
    size_t i;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    expect_assert_failure(bf_list_add_tail(NULL, NOT_NULL));
    expect_assert_failure(bf_list_get_tail(NULL));

    bf_list_init(&list, &free_ops);

    assert_null(bf_list_get_head(&list));

    // Fill list at tail with values from 1 to 10, expecting:
    // 1 -> 2 -> ... -> 9 -> 10
    init_and_fill(&list, 10, &free_ops, dummy_filler_tail);

    // Validate content of the list
    i = 1;

    bf_list_foreach (&list, it) {
        assert_non_null(it);
        assert_int_equal(i, *(int *)bf_list_node_get_data(it));
        ++i;
    }

    i = bf_list_size(&list);

    bf_list_foreach_rev (&list, it) {
        assert_non_null(it);
        assert_int_equal(i, *(int *)bf_list_node_get_data(it));
        --i;
    }

    bf_list_clean(&list);
}

Test(list, is_tail)
{
    bf_list l;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    expect_assert_failure(bf_list_is_tail(NULL, NOT_NULL));
    expect_assert_failure(bf_list_is_tail(NOT_NULL, NULL));

    init_and_fill(&l, 10, &free_ops, dummy_filler_head);

    assert_true(bf_list_is_tail(&l, bf_list_get_tail(&l)));
    assert_false(bf_list_is_tail(&l, bf_list_get_head(&l)));

    bf_list_clean(&l);
}

Test(list, prev_next_node_access)
{
    expect_assert_failure(bf_list_node_next(NULL));
    expect_assert_failure(bf_list_node_prev(NULL));

    {
        _free_bf_list_ bf_list *l = NULL;

        new_and_fill(&l, 0, NULL, bf_list_add_head);

        assert_null(bf_list_get_head(l));
        assert_null(bf_list_get_tail(l));
    }

    {
        _free_bf_list_ bf_list *l = NULL;

        new_and_fill(&l, 1, NULL, bf_list_add_head);

        assert_ptr_equal(bf_list_get_head(l), bf_list_get_tail(l));
        assert_null(bf_list_node_next(bf_list_get_tail(l)));
        assert_null(bf_list_node_prev(bf_list_get_head(l)));
    }

    {
        _free_bf_list_ bf_list *l = NULL;

        new_and_fill(&l, 2, NULL, bf_list_add_head);

        assert_ptr_not_equal(bf_list_get_head(l), bf_list_get_tail(l));
        assert_ptr_equal(bf_list_node_next(bf_list_get_head(l)),
                         bf_list_get_tail(l));
        assert_ptr_equal(bf_list_node_prev(bf_list_get_tail(l)),
                         bf_list_get_head(l));
    }
}

Test(list, node_take_data)
{
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    {
        _free_bf_list_ bf_list *l = NULL;

        new_and_fill(&l, 5, &free_ops, dummy_filler_tail);

        bf_list_foreach (l, node) {
            assert_non_null(node);
            assert_non_null(node->data);

            void *data = bf_list_node_take_data(node);
            assert_non_null(data);
            assert_null(node->data);

            free(data);
        }
    }
}

Test(list, push_to_list)
{
    bf_list list;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

    int dummy_int = 1;
    _cleanup_free_ int *dummy_int_ptr = NULL;
    _cleanup_free_ void *dummy_void_ptr_ptr = malloc(sizeof(void*));

    bf_list_init(&list, &free_ops);
    expect_assert_failure(bf_list_push(NULL, NULL));
    expect_assert_failure(bf_list_push(NULL, &dummy_void_ptr_ptr));
    expect_assert_failure(bf_list_push(NOT_NULL, NULL));

    dummy_int_ptr = malloc(sizeof(dummy_int));
    *dummy_int_ptr = dummy_int;

    bf_list_push(&list, (void **)&dummy_int_ptr);
    assert_int_equal(*(int *)bf_list_node_get_data(list.tail), dummy_int);
    assert_ptr_equal(list.head, list.tail);
    assert_null(dummy_int_ptr);
    assert_int_equal(bf_list_size(&list), 1);

    dummy_int = 2;
    dummy_int_ptr = malloc(sizeof(dummy_int));
    *dummy_int_ptr = dummy_int;

    bf_list_push(&list, (void **)&dummy_int_ptr);
    assert_int_equal(*(int *)bf_list_node_get_data(list.tail), dummy_int);
    assert_ptr_equal(list.head->next, list.tail);
    assert_ptr_equal(list.tail->prev, list.head);
    assert_null(dummy_int_ptr);
    assert_int_equal(bf_list_size(&list), 2);
    assert_null(list.tail->next);

    bf_list_clean(&list);
}
