/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/list.h>

#include "fake.h"
#include "test.h"

static void new_and_free(void **state)
{
    (void)state;

    {
        // Allocate and free, no operators

        bf_list *list;

        assert_int_equal(0, bf_list_new(&list, NULL));
        bf_list_free(&list);
        assert_null(list);
    }

    {
        // Allocate and free, custom operators, empty

        bf_list *list;
        bf_list_ops free_ops = bf_list_ops_default(freep, NULL);

        assert_int_equal(0, bf_list_new(&list, &free_ops));
        bf_list_free(&list);
        assert_null(list);
    }

    {
        // Allocate and free, custom operators, non-empty

        bf_list *list;

        assert_non_null(list = bft_list_dummy(10, bf_list_add_head));
        assert_int_equal(bf_list_size(list), 10);
        bf_list_free(&list);
        assert_null(list);
    }

    {
        // Allocate and auto free, custom operators, non-empty

        _free_bf_list_ bf_list *list = NULL;

        assert_non_null(list = bft_list_dummy(10, bf_list_add_head));
        assert_int_equal(bf_list_size(list), 10);
    }
}

static void init_and_clean(void **state)
{
    (void)state;
}

static void pack_and_unpack(void **state)
{
    _free_bf_list_ bf_list *source = NULL;
    _clean_bf_list_ bf_list destination;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t list_node, list_elem_node;
    const void *data;
    size_t data_len;

    (void)state;

    assert_non_null(source = bft_list_dummy(10, bf_list_add_head));
    destination = bf_list_default_from(*source);

    // Pack the source list
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_array(wpack, "list");
    assert_ok(bf_list_pack(source, wpack));
    bf_wpack_close_array(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack in the destination list
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_array(bf_rpack_root(rpack), "list", &list_node));
    bf_rpack_array_foreach (list_node, list_elem_node) {
        _cleanup_free_ size_t *value = NULL;

        assert_non_null(value = malloc(sizeof(*value)));
        assert_ok(bf_rpack_kv_u64(list_elem_node, "size_t", value));

        assert_ok(bf_list_push(&destination, (void **)&value));
    }

    assert_true(
        bft_list_eq(source, &destination, (bft_list_eq_cb)bft_list_dummy_eq));
}

static void move(void **state)
{
    _clean_bf_list_ bf_list destination;
    _free_bf_list_ bf_list *source = NULL;
    _free_bf_list_ bf_list *reference = NULL;

    (void)state;

    assert_non_null(source = bft_list_dummy(10, bf_list_add_head));
    assert_non_null(reference = bft_list_dummy(10, bf_list_add_head));

    destination = bf_list_move(*source);
    assert_true(bft_list_eq(reference, &destination,
                            (bft_list_eq_cb)bft_list_dummy_eq));
}

static void head_and_tail(void **state)
{
    _free_bf_list_ bf_list *list = NULL;

    (void)state;

    assert_non_null(list = bft_list_dummy(10, bf_list_add_head));
    assert_int_equal(bf_list_size(list), 10);
    assert_false(bf_list_is_empty(list));

    // Check head
    assert_false(bf_list_is_head(list, list->tail));
    assert_false(bf_list_is_head(list, list->head->next));
    assert_true(bf_list_is_head(list, list->head));
    assert_ptr_not_equal(bf_list_get_head(list), list->tail);
    assert_ptr_not_equal(bf_list_get_head(list), list->head->next);
    assert_ptr_equal(bf_list_get_head(list), list->head);

    // Check tail
    assert_false(bf_list_is_tail(list, list->head));
    assert_false(bf_list_is_tail(list, list->tail->prev));
    assert_true(bf_list_is_tail(list, list->tail));
    assert_ptr_not_equal(bf_list_get_tail(list), list->head);
    assert_ptr_not_equal(bf_list_get_tail(list), list->tail->prev);
    assert_ptr_equal(bf_list_get_tail(list), list->tail);
}

static void iterate(void **state)
{
    _free_bf_list_ bf_list *list = NULL;

    (void)state;

    assert_non_null(list = bft_list_dummy(10, bf_list_add_tail));

    {
        // Forward
        size_t i = 0;
        const bf_list_node *node0 = bf_list_get_head(list);

        assert_ptr_equal(node0, list->head);

        bf_list_foreach (list, node1) {
            assert_ptr_equal(node0, node1);
            assert_int_equal(i, *(size_t *)bf_list_node_get_data(node0));
            node0 = bf_list_node_next(node0);
            ++i;
        }
    }

    {
        // Backward
        size_t i = bf_list_size(list) - 1;
        const bf_list_node *node0 = bf_list_get_tail(list);

        assert_ptr_equal(node0, list->tail);

        bf_list_foreach_rev (list, node1) {
            assert_ptr_equal(node0, node1);
            assert_int_equal(i, *(size_t *)bf_list_node_get_data(node0));
            node0 = bf_list_node_prev(node0);
            --i;
        }
    }
}

static void insert(void **state)
{
    (void)state;

    {
        // Insert at tail
        _free_bf_list_ bf_list *list = NULL;
        _free_bf_list_ bf_list *reference = NULL;

        assert_non_null(list = bft_list_dummy(0, NULL));
        assert_non_null(reference = bft_list_dummy(10, bf_list_add_tail));

        for (size_t i = 0; i < bf_list_size(reference); ++i) {
            _cleanup_free_ size_t *value = NULL;

            assert_non_null(value = malloc(sizeof(*value)));
            *value = i;

            assert_ok(bf_list_add_tail(list, value));
            TAKE_PTR(value);
        }

        assert_true(
            bft_list_eq(list, reference, (bft_list_eq_cb)bft_list_dummy_eq));
    }

    {
        // Push
        _free_bf_list_ bf_list *list = NULL;
        _free_bf_list_ bf_list *reference = NULL;

        assert_non_null(list = bft_list_dummy(0, NULL));
        assert_non_null(reference = bft_list_dummy(10, bf_list_add_tail));

        for (size_t i = 0; i < bf_list_size(reference); ++i) {
            _cleanup_free_ size_t *value = NULL;

            assert_non_null(value = malloc(sizeof(*value)));
            *value = i;

            assert_ok(bf_list_push(list, (void **)&value));
        }

        assert_true(
            bft_list_eq(list, reference, (bft_list_eq_cb)bft_list_dummy_eq));
    }

    {
        // Insert at head
        _free_bf_list_ bf_list *list = NULL;
        _free_bf_list_ bf_list *reference = NULL;

        assert_non_null(list = bft_list_dummy(0, NULL));
        assert_non_null(reference = bft_list_dummy(10, bf_list_add_head));

        for (size_t i = 0; i < bf_list_size(reference); ++i) {
            _cleanup_free_ size_t *value = NULL;

            assert_non_null(value = malloc(sizeof(*value)));
            *value = i;

            assert_ok(bf_list_add_head(list, value));
            TAKE_PTR(value);
        }

        assert_true(
            bft_list_eq(list, reference, (bft_list_eq_cb)bft_list_dummy_eq));
    }
}

static void delete(void **state)
{
    _free_bf_list_ bf_list *list = NULL;
    _free_bf_list_ bf_list *reference = NULL;

    (void)state;

    assert_non_null(list = bft_list_dummy(10, bf_list_add_tail));
    assert_non_null(reference = bft_list_dummy(0, NULL));

    // Build the reference list
    for (size_t i = 1; i < bf_list_size(list) - 1; ++i) {
        _cleanup_free_ size_t *value = NULL;

        assert_non_null(value = malloc(sizeof(*value)));
        *value = i;

        assert_ok(bf_list_push(reference, (void *)&value));
    }

    // Validate bf_list_get_at for indexes outside of the list
    assert_null(bf_list_get_at(list, bf_list_size(list)));

    // Remove nodes starting from tail so we don't mess up the indexes
    bf_list_delete(list, list->head);
    bf_list_delete(list, list->tail);

    assert_true(
        bft_list_eq(list, reference, (bft_list_eq_cb)bft_list_dummy_eq));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),    cmocka_unit_test(init_and_clean),
        cmocka_unit_test(pack_and_unpack), cmocka_unit_test(move),
        cmocka_unit_test(head_and_tail),   cmocka_unit_test(iterate),
        cmocka_unit_test(insert),          cmocka_unit_test(delete),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
