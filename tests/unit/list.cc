#include <gtest/gtest.h>

extern "C" {
#include "core/list.h"
#include "shared/helper.h"
#include "shared/mem.h"
}

static void noop_free(void **data)
{
    UNUSED(data);
}

static bf_list_ops noop_ops = {.free = noop_free};

static int _dummy_filler(bf_list *l, void *data,
                         int (*add)(bf_list *l, void *data))
{
    __cleanup_free__ int *_data;
    int r;

    _data = static_cast<int *>(malloc(sizeof(*_data)));
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

static void dummy_free(void **data)
{
    free(*data);
    *data = nullptr;
}

static bf_list_ops dummy_ops = {.free = dummy_free};

static void new_and_fill(bf_list **l, size_t count, const bf_list_ops *ops,
                         int (*filler)(bf_list *l, void *data))
{
    EXPECT_EQ(0, bf_list_new(l, ops));

    for (size_t i = 1; i <= count; ++i)
        EXPECT_EQ(0, filler(*l, &i));

    EXPECT_EQ(count, bf_list_size(*l));
}

static void init_and_fill(bf_list *l, size_t count, const bf_list_ops *ops,
                          int (*filler)(bf_list *l, void *data))
{
    bf_list_init(l, ops);

    for (size_t i = 1; i <= count; ++i)
        EXPECT_EQ(0, filler(l, &i));

    EXPECT_EQ(count, bf_list_size(l));
}

TEST(list, new_and_free)
{
    bf_list *l = nullptr;

    {
        // With noop operators
        EXPECT_EQ(0, bf_list_new(&l, &noop_ops));
        EXPECT_EQ(0, l->len);
        EXPECT_EQ(nullptr, l->head);
        EXPECT_EQ(nullptr, l->tail);

        bf_list_free(&l);
        EXPECT_EQ(nullptr, l);

        new_and_fill(&l, 3, &noop_ops, bf_list_add_head);
        EXPECT_EQ(3, l->len);
        EXPECT_NE(nullptr, l->head);
        EXPECT_NE(nullptr, l->tail);

        bf_list_free(&l);
        EXPECT_EQ(nullptr, l);
    }

    {
        // With dummy operators which allocate memory
        bf_list_new(&l, &dummy_ops);
        EXPECT_EQ(0, l->len);
        EXPECT_EQ(nullptr, l->head);
        EXPECT_EQ(nullptr, l->tail);

        bf_list_free(&l);
        EXPECT_EQ(nullptr, l);

        new_and_fill(&l, 3, &dummy_ops, dummy_filler_head);
        EXPECT_EQ(3, l->len);
        EXPECT_NE(nullptr, l->head);
        EXPECT_NE(nullptr, l->tail);

        bf_list_free(&l);
        EXPECT_EQ(nullptr, l);
    }
}

TEST(list, init_and_clean)
{
    bf_list l;

    {
        // With noop operators
        bf_list_init(&l, &noop_ops);
        EXPECT_EQ(0, l.len);
        EXPECT_EQ(nullptr, l.head);
        EXPECT_EQ(nullptr, l.tail);

        bf_list_clean(&l);
        EXPECT_EQ(0, l.len);
        EXPECT_EQ(nullptr, l.head);
        EXPECT_EQ(nullptr, l.tail);

        init_and_fill(&l, 3, &noop_ops, bf_list_add_head);
        EXPECT_EQ(3, l.len);
        EXPECT_NE(nullptr, l.head);
        EXPECT_NE(nullptr, l.tail);

        bf_list_clean(&l);
        EXPECT_EQ(0, l.len);
        EXPECT_EQ(nullptr, l.head);
        EXPECT_EQ(nullptr, l.tail);
    }

    {
        // With dummy operators which allocate memory
        bf_list_init(&l, &dummy_ops);
        EXPECT_EQ(0, l.len);
        EXPECT_EQ(nullptr, l.head);
        EXPECT_EQ(nullptr, l.tail);

        bf_list_clean(&l);
        EXPECT_EQ(0, l.len);
        EXPECT_EQ(nullptr, l.head);
        EXPECT_EQ(nullptr, l.tail);

        init_and_fill(&l, 3, &dummy_ops, dummy_filler_head);
        EXPECT_EQ(3, l.len);
        EXPECT_NE(nullptr, l.head);
        EXPECT_NE(nullptr, l.tail);

        bf_list_clean(&l);
        EXPECT_EQ(0, l.len);
        EXPECT_EQ(nullptr, l.head);
        EXPECT_EQ(nullptr, l.tail);
    }
}

TEST(list, fill_from_head_and_check)
{
    bf_list list;
    size_t i;

    bf_list_init(&list, &dummy_ops);

    // Invalid pointer and empty list
    EXPECT_DEATH(bf_list_get_head(nullptr), "");
    EXPECT_EQ(nullptr, bf_list_get_head(&list));

    // Fill list at head with values from 1 to 10, expecting:
    // 10 -> 9 -> ... -> 2 -> 1
    init_and_fill(&list, 10, &dummy_ops, dummy_filler_head);

    // Validate content of the list
    i = bf_list_size(&list);

    bf_list_foreach (&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ(i, *(int *)bf_list_node_get_data(it));
        --i;
    }

    i = 1;

    bf_list_foreach_rev (&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ(i, *(int *)bf_list_node_get_data(it));
        ++i;
    }

    bf_list_clean(&list);
}

TEST(list, iterate_and_remove)
{
    bf_list l;

    init_and_fill(&l, 10, &dummy_ops, dummy_filler_head);

    bf_list_foreach (&l, node)
        bf_list_delete(&l, node);

    EXPECT_EQ(0, bf_list_size(&l));
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);

    bf_list_clean(&l);

    bf_list_foreach_rev (&l, node)
        bf_list_delete(&l, node);

    EXPECT_EQ(0, bf_list_size(&l));
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);

    bf_list_clean(&l);
}

TEST(list, fill_from_tail_and_check)
{
    bf_list list;
    size_t i;

    bf_list_init(&list, &dummy_ops);

    // Invalid pointer and empty list
    EXPECT_DEATH(bf_list_get_head(nullptr), "");
    EXPECT_EQ(nullptr, bf_list_get_head(&list));

    // Fill list at tail with values from 1 to 10, expecting:
    // 1 -> 2 -> ... -> 9 -> 10
    init_and_fill(&list, 10, &dummy_ops, dummy_filler_tail);

    // Validate content of the list
    i = 1;

    bf_list_foreach (&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ(i, *(int *)bf_list_node_get_data(it));
        ++i;
    }

    i = bf_list_size(&list);

    bf_list_foreach_rev (&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ(i, *(int *)bf_list_node_get_data(it));
        --i;
    }

    bf_list_clean(&list);
}

TEST(list, ensure_reject_null_params)
{
    bf_list list = {};
    bf_list *plist = nullptr;

    EXPECT_DEATH(bf_list_new(nullptr, &noop_ops), "");
    EXPECT_DEATH(bf_list_new(&plist, nullptr), "");
    EXPECT_DEATH(bf_list_free(nullptr), "");
    EXPECT_DEATH(bf_list_init(nullptr, &noop_ops), "");
    EXPECT_DEATH(bf_list_init(&list, nullptr), "");
    EXPECT_DEATH(bf_list_clean(nullptr), "");
    EXPECT_DEATH(bf_list_size(nullptr), "");
    EXPECT_DEATH(bf_list_add_head(nullptr, nullptr), "");
    EXPECT_DEATH(bf_list_add_tail(nullptr, nullptr), "");
    EXPECT_DEATH(bf_list_get_head(nullptr), "");
    EXPECT_DEATH(bf_list_get_tail(nullptr), "");
    EXPECT_DEATH(bf_list_node_next(nullptr), "");
    EXPECT_DEATH(bf_list_node_prev(nullptr), "");
    EXPECT_DEATH(bf_list_node_get_data(nullptr), "");
    EXPECT_DEATH(bf_list_node_take_data(nullptr), "");
}
