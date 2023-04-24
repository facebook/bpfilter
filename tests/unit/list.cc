#include <gtest/gtest.h>

extern "C" {
#include "core/list.h"
}

static void init_and_fill(bf_list *l, size_t count, int (*filler)(bf_list *l, void *data))
{
    bf_list_init(l);

    for (size_t i = 1; i <= count; ++i)
        EXPECT_EQ(0, filler(l, (void *)i));

    EXPECT_EQ(count, bf_list_size(l));
}

TEST(list, init_and_clean)
{
    bf_list l;

    bf_list_init(&l);
    EXPECT_EQ(0, l.len);
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);

    bf_list_clean(&l);
    EXPECT_EQ(0, l.len);
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);

    init_and_fill(&l, 3, bf_list_add_head);
    EXPECT_EQ(3, l.len);
    EXPECT_NE(nullptr, l.head);
    EXPECT_NE(nullptr, l.tail);

    bf_list_clean(&l);
    EXPECT_EQ(0, l.len);
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);
}

TEST(list, fill_from_head_and_check)
{
    bf_list list;
    size_t i;

    bf_list_init(&list);

    // Invalid pointer and empty list
    EXPECT_DEATH(bf_list_get_head(nullptr), "");
    EXPECT_EQ(nullptr, bf_list_get_head(&list));

    // Fill list at head with values from 1 to 10, expecting:
    // 10 -> 9 -> ... -> 2 -> 1
    init_and_fill(&list, 10, bf_list_add_head);

    // Validate content of the list
    i = bf_list_size(&list);

    bf_list_foreach(&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ((void *)i, bf_list_node_data(it));
        --i;
    }

    i = 1;

    bf_list_foreach_rev(&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ((void *)i, bf_list_node_data(it));
        ++i;
    }

    bf_list_clean(&list);
}

TEST(list, iterate_and_remove)
{
    bf_list l;

    init_and_fill(&l, 10, bf_list_add_head);

    bf_list_foreach(&l, node) {
        bf_list_delete(&l, node);
    }

    EXPECT_EQ(0, bf_list_size(&l));
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);

    bf_list_clean(&l);

    bf_list_foreach_rev(&l, node) {
        bf_list_delete(&l, node);
    }

    EXPECT_EQ(0, bf_list_size(&l));
    EXPECT_EQ(nullptr, l.head);
    EXPECT_EQ(nullptr, l.tail);

    bf_list_clean(&l);
}

TEST(list, fill_from_tail_and_check)
{
    bf_list list;
    size_t i;

    bf_list_init(&list);

    // Invalid pointer and empty list
    EXPECT_DEATH(bf_list_get_head(nullptr), "");
    EXPECT_EQ(nullptr, bf_list_get_head(&list));

    // Fill list at tail with values from 1 to 10, expecting:
    // 1 -> 2 -> ... -> 9 -> 10
    init_and_fill(&list, 10, bf_list_add_tail);

    // Validate content of the list
    i = 1;

    bf_list_foreach(&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ((void *)i, bf_list_node_data(it));
        ++i;
    }

    i = bf_list_size(&list);

    bf_list_foreach_rev(&list, it) {
        EXPECT_NE(nullptr, it);
        EXPECT_EQ((void *)i, bf_list_node_data(it));
        --i;
    }

    bf_list_clean(&list);
}

TEST(list, ensure_reject_null_params)
{
    EXPECT_DEATH(bf_list_init(nullptr), "");
    EXPECT_DEATH(bf_list_clean(nullptr), "");
    EXPECT_DEATH(bf_list_size(nullptr), "");
    EXPECT_DEATH(bf_list_add_head(nullptr, nullptr), "");
    EXPECT_DEATH(bf_list_add_tail(nullptr, nullptr), "");
    EXPECT_DEATH(bf_list_get_head(nullptr), "");
    EXPECT_DEATH(bf_list_get_tail(nullptr), "");
    EXPECT_DEATH(bf_list_node_next(nullptr), "");
    EXPECT_DEATH(bf_list_node_prev(nullptr), "");
    EXPECT_DEATH(bf_list_node_data(nullptr), "");
}
