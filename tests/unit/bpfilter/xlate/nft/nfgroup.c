/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/xlate/nft/nfgroup.c"

#include <linux/netfilter/nf_tables.h>

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(nfgroup, new_and_free)
{
    expect_assert_failure(bf_nfgroup_new(NULL));
    expect_assert_failure(bf_nfgroup_free(NULL));

    {
        struct bf_nfgroup *gp = NULL;

        bf_nfgroup_free(&gp);
        assert_int_equal(bf_nfgroup_new(&gp), 0);
        assert_non_null(gp);
        bf_nfgroup_free(&gp);
    }

    {
        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;

        assert_int_equal(bf_nfgroup_new(&gp), 0);
        assert_non_null(gp);
    }

    {
        // calloc failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(calloc, NULL);
        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;

        assert_int_equal(bf_nfgroup_new(&gp), -ENOMEM);
    }
}

Test(nfgroup, new_from_stream)
{
    expect_assert_failure(bf_nfgroup_new_from_stream(NULL, NOT_NULL, 0));
    expect_assert_failure(bf_nfgroup_new_from_stream(NOT_NULL, NULL, 0));
    expect_assert_failure(bf_nfgroup_add_message(NULL, NOT_NULL));
    expect_assert_failure(bf_nfgroup_add_message(NOT_NULL, NULL));

    {
        // 1 Netlink message
        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;
        size_t nlh_len = 0;
        _cleanup_free_ struct nlmsghdr *nlh = bf_test_get_nlmsghdr(1, &nlh_len);

        assert_int_equal(bf_nfgroup_new_from_stream(&gp, nlh, nlh_len), 0);
        assert_non_null(gp);
    }

    {
        // 2 Netlink messages
        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;
        size_t nlh_len = 0;
        _cleanup_free_ struct nlmsghdr *nlh = bf_test_get_nlmsghdr(2, &nlh_len);

        assert_int_equal(bf_nfgroup_new_from_stream(&gp, nlh, nlh_len), 0);
        assert_non_null(gp);
    }
}

Test(nfgroup, helpers)
{
    expect_assert_failure(bf_nfgroup_messages(NULL));
    expect_assert_failure(bf_nfgroup_size(NULL));
    expect_assert_failure(bf_nfgroup_is_empty(NULL));

    for (int i = 0; i < 10; ++i) {
        size_t len;
        _free_bf_nfgroup_ struct bf_nfgroup *gp =
            bf_test_get_nfgroup(i, &len);

        assert_int_equal(bf_nfgroup_is_empty(gp), i == 0);

        const bf_list *msgs = bf_nfgroup_messages(gp);
        assert_non_null(msgs);
        assert_int_equal(bf_list_size(msgs), i);
        assert_int_equal(bf_nfgroup_size(gp), len);
    }
}

Test(nfgroup, add_new_message)
{
    expect_assert_failure(bf_nfgroup_add_new_message(NULL, NOT_NULL, 0, 0));

    {
        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;

        assert_int_equal(bf_nfgroup_new(&gp), 0);

        for (int i = 0; i < 10; ++i) {
            struct bf_nfmsg *msg = NULL;
            assert_int_equal(bf_nfgroup_add_new_message(gp, &msg, 0, 0), 0);

            assert_non_null(msg);
            assert_int_equal(bf_list_size(bf_nfgroup_messages(gp)), i + 1);
        }
    }

    {
        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;

        assert_int_equal(bf_nfgroup_new(&gp), 0);

        for (int i = 0; i < 10; ++i) {
            assert_int_equal(bf_nfgroup_add_new_message(gp, NULL, 0, 0), 0);
            assert_int_equal(bf_list_size(bf_nfgroup_messages(gp)), i + 1);
        }
    }
}

Test(nfgroup, to_response)
{
    size_t done_msg_len = sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg);
    expect_assert_failure(bf_nfgroup_to_response(NULL, NOT_NULL));
    expect_assert_failure(bf_nfgroup_to_response(NOT_NULL, NULL));

    {
        // Group without any message

        _free_bf_nfgroup_ struct bf_nfgroup *gp = NULL;
        _free_bf_response_ struct bf_response *res = NULL;

        assert_int_equal(bf_nfgroup_new(&gp), 0);
        assert_int_equal(bf_nfgroup_to_response(gp, &res), 0);
        assert_non_null(res);
        assert_int_equal(res->status, 0);
        assert_int_equal(res->data_len, done_msg_len);
    }

    {
        // Group without multiple messages

        size_t len;
        _free_bf_nfgroup_ struct bf_nfgroup *gp =
            bf_test_get_nfgroup(10, &len);
        _free_bf_response_ struct bf_response *res = NULL;

        assert_int_equal(bf_nfgroup_to_response(gp, &res), 0);
        assert_non_null(res);
        assert_int_equal(res->status, 0);
        assert_int_equal(res->data_len, len + done_msg_len);

        struct nlmsghdr *last =
            (struct nlmsghdr *)(res->data + res->data_len - done_msg_len);

        assert_int_equal(last->nlmsg_type, NLMSG_DONE);
    }
}
