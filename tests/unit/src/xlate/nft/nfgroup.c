/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nfgroup.c"

#include <linux/netfilter/nf_tables.h>

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

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
        _cleanup_bf_nfgroup_ struct bf_nfgroup *gp = NULL;

        assert_int_equal(bf_nfgroup_new(&gp), 0);
        assert_non_null(gp);
    }

    {
        // calloc failure
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);
        _cleanup_bf_nfgroup_ struct bf_nfgroup *gp = NULL;

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
        _cleanup_bf_nfgroup_ struct bf_nfgroup *gp = NULL;
        size_t nlh_len = 0;
        _cleanup_free_ struct nlmsghdr *nlh = bf_test_get_nlmsghdr(1, &nlh_len);

        assert_int_equal(bf_nfgroup_new_from_stream(&gp, nlh, nlh_len), 0);
        assert_non_null(gp);
    }

    {
        // 2 Netlink messages
        _cleanup_bf_nfgroup_ struct bf_nfgroup *gp = NULL;
        size_t nlh_len = 0;
        _cleanup_free_ struct nlmsghdr *nlh = bf_test_get_nlmsghdr(2, &nlh_len);

        assert_int_equal(bf_nfgroup_new_from_stream(&gp, nlh, nlh_len), 0);
        assert_non_null(gp);
    }
}
