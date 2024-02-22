/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nfmsg.c"

#include <linux/netfilter/nf_tables.h>

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(nfmsg, new_and_free)
{
    expect_assert_failure(bf_nfmsg_new(NULL, 0, 0));
    expect_assert_failure(bf_nfmsg_free(NULL));

    {
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
        assert_non_null(msg);
    }

    {
        struct bf_nfmsg *msg = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
        assert_non_null(msg);

        bf_nfmsg_free(&msg);
        assert_null(msg);
    }

    {
        // calloc failure
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_int_not_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }

    {
        // nlmsg_put failure
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(nlmsg_alloc, NULL);
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_int_not_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }

    {
        // nlmsg_put failure
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(nlmsg_put, NULL);
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_int_not_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }

    {
        // nlmsg_append failure
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(nlmsg_append, -1);
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_int_not_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }
}
