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
    expect_assert_failure(bf_nfmsg_hdr(NULL));
    expect_assert_failure(bf_nfmsg_command(NULL));
    expect_assert_failure(bf_nfmsg_seqnr(NULL));

    {
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
        assert_non_null(msg);
        assert_int_equal(NFT_MSG_GETRULE, bf_nfmsg_command(msg));
        assert_int_equal(17, bf_nfmsg_seqnr(msg));
        assert_int_equal(sizeof(struct nfgenmsg), bf_nfmsg_data_len(msg));
    }

    {
        struct bf_nfmsg *msg = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
        assert_non_null(msg);
        assert_int_equal(NFT_MSG_GETRULE, bf_nfmsg_command(msg));
        assert_int_equal(17, bf_nfmsg_seqnr(msg));
        assert_int_equal(sizeof(struct nfgenmsg), bf_nfmsg_data_len(msg));

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

Test(nfmsg, new_from_nlmsghdr)
{
    expect_assert_failure(bf_nfmsg_new_from_nlmsghdr(NULL, NOT_NULL));
    expect_assert_failure(bf_nfmsg_new_from_nlmsghdr(NOT_NULL, NULL));

    {
        // Create a bf_nfmsg from a nlmsghdr
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));
        assert_int_equal(0,
                         bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
        assert_int_equal(bf_nfmsg_command(msg0), bf_nfmsg_command(msg1));
        assert_int_equal(bf_nfmsg_seqnr(msg0), bf_nfmsg_seqnr(msg1));
        assert_int_equal(bf_nfmsg_data_len(msg0), bf_nfmsg_data_len(msg1));
    }

    {
        // Invalid message type
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));
        bf_nfmsg_hdr(msg0)->nlmsg_type = 0;
        assert_int_not_equal(
            0, bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
    }

    {
        // calloc failed
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));

        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_int_not_equal(
            0, bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
    }

    {
        // nlmsg_convert failed
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;

        assert_int_equal(0, bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));

        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(nlmsg_convert, NULL);
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_int_not_equal(
            0, bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
    }
}
