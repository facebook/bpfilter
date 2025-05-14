/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/xlate/nft/nfmsg.c"

#include <linux/netfilter/nf_tables.h>

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(nfmsg, new_and_free)
{
    expect_assert_failure(bf_nfmsg_new(NULL, 0, 0));
    expect_assert_failure(bf_nfmsg_free(NULL));
    expect_assert_failure(bf_nfmsg_hdr(NULL));
    expect_assert_failure(bf_nfmsg_command(NULL));
    expect_assert_failure(bf_nfmsg_seqnr(NULL));

    {
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_success(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
        assert_non_null(msg);
        assert_int_equal(NFT_MSG_GETRULE, bf_nfmsg_command(msg));
        assert_int_equal(17, bf_nfmsg_seqnr(msg));
        assert_int_equal(sizeof(struct nfgenmsg), bf_nfmsg_data_len(msg));
    }

    {
        struct bf_nfmsg *msg = NULL;

        assert_success(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
        assert_non_null(msg);
        assert_int_equal(NFT_MSG_GETRULE, bf_nfmsg_command(msg));
        assert_int_equal(17, bf_nfmsg_seqnr(msg));
        assert_int_equal(sizeof(struct nfgenmsg), bf_nfmsg_data_len(msg));

        bf_nfmsg_free(&msg);
        assert_null(msg);
    }

    {
        // calloc failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(calloc, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }

    {
        // nlmsg_put failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_alloc, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }

    {
        // nlmsg_put failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_put, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }

    {
        // nlmsg_append failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_append, -1);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    }
}

Test(nfmsg, new_done)
{
    expect_assert_failure(bf_nfmsg_new_done(NULL));

    {
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_success(bf_nfmsg_new_done(&msg));
        assert_non_null(msg);
    }

    {
        // calloc failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(calloc, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new_done(&msg));
    }

    {
        // nlmsg_put failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_alloc, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new_done(&msg));
    }

    {
        // nlmsg_put failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_put, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new_done(&msg));
    }

    {
        // nlmsg_append failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_append, -1);
        _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        assert_error(bf_nfmsg_new_done(&msg));
    }
}

Test(nfmsg, new_from_nlmsghdr)
{
    expect_assert_failure(bf_nfmsg_new_from_nlmsghdr(NULL, NOT_NULL));
    expect_assert_failure(bf_nfmsg_new_from_nlmsghdr(NOT_NULL, NULL));

    {
        // Create a bf_nfmsg from a nlmsghdr
        _free_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;
        _free_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_success(bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));
        assert_int_equal(0,
                         bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
        assert_int_equal(bf_nfmsg_command(msg0), bf_nfmsg_command(msg1));
        assert_int_equal(bf_nfmsg_seqnr(msg0), bf_nfmsg_seqnr(msg1));
        assert_int_equal(bf_nfmsg_data_len(msg0), bf_nfmsg_data_len(msg1));
    }

    {
        // Invalid message type
        _free_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;
        _free_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_success(bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));
        bf_nfmsg_hdr(msg0)->nlmsg_type = 0;
        assert_error(bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
    }

    {
        // calloc failed
        _free_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;

        assert_success(bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));

        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(calloc, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_error(bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
    }

    {
        // nlmsg_convert failed
        _free_bf_nfmsg_ struct bf_nfmsg *msg0 = NULL;

        assert_success(bf_nfmsg_new(&msg0, NFT_MSG_GETRULE, 17));

        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(nlmsg_convert, NULL);
        _free_bf_nfmsg_ struct bf_nfmsg *msg1 = NULL;

        assert_error(bf_nfmsg_new_from_nlmsghdr(&msg1, bf_nfmsg_hdr(msg0)));
    }
}

Test(nfmsg, write_attributes)
{
    _free_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

    const bf_nfpolicy test_policy[] = {
        [0] = {.type = NLA_U8},     [1] = {.type = NLA_U16},
        [2] = {.type = NLA_U32},    [3] = {.type = NLA_U64},
        [4] = {.type = NLA_STRING}, [5] = {.type = NLA_NESTED},
    };
    bf_nfattr *attrs[ARRAY_SIZE(test_policy)] = {};
    bf_nfattr *nested_attrs[ARRAY_SIZE(test_policy)] = {};

    expect_assert_failure(bf_nfmsg_attr_push(NULL, 0, NOT_NULL, 0));
    expect_assert_failure(bf_nfmsg_attr_push(NOT_NULL, 0, NULL, 0));
    expect_assert_failure(bf_nfmsg_nest_init(NULL, NOT_NULL, 0));
    expect_assert_failure(bf_nfmsg_nest_init(NOT_NULL, NULL, 0));

    assert_success(bf_nfmsg_new(&msg, NFT_MSG_GETRULE, 17));
    assert_success(bf_nfmsg_push_u8(msg, 0, 0));
    assert_success(bf_nfmsg_push_u16(msg, 1, 1));
    assert_success(bf_nfmsg_push_u32(msg, 2, 2));
    assert_success(bf_nfmsg_push_u64(msg, 3, 3));
    assert_success(bf_nfmsg_push_str(msg, 4, "4"));
    {
        _clean_bf_nfnest_ struct bf_nfnest nest;

        assert_success(bf_nfmsg_nest_init(&nest, msg, 5));
        assert_success(bf_nfmsg_push_u8(msg, 0, 0));
        assert_success(bf_nfmsg_push_u16(msg, 1, 1));
        assert_success(bf_nfmsg_push_u32(msg, 2, 2));
        assert_success(bf_nfmsg_push_u64(msg, 3, 3));
        assert_success(bf_nfmsg_push_str(msg, 4, "4"));
    }

    assert_int_equal(
        0, bf_nfmsg_parse(msg, attrs, ARRAY_SIZE(attrs), test_policy));
    assert_success(bf_nfattr_get_u8(attrs[0]));
    assert_int_equal(1, bf_nfattr_get_u16(attrs[1]));
    assert_int_equal(2, bf_nfattr_get_u32(attrs[2]));
    assert_int_equal(3, bf_nfattr_get_u64(attrs[3]));
    assert_string_equal("4", bf_nfattr_get_str(attrs[4]));

    assert_success(bf_nfattr_parse(attrs[5], nested_attrs,
                                   ARRAY_SIZE(nested_attrs), test_policy));
    assert_int_equal(0, bf_nfattr_get_u8(nested_attrs[0]));
    assert_int_equal(1, bf_nfattr_get_u16(nested_attrs[1]));
    assert_int_equal(2, bf_nfattr_get_u32(nested_attrs[2]));
    assert_int_equal(3, bf_nfattr_get_u64(nested_attrs[3]));
    assert_string_equal("4", bf_nfattr_get_str(nested_attrs[4]));
}
