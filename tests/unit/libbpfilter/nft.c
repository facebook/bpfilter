/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netlink.h>

#include <errno.h>

#include <bpfilter/bpfilter.h>

#include "fake.h"
#include "test.h"

static void nft_send(void **state)
{
    (void)state;

    char data[32] = {0};

    // NULL data should fail
    assert_int_equal(bf_nft_send(NULL, sizeof(data)), -EINVAL);

    // Zero length should fail
    assert_int_equal(bf_nft_send(data, 0), -EINVAL);

    // Can't connect to daemon during unit tests
    assert_err(bf_nft_send(data, sizeof(data)));
}

static void nft_sendrecv(void **state)
{
    (void)state;

    struct nlmsghdr req = {0};
    struct nlmsghdr res = {0};
    size_t res_len = sizeof(res);

    req.nlmsg_len = sizeof(req);

    // NULL request should fail
    assert_int_equal(bf_nft_sendrecv(NULL, sizeof(req), &res, &res_len),
                     -EINVAL);

    // Zero request length should fail
    assert_int_equal(bf_nft_sendrecv(&req, 0, &res, &res_len), -EINVAL);

    // NULL response should fail
    assert_int_equal(bf_nft_sendrecv(&req, sizeof(req), NULL, &res_len),
                     -EINVAL);

    // NULL response length should fail
    assert_int_equal(bf_nft_sendrecv(&req, sizeof(req), &res, NULL), -EINVAL);

    // Mismatched request length should fail
    assert_int_equal(bf_nft_sendrecv(&req, sizeof(req) + 1, &res, &res_len),
                     -EINVAL);

    // Can't connect to daemon during unit tests
    assert_err(bf_nft_sendrecv(&req, sizeof(req), &res, &res_len));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(nft_send),
        cmocka_unit_test(nft_sendrecv),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
