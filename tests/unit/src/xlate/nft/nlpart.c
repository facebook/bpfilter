/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nlpart.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(nlpart, create_new_part)
{
    expect_assert_failure(bf_nlpart_new(NULL, 0, 0, 0, 0));

    {
        struct bf_nlpart *part;

        assert_int_equal(0, bf_nlpart_new(&part, 1, 2, 3, 4));
        assert_int_equal(1, bf_nlpart_family(part));
        assert_int_equal(2, bf_nlpart_command(part));
        assert_int_equal(3, bf_nlpart_flags(part));
        assert_int_equal(4, bf_nlpart_seqnr(part));

        bf_nlpart_free(&part);
        assert_null(part);
    }

    {
        _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;
    }

    {
        _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;

        assert_int_equal(0, bf_nlpart_new(&part, 0, 0, 0, 0));
    }

    {
        // Failling calloc()
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);
        _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;

        assert_true(bf_nlpart_new(&part, 0, 0, 0, 0) < 0);
    }
}

Test(nlpart, add_extra_hdr)
{
    _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;
    struct nfgenmsg genmsg = {
        .nfgen_family = 1,
        .version = 2,
        .res_id = 3,
    };
    struct nfgenmsg *genmsgp;

    assert_int_equal(0, bf_nlpart_new(&part, 0, 0, 0, 0));
    assert_int_equal(0,
                     bf_nlpart_put_extra_header(part, &genmsg, sizeof(genmsg)));

    genmsgp = bf_nlpart_data(part);
    assert_int_equal(1, genmsgp->nfgen_family);
    assert_int_equal(2, genmsgp->version);
    assert_int_equal(3, genmsgp->res_id);
}
