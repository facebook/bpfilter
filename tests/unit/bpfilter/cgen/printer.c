/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/printer.c"

#include "fake.h"
#include "harness/test.h"
#include "harness/filters.h"
#include "mock.h"

Test(printer, msg_lifetime)
{
    expect_assert_failure(_bf_printer_msg_new(NULL));

    {
        // Automatic cleanup
        _free_bf_printer_msg_ struct bf_printer_msg *msg = NULL;

        assert_int_equal(_bf_printer_msg_new(&msg), 0);
    }

    {
        // Manual cleanup
        struct bf_printer_msg *msg = NULL;

        assert_int_equal(_bf_printer_msg_new(&msg), 0);

        _bf_printer_msg_free(&msg);
        assert_ptr_equal(msg, NULL);

        // We should be able to call free() twice
        _bf_printer_msg_free(&msg);
        assert_ptr_equal(msg, NULL);
    }

    {
        // Allocation failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(calloc, NULL);
        struct bf_printer_msg *msg = NULL;

        assert_error(_bf_printer_msg_new(&msg));
        assert_ptr_equal(msg, NULL);
    }
}

Test(printer, printer_lifetime)
{
    expect_assert_failure(bf_printer_new(NULL));

    {
        // Automatic cleanup
        _free_bf_printer_ struct bf_printer *printer = NULL;

        assert_int_equal(bf_printer_new(&printer), 0);
    }

    {
        // Manual cleanup
        struct bf_printer *printer = NULL;

        assert_int_equal(bf_printer_new(&printer), 0);

        bf_printer_free(&printer);
        assert_ptr_equal(printer, NULL);

        // We should be able to call free() twice
        bf_printer_free(&printer);
        assert_ptr_equal(printer, NULL);
    }

    {
        // Allocation failure
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);
        struct bf_printer *printer = NULL;

        assert_error(bf_printer_new(&printer));
        assert_ptr_equal(printer, NULL);
    }
}

static const char *_bft_printer_test_messages[] = {
    "C'est au pays des paresseux",
    "Que Bébé dort le mieux.",
    "Tu n'as plus qu'à fermer les yeux.",
    "Quel endroit merveilleux !",
    "Minarono",
    "Murano",
    "Gribouille",
    "Beleuse",
};

static struct bf_printer *_bft_printer_get(size_t n_messages)
{
    _free_bf_printer_ struct bf_printer *printer = NULL;
    int r;

    r = bf_printer_new(&printer);
    if (r) {
        bf_err("failed to create a dummy bf_printer object");
        return NULL;
    }

    for (size_t i = 0; i < n_messages; ++i) {
        const struct bf_printer_msg *msg = bf_printer_add_msg(printer, _bft_printer_test_messages[i % ARRAY_SIZE(_bft_printer_test_messages)]);
        if (!msg) {
            bf_err("failed to insert test message into dummy bf_printer object");
            return NULL;
        }
    }

    return TAKE_PTR(printer);
}

static bool _bft_printer_msg_eq(const struct bf_printer_msg *lhs, const struct bf_printer_msg *rhs)
{
    return lhs->offset == rhs->offset && lhs->len == rhs->len && bf_streq(lhs->str, rhs->str);
}

static bool _bft_printer_eq(const struct bf_printer *lhs, const struct bf_printer *rhs)
{
    return bft_list_eq(&lhs->msgs, &rhs->msgs, (bft_list_eq_cb)_bft_printer_msg_eq);
}

Test(printer, pack_unpack)
{
    _free_bf_printer_ struct bf_printer *printer0 = NULL;
    _free_bf_printer_ struct bf_printer *printer1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    expect_assert_failure(bf_printer_pack(NULL, NOT_NULL));
    expect_assert_failure(bf_printer_pack(NOT_NULL, NULL));

    assert_non_null(printer0 = _bft_printer_get(10));

    assert_success(bf_wpack_new(&wpack));
    assert_success(bf_printer_pack(printer0, wpack));
    assert_success(bf_wpack_get_data(wpack, &data, &data_len));

    assert_success(bf_rpack_new(&rpack, data, data_len));
    assert_success(bf_printer_new_from_pack(&printer1, bf_rpack_root(rpack)));

    assert_true(_bft_printer_eq(printer0, printer1));
}
