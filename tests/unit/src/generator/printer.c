/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/printer.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(printer, msg_lifetime)
{
    expect_assert_failure(_bf_printer_msg_new(NULL));

    {
        // Automatic cleanup
        _cleanup_bf_printer_msg_ struct bf_printer_msg *msg = NULL;

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
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);
        struct bf_printer_msg *msg = NULL;

        assert_error(_bf_printer_msg_new(&msg));
        assert_ptr_equal(msg, NULL);
    }
}

Test(printer, msg_marsh_unmarsh)
{
    expect_assert_failure(_bf_printer_msg_new_from_marsh(NULL, NOT_NULL));
    expect_assert_failure(_bf_printer_msg_new_from_marsh(NOT_NULL, NULL));
    expect_assert_failure(_bf_printer_msg_new_from_marsh(NULL, NULL));
    expect_assert_failure(_bf_printer_msg_marsh(NULL, NOT_NULL));
    expect_assert_failure(_bf_printer_msg_marsh(NOT_NULL, NULL));
    expect_assert_failure(_bf_printer_msg_marsh(NULL, NULL));

    _cleanup_bf_printer_msg_ struct bf_printer_msg *msg0 = NULL;
    _cleanup_bf_printer_msg_ struct bf_printer_msg *msg1 = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

    assert_int_equal(_bf_printer_msg_new(&msg0), 0);
    msg0->offset = 17;
    msg0->len = 6;
    msg0->str = strdup("hello");
    assert_ptr_not_equal(msg0->str, NULL);

    assert_int_equal(_bf_printer_msg_marsh(msg0, &marsh), 0);
    assert_int_equal(_bf_printer_msg_new_from_marsh(&msg1, marsh), 0);

    assert_int_equal(bf_printer_msg_offset(msg0), bf_printer_msg_offset(msg1));
    assert_int_equal(bf_printer_msg_len(msg0), bf_printer_msg_len(msg1));
    assert_string_equal(msg0->str, msg1->str);
}

Test(printer, printer_lifetime)
{
    expect_assert_failure(bf_printer_new(NULL));

    {
        // Automatic cleanup
        _cleanup_bf_printer_ struct bf_printer *printer = NULL;

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
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(malloc, NULL);
        struct bf_printer *printer = NULL;

        assert_error(bf_printer_new(&printer));
        assert_ptr_equal(printer, NULL);
    }
}

Test(printer, printer_marsh_unmarsh)
{
    expect_assert_failure(bf_printer_new_from_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_printer_new_from_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_printer_new_from_marsh(NULL, NULL));
    expect_assert_failure(bf_printer_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_printer_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_printer_marsh(NULL, NULL));
    expect_assert_failure(_bf_printer_total_size(NULL));
    expect_assert_failure(bf_printer_add_msg(NULL, NOT_NULL));
    expect_assert_failure(bf_printer_add_msg(NOT_NULL, NULL));
    expect_assert_failure(bf_printer_add_msg(NULL, NULL));

    _cleanup_bf_printer_ struct bf_printer *printer0 = NULL;
    _cleanup_bf_printer_ struct bf_printer *printer1 = NULL;
    const struct bf_printer_msg *msg0;
    const struct bf_printer_msg *msg1;
    const struct bf_printer_msg *msg2;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

    // Insert messages into the printer, and ensure inserting 2 times the
    // same message will only create 1 message.
    assert_int_equal(bf_printer_new(&printer0), 0);
    msg0 = bf_printer_add_msg(printer0, "hello");
    assert_ptr_not_equal(msg0, NULL);
    msg1 = bf_printer_add_msg(printer0, "world");
    assert_ptr_not_equal(msg1, NULL);
    assert_ptr_not_equal(msg0, msg1);
    msg2 = bf_printer_add_msg(printer0, "world");
    assert_ptr_equal(msg1, msg2);

    // Total size if 6 ("hello\0") + 6 ("world\0")
    assert_int_equal(_bf_printer_total_size(printer0), 12);

    // Serialise and deserialise the printer
    assert_int_equal(bf_printer_marsh(printer0, &marsh), 0);
    assert_int_equal(bf_printer_new_from_marsh(&printer1, marsh), 0);

    assert_int_equal(_bf_printer_total_size(printer0),
                     _bf_printer_total_size(printer1));
}
