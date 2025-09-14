/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/helper.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

static const char content[] =
    "Il est assis au fond du métro, où personne ne regarde"
    "Silence pesant, trois mecs montent, visages menaçants"
    "\"Allez, tombe la veste, on est accroc d'elle\""
    "Mais lui supplie, commence à pleurer, son père lui a offert à Noël"
    "Elle change de main, il a beau dire que ses parents n'ont pas un sou"
    "Au fond, tout le monde s'en fout, les trois types, les gens autour";

Test(helper, read_file_assert_failure)
{
    expect_assert_failure(bf_read_file(NULL, NOT_NULL, NOT_NULL));
    expect_assert_failure(bf_read_file(NOT_NULL, NULL, NOT_NULL));
    expect_assert_failure(bf_read_file(NOT_NULL, NOT_NULL, NULL));
}

Test(helper, write_file_assert_failure)
{
    expect_assert_failure(bf_write_file(NULL, NOT_NULL, 0));
    expect_assert_failure(bf_write_file(NOT_NULL, NULL, 0));
}

Test(helper, read_failure)
{
    {
        // Can not open the file to read.
        _free_tmp_file_ char *tmp = bf_test_filepath_new_rw();
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(open, -1);

        assert_true(bf_read_file(tmp, NOT_NULL, NOT_NULL) < 0);
    }

    {
        // Can not allocate memory to read the content of the file.
        _free_tmp_file_ char *tmp = bf_test_filepath_new_rw();
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);

        assert_true(bf_read_file(tmp, NOT_NULL, NOT_NULL) < 0);
    }

    {
        // Can not read the content of the file.
        _free_tmp_file_ char *tmp = bf_test_filepath_new_rw();
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(read, -1);

        assert_true(bf_read_file(tmp, NOT_NULL, NOT_NULL) < 0);
    }
}

Test(helper, write_failure)
{
    {
        // Can not open the output file.
        _free_tmp_file_ char *tmp = bf_test_filepath_new_rw();
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(open, -1);

        assert_true(bf_write_file(tmp, NOT_NULL, 1) < 0);
    }

    {
        // Can not write to the output file.
        _free_tmp_file_ char *tmp = bf_test_filepath_new_rw();
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(write, -1);

        assert_true(bf_write_file(tmp, NOT_NULL, 1) < 0);
    }

    {
        // Can not write the full buffer to the output file.
        _free_tmp_file_ char *tmp = bf_test_filepath_new_rw();
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(write, 10);

        assert_true(bf_write_file(tmp, NOT_NULL, 100) < 0);
    }
}

Test(helper, write_and_read_file)
{
    _free_tmp_file_ char *filepath = bf_test_filepath_new_rw();
    _cleanup_free_ char *read_data = NULL;
    size_t read_len;

    assert_success(bf_write_file(filepath, content, strlen(content)));
    assert_success(bf_read_file(filepath, (void **)&read_data, &read_len));
    assert_int_equal(strlen(content), read_len);
    assert_int_equal(0, memcmp(content, read_data, read_len));
}
