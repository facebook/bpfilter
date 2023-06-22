/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/helper.c"

#include <criterion/criterion.h>

#include "test.h"

static const char content[] =
    "Il est assis au fond du métro, où personne ne regarde"
    "Silence pesant, trois mecs montent, visages menaçants"
    "\"Allez, tombe la veste, on est accroc d'elle\""
    "Mais lui supplie, commence à pleurer, son père lui a offert à Noël"
    "Elle change de main, il a beau dire que ses parents n'ont pas un sou"
    "Au fond, tout le monde s'en fout, les trois types, les gens autour";

TestAssert(src_core_helper, bf_read_file, 0, (NULL, NOT_NULL, NOT_NULL));
TestAssert(src_core_helper, bf_read_file, 1, (NOT_NULL, NULL, NOT_NULL));
TestAssert(src_core_helper, bf_read_file, 2, (NOT_NULL, NOT_NULL, NULL));
TestAssert(src_core_helper, bf_write_file, 0, (NULL, NOT_NULL, 0));
TestAssert(src_core_helper, bf_write_file, 1, (NOT_NULL, NULL, 0));

Test(src_core_helper, write_and_read_file)
{
    static const char *filepath = "/tmp/bpfilter_src_core_helper_test";
    _cleanup_free_ char *read_data = NULL;
    size_t read_len;

    cr_assert_eq(0, bf_write_file(filepath, content, strlen(content)));
    cr_assert_eq(0, bf_read_file(filepath, (void **)&read_data, &read_len));
    cr_assert_eq(strlen(content), read_len);
    cr_assert_eq(0, memcmp(content, read_data, read_len));
}
