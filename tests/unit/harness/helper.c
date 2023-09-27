/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/helper.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "generator/codegen.h"
#include "generator/program.h"
#include "harness/cmocka.h"
#include "shared/helper.h"

static const char *_readable_file_content = "Hello, world!";

char *bf_test_get_readable_tmp_filepath(void)
{
    int fd;
    size_t len = strlen(_readable_file_content);
    char tmppath[] = "/tmp/bpfltr_XXXXXX";
    char *path = NULL;

    fd = mkstemp(tmppath);
    if (fd < 0)
        fail_msg("HARNESS: failed to create a temporary file");

    if ((ssize_t)len != write(fd, _readable_file_content, len))
        fail_msg("HARNESS: failed to write to temporary file");

    close(fd);

    path = strdup(tmppath);
    if (!path)
        fail_msg("HARNESS: failed to write to temporary file");

    return path;
}

void bf_test_remove_tmp_file(char **path)
{
    if (!*path)
        return;

    if (unlink(*path) < 0)
        fail_msg("HARNESS: failed to remove '%s'", *path);

    free(*path);
    *path = NULL;
}

int bf_test_make_codegen(struct bf_codegen **codegen, enum bf_hook hook,
                         int nprogs)
{
    _cleanup_bf_codegen_ struct bf_codegen *c = NULL;
    int r;

    bf_assert(codegen);

    // So ifindex start a 1
    ++nprogs;

    r = bf_codegen_new(&c);
    if (r < 0)
        return r;

    for (int i = 1; i < nprogs; ++i) {
        _cleanup_bf_program_ struct bf_program *p = NULL;

        r = bf_program_new(&p, i, hook, BF_FRONT_IPT);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&c->programs, p);
        if (r < 0)
            return r;

        TAKE_PTR(p);
    }

    *codegen = TAKE_PTR(c);

    return 0;
}
