/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "mock.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

static const char *_bf_readable_file_content = "Hello, world!";

char *bf_test_filepath_new_rw(void)
{
    int fd;
    size_t len = strlen(_bf_readable_file_content);
    char tmppath[] = "/tmp/bpfltr_XXXXXX";
    char *path = NULL;

    fd = mkstemp(tmppath);
    if (fd < 0) {
        bf_err_r(errno, "failed to create a temporary file path");
        return NULL;
    }

    if ((ssize_t)len != write(fd, _bf_readable_file_content, len)) {
        bf_err_r(errno, "failed to write to the temporary filepath");
        return NULL;
    }

    close(fd);

    path = strdup(tmppath);
    if (!path) {
        bf_err_r(errno, "failed to allocate memory for the new filepath");
        return NULL;
    }

    return path;
}

void bf_test_filepath_free(char **path)
{
    bf_assert(path);

    if (!*path)
        return;

    if (unlink(*path) < 0)
        bf_err_r(errno, "failed to remove '%s'", *path);

    freep((void *)path);
}

void bf_test_mock_clean(bf_test_mock *mock)
{
    mock->disable();
}
