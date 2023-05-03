/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)

/**
 * @brief Get the number of element in an array.
 *
 * @param x The array.
 * @return size_t The number of elements in the array.
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __cleanup_free__ __attribute__((__cleanup__(freep)))
#define __cleanup_close__ __attribute__((__cleanup__(closep)))

/*
 * Thank you Lennart:
 * https://github.com/systemd/systemd/blame/5809f340fd7e5e6c76e229059c50d92e1f57e8d8/src/basic/alloc-util.h#L50-L54
 */
static inline void freep(void *p)
{
    free(*(void **)p);
    *(void **)p = NULL;
}

static inline void closep(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}
