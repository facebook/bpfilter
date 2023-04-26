/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdlib.h>

#define UNUSED(x) (void)(x)


/*
 * Thank you Lennart:
 * https://github.com/systemd/systemd/blame/5809f340fd7e5e6c76e229059c50d92e1f57e8d8/src/basic/alloc-util.h#L50-L54
 */
static inline void freep(void *p)
{
    free(*(void **)p);
}
