/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

// clang-format off
// Include net/if.h before any kernel header to avoid conflicts.
#include <net/if.h>
// clang-format on

#include "bpfilter/if.h"

#include <errno.h>
#include <limits.h>
#include <sys/types.h>

#include "bpfilter/helper.h"

static char _bf_if_name[IFNAMSIZ];

int bf_if_index_from_name(const char *name)
{
    unsigned int r;

    assert(name);

    r = if_nametoindex(name);
    if (r == 0)
        return -ENOENT;

    if (r > INT_MAX)
        return -E2BIG;

    return (int)r;
}

const char *bf_if_name_from_index(int index)
{
    if (!if_indextoname(index, _bf_if_name))
        return NULL;

    return _bf_if_name;
}

int bf_if_index_from_str(const char *str, uint32_t *ifindex)
{
    int idx;
    unsigned long parsed;
    char *endptr;

    assert(str);
    assert(ifindex);

    idx = bf_if_index_from_name(str);
    if (idx > 0) {
        *ifindex = (uint32_t)idx;
        return 0;
    }

    errno = 0;
    parsed = strtoul(str, &endptr, BF_BASE_10);
    if (*endptr == '\0' && errno == 0 && parsed > 0 && parsed <= UINT32_MAX) {
        *ifindex = (uint32_t)parsed;
        return 0;
    }

    return -EINVAL;
}
