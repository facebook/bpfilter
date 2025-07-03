/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

// clang-format off
// Include net/if.h before any kernel header to avoid conflicts.
#include <net/if.h>
// clang-format on

#include "core/if.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "core/helper.h"
#include "core/logger.h"

static char _bf_if_name[IFNAMSIZ];

int bf_if_index_from_name(const char *name)
{
    unsigned int r;

    bf_assert(name);

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

ssize_t bf_if_get_ifaces(struct bf_if_iface **ifaces)
{
    _cleanup_free_ struct bf_if_iface *_ifaces = NULL;
    struct if_nameindex *if_ni, *it;
    ssize_t n_ifaces = 0;
    size_t i = 0;

    bf_assert(ifaces);

    if_ni = if_nameindex();
    if (!if_ni)
        return bf_err_r(errno, "failed to fetch interfaces details");

    // Gather the number of interfaces to allocate the memory.
    for (it = if_ni; it->if_index != 0 || it->if_name != NULL; ++it)
        ++n_ifaces;

    if (n_ifaces == 0)
        return 0;

    _ifaces = malloc(n_ifaces * sizeof(*_ifaces));
    if (!_ifaces) {
        if_freenameindex(if_ni);
        return bf_err_r(-ENOMEM,
                        "failed to allocate memory for interfaces buffer");
    }

    for (it = if_ni; it->if_index != 0 || it->if_name != NULL; ++it) {
        _ifaces[i].index = it->if_index;

        if (it->if_index)
            strncpy(_ifaces[i].name, it->if_name, IF_NAMESIZE);
        else
            bf_warn("interface %d has no name", it->if_index);

        ++i;
    }

    *ifaces = TAKE_PTR(_ifaces);

    if_freenameindex(if_ni);

    return n_ifaces;
}
