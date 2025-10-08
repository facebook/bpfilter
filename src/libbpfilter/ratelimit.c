/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include "bpfilter/ratelimit.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/helper.h"

int bf_ratelimit_new(struct bf_ratelimit **ratelimit, uint64_t current,
                     uint64_t last_time)
{
    _cleanup_free_ struct bf_ratelimit *_ratelimit = NULL;

    bf_assert(ratelimit);

    _ratelimit = malloc(sizeof(*_ratelimit));
    if (!_ratelimit)
        return -ENOMEM;

    _ratelimit->current = current;
    _ratelimit->last_time = last_time;

    *ratelimit = TAKE_PTR(_ratelimit);

    return 0;
}

int bf_ratelimit_new_from_pack(struct bf_ratelimit **ratelimit,
                               bf_rpack_node_t node)
{
    _free_bf_ratelimit_ struct bf_ratelimit *_ratelimit = NULL;
    int r;

    bf_assert(ratelimit);

    r = bf_ratelimit_new(&_ratelimit, 0, 0);
    if (r)
        return r;

    r = bf_rpack_kv_u64(node, "current", &_ratelimit->current);
    if (r)
        return bf_rpack_key_err(r, "bf_ratelimit.current");

    r = bf_rpack_kv_u64(node, "last_time", &_ratelimit->last_time);
    if (r)
        return bf_rpack_key_err(r, "bf_ratelimit.last_time");

    *ratelimit = TAKE_PTR(_ratelimit);

    return 0;
}

void bf_ratelimit_free(struct bf_ratelimit **ratelimit)
{
    bf_assert(ratelimit);

    if (!*ratelimit)
        return;

    freep((void *)ratelimit);
}

int bf_ratelimit_pack(const struct bf_ratelimit *ratelimit, bf_wpack_t *pack)
{
    bf_assert(ratelimit);
    bf_assert(pack);

    bf_wpack_kv_u64(pack, "current", ratelimit->current);
    bf_wpack_kv_u64(pack, "last_time", ratelimit->last_time);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}
