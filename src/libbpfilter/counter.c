/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */
#include "bpfilter/counter.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/helper.h"

int bf_counter_new(struct bf_counter **counter, uint64_t packets,
                   uint64_t bytes)
{
    _cleanup_free_ struct bf_counter *_counter = NULL;

    bf_assert(counter);

    _counter = malloc(sizeof(*_counter));
    if (!_counter)
        return -ENOMEM;

    _counter->bytes = bytes;
    _counter->packets = packets;

    *counter = TAKE_PTR(_counter);

    return 0;
}

int bf_counter_new_from_pack(struct bf_counter **counter, bf_rpack_node_t node)
{
    _free_bf_counter_ struct bf_counter *_counter = NULL;
    int r;

    bf_assert(counter);

    r = bf_counter_new(&_counter, 0, 0);
    if (r)
        return r;

    r = bf_rpack_kv_u64(node, "packets", &_counter->packets);
    if (r)
        return bf_rpack_key_err(r, "bf_counter.packets");

    r = bf_rpack_kv_u64(node, "bytes", &_counter->bytes);
    if (r)
        return bf_rpack_key_err(r, "bf_counter.bytes");

    *counter = TAKE_PTR(_counter);

    return 0;
}

void bf_counter_free(struct bf_counter **counter)
{
    bf_assert(counter);

    if (!*counter)
        return;

    freep((void *)counter);
}

int bf_counter_pack(const struct bf_counter *counter, bf_wpack_t *pack)
{
    bf_assert(counter);
    bf_assert(pack);

    bf_wpack_kv_u64(pack, "packets", counter->packets);
    bf_wpack_kv_u64(pack, "bytes", counter->bytes);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}
