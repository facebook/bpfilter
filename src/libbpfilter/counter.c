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

int bf_counter_new(struct bf_counter **counter, uint64_t count, uint64_t size)
{
    _cleanup_free_ struct bf_counter *_counter = NULL;

    assert(counter);

    _counter = malloc(sizeof(*_counter));
    if (!_counter)
        return -ENOMEM;

    _counter->count = count;
    _counter->size = size;

    *counter = TAKE_PTR(_counter);

    return 0;
}

int bf_counter_new_from_pack(struct bf_counter **counter, bf_rpack_node_t node)
{
    _free_bf_counter_ struct bf_counter *_counter = NULL;
    int r;

    assert(counter);

    r = bf_counter_new(&_counter, 0, 0);
    if (r)
        return r;

    r = bf_rpack_kv_u64(node, "count", &_counter->count);
    if (r)
        return bf_rpack_key_err(r, "bf_counter.count");

    r = bf_rpack_kv_u64(node, "size", &_counter->size);
    if (r)
        return bf_rpack_key_err(r, "bf_counter.size");

    *counter = TAKE_PTR(_counter);

    return 0;
}

void bf_counter_free(struct bf_counter **counter)
{
    assert(counter);

    if (!*counter)
        return;

    freep((void *)counter);
}

int bf_counter_pack(const struct bf_counter *counter, bf_wpack_t *pack)
{
    assert(counter);
    assert(pack);

    bf_wpack_kv_u64(pack, "count", counter->count);
    bf_wpack_kv_u64(pack, "size", counter->size);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}
