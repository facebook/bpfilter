/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/dynbuf.h"

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

static inline size_t _bf_round_next_power_of_2(size_t value)
{
    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;

    return ++value;
}

void bf_dynbuf_clean(struct bf_dynbuf *buf)
{
    bf_assert(buf);

    buf->len = 0;
    buf->rem = 0;
    freep((void *)&buf->data);
}

static int _bf_dynbuf_grow(struct bf_dynbuf *buf, size_t req_cap)
{
    size_t new_cap;
    int r;

    bf_assert(buf);

    if (req_cap == 0)
        return 0;

    new_cap = _bf_round_next_power_of_2(buf->len + buf->rem + req_cap);
    r = bf_realloc(&buf->data, new_cap);
    if (r)
        return r;

    buf->rem = new_cap - buf->len;

    return 0;
}

int bf_dynbuf_write(struct bf_dynbuf *buf, const void *data, size_t data_len)
{
    int r;

    bf_assert(buf);
    bf_assert(data);

    if (buf->rem < data_len) {
        r = _bf_dynbuf_grow(buf, data_len);
        if (r)
            return r;
    }

    memcpy(buf->data + buf->len, data, data_len);
    buf->len += data_len;
    buf->rem -= data_len;

    return 0;
}

void *bf_dynbuf_take(struct bf_dynbuf *buf)
{
    bf_assert(buf);

    buf->len = 0;
    buf->rem = 0;

    return TAKE_PTR(buf->data);
}
