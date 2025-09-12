/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

struct bf_dynbuf;

#define _clean_bf_dynbuf_ __attribute__((cleanup(bf_dynbuf_clean)))

struct bf_dynbuf
{
    size_t len;
    size_t rem;
    void *data;
};

#define bf_dynbuf_default()                                                    \
    (struct bf_dynbuf)                                                         \
    {                                                                          \
        .len = 0, .rem = 0, .data = NULL                                       \
    }

void bf_dynbuf_clean(struct bf_dynbuf *buf);
int bf_dynbuf_write(struct bf_dynbuf *buf, const void *data, size_t data_len);
void *bf_dynbuf_take(struct bf_dynbuf *buf);
