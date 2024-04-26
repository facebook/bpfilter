// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "generator/print.h"

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include "core/bpf.h"
#include "core/logger.h"
#include "opts.h"
#include "shared/helper.h"

#define make_print_str(id, str) [id] = {0, 0, "%d: " str}

static struct
{
    size_t offset;
    size_t len;
    const char *str;
} _bf_print_strings[] = {
    make_print_str(BF_PRINT_NO_DYNPTR, "failed to create a dynamic pointer"),
    make_print_str(BF_PRINT_NO_SLICE,
                   "failed to create a dynamic pointer slice"),
    make_print_str(BF_PRINT_NO_L2, "no L2 header available in packet data"),
    make_print_str(BF_PRINT_NO_L3, "no L3 header available in packet data"),
    make_print_str(BF_PRINT_NO_IPV4, "L3 header is not IPv4"),
};

static int _bf_fd;
static const char *_bf_print_strs_path = "/sys/fs/bpf/bf_print_strs";

size_t _bf_compute_offsets(void)
{
    size_t next_offset = 0;

    for (size_t i = 0; i < ARRAY_SIZE(_bf_print_strings); ++i) {
        _bf_print_strings[i].offset = next_offset;
        _bf_print_strings[i].len = strlen(_bf_print_strings[i].str + 1);
        next_offset += _bf_print_strings[i].len;
    }

    return next_offset;
}

int bf_print_setup(void)
{
    _cleanup_free_ char *strings = NULL;
    _cleanup_close_ int fd = -1;
    size_t total_size;
    int r;

    total_size = _bf_compute_offsets();

    strings = malloc(total_size);
    if (!strings)
        return bf_err_code(-EINVAL, "could not allocate memory");

    for (size_t i = 0; i < ARRAY_SIZE(_bf_print_strings); ++i) {
        memcpy(strings + _bf_print_strings[i].offset, _bf_print_strings[i].str,
               _bf_print_strings[i].len);
    }

    r = bf_bpf_map_create("bf_print_strs", BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
                          total_size, 1, BPF_F_RDONLY_PROG, &fd);
    if (r < 0)
        return bf_err_code(r, "failed to create strings map");

    r = bf_bpf_map_update_elem(fd, (void *)(uint32_t[]) {0}, strings);
    if (r < 0)
        return bf_err_code(r, "failed to insert strings into the map");

    r = bf_bpf_map_freeze(fd);
    if (r < 0)
        return bf_err_code(r, "failed to freeze strings map");

    if (!bf_opts_transient()) {
        r = bf_bpf_obj_pin(_bf_print_strs_path, fd);
        if (r < 0)
            return bf_err_code(r, "failed to pin strings map");
    }

    _bf_fd = TAKE_FD(fd);

    return 0;
}

void bf_print_teardown(void)
{
    closep(&_bf_fd);
}

int bf_print_fd(void)
{
    bf_assert(_bf_fd >= 0);

    return _bf_fd;
}

size_t bf_print_msg_size(enum bf_print_msg msg_id)
{
    bf_assert(0 <= msg_id && msg_id < _BF_PRINT_MAX);

    return _bf_print_strings[msg_id].len;
}

size_t bf_print_msg_offset(enum bf_print_msg msg_id)
{
    bf_assert(0 <= msg_id && msg_id < _BF_PRINT_MAX);

    return _bf_print_strings[msg_id].offset;
}
