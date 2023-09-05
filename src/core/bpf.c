// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/bpf.h"

#include <linux/bpf.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "core/logger.h"
#include "opts.h"
#include "shared/helper.h"

#define _bf_ptr_to_u64(ptr) ((unsigned long long)(ptr))

/**
 * @brief BPF system call.
 *
 * @param cmd BPF command to run.
 * @param attr Attributes of the system call.
 * @return System call return value on success, or negative errno value on
 * failure.
 */
static int _bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int bf_bpf_prog_load(const char *name, unsigned int prog_type, void *img,
                     size_t img_len, int *fd)
{
    _cleanup_free_ char *log_buf = NULL;
    union bpf_attr attr = {
        .prog_type = prog_type,
        .insns = _bf_ptr_to_u64(img),
        .insn_cnt = (unsigned int)img_len,
        .license = _bf_ptr_to_u64("GPL"),
    };
    int r;

    assert(name);
    assert(img);
    assert(fd);

    if (bf_opts_verbose()) {
        log_buf = malloc(1 << bf_opts_bpf_log_buf_len_pow());
        if (!log_buf)
            return -ENOMEM;

        attr.log_buf = _bf_ptr_to_u64(log_buf);
        attr.log_size = (uint32_t)(1 << bf_opts_bpf_log_buf_len_pow());
        attr.log_level = 1;
    }

    snprintf(attr.prog_name, BPF_OBJ_NAME_LEN, "%s", name);

    r = _bpf(BPF_PROG_LOAD, &attr);
    if (r < 0) {
        return bf_err_code(r, "failed to load BPF program: %s\n%s",
                           bf_strerror(errno), log_buf);
    }

    *fd = r;

    return 0;
}

int bf_bpf_map_create(const char *name, unsigned int type, size_t key_size,
                      size_t value_size, size_t max_entries, int *fd)
{
    union bpf_attr attr = {
        .map_type = type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };
    int r;

    snprintf(attr.map_name, BPF_OBJ_NAME_LEN, "%s", name);

    r = _bpf(BPF_MAP_CREATE, &attr);
    if (r < 0)
        return r;

    *fd = r;

    return 0;
}

int bf_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
    };

    assert(key);
    assert(value);

    return _bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

int bf_bpf_obj_pin(const char *path, int fd)
{
    union bpf_attr attr = {
        .pathname = _bf_ptr_to_u64(path),
        .bpf_fd = fd,
    };

    return _bpf(BPF_OBJ_PIN, &attr);
}

int bf_bpf_obj_get(const char *path, int *fd)
{
    union bpf_attr attr = {
        .pathname = _bf_ptr_to_u64(path),
    };
    int r;

    assert(path);
    assert(fd);

    r = _bpf(BPF_OBJ_GET, &attr);
    if (r < 0)
        return -errno;

    *fd = r;

    return 0;
}
