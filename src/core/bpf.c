// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/bpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core/helper.h"
#include "core/logger.h"
#include "core/opts.h"

#if defined(__i386__)
#define _BF_NR_bpf 357
#elif defined(__x86_64__)
#define _BF_NR_bpf 321
#elif defined(__aarch64__)
#define _BF_NR_bpf 280
#else
#error _BF_NR_bpf not defined. bpfilter does not support your arch.
#endif

int bf_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    int r = (int)syscall(_BF_NR_bpf, cmd, attr, sizeof(*attr));
    if (r < 0)
        return -errno;

    return r;
}

int bf_bpf_prog_load(const char *name, unsigned int prog_type, void *img,
                     size_t img_len, enum bpf_attach_type attach_type, int *fd)
{
    _cleanup_free_ char *log_buf = NULL;
    union bpf_attr attr = {
        .prog_type = prog_type,
        .insns = bf_ptr_to_u64(img),
        .insn_cnt = (unsigned int)img_len,
        .license = bf_ptr_to_u64("GPL"),
        .expected_attach_type = attach_type,
    };
    int r;

    bf_assert(name && img && fd);

    if (bf_opts_is_verbose(BF_VERBOSE_BPF)) {
        log_buf = malloc(1 << bf_opts_bpf_log_buf_len_pow());
        if (!log_buf)
            return -ENOMEM;

        attr.log_buf = bf_ptr_to_u64(log_buf);
        attr.log_size = (uint32_t)(1 << bf_opts_bpf_log_buf_len_pow());
        attr.log_level = 1;
    }

    (void)snprintf(attr.prog_name, BPF_OBJ_NAME_LEN, "%s", name);

    r = bf_bpf(BPF_PROG_LOAD, &attr);
    if (r < 0) {
        return bf_err_r(r, "failed to load BPF program (%lu bytes):\n%s\n",
                        img_len, log_buf ?: "(no log buffer available)");
    }

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

    bf_assert(key);
    bf_assert(value);

    return bf_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

int bf_bpf_map_update_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = bf_ptr_to_u64(key),
        .value = bf_ptr_to_u64(value),
        .flags = BPF_ANY,
    };

    return bf_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

int bf_bpf_obj_pin(const char *path, int fd, int dir_fd)
{
    union bpf_attr attr = {
        .pathname = bf_ptr_to_u64(path),
        .bpf_fd = fd,
        .file_flags = dir_fd ? BPF_F_PATH_FD : 0,
        .path_fd = dir_fd,
    };

    bf_assert(path);
    bf_assert(dir_fd >= 0);
    bf_assert(path[0] == '/' ? !dir_fd : 1);

    int r = bf_bpf(BPF_OBJ_PIN, &attr);
    return r;
}

int bf_bpf_obj_get(const char *path, int dir_fd, int *fd)
{
    union bpf_attr attr = {
        .pathname = bf_ptr_to_u64(path),
        .file_flags = dir_fd ? BPF_F_PATH_FD : 0,
        .path_fd = dir_fd,
    };
    int r;

    bf_assert(path && fd);
    bf_assert(dir_fd >= 0);
    bf_assert(path[0] == '/' ? !dir_fd : 1);

    r = bf_bpf(BPF_OBJ_GET, &attr);
    if (r < 0)
        return r;

    *fd = r;

    return 0;
}

int bf_prog_run(int prog_fd, const void *pkt, size_t pkt_len, const void *ctx,
                size_t ctx_len)
{
    union bpf_attr attr = {};
    int r;

    bf_assert(pkt);
    bf_assert(pkt_len > 0);
    bf_assert(!(!!ctx ^ !!ctx_len));

    attr.test.prog_fd = prog_fd;
    attr.test.data_size_in = pkt_len;
    attr.test.data_in = ((unsigned long long)(pkt));
    attr.test.repeat = 1;

    if (ctx_len) {
        attr.test.ctx_size_in = ctx_len;
        attr.test.ctx_in = ((unsigned long long)(ctx));
    }

    r = bf_bpf(BPF_PROG_TEST_RUN, &attr);
    if (r)
        return bf_err_r(r, "failed to run the test program");

    return (int)attr.test.retval;
}
