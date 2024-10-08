// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/bpf.h"

#include <linux/bpf.h>
#include <linux/netfilter.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/nf.h"
#include "core/opts.h"

#define _bf_ptr_to_u64(ptr) ((unsigned long long)(ptr))

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
        .insns = _bf_ptr_to_u64(img),
        .insn_cnt = (unsigned int)img_len,
        .license = _bf_ptr_to_u64("GPL"),
        .expected_attach_type = attach_type,
    };
    int r;

    bf_assert(name && img && fd);

    if (bf_opts_is_verbose(BF_VERBOSE_BPF)) {
        log_buf = malloc(1 << bf_opts_bpf_log_buf_len_pow());
        if (!log_buf)
            return -ENOMEM;

        attr.log_buf = _bf_ptr_to_u64(log_buf);
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

int bf_bpf__map_create(const char *name, unsigned int type, size_t key_size,
                       size_t value_size, size_t max_entries, uint32_t flags,
                       int *fd)
{
    union bpf_attr attr = {
        .map_type = type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
        .map_flags = flags,
    };
    int r;

    (void)snprintf(attr.map_name, BPF_OBJ_NAME_LEN, "%s", name);

    r = bf_bpf(BPF_MAP_CREATE, &attr);
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

    bf_assert(key);
    bf_assert(value);

    return bf_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

int bf_bpf_map_update_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = _bf_ptr_to_u64(key),
        .value = _bf_ptr_to_u64(value),
        .flags = BPF_ANY,
    };

    return bf_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

int bf_bpf_obj_pin(const char *path, int fd)
{
    union bpf_attr attr = {
        .pathname = _bf_ptr_to_u64(path),
        .bpf_fd = fd,
    };

    return bf_bpf(BPF_OBJ_PIN, &attr);
}

int bf_bpf_obj_get(const char *path, int *fd)
{
    union bpf_attr attr = {
        .pathname = _bf_ptr_to_u64(path),
    };
    int r;

    bf_assert(path);
    bf_assert(fd);

    r = bf_bpf(BPF_OBJ_GET, &attr);
    if (r < 0)
        return r;

    *fd = r;

    return 0;
}

int bf_bpf_tc_link_create(int prog_fd, unsigned int ifindex,
                          enum bpf_attach_type hook, int *link_fd)
{
    union bpf_attr attr = {};
    int r;

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = ifindex;
    attr.link_create.attach_type = hook;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    *link_fd = r;

    return 0;
}

int bf_bpf_nf_link_create(int prog_fd, enum bf_hook hook, int priority,
                          int *link_fd)
{
    union bpf_attr attr = {};
    int r;

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.attach_type = BPF_NETFILTER;
    attr.link_create.netfilter.pf = NFPROTO_IPV4;
    attr.link_create.netfilter.hooknum = bf_hook_to_nf_hook(hook);
    attr.link_create.netfilter.priority = priority;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    *link_fd = r;

    return 0;
}

int bf_bpf_xdp_link_create(int prog_fd, unsigned int ifindex, int *link_fd,
                           enum bf_xdp_attach_mode mode)
{
    union bpf_attr attr = {};
    int r;

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = ifindex;
    attr.link_create.attach_type = BPF_XDP;
    attr.link_create.flags = mode;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    *link_fd = r;

    return 0;
}

int bf_bpf_cgroup_link_create(int prog_fd, int cgroup_fd,
                              enum bpf_attach_type type, int *link_fd)
{
    union bpf_attr attr = {};
    int r;

    bf_assert(link_fd);

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = cgroup_fd;
    attr.link_create.attach_type = type;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    *link_fd = r;

    return 0;
}

int bf_bpf_xdp_link_update(int link_fd, int prog_fd)
{
    union bpf_attr attr = {};

    attr.link_update.link_fd = link_fd;
    attr.link_update.new_prog_fd = prog_fd;

    return bf_bpf(BPF_LINK_UPDATE, &attr);
}

int bf_bpf_link_update(int link_fd, int prog_fd)
{
    union bpf_attr attr = {};

    attr.link_update.link_fd = link_fd;
    attr.link_update.new_prog_fd = prog_fd;

    return bf_bpf(BPF_LINK_UPDATE, &attr);
}

int bf_bpf_link_detach(int link_fd)
{
    union bpf_attr attr = {
        .link_detach.link_fd = link_fd,
    };

    return bf_bpf(BPF_LINK_DETACH, &attr);
}
