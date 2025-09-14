/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stdbool.h>
#include <stddef.h>

#include "harness/mock.h"
#include "bpfilter/bpf_types.h"
#include "bpfilter/btf.h"

struct btf;
struct nl_msg;
struct nlmsghdr;

bf_test_mock_declare(void *, malloc, (size_t size));
bf_test_mock_declare(void *, calloc, (size_t nmemb, size_t size));
bf_test_mock_declare(int, open, (const char *pathname, int flags, mode_t mode));
bf_test_mock_declare(ssize_t, read, (int fd, void *buf, size_t count));
bf_test_mock_declare(ssize_t, write, (int fd, const void *buf, size_t count));
bf_test_mock_declare(struct btf *, btf__load_vmlinux_btf, (void));
bf_test_mock_declare(struct nl_msg *, nlmsg_alloc, ());
bf_test_mock_declare(struct nl_msg *, nlmsg_convert, (struct nlmsghdr * nlh));
bf_test_mock_declare(struct nlmsghdr *, nlmsg_put,
                    (struct nl_msg * nlmsg, uint32_t pid, uint32_t seq,
                    int type, int payload, int flags));
bf_test_mock_declare(int, nlmsg_append,
                    (struct nl_msg * nlmsg, void *data, size_t len, int pad));
bf_test_mock_declare(int, bf_bpf_obj_get, (const char *path, int *fd));
bf_test_mock_declare(int, vsnprintf,
                    (char *str, size_t size, const char *fmt, va_list args));
bf_test_mock_declare(int, snprintf,
                    (char *str, size_t size, const char *fmt, ...));
bf_test_mock_declare(int, bf_bpf, (enum bf_bpf_cmd cmd, union bpf_attr *attr));
bf_test_mock_declare(int, bf_ctx_token, (void));
bf_test_mock_declare(int, bf_btf_get_id, (const char *name));
bf_test_mock_declare(int, bf_bpf_map_create, (const char *name, enum bf_bpf_map_type type,
                      size_t key_size, size_t value_size, size_t n_elems,
                      const struct bf_btf *btf, int token_fd));
