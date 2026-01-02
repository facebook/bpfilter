// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/bpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdint.h>

#include "bpfilter/bpf_types.h"
#include "bpfilter/hook.h"
#include "mock.h"
#include "test.h"

static void bpf_success(void **state)
{
    union bpf_attr attr;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    memset(&attr, 0, sizeof(attr));

    // Test successful syscall returning a file descriptor
    bft_mock_syscall_set_retval(42);
    r = bf_bpf(BF_BPF_MAP_CREATE, &attr);
    assert_int_equal(r, 42);
}

static void bpf_failure(void **state)
{
    union bpf_attr attr;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    memset(&attr, 0, sizeof(attr));

    // Test failed syscall
    bft_mock_syscall_set_retval(-EPERM);
    r = bf_bpf(BF_BPF_MAP_CREATE, &attr);
    assert_int_equal(r, -EPERM);
}

static void bpf_prog_load_success(void **state)
{
    uint64_t img[] = {0x95, 0x00, 0x00, 0x00}; // BPF_EXIT_INSN
    int fd = -1;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    // Return fd 10
    bft_mock_syscall_set_retval(10);
    r = bf_bpf_prog_load("test_prog", BF_BPF_PROG_TYPE_XDP, img, 1,
                         BF_BPF_XDP, NULL, 0, -1, &fd);
    assert_ok(r);
    assert_int_equal(fd, 10);
}

static void bpf_prog_load_failure(void **state)
{
    uint64_t img[] = {0x95, 0x00, 0x00, 0x00}; // BPF_EXIT_INSN
    int fd = -1;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    // Return error
    bft_mock_syscall_set_retval(-EINVAL);
    r = bf_bpf_prog_load("test_prog", BF_BPF_PROG_TYPE_XDP, img, 1,
                         BF_BPF_XDP, NULL, 0, -1, &fd);
    assert_err(r);
    assert_int_equal(fd, -1); // fd unchanged on error
}

static void bpf_prog_load_with_token(void **state)
{
    uint64_t img[] = {0x95, 0x00, 0x00, 0x00}; // BPF_EXIT_INSN
    int fd = -1;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    // Test with token_fd
    bft_mock_syscall_set_retval(15);
    r = bf_bpf_prog_load("test_prog", BF_BPF_PROG_TYPE_XDP, img, 1,
                         BF_BPF_XDP, NULL, 0, 5, &fd);
    assert_ok(r);
    assert_int_equal(fd, 15);
}

static void bpf_map_lookup_elem_success(void **state)
{
    uint32_t key = 0;
    uint64_t value = 0;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_map_lookup_elem(10, &key, &value);
    assert_ok(r);
}

static void bpf_map_lookup_elem_failure(void **state)
{
    uint32_t key = 0;
    uint64_t value = 0;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-ENOENT);
    r = bf_bpf_map_lookup_elem(10, &key, &value);
    assert_int_equal(r, -ENOENT);
}

static void bpf_obj_pin_success(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_obj_pin("/sys/fs/bpf/test", 10, 0);
    assert_ok(r);
}

static void bpf_obj_pin_relative(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    // Test with dir_fd (relative path)
    bft_mock_syscall_set_retval(0);
    r = bf_bpf_obj_pin("test_obj", 10, 5);
    assert_ok(r);
}

static void bpf_obj_get_success(void **state)
{
    int fd = -1;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(20);
    r = bf_bpf_obj_get("/sys/fs/bpf/test", 0, &fd);
    assert_ok(r);
    assert_int_equal(fd, 20);
}

static void bpf_obj_get_failure(void **state)
{
    int fd = -1;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-ENOENT);
    r = bf_bpf_obj_get("/sys/fs/bpf/test", 0, &fd);
    assert_int_equal(r, -ENOENT);
    assert_int_equal(fd, -1); // fd unchanged on error
}

static void bpf_prog_run_success(void **state)
{
    char pkt[] = {0x00, 0x01, 0x02, 0x03};
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    // Note: bf_bpf_prog_run returns attr.test.retval on success
    // but our mock just returns 0 for the syscall
    bft_mock_syscall_set_retval(0);
    r = bf_bpf_prog_run(10, pkt, sizeof(pkt), NULL, 0);
    // The return value is attr.test.retval which is 0 since we zero-init the attr
    assert_int_equal(r, 0);
}

static void bpf_prog_run_with_ctx(void **state)
{
    char pkt[] = {0x00, 0x01, 0x02, 0x03};
    char ctx[] = {0x10, 0x20};
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_prog_run(10, pkt, sizeof(pkt), ctx, sizeof(ctx));
    assert_int_equal(r, 0);
}

static void bpf_prog_run_failure(void **state)
{
    char pkt[] = {0x00, 0x01, 0x02, 0x03};
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-EINVAL);
    r = bf_bpf_prog_run(10, pkt, sizeof(pkt), NULL, 0);
    assert_int_equal(r, -EINVAL);
}

static void bpf_token_create_success(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(30);
    r = bf_bpf_token_create(5);
    assert_int_equal(r, 30);
}

static void bpf_token_create_failure(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-EPERM);
    r = bf_bpf_token_create(5);
    assert_int_equal(r, -EPERM);
}

static void bpf_btf_load_success(void **state)
{
    char btf_data[] = {0x00}; // Dummy BTF data
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(25);
    r = bf_bpf_btf_load(btf_data, -1);
    assert_int_equal(r, 25);
}

static void bpf_btf_load_with_token(void **state)
{
    char btf_data[] = {0x00}; // Dummy BTF data
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(26);
    r = bf_bpf_btf_load(btf_data, 5);
    assert_int_equal(r, 26);
}

static void bpf_map_create_success(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(100);
    r = bf_bpf_map_create("test_map", BF_BPF_MAP_TYPE_HASH, 4, 8, 1024, NULL,
                          -1);
    assert_int_equal(r, 100);
}

static void bpf_map_create_lpm_trie(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    // LPM_TRIE sets BPF_F_NO_PREALLOC flag
    bft_mock_syscall_set_retval(101);
    r = bf_bpf_map_create("test_lpm", BF_BPF_MAP_TYPE_LPM_TRIE, 8, 8, 1024, NULL,
                          -1);
    assert_int_equal(r, 101);
}

static void bpf_map_create_with_token(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(102);
    r = bf_bpf_map_create("test_map", BF_BPF_MAP_TYPE_ARRAY, 4, 8, 100, NULL, 5);
    assert_int_equal(r, 102);
}

static void bpf_map_update_elem_success(void **state)
{
    uint32_t key = 0;
    uint64_t value = 42;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_map_update_elem(10, &key, &value, 0);
    assert_ok(r);
}

static void bpf_map_update_elem_failure(void **state)
{
    uint32_t key = 0;
    uint64_t value = 42;
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-EEXIST);
    r = bf_bpf_map_update_elem(10, &key, &value, BPF_NOEXIST);
    assert_int_equal(r, -EEXIST);
}

static void bpf_map_update_batch_success(void **state)
{
    uint32_t keys[] = {0, 1, 2};
    uint64_t values[] = {10, 20, 30};
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_map_update_batch(10, keys, values, 3, 0);
    assert_ok(r);
}

static void bpf_link_create_success(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(50);
    // Non-netfilter hook doesn't require family/priority
    r = bf_bpf_link_create(10, 5, BF_HOOK_XDP, 0, 0, 0);
    assert_int_equal(r, 50);
}

static void bpf_link_create_netfilter(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(51);
    // Netfilter hook with family=2 (AF_INET) and priority=100
    r = bf_bpf_link_create(10, 0, BF_HOOK_NF_PRE_ROUTING, 0, 2, 100);
    assert_int_equal(r, 51);
}

static void bpf_link_update_success(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_link_update(50, 11);
    assert_ok(r);
}

static void bpf_link_update_failure(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-EINVAL);
    r = bf_bpf_link_update(50, 11);
    assert_int_equal(r, -EINVAL);
}

static void bpf_link_detach_success(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(0);
    r = bf_bpf_link_detach(50);
    assert_ok(r);
}

static void bpf_link_detach_failure(void **state)
{
    int r;

    (void)state;

    _clean_bft_mock_ bft_mock mock = bft_mock_get(syscall);
    (void)mock;

    bft_mock_syscall_set_retval(-EINVAL);
    r = bf_bpf_link_detach(50);
    assert_int_equal(r, -EINVAL);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(bpf_success),
        cmocka_unit_test(bpf_failure),
        cmocka_unit_test(bpf_prog_load_success),
        cmocka_unit_test(bpf_prog_load_failure),
        cmocka_unit_test(bpf_prog_load_with_token),
        cmocka_unit_test(bpf_map_lookup_elem_success),
        cmocka_unit_test(bpf_map_lookup_elem_failure),
        cmocka_unit_test(bpf_obj_pin_success),
        cmocka_unit_test(bpf_obj_pin_relative),
        cmocka_unit_test(bpf_obj_get_success),
        cmocka_unit_test(bpf_obj_get_failure),
        cmocka_unit_test(bpf_prog_run_success),
        cmocka_unit_test(bpf_prog_run_with_ctx),
        cmocka_unit_test(bpf_prog_run_failure),
        cmocka_unit_test(bpf_token_create_success),
        cmocka_unit_test(bpf_token_create_failure),
        cmocka_unit_test(bpf_btf_load_success),
        cmocka_unit_test(bpf_btf_load_with_token),
        cmocka_unit_test(bpf_map_create_success),
        cmocka_unit_test(bpf_map_create_lpm_trie),
        cmocka_unit_test(bpf_map_create_with_token),
        cmocka_unit_test(bpf_map_update_elem_success),
        cmocka_unit_test(bpf_map_update_elem_failure),
        cmocka_unit_test(bpf_map_update_batch_success),
        cmocka_unit_test(bpf_link_create_success),
        cmocka_unit_test(bpf_link_create_netfilter),
        cmocka_unit_test(bpf_link_update_success),
        cmocka_unit_test(bpf_link_update_failure),
        cmocka_unit_test(bpf_link_detach_success),
        cmocka_unit_test(bpf_link_detach_failure),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
