/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

// clang-format off
#include <stdarg.h> // NOLINT: required by cmocka.h
#include <stddef.h> // NOLINT: required by cmocka.h
#include <stdint.h> // NOLINT: required by cmocka.h
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h> // NOLINT: required by cmocka.h
// clang-format on

#include <linux/kcmp.h>

#include <sys/syscall.h>
#include <unistd.h>

#include "fake.h"

struct bf_set;
struct bf_counter;

#define assert_ok(expr) assert_true((expr) == 0)
#define assert_err(expr) assert_true((expr) < 0)
#define assert_int_gt(expr, ref) assert_true((expr) > (ref))
#define assert_int_gte(expr, ref) assert_true((expr) >= (ref))
#define assert_int_lt(expr, ref) assert_true((expr) < (ref))
#define assert_int_lte(expr, ref) assert_true((expr) <= (ref))

#define assert_enum_to_str(type, to_str, first, max)                           \
    do {                                                                       \
        for (type _start = first; _start < max; ++_start)                      \
            assert_non_null(to_str(_start));                                   \
        assert_non_null(to_str(first - 1));                                    \
        assert_non_null(to_str(max));                                          \
    } while (0)

#define assert_enum_to_from_str(type, to_str, from_str, first, max)            \
    do {                                                                       \
        type back;                                                             \
        for (type _start = first; _start < max; ++_start) {                    \
            const char *str = to_str(_start);                                  \
            assert_non_null(str);                                              \
            assert_ok(((int (*)(const char *, type *))from_str)(str, &back));  \
            assert_int_equal(_start, back);                                    \
        }                                                                      \
        assert_non_null(to_str(first - 1));                                    \
        assert_non_null(to_str(max));                                          \
        assert_err(from_str(NULL, &back));                                     \
        assert_err(from_str("", &back));                                       \
        assert_err(from_str("invalid", &back));                                \
    } while (0)

#define assert_fd_equal(fd0, fd1)                                              \
    do {                                                                       \
        assert_int_equal(                                                      \
            syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, (fd0), (fd1)),    \
            0);                                                                \
    } while (0)
#define assert_fd_empty(fd) assert_int_equal(fd, -1)

#define assert_rule_equal(rule0, rule1)                                        \
    do {                                                                       \
        assert_true(bft_rule_equal(rule0, rule1));                             \
    } while (0)

/**
 * @brief Compare two `bf_list` objects.
 *
 * @param lhs First list to compare.
 * @param rhs Second list to compare.
 * @param cb Callback used to compare the nodes payload. If `NULL`, the node's
 *        payload is not compared. If set, `cb` is called with the payload
 *        of `lhs` and `rhs` node, for each node.
 * @return True if both lists are equal, false otherwise.
 */
bool bft_list_eq(const bf_list *lhs, const bf_list *rhs, bft_list_eq_cb cb);

bool bft_set_eq(const struct bf_set *lhs, const struct bf_set *rhs);
bool bft_counter_eq(const struct bf_counter *lhs, const struct bf_counter *rhs);
bool bft_chain_equal(const struct bf_chain *chain0,
                     const struct bf_chain *chain1);
bool bft_rule_equal(const struct bf_rule *rule0, const struct bf_rule *rule1);
bool bft_matcher_equal(const struct bf_matcher *matcher0,
                       const struct bf_matcher *matcher1);

int btf_setup_redirect_streams(void **state);
int bft_teardown_redirect_streams(void **state);

#define bft_streams_flush(streams)                                             \
    do {                                                                       \
        (void)fflush((streams)->new_stdout);                                   \
        (void)fflush((streams)->new_stderr);                                   \
    } while (0)

struct bft_streams
{
    FILE *new_stdout;
    FILE *old_stdout;
    char *stdout_buf;
    size_t stdout_len;

    FILE *new_stderr;
    FILE *old_stderr;
    char *stderr_buf;
    size_t stderr_len;
};

int bft_streams_new(struct bft_streams **streams);
void bft_stream_free(struct bft_streams **streams);

int btf_setup_create_sockets(void **state);
int bft_teardown_close_sockets(void **state);

struct bft_sockets
{
    int client_fd;
    int server_fd;
};

int bft_sockets_new(struct bft_sockets **sockets);
void bft_sockets_free(struct bft_sockets **sockets);

int btf_setup_create_tmpdir(void **state);
int bft_teardown_close_tmpdir(void **state);

struct bft_tmpdir
{
    char template[1024];
    char *dir_path;
};

int bft_tmpdir_new(struct bft_tmpdir **tmpdir);
void bft_tmpdir_free(struct bft_tmpdir **tmpdir);
