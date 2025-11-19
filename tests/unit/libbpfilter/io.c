/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/io.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpfilter/request.h>
#include <bpfilter/response.h>

#include "fake.h"
#include "test.h"

#define BFT_RANDOM_PAYLOAD_SIZE 4096

static void connect_to_daemon(void **state)
{
    (void)state;

    // Can't connect to daemon during unit tests, so it should fail
    assert_err(bf_connect_to_daemon());
}

static void send_and_recv_small(void **state)
{
    const char *input = "Even the darkest night will end";
    const char *output = "and the sun will rise";

    struct bft_sockets *sockets = *(struct bft_sockets **)state;
    pid_t pid;

    assert_non_null(input);
    assert_non_null(output);
    assert_int_gte(pid = fork(), 0);

    if (pid != 0) {
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        assert_ok(bf_recv_request(sockets->server_fd, &request));
        assert_string_equal(bf_request_data(request), input);

        assert_ok(
            bf_response_new_success(&response, output, strlen(output) + 1));
        assert_ok(bf_send_response(sockets->server_fd, response));

        waitpid(pid, NULL, 0);
    } else {
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        assert_ok(bf_request_new(&request, BF_FRONT_CLI, BF_REQ_CHAIN_GET,
                                 input, strlen(input) + 1));
        assert_ok(bf_send(sockets->client_fd, request, &response, NULL));

        assert_string_equal(bf_response_data(response), output);

        exit(0);
    }
}

static void send_and_recv_big(void **state)
{
    _cleanup_free_ const char *input =
        bft_get_randomly_filled_buffer(BFT_RANDOM_PAYLOAD_SIZE);
    _cleanup_free_ const char *output =
        bft_get_randomly_filled_buffer(BFT_RANDOM_PAYLOAD_SIZE);

    struct bft_sockets *sockets = *(struct bft_sockets **)state;
    pid_t pid;

    assert_non_null(input);
    assert_non_null(output);
    assert_int_gte(pid = fork(), 0);

    if (pid != 0) {
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        assert_ok(bf_recv_request(sockets->server_fd, &request));
        assert_string_equal(bf_request_data(request), input);

        assert_ok(
            bf_response_new_success(&response, output, strlen(output) + 1));
        assert_ok(bf_send_response(sockets->server_fd, response));

        waitpid(pid, NULL, 0);
    } else {
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        assert_ok(bf_request_new(&request, BF_FRONT_CLI, BF_REQ_CHAIN_GET,
                                 input, strlen(input) + 1));
        assert_ok(bf_send(sockets->client_fd, request, &response, NULL));

        assert_string_equal(bf_response_data(response), output);

        exit(0);
    }
}

static void send_and_recv_fd(void **state)
{
    _cleanup_free_ const char *input =
        bft_get_randomly_filled_buffer(BFT_RANDOM_PAYLOAD_SIZE);
    _cleanup_free_ const char *output =
        bft_get_randomly_filled_buffer(BFT_RANDOM_PAYLOAD_SIZE);
    struct bft_sockets *sockets = *(struct bft_sockets **)state;
    _cleanup_close_ int sent_fd = -1;
    _cleanup_close_ int recv_fd = -1;
    pid_t pid;

    assert_non_null(input);
    assert_non_null(output);
    assert_int_gte(sent_fd = open("/dev/random", O_RDONLY), 0);
    assert_int_gte(pid = fork(), 0);

    if (pid != 0) {
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        assert_ok(bf_recv_request(sockets->server_fd, &request));
        assert_string_equal(bf_request_data(request), input);

        assert_ok(bf_send_fd(sockets->server_fd, sent_fd));
        assert_ok(
            bf_response_new_success(&response, output, strlen(output) + 1));
        assert_ok(bf_send_response(sockets->server_fd, response));

        waitpid(pid, NULL, 0);
    } else {
        _free_bf_request_ struct bf_request *request = NULL;
        _free_bf_response_ struct bf_response *response = NULL;

        assert_ok(bf_request_new(&request, BF_FRONT_CLI, BF_REQ_CHAIN_GET,
                                 input, strlen(input) + 1));
        assert_ok(bf_send(sockets->client_fd, request, &response, &recv_fd));

        assert_string_equal(bf_response_data(response), output);
        assert_fd_equal(sent_fd, recv_fd);

        exit(0);
    }
}

static void manage_dir(void **state)
{
    _cleanup_close_ int fake_file_fd = -1;
    _cleanup_close_ int fd_tmpdir = -1;
    _cleanup_close_ int fd_tmpdir_testdir = -1;
    _cleanup_close_ int fd_tmpdir_testdir_nested = -1;
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    char dirpath[1024];

    (void)snprintf(filepath, sizeof(filepath), "%s/testfile", tmpdir->dir_path);
    (void)snprintf(dirpath, sizeof(dirpath), "%s/testdir", tmpdir->dir_path);

    // Open the base directory. Use bf_ensure_dir() twice to validate idempotency
    assert_err(bf_opendir("/directory_doesnt_exist"));
    assert_ok(bf_ensure_dir(tmpdir->dir_path));
    assert_ok(bf_ensure_dir(tmpdir->dir_path));
    assert_int_gte(fd_tmpdir = bf_opendir(tmpdir->dir_path), 0);

    // bf_ensure_dir() fails if directory ("testfile" here) can't be accessed
    fake_file_fd = open(filepath, O_CREAT | O_WRONLY, 0666);
    assert_int_gte(fake_file_fd, 0);
    assert_err(bf_ensure_dir(filepath));

    // bf_opendir_at(): directory exists
    assert_ok(bf_ensure_dir(dirpath));
    assert_int_gte(
        fd_tmpdir_testdir = bf_opendir_at(fd_tmpdir, "testdir", false), 0);

    // bf_opendir_at(): directory doesn't exist
    assert_err(bf_opendir_at(fd_tmpdir_testdir, "nested", false));
    assert_int_gte(fd_tmpdir_testdir_nested =
                       bf_opendir_at(fd_tmpdir_testdir, "nested", true),
                   0);

    // Remove the directories
    assert_err(bf_rmdir_at(INT_MAX, "dir", false));
    assert_err(bf_rmdir_at(INT_MAX, "dir", true));
    assert_err(bf_rmdir_at(fd_tmpdir, "testdir", false));
    assert_ok(bf_rmdir_at(fd_tmpdir, "testdir", true));
}

static void lock_file(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];

    // Can't lock a lockfile twice
    (void)snprintf(filepath, sizeof(filepath), "%s/file.lock",
                   tmpdir->dir_path);
    assert_int_gte(fd = bf_acquire_lock(filepath), 0);
    assert_err(bf_acquire_lock(filepath));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(connect_to_daemon),
        cmocka_unit_test_setup_teardown(send_and_recv_small,
                                        btf_setup_create_sockets,
                                        bft_teardown_close_sockets),
        cmocka_unit_test_setup_teardown(send_and_recv_big,
                                        btf_setup_create_sockets,
                                        bft_teardown_close_sockets),
        cmocka_unit_test_setup_teardown(send_and_recv_fd,
                                        btf_setup_create_sockets,
                                        bft_teardown_close_sockets),
        cmocka_unit_test_setup_teardown(manage_dir, btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(lock_file, btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
