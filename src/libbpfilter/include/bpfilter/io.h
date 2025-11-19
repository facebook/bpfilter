/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <sys/types.h>

#define BF_RUNTIME_DIR "/run/bpfilter"
#define BF_SOCKET_PATH BF_RUNTIME_DIR "/daemon.sock"
#define BF_LOCK_PATH BF_RUNTIME_DIR "/daemon.lock"

struct bf_request;
struct bf_response;

/**
 * @brief Connect to the bpfilter daemon and return the socket.
 *
 * @return A file descriptor to communicate with the daemon on success, or a
 *         negative error value on failure.
 */
int bf_connect_to_daemon(void);

/**
 * @brief Send a request to the daemon, receive a response. Can receive an extra
 * file descriptor.
 *
 * Communicate back and forth with the daemon (send a request, receive a
 * response). Some responses include a file descriptor.
 *
 * @pre
 * - `request` is a valid, non-NULL request
 * - `response != NULL`
 *
 * @param fd File descriptor of the socket to send the data over.
 * @param request Request to send to the daemon.
 * @param response Response received from the daemon, allocated by
 *        `bf_send()`.
 * @param recv_fd File descriptor sent by the daemon. If NULL, no file
 *        descriptor is expected.
 * @return 0 on success, negative error value on failure.
 */
int bf_send(int fd, const struct bf_request *request,
            struct bf_response **response, int *recv_fd);

/**
 * Received a request from the file descriptor.
 *
 * @param fd File descriptor to receive the request from. Must be a valid file
 *        descriptor.
 * @param request Request to receive. Can't be NULL. Will be allocated by the
 *        function.
 * @return 0 on success, negative error code on failure.
 */
int bf_recv_request(int fd, struct bf_request **request);

/**
 * Send a response to the given file descriptor.
 *
 * @param fd File descriptor to send the response to. Must be a valid file
 *        descriptor.
 * @param response Response to send. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_send_response(int fd, struct bf_response *response);

/**
 * @brief Send a file descriptor over a Unix Domain Socket.
 *
 * @param sock_fd File descriptor of a Unix Domain Socket, used to send `fd`.
 * @param fd File descriptor to send.
 * @return 0, or a negative error value on failure.
 */
int bf_send_fd(int sock_fd, int fd);

/**
 * Ensure @p dir exists and can be read/writen by the current process.
 *
 * Check if the current process can access @p dir. If it doesn't exists,
 * create it with the appropriate permissions. If it exists, check that it is
 * a writable directory.
 *
 * @param dir Directory to validate. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ensure_dir(const char *dir);

/**
 * @brief Open a directory and return its file descriptor.
 *
 * @param path Path of the directory to open. Can't be NULL.
 * @return A file descriptor of the open directory on success, or a negative
 *         errno value on failure.
 */
int bf_opendir(const char *path);

/**
 * @brief Open a directory from a parent directory file descriptor.
 *
 * @param parent_fd File descriptor of the parent directory to open the
 *        directory from.
 * @param dir_name Name of the directory to open. Can't be NULL.
 * @param mkdir_if_missing If true, `dir_name` will be created (if missing)
 *        before opening it.
 * @return File descriptor of the open directory, or a negative errno value
 *         on failure.
 */
int bf_opendir_at(int parent_fd, const char *dir_name, bool mkdir_if_missing);

/**
 * @brief Remove a directory from a parent directory file descriptor.
 *
 * @param parent_fd File descriptor of the parent directory to remove
 *        `dir_name` from.
 * @param dir_name Name of the directory to remove. Can't be NULL.
 * @param recursive If true, remove the content of the directory before removing
 *        the directory. If false, fails if the directory is not empty.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_rmdir_at(int parent_fd, const char *dir_name, bool recursive);

/**
 * @brief Open an acquire an exclusive file lock on `path`.
 *
 * @param path Path to the file to get a lock on, it will be created if it
 *             doesn't exist. Can't be NULL.
 * @return A file descriptor to the lock on success, or a negative errno value
 *         on failure. The caller is responsible for closing the lock file
 *         descriptor.
 */
int bf_acquire_lock(const char *path);
