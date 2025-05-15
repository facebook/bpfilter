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
 * Send a request to the given file descriptor.
 *
 * @param fd File descriptor to send the request to. Must be a valid file
 *        descriptor.
 * @param request Request to send. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_send_request(int fd, const struct bf_request *request);

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
 * Received a response from the file descriptor.
 *
 * @param fd File descriptor to receive the response from. Must be a valid file
 *        descriptor.
 * @param response Response to receive. Can't be NULL. Will be allocated by the
 *        function.
 * @return 0 on success, negative error code on failure.
 */
int bf_recv_response(int fd, struct bf_response **response);

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
