/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#define BF_RUNTIME_DIR "/run/bpfilter"
#define BF_SOCKET_PATH BF_RUNTIME_DIR "/daemon.sock"
#define BF_PIN_DIR "/sys/fs/bpf/bpfilter"

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
